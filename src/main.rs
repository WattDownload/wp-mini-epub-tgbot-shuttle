use shuttle_runtime::{ SecretStore, Service };

use anyhow::Result;
use teloxide::utils::markdown::escape;
use teloxide::{
    dispatching::dialogue::InMemStorage,
    prelude::*,
    types::{InlineKeyboardButton, InlineKeyboardMarkup, MessageId},
    utils::command::BotCommands,
};
use wp_mini::field::StoryField;
use wp_mini::{WattpadClient, WattpadError};

use reqwest::Client;
use std::sync::Arc;
use wp_mini_epub::{download_story_to_memory, login, AppError};

use std::time::Duration;

#[derive(BotCommands, Clone)]
#[command(rename_rule = "lowercase", description = "Available commands:")]
enum Command {
    #[command(description = "Show this help message.")]
    Help,
    #[command(description = "Start the bot and see a welcome message.")]
    Start,
    #[command(description = "Start the download process.")]
    Download,
    #[command(description = "Cancel the current operation.")]
    Cancel,
}

#[derive(Clone, Default)]
pub enum State {
    #[default]
    Start,
    ReceiveStoryId,
    ReceiveStoryConfirmation {
        story_id: String,
    },
    ReceiveImageOption {
        story_id: String,
    },
    ReceiveLoginDecision {
        story_id: String,
        embed_images: bool,
    },
    ReceiveUsername {
        story_id: String,
        embed_images: bool,
        prompt_message_id: MessageId,
    },
    ReceivePassword {
        story_id: String,
        embed_images: bool,
        username: String,
        prompt_message_id: MessageId,
    },
}

type MyDialogue = Dialogue<State, InMemStorage<State>>;
type HandlerResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

struct WattpadBot {
    bot: Bot,
    http_client: Arc<Client>,
    wattpad_client: Arc<WattpadClient>,
}

#[shuttle_runtime::async_trait]
impl Service for WattpadBot {
    async fn bind(mut self, _addr: std::net::SocketAddr) -> Result<(), shuttle_runtime::Error> {

        let handler = Update::filter_message()
            .enter_dialogue::<Message, InMemStorage<State>, State>()
            .branch(
                dptree::entry()
                    .filter_command::<Command>()
                    .endpoint(command_handler),
            )
            .branch(dptree::case![State::ReceiveStoryId].endpoint(receive_story_id))
            .branch(
                dptree::case![State::ReceiveUsername {
                    story_id,
                    embed_images,
                    prompt_message_id
                }]
                .endpoint(receive_username),
            )
            .branch(
                dptree::case![State::ReceivePassword {
                    story_id,
                    embed_images,
                    username,
                    prompt_message_id
                }]
                .endpoint(receive_password),
            );

        let callback_handler = Update::filter_callback_query()
            .enter_dialogue::<CallbackQuery, InMemStorage<State>, State>()
            .endpoint(callback_query_handler);

        Dispatcher::builder(
            self.bot,
            dptree::entry().branch(handler).branch(callback_handler),
        )
        .dependencies(dptree::deps![
            InMemStorage::<State>::new(),
            self.http_client,
            self.wattpad_client
        ])
        .enable_ctrlc_handler()
        .build()
        .dispatch()
        .await;

        Ok(())
    }
}

#[shuttle_runtime::main]
async fn main(
    #[shuttle_runtime::Secrets] secret_store: SecretStore,
) -> Result<WattpadBot, shuttle_runtime::Error> {
    let token = secret_store
        .get("TELOXIDE_TOKEN")
        .expect("TELOXIDE_TOKEN must be set");

    let bot = Bot::new(token);

    const APP_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36";
    let http_client = Arc::new(
        Client::builder()
            .user_agent(APP_USER_AGENT)
            .timeout(Duration::from_secs(300))
            .build()
            .expect("Failed to create reqwest client"),
    );

    let wattpad_client = Arc::new(WattpadClient::new());

    Ok(WattpadBot {
        bot,
        http_client,
        wattpad_client,
    })
}

fn create_logged_in_client() -> Client {
    const APP_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36";

    Client::builder()
        .user_agent(APP_USER_AGENT)
        .cookie_store(true)
        .timeout(Duration::from_secs(300))
        .build()
        .expect("Failed to create temporary reqwest client")
}

async fn command_handler(
    bot: Bot,
    dialogue: MyDialogue,
    cmd: Command,
    msg: Message,
) -> HandlerResult {
    match cmd {
        Command::Start => {
            bot.send_message(
                msg.chat.id,
                "Welcome to the Wattpad Downloader Bot! 📚\n\nUse /download to begin saving a story as an EPUB.\nUse /cancel to cancel the download.",
            )
                .await?;
        }
        Command::Help => {
            bot.send_message(msg.chat.id, Command::descriptions().to_string())
                .await?;
        }
        Command::Download => {
            bot.send_message(
                msg.chat.id,
                "Let's begin! Please send me the Wattpad Story ID.",
            )
            .await?;
            dialogue.update(State::ReceiveStoryId).await?;
        }
        Command::Cancel => {
            bot.send_message(msg.chat.id, "Operation cancelled.")
                .await?;
            dialogue.exit().await?;
        }
    }
    Ok(())
}

async fn receive_story_id(
    bot: Bot,
    dialogue: MyDialogue,
    msg: Message,
    client: Arc<WattpadClient>,
) -> HandlerResult {
    let story_id_str = match msg.text() {
        Some(text) => text.to_string(),
        None => {
            bot.send_message(msg.chat.id, "Please send the Story ID as plain text.")
                .await?;
            return Ok(());
        }
    };

    let story_id_num: u64 = match story_id_str.parse() {
        Ok(id) => id,
        Err(_) => {
            bot.send_message(
                msg.chat.id,
                "That doesn't look like a valid Story ID. Please send numbers only.",
            )
            .await?;
            return Ok(());
        }
    };

    let status_msg = bot
        .send_message(msg.chat.id, "🔍 Fetching story details...")
        .await?;

    let fields = &[
        StoryField::Title,
        StoryField::Cover,
        StoryField::Description,
        StoryField::Mature,
    ];

        match client
        .story
        .get_story_info(story_id_num, Some(fields))
        .await
    {
        Ok(info) => {
            bot.delete_message(msg.chat.id, status_msg.id).await.ok();

            // Telegram API Limits
            const MAX_CAPTION_LENGTH: usize = 1024;

            let mature_text = if info.mature.unwrap_or(false) {
                "Yes"
            } else {
                "No"
            };

            let title = info
                .title
                .unwrap_or_else(|| "No title available".to_string());
            let description = info
                .description
                .unwrap_or_else(|| "No description available.".to_string());

            // Calculate the length of the caption's "frame" (everything *except* the description).
            let title_part = format!("**{}**", escape(&title));
            let mature_part = format!("**Mature:** {}", mature_text);
            // The two `\n\n` separators add 4 characters.
            let frame_len = title_part.len() + mature_part.len() + 4;

            // Calculate the space left for the description.
            if frame_len < MAX_CAPTION_LENGTH {
                let available_space = MAX_CAPTION_LENGTH - frame_len;
                let ellipsis = "...";

                // Trim the description if it exceeds the available space.
                if description.chars().count() > available_space {
                    if available_space > ellipsis.len() {
                        // Shorten description to fit, leaving room for "..."
                        let trim_to = available_space - ellipsis.len();
                        description = description.chars().take(trim_to).collect();
                        description.push_str(ellipsis);
                    } else {
                        // Not even enough space for an ellipsis, so just clear the description.
                        description.clear();
                    }
                }
            } else {
                // If the title and mature text alone are too long, we can't include a description.
                description.clear();
            }

            let full_caption = format!(
                "{}\n\n{}\n\n{}",
                title_part,
                escape(&description),
                mature_part
            );

            // Determine if we can send the cover photo
            let maybe_photo = if let Some(cover_url_string) = info.cover {
                cover_url_string.parse().ok().map(teloxide::types::InputFile::url)
            } else {
                None
            };

            if let Some(photo) = maybe_photo {
                bot.send_photo(msg.chat.id, photo)
                    .caption(full_caption)
                    .parse_mode(teloxide::types::ParseMode::MarkdownV2)
                    .reply_markup(make_confirm_keyboard())
                    .await?;
            } else {
                // No cover, send as a single text message
                bot.send_message(msg.chat.id, full_caption)
                    .parse_mode(teloxide::types::ParseMode::MarkdownV2)
                    .reply_markup(make_confirm_keyboard())
                    .await?;
            }

            dialogue
                .update(State::ReceiveStoryConfirmation {
                    story_id: story_id_str,
                })
                .await?;
        }
        Err(WattpadError::RequestError(_)) => {
            bot.edit_message_text(
                msg.chat.id,
                status_msg.id,
                "❌ Sorry, a story with that ID could not be found. Please try another one.",
            )
            .await?;
        }
        Err(e) => {
            log::error!("Wattpad API Error: {:?}", e);
            bot.edit_message_text(
                msg.chat.id,
                status_msg.id,
                "⚠️ An unexpected error occurred while fetching story details. Please try again.",
            )
            .await?;
        }
    }

    Ok(())
}

async fn callback_query_handler(
    bot: Bot,
    dialogue: MyDialogue,
    q: CallbackQuery,
    http_client: Arc<Client>,
) -> HandlerResult {
    bot.answer_callback_query(q.id).await?;

    let data = match q.data {
        Some(d) => d,
        None => return Ok(()),
    };

    let state = dialogue.get().await?.unwrap_or_default();

    match state {
        State::ReceiveStoryConfirmation { story_id } => {
            if data == "confirm" {
                if let Some(teloxide::types::MaybeInaccessibleMessage::Regular(msg)) = q.message {
                    bot.edit_message_caption(msg.chat.id, msg.id)
                        .caption("✅ Confirmed! Let's proceed.")
                        .await?;
                }

                let keyboard = make_yes_no_keyboard();
                bot.send_message(dialogue.chat_id(), "Would you like to embed images?")
                    .reply_markup(keyboard)
                    .await?;
                dialogue
                    .update(State::ReceiveImageOption { story_id })
                    .await?;
            } else {
                if let Some(teloxide::types::MaybeInaccessibleMessage::Regular(msg)) = q.message {
                    bot.edit_message_caption(msg.chat.id, msg.id)
                        .caption("❌ Operation restarted.")
                        .await?;
                }
                bot.send_message(
                    dialogue.chat_id(),
                    "Okay, let's start over. Please send me a Wattpad Story ID.",
                )
                .await?;
                dialogue.update(State::ReceiveStoryId).await?;
            }
        }
        State::ReceiveImageOption { story_id } => {
            if let Some(teloxide::types::MaybeInaccessibleMessage::Regular(msg)) = q.message {
                let confirmation_text = if data == "yes" {
                    "✅ We'll embed images for you."
                } else {
                    "❌ We won't embed images."
                };
                bot.edit_message_text(msg.chat.id, msg.id, confirmation_text)
                    .await?;
            }

            let embed_images = data == "yes";
            let keyboard = make_yes_no_keyboard();
            bot.send_message(
                dialogue.chat_id(),
                "Do you want to log in for this download? (Required for purchased content)",
            )
            .reply_markup(keyboard)
            .await?;
            dialogue
                .update(State::ReceiveLoginDecision {
                    story_id,
                    embed_images,
                })
                .await?;
        }
        State::ReceiveLoginDecision {
            story_id,
            embed_images,
        } => {
            if let Some(teloxide::types::MaybeInaccessibleMessage::Regular(msg)) = q.message {
                let confirmation_text = if data == "yes" {
                    "✅ Proceeding with login."
                } else {
                    "❌ Proceeding without login."
                };
                bot.edit_message_text(msg.chat.id, msg.id, confirmation_text)
                    .await?;
            }

            if data == "yes" {
                let prompt_msg = bot
                    .send_message(dialogue.chat_id(), "Please send your Wattpad username.")
                    .await?;

                dialogue
                    .update(State::ReceiveUsername {
                        story_id,
                        embed_images,
                        prompt_message_id: prompt_msg.id,
                    })
                    .await?;
            } else {
                let status_msg = bot
                    .send_message(
                        dialogue.chat_id(),
                        "We got you. Starting the download process... ⏳",
                    )
                    .await?;

                trigger_epub_generation(
                    &bot,
                    dialogue.chat_id(),
                    &dialogue,
                    &story_id,
                    embed_images,
                    None,
                    Some(status_msg.id),
                    &http_client,
                )
                .await?;
            }
        }
        _ => {
            bot.send_message(
                dialogue.chat_id(),
                "Something went wrong. Please start over with /download.",
            )
            .await?;
            dialogue.exit().await?;
        }
    }

    Ok(())
}

async fn receive_username(
    bot: Bot,
    dialogue: MyDialogue,
    msg: Message,
    (story_id, embed_images, prompt_message_id): (String, bool, MessageId),
) -> HandlerResult {
    bot.delete_message(msg.chat.id, prompt_message_id)
        .await
        .ok();

    match msg.text() {
        Some(username) => {
            bot.delete_message(msg.chat.id, msg.id).await.ok();

            let new_prompt = bot
                .send_message(msg.chat.id, "Please send your password.")
                .await?;

            dialogue
                .update(State::ReceivePassword {
                    story_id,
                    embed_images,
                    username: username.to_string(),
                    prompt_message_id: new_prompt.id,
                })
                .await?;
        }
        None => {
            bot.send_message(msg.chat.id, "Please send your username as plain text.")
                .await?;
        }
    }
    Ok(())
}

async fn receive_password(
    bot: Bot,
    dialogue: MyDialogue,
    msg: Message,
    (story_id, embed_images, username, prompt_message_id): (String, bool, String, MessageId),
) -> HandlerResult {
    bot.delete_message(msg.chat.id, msg.id).await.ok();
    bot.delete_message(msg.chat.id, prompt_message_id)
        .await
        .ok();

    let password = match msg.text() {
        Some(text) => text.to_string(),
        None => {
            bot.send_message(msg.chat.id, "An error occurred. Please start over.")
                .await?;
            dialogue.exit().await?;
            return Ok(());
        }
    };

    let status_msg = bot
        .send_message(msg.chat.id, "🔐 Verifying credentials...")
        .await?;

    let logged_in_client = create_logged_in_client();

    // Attempt to log in FIRST
    match login(&logged_in_client, &username, &password).await {
        Ok(_) => {
            // Login successful, now trigger the download
            let generating_msg = bot
                .edit_message_text(
                    msg.chat.id,
                    status_msg.id,
                    format!(
                        "✅ We got you, @{}! Credentials verified. Generating EPUB now... ⏳",
                        username
                    ),
                )
                .await?;

            let credentials = Some((username, password));

            trigger_epub_generation(
                &bot,
                msg.chat.id,
                &dialogue,
                &story_id,
                embed_images,
                credentials,
                Some(generating_msg.id),
                &logged_in_client,
            )
            .await?;
        }
        Err(e) => {
            // Login failed, notify the user and restart the login process
            log::error!("Authentication failed: {:?}", e);
            bot.edit_message_text(
                msg.chat.id,
                status_msg.id,
                "❌ Authentication failed. Please check your credentials and try again.",
            )
            .await?;

            // Ask for username again
            let prompt_msg = bot
                .send_message(dialogue.chat_id(), "Please send your Wattpad username.")
                .await?;
            dialogue
                .update(State::ReceiveUsername {
                    story_id,
                    embed_images,
                    prompt_message_id: prompt_msg.id,
                })
                .await?;
        }
    }

    Ok(())
}

fn make_yes_no_keyboard() -> InlineKeyboardMarkup {
    let buttons = vec![
        InlineKeyboardButton::callback("✅ Yes", "yes"),
        InlineKeyboardButton::callback("❌ No", "no"),
    ];
    InlineKeyboardMarkup::new(vec![buttons])
}

fn make_confirm_keyboard() -> InlineKeyboardMarkup {
    let buttons = vec![
        InlineKeyboardButton::callback("✅ Confirm", "confirm"),
        InlineKeyboardButton::callback("🔄 Restart", "restart"),
    ];
    InlineKeyboardMarkup::new(vec![buttons])
}

async fn trigger_epub_generation(
    bot: &Bot,
    chat_id: ChatId,
    dialogue: &MyDialogue,
    story_id: &str,
    embed_images: bool,
    credentials: Option<(String, String)>,
    status_message_id: Option<MessageId>,
    http_client: &Client,
) -> HandlerResult {
    const CONCURRENT_CHAPTER_REQUESTS: usize = 10;
    let story_id_num: u64 = story_id.parse()?;

    if credentials.is_some() {
        log::info!("Handling authenticated EPUB request.");
    } else {
        log::info!("Handling anonymous EPUB request.");
    }

    let epub_result = download_story_to_memory(
        &http_client,
        story_id_num,
        embed_images,
        CONCURRENT_CHAPTER_REQUESTS,
    )
    .await;

    match epub_result {
        Ok(epub_bytes) => {
            if let Some(id) = status_message_id {
                bot.delete_message(chat_id, id).await.ok();
            }

            bot.send_message(
                chat_id,
                "We've generated the epub for you. Will be available soon.",
            )
            .await?;

            let filename = format!("story_{}.epub", story_id);
            let file_to_send = teloxide::types::InputFile::memory(epub_bytes).file_name(filename);

            bot.send_document(chat_id, file_to_send).await?;
        }
        Err(e) => {
            if let Some(app_error) = e.downcast_ref::<AppError>() {
                log::error!("Failed to generate EPUB: {:?}", app_error);
                let user_message = match app_error {
                    AppError::AuthenticationFailed => {
                        "Authentication failed. Please check your credentials."
                    }
                    AppError::StoryNotFound(_) => "The requested story could not be found.",
                    _ => "Sorry, something went wrong while generating the EPUB.",
                };
                bot.send_message(chat_id, user_message).await?;
            } else {
                log::error!("An unexpected error occurred: {:?}", e);
                bot.send_message(chat_id, "Sorry, an unexpected error occurred.")
                    .await?;
            }
        }
    }

    dialogue.exit().await?;
    Ok(())
}
