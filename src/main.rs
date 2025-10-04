use shuttle_runtime::{SecretStore, Service};
use std::error::Error;

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

use reqwest::{Client, ClientBuilder};
use std::sync::Arc;
use wp_mini_epub::{download_story_to_memory, login, AppError};

use log::{error, info};
use once_cell::sync::Lazy;
use regex::Regex;
use std::time::Duration;

static STORY_URL_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^https?://(?:www\.)?wattpad\.com/story/(\d+).*").unwrap());
static PART_URL_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^https?://(?:www\.)?wattpad\.com/(\d+).*").unwrap());

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
        story_id: u64,
        title: String,
    },
    ReceiveImageOption {
        story_id: u64,
        title: String,
    },
    ReceiveLoginDecision {
        story_id: u64,
        title: String,
        embed_images: bool,
    },
    ReceiveUsername {
        story_id: u64,
        title: String,
        embed_images: bool,
        prompt_message_id: MessageId,
    },
    ReceivePassword {
        story_id: u64,
        title: String,
        embed_images: bool,
        username: String,
        prompt_message_id: MessageId,
    },
}

type MyDialogue = Dialogue<State, InMemStorage<State>>;
type HandlerResult = Result<(), Box<dyn Error + Send + Sync>>;

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
                    title,
                    embed_images,
                    prompt_message_id
                }]
                .endpoint(receive_username),
            )
            .branch(
                dptree::case![State::ReceivePassword {
                    story_id,
                    title,
                    embed_images,
                    username,
                    prompt_message_id
                }]
                .endpoint(receive_password),
            )
            .branch(dptree::endpoint(unhandled_message_handler));

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

fn http_client_builder() -> ClientBuilder {
    const APP_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36";

    Client::builder()
        .user_agent(APP_USER_AGENT)
        .timeout(Duration::from_secs(300))
}

fn build_http_client() -> Client {
    http_client_builder()
        .build()
        .expect("Failed to create reqwest client")
}

fn create_logged_in_http_client() -> Client {
    http_client_builder()
        .cookie_store(true)
        .build()
        .expect("Failed to create temporary reqwest client")
}

async fn parse_story_id_from_input(input: &str, client: &WattpadClient) -> Result<u64, String> {
    // Try to match a full story URL
    if let Some(captures) = STORY_URL_REGEX.captures(input) {
        if let Some(id_match) = captures.get(1) {
            let story_id_str = id_match.as_str();
            info!("Matched story URL, found ID: {}", story_id_str);
            return story_id_str
                .parse::<u64>()
                .map_err(|_| "Invalid story ID found in URL.".to_string());
        }
    }

    // If not a story URL, try to match a chapter/part URL
    if let Some(captures) = PART_URL_REGEX.captures(input) {
        if let Some(id_match) = captures.get(1) {
            let part_id_str = id_match.as_str();
            info!("Matched part URL, found part ID: {}", part_id_str);
            let part_id = part_id_str
                .parse::<u64>()
                .map_err(|_| "Invalid chapter ID found in URL.".to_string())?;

            // Make an API call to get the main story ID
            info!("Fetching story ID for part ID: {}", part_id);
            return match client
                .story
                .get_part_info(part_id, Some(&[wp_mini::field::PartField::GroupId]))
                .await
            {
                Ok(part_info) => {
                    // Check if the API returned a valid ID string.
                    if let Some(id_string) = part_info.group_id { // `id_string` is now a String
                        info!("Successfully found story ID string: {}", id_string);

                        // This can fail if the string is not a valid number.
                        match id_string.parse::<u64>() {
                            Ok(id_num) => Ok(id_num), // If parsing succeeds, return the number.
                            Err(_) => {
                                // If parsing fails, return an error.
                                error!("API returned a non-numeric group_id: {}", id_string);
                                Err("Story ID returned by API was invalid.".to_string())
                            }
                        }
                    } else {
                        // The API returned `None`, which is still an error.
                        error!("API did not return a group_id for part {}", part_id);
                        Err("Could not find a story for that chapter URL.".to_string())
                    }
                }
                Err(_) => {
                    Err("Could not find a story associated with that chapter URL.".to_string())
                }
            };
        }
    }

    // If neither matched, assume it's a plain ID
    info!("No URL matched, attempting to parse as plain ID: {}", input);
    input
        .parse::<u64>()
        .map_err(|_| "Input is not a valid Wattpad ID or URL. Please try again.".to_string())
}

#[shuttle_runtime::main]
async fn main(
    #[shuttle_runtime::Secrets] secret_store: SecretStore,
) -> Result<WattpadBot, shuttle_runtime::Error> {
    let token = secret_store
        .get("TELOXIDE_TOKEN")
        .expect("TELOXIDE_TOKEN must be set");

    let bot = Bot::new(token);

    let http_client = Arc::new(build_http_client());
    let wattpad_client = Arc::new(WattpadClient::new());

    Ok(WattpadBot {
        bot,
        http_client,
        wattpad_client,
    })
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
                "Welcome to the WattDownload Bot! 📚\n\nUse /download to begin saving a story as an EPUB.\nUse /cancel to cancel the download.",
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
                "Let's begin! Please send me the Wattpad Story ID / Link",
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

async fn unhandled_message_handler(bot: Bot, msg: Message) -> HandlerResult {
    bot.send_message(
        msg.chat.id,
        "Sorry, I didn't understand that. Please use /download to start.",
    )
    .await?;
    Ok(())
}

async fn receive_story_id(
    bot: Bot,
    dialogue: MyDialogue,
    msg: Message,
    client: Arc<WattpadClient>,
) -> HandlerResult {
    // 1. Get the user's input text (which could be an ID, story URL, or part URL)
    let input_text = match msg.text() {
        Some(text) => text,
        None => {
            bot.send_message(msg.chat.id, "Please send a Story ID / Link")
                .await?;
            return Ok(());
        }
    };

    // 2. Send an initial "processing" message that we can edit later
    let status_msg = bot
        .send_message(msg.chat.id, "🔍 Processing your request...")
        .await?;

    // 3. Call our universal parser to get the story ID
    match parse_story_id_from_input(input_text, &client).await {
        // --- Success Case: A valid Story ID was found ---
        Ok(story_id_num) => {
            bot.edit_message_text(
                msg.chat.id,
                status_msg.id,
                "✅ ID found! Fetching story details...",
            )
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

                    let mature = info.mature.unwrap_or(false);
                    let title = info
                        .title
                        .unwrap_or_else(|| "No title available".to_string());

                    let mature_text = if mature { "Yes" } else { "No" };
                    let mut description = info
                        .description
                        .unwrap_or_else(|| "No description available.".to_string());

                    const MAX_CAPTION_LENGTH: usize = 1024;
                    let title_part = format!("**{}**", escape(&title));
                    let mature_part = format!("**Mature:** {}", mature_text);
                    let frame_len = title_part.len() + mature_part.len() + 4;

                    if frame_len < MAX_CAPTION_LENGTH {
                        let available_space = MAX_CAPTION_LENGTH - frame_len;
                        let ellipsis = "...";

                        if description.chars().count() > available_space {
                            if available_space > ellipsis.len() {
                                let trim_to = available_space - ellipsis.len();
                                description = description.chars().take(trim_to).collect();
                                description.push_str(ellipsis);
                            } else {
                                description.clear();
                            }
                        }
                    } else {
                        description.clear();
                    }

                    let full_caption = format!(
                        "{}\n\n{}\n\n{}",
                        title_part,
                        escape(&description),
                        mature_part
                    );

                    let maybe_photo = if let Some(cover_url_string) = info.cover {
                        cover_url_string
                            .parse()
                            .ok()
                            .map(teloxide::types::InputFile::url)
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
                        bot.send_message(msg.chat.id, full_caption)
                            .parse_mode(teloxide::types::ParseMode::MarkdownV2)
                            .reply_markup(make_confirm_keyboard())
                            .await?;
                    }

                    dialogue
                        .update(State::ReceiveStoryConfirmation {
                            story_id: story_id_num,
                            title,
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
                    error!("Wattpad API Error: {:?}", e);
                    bot.edit_message_text(
                        msg.chat.id,
                        status_msg.id,
                        "⚠️ An unexpected error occurred while fetching story details. Please try again.",
                    )
                        .await?;
                }
            }
        }
        Err(error_message) => {
            bot.edit_message_text(msg.chat.id, status_msg.id, format!("❌ {}", error_message))
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
        State::ReceiveStoryConfirmation { story_id, title } => {
            if data == "confirm" {
                if let Some(teloxide::types::MaybeInaccessibleMessage::Regular(msg)) = q.message {
                    bot.edit_message_caption(msg.chat.id, msg.id)
                        .caption(format!(
                            "✅ Confirmed! Let's proceed for story: \n  -> {}",
                            &title
                        ))
                        .await?;
                }

                let keyboard = make_yes_no_keyboard();
                bot.send_message(dialogue.chat_id(), "Would you like to embed images?")
                    .reply_markup(keyboard)
                    .await?;
                dialogue
                    .update(State::ReceiveImageOption { story_id, title })
                    .await?;
            } else {
                if let Some(teloxide::types::MaybeInaccessibleMessage::Regular(msg)) = q.message {
                    bot.edit_message_caption(msg.chat.id, msg.id)
                        .caption("❌ Operation restarted.")
                        .await?;
                }
                bot.send_message(
                    dialogue.chat_id(),
                    "Okay, let's start over. Please send me a Wattpad Story ID / URL",
                )
                .await?;
                dialogue.update(State::ReceiveStoryId).await?;
            }
        }
        State::ReceiveImageOption { story_id, title } => {
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
                    title,
                    embed_images,
                })
                .await?;
        }
        State::ReceiveLoginDecision {
            story_id,
            title,
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
                        title,
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
                    story_id,
                    &title,
                    embed_images,
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
    (story_id, title, embed_images, prompt_message_id): (u64, String, bool, MessageId),
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
                    title,
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
    (story_id, title, embed_images, username, prompt_message_id): (
        u64,
        String,
        bool,
        String,
        MessageId,
    ),
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

    let logged_in_client = create_logged_in_http_client();

    // Attempt to log in FIRST
    match login(&logged_in_client, &username, &password).await {
        Ok(_) => {
            info!("Logged in successfully. for username {}", username);
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

            trigger_epub_generation(
                &bot,
                msg.chat.id,
                &dialogue,
                story_id,
                &title,
                embed_images,
                Some(generating_msg.id),
                &logged_in_client,
            )
            .await?;
        }
        Err(e) => {
            // Login failed, notify the user and restart the login process
            error!("Authentication failed: {:?} for user {}", e, username);
            bot.edit_message_text(
                msg.chat.id,
                status_msg.id,
                format!("❌ Authentication failed for @{}.  Please check your credentials and try again.", username),
            )
            .await?;

            // Ask for username again
            let prompt_msg = bot
                .send_message(dialogue.chat_id(), "Please send your Wattpad username.")
                .await?;
            dialogue
                .update(State::ReceiveUsername {
                    story_id,
                    title,
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
    story_id: u64,
    title: &str,
    embed_images: bool,
    status_message_id: Option<MessageId>,
    http_client: &Client,
) -> HandlerResult {
    const CONCURRENT_CHAPTER_REQUESTS: usize = 10;

    info!("Generating EPUB for story_id: {}", story_id);

    let epub_result = download_story_to_memory(
        &http_client,
        story_id,
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

            let sanitized_title = sanitize_filename(title);
            let filename = format!("{}-{}.epub", sanitized_title, story_id);

            let file_to_send = teloxide::types::InputFile::memory(epub_bytes).file_name(filename);

            bot.send_document(chat_id, file_to_send).await?;
        }
        Err(e) => {
            if let Some(app_error) = e.downcast_ref::<AppError>() {
                error!("Failed to generate EPUB: {:?}", app_error);
                let user_message = match app_error {
                    AppError::AuthenticationFailed => {
                        "Authentication failed. Please check your credentials."
                    }
                    AppError::StoryNotFound(_) => "The requested story could not be found.",
                    _ => "Sorry, something went wrong while generating the EPUB.",
                };
                bot.send_message(chat_id, user_message).await?;
            } else {
                error!("An unexpected error occurred: {:?}", e);
                bot.send_message(chat_id, "Sorry, an unexpected error occurred.")
                    .await?;
            }
        }
    }

    dialogue.exit().await?;
    Ok(())
}

fn sanitize_filename(name: &str) -> String {
    let invalid_chars = ['<', '>', ':', '"', '/', '\\', '|', '?', '*'];
    name.chars()
        .map(|c| if invalid_chars.contains(&c) { '_' } else { c })
        .collect()
}
