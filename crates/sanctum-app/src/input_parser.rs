//! Input parsing: distinguishes messages from slash commands.

/// Parsed user input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Input {
    /// Regular chat message.
    Message(String),
    /// Slash command.
    Command(SlashCommand),
    /// Empty input (ignore).
    Empty,
}

/// Recognized slash commands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlashCommand {
    /// Exit the chat session.
    Exit,
    /// Show help.
    Help,
    /// Show room status.
    Status,
    /// List connected members.
    Members,
    /// Invite a user: /invite <fingerprint> [role]
    Invite { fingerprint: String, role: Option<String> },
    /// Kick a user: /kick <fingerprint>
    Kick { fingerprint: String },
    /// Change alias: /alias <new_alias>
    Alias { new_alias: String },
    /// Unknown command.
    Unknown(String),
}

/// Parse raw user input into an Input variant.
pub fn parse_input(raw: &str) -> Input {
    let trimmed = raw.trim();

    if trimmed.is_empty() {
        return Input::Empty;
    }

    if !trimmed.starts_with('/') {
        return Input::Message(trimmed.to_string());
    }

    let parts: Vec<&str> = trimmed.splitn(3, ' ').collect();
    let cmd = parts[0].to_lowercase();

    match cmd.as_str() {
        "/exit" | "/quit" | "/q" => Input::Command(SlashCommand::Exit),
        "/help" | "/h" | "/?" => Input::Command(SlashCommand::Help),
        "/status" => Input::Command(SlashCommand::Status),
        "/members" | "/who" => Input::Command(SlashCommand::Members),
        "/invite" => {
            if parts.len() < 2 {
                Input::Command(SlashCommand::Unknown("/invite <fingerprint> [role]".into()))
            } else {
                Input::Command(SlashCommand::Invite {
                    fingerprint: parts[1].to_string(),
                    role: parts.get(2).map(|s| s.to_string()),
                })
            }
        }
        "/kick" => {
            if parts.len() < 2 {
                Input::Command(SlashCommand::Unknown("/kick <fingerprint>".into()))
            } else {
                Input::Command(SlashCommand::Kick {
                    fingerprint: parts[1].to_string(),
                })
            }
        }
        "/alias" | "/nick" => {
            if parts.len() < 2 {
                Input::Command(SlashCommand::Unknown("/alias <new_alias>".into()))
            } else {
                Input::Command(SlashCommand::Alias {
                    new_alias: parts[1].to_string(),
                })
            }
        }
        _ => Input::Command(SlashCommand::Unknown(cmd)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_regular_message() {
        assert_eq!(parse_input("Hello world"), Input::Message("Hello world".into()));
    }

    #[test]
    fn parse_message_with_leading_spaces() {
        assert_eq!(parse_input("  Hello  "), Input::Message("Hello".into()));
    }

    #[test]
    fn parse_empty() {
        assert_eq!(parse_input(""), Input::Empty);
        assert_eq!(parse_input("   "), Input::Empty);
    }

    #[test]
    fn parse_exit() {
        assert_eq!(parse_input("/exit"), Input::Command(SlashCommand::Exit));
        assert_eq!(parse_input("/quit"), Input::Command(SlashCommand::Exit));
        assert_eq!(parse_input("/q"), Input::Command(SlashCommand::Exit));
    }

    #[test]
    fn parse_exit_case_insensitive() {
        assert_eq!(parse_input("/EXIT"), Input::Command(SlashCommand::Exit));
        assert_eq!(parse_input("/Quit"), Input::Command(SlashCommand::Exit));
    }

    #[test]
    fn parse_help() {
        assert_eq!(parse_input("/help"), Input::Command(SlashCommand::Help));
        assert_eq!(parse_input("/?"), Input::Command(SlashCommand::Help));
    }

    #[test]
    fn parse_status() {
        assert_eq!(parse_input("/status"), Input::Command(SlashCommand::Status));
    }

    #[test]
    fn parse_members() {
        assert_eq!(parse_input("/members"), Input::Command(SlashCommand::Members));
        assert_eq!(parse_input("/who"), Input::Command(SlashCommand::Members));
    }

    #[test]
    fn parse_invite() {
        let input = parse_input("/invite 4A7B3C2D admin");
        assert_eq!(
            input,
            Input::Command(SlashCommand::Invite {
                fingerprint: "4A7B3C2D".into(),
                role: Some("admin".into()),
            })
        );
    }

    #[test]
    fn parse_invite_no_role() {
        let input = parse_input("/invite 4A7B3C2D");
        assert_eq!(
            input,
            Input::Command(SlashCommand::Invite {
                fingerprint: "4A7B3C2D".into(),
                role: None,
            })
        );
    }

    #[test]
    fn parse_invite_missing_args() {
        let input = parse_input("/invite");
        assert!(matches!(input, Input::Command(SlashCommand::Unknown(_))));
    }

    #[test]
    fn parse_kick() {
        let input = parse_input("/kick 4A7B3C2D");
        assert_eq!(
            input,
            Input::Command(SlashCommand::Kick {
                fingerprint: "4A7B3C2D".into(),
            })
        );
    }

    #[test]
    fn parse_alias() {
        let input = parse_input("/alias newname");
        assert_eq!(
            input,
            Input::Command(SlashCommand::Alias {
                new_alias: "newname".into(),
            })
        );
    }

    #[test]
    fn parse_unknown_command() {
        let input = parse_input("/foobar");
        assert_eq!(
            input,
            Input::Command(SlashCommand::Unknown("/foobar".into()))
        );
    }

    #[test]
    fn parse_unicode_message() {
        assert_eq!(
            parse_input("Bonjour 🌍 こんにちは"),
            Input::Message("Bonjour 🌍 こんにちは".into())
        );
    }

    #[test]
    fn slash_in_middle_is_message() {
        assert_eq!(
            parse_input("hello /world"),
            Input::Message("hello /world".into())
        );
    }
}