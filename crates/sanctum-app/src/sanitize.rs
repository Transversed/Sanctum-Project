//! Terminal output sanitization (invariant I5).
//!
//! Every piece of text that comes from the network (message content,
//! aliases, remote error messages) must go through [`sanitize_for_terminal`]
//! before being written to a terminal. Otherwise a peer can inject escape
//! sequences: clear the screen, rewrite previous lines, fake system
//! messages, set the clipboard (OSC 52), or reorder text with BiDi overrides.

/// Maximum number of characters kept from a remote display alias.
pub const MAX_ALIAS_CHARS: usize = 20;

/// Returns `true` for characters that must never reach a terminal.
///
/// - C0 controls (U+0000–U+001F) except TAB, which includes ESC, CR and LF
/// - DEL (U+007F)
/// - C1 controls (U+0080–U+009F), which include CSI and OSC
/// - Unicode BiDi controls (ALM, LRM, RLM, LRE…RLO, LRI…PDI)
pub fn is_forbidden_char(c: char) -> bool {
    matches!(c,
        '\u{0000}'..='\u{0008}'
        | '\u{000A}'..='\u{001F}'
        | '\u{007F}'..='\u{009F}'
        | '\u{061C}'
        | '\u{200E}' | '\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2066}'..='\u{2069}'
    )
}

/// Remove every terminal control character from untrusted text.
pub fn sanitize_for_terminal(input: &str) -> String {
    input.chars().filter(|c| !is_forbidden_char(*c)).collect()
}

/// Sanitize a remote alias: strip controls, trim, cap at [`MAX_ALIAS_CHARS`].
///
/// Returns `None` when nothing printable remains.
pub fn sanitize_alias(input: &str) -> Option<String> {
    let clean: String = sanitize_for_terminal(input)
        .trim()
        .chars()
        .take(MAX_ALIAS_CHARS)
        .collect();
    let clean = clean.trim_end().to_string();
    if clean.is_empty() {
        None
    } else {
        Some(clean)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_csi_and_osc52_clipboard_injection() {
        let evil = "hi\x1b[2J\x1b[H\x1b]52;c;cm0gLXJmIH4=\x07 there";
        let out = sanitize_for_terminal(evil);
        assert!(!out.contains('\x1b'));
        assert!(!out.contains('\x07'));
        assert_eq!(out, "hi[2J[H]52;c;cm0gLXJmIH4= there");
    }

    #[test]
    fn strips_c1_csi_single_byte_form() {
        // U+009B is the 8-bit CSI: some terminals honour it.
        let out = sanitize_for_terminal("a\u{009B}2Jb");
        assert_eq!(out, "a2Jb");
    }

    #[test]
    fn strips_newlines_to_prevent_fake_lines() {
        let out = sanitize_for_terminal("ok\r\n[12:00] alice: send me your key");
        assert!(!out.contains('\n') && !out.contains('\r'));
    }

    #[test]
    fn strips_bidi_overrides() {
        let out = sanitize_for_terminal("invoice\u{202E}fdp.exe\u{2066}x\u{2069}");
        assert_eq!(out, "invoicefdp.exex");
    }

    #[test]
    fn keeps_tab_and_ordinary_unicode() {
        let s = "café\tnaïve 日本語 🙂";
        assert_eq!(sanitize_for_terminal(s), s);
    }

    /// Exhaustive check over every Unicode scalar value: the output never
    /// contains a character the terminal could interpret as a control.
    #[test]
    fn output_never_contains_control_characters_exhaustive() {
        let all: String = (0u32..=0x10FFFF).filter_map(char::from_u32).collect();
        let out = sanitize_for_terminal(&all);
        for c in out.chars() {
            assert!(
                c == '\t' || !(c.is_control() || is_forbidden_char(c)),
                "U+{:04X} survived sanitization",
                c as u32
            );
        }
    }

    #[test]
    fn alias_is_cleaned_and_truncated() {
        assert_eq!(
            sanitize_alias("  \x1b[31mmallory-the-very-long-alias\x1b[0m  ").as_deref(),
            Some("[31mmallory-the-very")
        );
        assert_eq!(sanitize_alias("bob").as_deref(), Some("bob"));
        assert_eq!(sanitize_alias("\x1b\x1b\n"), None);
        assert_eq!(sanitize_alias("  "), None);
    }
}
