//! ASCII art banner for Sanctum.

use crossterm::style::{Attribute, Color, ResetColor, SetAttribute, SetForegroundColor};
use std::io::Write;

/// Print the Sanctum banner to stdout.
pub fn print_banner() {
    let mut out = std::io::stdout();
    let _ = write!(
        out,
        "{cyan}{bold}\
   █████████    █████████   ██████   █████   █████████  ███████████ █████  █████ ██████   ██████
  ███▒▒▒▒▒███  ███▒▒▒▒▒███ ▒▒██████ ▒▒███   ███▒▒▒▒▒███▒█▒▒▒███▒▒▒█▒▒███  ▒▒███ ▒▒██████ ██████ 
 ▒███    ▒▒▒  ▒███    ▒███  ▒███▒███ ▒███  ███     ▒▒▒ ▒   ▒███  ▒  ▒███   ▒███  ▒███▒█████▒███ 
 ▒▒█████████  ▒███████████  ▒███▒▒███▒███ ▒███             ▒███     ▒███   ▒███  ▒███▒▒███ ▒███ 
  ▒▒▒▒▒▒▒▒███ ▒███▒▒▒▒▒███  ▒███ ▒▒██████ ▒███             ▒███     ▒███   ▒███  ▒███ ▒▒▒  ▒███ 
  ███    ▒███ ▒███    ▒███  ▒███  ▒▒█████ ▒▒███     ███    ▒███     ▒███   ▒███  ▒███      ▒███ 
 ▒▒█████████  █████   █████ █████  ▒▒█████ ▒▒█████████     █████    ▒▒████████   █████     █████
  ▒▒▒▒▒▒▒▒▒  ▒▒▒▒▒   ▒▒▒▒▒ ▒▒▒▒▒    ▒▒▒▒▒   ▒▒▒▒▒▒▒▒▒     ▒▒▒▒▒      ▒▒▒▒▒▒▒▒   ▒▒▒▒▒     ▒▒▒▒▒ 
{reset}{dim}  encrypted group chat over Tor hidden services{reset}
",
        cyan = SetForegroundColor(Color::Cyan),
        bold = SetAttribute(Attribute::Bold),
        dim = SetAttribute(Attribute::Dim),
        reset = ResetColor,
    );
    let _ = writeln!(out);
    let _ = out.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_does_not_panic() {
        print_banner();
    }
}