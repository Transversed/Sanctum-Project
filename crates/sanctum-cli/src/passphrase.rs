//! Passphrase input for the encrypted identity key.
//!
//! Interactive: read from the terminal without echo. Automation (scripts,
//! tests): the `SANCTUM_PASSPHRASE` environment variable is used when set.
//! Environment variables are visible to other processes of the same user
//! (`/proc/<pid>/environ`): prefer the prompt for real use.

use zeroize::Zeroizing;

/// Environment variable read instead of prompting.
pub const ENV_VAR: &str = "SANCTUM_PASSPHRASE";
/// Minimum length of a new passphrase.
pub const MIN_LEN: usize = 8;

type BoxError = Box<dyn std::error::Error>;

fn from_env() -> Option<Zeroizing<String>> {
    std::env::var(ENV_VAR).ok().map(Zeroizing::new)
}

fn prompt(text: &str) -> Result<Zeroizing<String>, BoxError> {
    rpassword::prompt_password(text)
        .map(Zeroizing::new)
        .map_err(|e| {
            format!("cannot read the passphrase ({e}); set {ENV_VAR} for non-interactive use")
                .into()
        })
}

/// Passphrase to unlock the existing identity.
pub fn read_existing() -> Result<Zeroizing<String>, BoxError> {
    match from_env() {
        Some(p) => Ok(p),
        None => prompt("[sanctum] passphrase: "),
    }
}

/// Validate a new passphrase.
pub fn check_new(passphrase: &str) -> Result<(), BoxError> {
    if passphrase.chars().count() < MIN_LEN {
        return Err(format!("the passphrase must have at least {MIN_LEN} characters").into());
    }
    Ok(())
}

/// New passphrase (typed twice when interactive).
pub fn read_new() -> Result<Zeroizing<String>, BoxError> {
    let pass = match from_env() {
        Some(p) => p,
        None => {
            let first = prompt("[sanctum] new passphrase (protects your identity key): ")?;
            let again = prompt("[sanctum] repeat passphrase: ")?;
            if *first != *again {
                return Err("passphrases do not match".into());
            }
            first
        }
    };
    check_new(&pass)?;
    Ok(pass)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_passphrases_are_refused() {
        assert!(check_new("short").is_err());
        assert!(check_new("long enough").is_ok());
        assert!(check_new("ééééééé").is_err(), "counted in characters");
    }
}
