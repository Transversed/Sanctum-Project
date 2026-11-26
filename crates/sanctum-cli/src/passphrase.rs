//! Passphrase input for the encrypted identity key and, in persistent mode,
//! for the host store.
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

// ── Host store passphrase (persistent mode) ──

/// systemd credential name (`LoadCredential=` / `LoadCredentialEncrypted=`).
pub const HOST_CREDENTIAL: &str = "sanctum-host-passphrase";
/// Environment variable for tests and scripts (visible to the same user).
pub const HOST_ENV_VAR: &str = "SANCTUM_HOST_PASSPHRASE";

/// The host passphrase from a systemd credential, then the environment.
fn host_from_service() -> Result<Option<Zeroizing<String>>, BoxError> {
    if let Some(dir) = std::env::var_os("CREDENTIALS_DIRECTORY") {
        let path = std::path::Path::new(&dir).join(HOST_CREDENTIAL);
        if path.is_file() {
            let raw = Zeroizing::new(
                std::fs::read_to_string(&path)
                    .map_err(|e| format!("cannot read the {HOST_CREDENTIAL} credential: {e}"))?,
            );
            return Ok(Some(Zeroizing::new(
                raw.trim_end_matches(['\n', '\r']).to_string(),
            )));
        }
    }
    Ok(std::env::var(HOST_ENV_VAR).ok().map(Zeroizing::new))
}

fn host_prompt(text: &str) -> Result<Zeroizing<String>, BoxError> {
    rpassword::prompt_password(text)
        .map(Zeroizing::new)
        .map_err(|e| {
            format!(
                "cannot read the host passphrase ({e}); under systemd, provide the \
                 `{HOST_CREDENTIAL}` credential"
            )
            .into()
        })
}

/// Passphrase of an existing host store.
pub fn read_host_existing() -> Result<Zeroizing<String>, BoxError> {
    match host_from_service()? {
        Some(p) => Ok(p),
        None => host_prompt("[sanctum] host store passphrase: "),
    }
}

/// Passphrase for a new host store (typed twice when interactive). It is
/// independent of any identity passphrase: the host holds no identity.
pub fn read_host_new() -> Result<Zeroizing<String>, BoxError> {
    let pass = match host_from_service()? {
        Some(p) => p,
        None => {
            let first = host_prompt("[sanctum] new host store passphrase: ")?;
            let again = host_prompt("[sanctum] repeat passphrase: ")?;
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
