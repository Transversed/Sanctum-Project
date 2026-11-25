//! `sanctum export-manifest` — export a release manifest (NFO).

/// Run the export-manifest command.
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = serde_json::json!({
        "name": "sanctum",
        "version": env!("CARGO_PKG_VERSION"),
        "description": "Encrypted group chat over Tor hidden services",
        "license": "AGPL-3.0-only",
        "repository": env!("CARGO_PKG_REPOSITORY"),
        "features": {
            "encryption": "Noise NK + X3DH + Double Ratchet",
            "transport": "Tor v3 Hidden Services",
            "storage": "none (ephemeral only in v0.1.x)",
            "identity": "Ed25519",
            "modes": ["ephemeral"],
        },
        "crates": [
            "sanctum-domain",
            "sanctum-crypto",
            "sanctum-app",
            "sanctum-infra",
            "sanctum-cli",
        ],
    });

    println!("{}", serde_json::to_string_pretty(&manifest)?);
    Ok(())
}
