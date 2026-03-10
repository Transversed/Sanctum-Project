# Sanctum Runbook

Guide opérationnel pour installer, configurer et diagnostiquer Sanctum.

## Installation

### 1. Installer Tor

```bash
# Automatique
./scripts/setup-tor.sh

# Manuel (Debian/Ubuntu)
sudo apt install tor
sudo systemctl enable tor
sudo systemctl start tor
```

Vérifier que le control port est activé dans `/etc/tor/torrc` :

```
ControlPort 9051
CookieAuthentication 1
```

### 2. Builder Sanctum

```bash
# Debug
cargo build --workspace

# Release (statique)
cargo build --release --target x86_64-unknown-linux-musl

# Copier le binaire
cp target/x86_64-unknown-linux-musl/release/sanctum /usr/local/bin/
```

### 3. Initialiser un profil

```bash
sanctum init --alias alice
# Crée ~/.sanctum/ avec permissions 0700
```

### 4. Importer une clé PGP

```bash
sanctum identity import ~/.gnupg/signing.key
sanctum identity show
# Affiche : [sanctum] fingerprint: [4A7B...5A6B]
```

## Héberger une room

### Room éphémère (zéro trace)

```bash
sanctum host create ops-room --mode ephemeral --chat
```

- Aucun fichier créé dans `~/.sanctum/data/`
- Les messages existent uniquement en RAM
- Tout disparaît à l'arrêt

### Room persistante (backlog chiffré)

```bash
sanctum host create ops-room --mode persistent \
    --backlog-max 500 --backlog-hours 72 --chat
```

- Backlog chiffré dans `~/.sanctum/data/db.sqlite`
- GC automatique toutes les 15 minutes
- Les messages de plus de 72h sont purgés

### Inviter un membre

```bash
# Sur le host
sanctum room invite <room_id> <fingerprint_bob> --role member
# → Affiche un token base64url

# Transmettre le token à Bob via un canal sécurisé (Signal, en personne, etc.)
```

## Rejoindre une room

```bash
sanctum join <invite_token>
# → Connexion Tor → Handshake Noise → Auth PGP → Session interactive
```

## Diagnostics

### Vérifier l'état du système

```bash
sanctum status
```

Affiche : profil, identité, ports Tor, configuration host.

### Vérifier la connectivité Tor

```bash
# SOCKS proxy fonctionne ?
curl --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip

# Control port accessible ?
echo 'PROTOCOLINFO' | nc 127.0.0.1 9051
```

### Problèmes courants

| Symptôme | Cause probable | Solution |
|----------|---------------|----------|
| "Tor unavailable" | Tor daemon pas lancé | `sudo systemctl start tor` |
| "cookie auth failed" | Permissions cookie | `sudo usermod -a -G debian-tor $USER` |
| "connection refused :9738" | Firewall local | Vérifier que localhost:9738 est ouvert |
| "nonce already used" | Bug de replay ou clock skew | Vérifier l'horloge système (`timedatectl`) |
| "fingerprint not authorized" | Pas invité | Vérifier le token avec l'host |
| "room full" | max_members atteint | Host doit augmenter la limite |
| Terminal cassé après crash | Raw mode pas restauré | `reset` dans le terminal |

### Vérifier le mode éphémère (AT-07)

```bash
./scripts/check-no-disk-writes.sh target/release/sanctum
```

### Logs

Par défaut, les logs sont désactivés. Pour activer :

```bash
sanctum --log-level debug host create test-room --chat
# Ou via config.toml :
# [logging]
# level = "debug"
```

Les logs n'incluent **jamais** de secrets (clés, fingerprints complets, contenus de messages).

## Maintenance

### Purge manuelle du backlog

```sql
-- Via sqlite3 (mode persistant uniquement)
sqlite3 ~/.sanctum/data/db.sqlite
DELETE FROM messages WHERE stored_at < strftime('%s', 'now') - 86400;
VACUUM;
```

### Réinitialiser le profil

```bash
rm -rf ~/.sanctum/
sanctum init --alias alice
```

### Mettre à jour

```bash
git pull
cargo build --release --target x86_64-unknown-linux-musl
cp target/x86_64-unknown-linux-musl/release/sanctum /usr/local/bin/
```