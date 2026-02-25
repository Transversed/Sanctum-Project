# Sanctum CLI — Documentation Complète

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Rôle dans l'architecture](#2-rôle-dans-larchitecture)
3. [Structure des fichiers](#3-structure-des-fichiers)
4. [Les dépendances](#4-les-dépendances)
5. [main.rs — Le point d'entrée](#5-mainrs--le-point-dentrée)
   - 5.1 [Le parsing Clap](#51-le-parsing-clap)
   - 5.2 [Le panic hook](#52-le-panic-hook)
   - 5.3 [Le signal handler](#53-le-signal-handler)
   - 5.4 [Le runtime Tokio](#54-le-runtime-tokio)
6. [banner.rs — L'ASCII art](#6-bannerrs--lascii-art)
7. [config.rs — La configuration](#7-configrs--la-configuration)
   - 7.1 [Les sections](#71-les-sections)
   - 7.2 [La précédence](#72-la-précédence)
   - 7.3 [Le fichier config.toml](#73-le-fichier-configtoml)
8. [Les commandes](#8-les-commandes)
   - 8.1 [init — Initialiser un profil](#81-init--initialiser-un-profil)
   - 8.2 [identity — Gérer les clés](#82-identity--gérer-les-clés)
   - 8.3 [host — Héberger une room](#83-host--héberger-une-room)
   - 8.4 [join — Rejoindre une room](#84-join--rejoindre-une-room)
   - 8.5 [chat — Session interactive](#85-chat--session-interactive)
   - 8.6 [room — Gestion des rooms](#86-room--gestion-des-rooms)
   - 8.7 [send — Envoi non-interactif](#87-send--envoi-non-interactif)
   - 8.8 [read — Lecture non-interactif](#88-read--lecture-non-interactif)
   - 8.9 [status — Statut système](#89-status--statut-système)
   - 8.10 [export-manifest — Manifeste JSON](#810-export-manifest--manifeste-json)
9. [Le câblage des adapters](#9-le-câblage-des-adapters)
10. [Flux utilisateur complet](#10-flux-utilisateur-complet)
11. [Résumé des tests](#11-résumé-des-tests)

---

## 1. Vue d'ensemble

Le crate `sanctum-cli` est le **binaire exécutable** de Sanctum. C'est lui que l'utilisateur lance dans son terminal. Son rôle est triple :

- **Parser** les arguments de la ligne de commande (via Clap)
- **Câbler** les adapters de l'infra vers les services de l'app
- **Orchestrer** le cycle de vie : démarrage, signal handling, shutdown propre

Le binaire s'appelle `sanctum` et expose une interface à la Unix : sous-commandes, flags, pipes.

```
$ sanctum --help
$ sanctum init --alias alice
$ sanctum host create my-room --mode ephemeral --chat
$ sanctum join <invite_token>
$ sanctum chat <room_id>
$ sanctum status
```

---

## 2. Rôle dans l'architecture

```
┌──────────────────────────────────────────────┐
│  CLI (ici) — sanctum-cli                     │
│    Parse les arguments (Clap)                │
│    Câble les adapters (infra → app)          │
│    Gère le lifecycle (signals, shutdown)     │
├──────────────────────────────────────────────┤
│  APP — sanctum-app                           │
│    Services (Auth, Room, Message, Host, etc.)│
├──────────────────────────────────────────────┤
│  INFRA — sanctum-infra                       │
│    Adapters concrets (Tor, SQLite, Terminal) │
├──────────────────────────────────────────────┤
│  DOMAIN — sanctum-domain                     │
│    Entités, Ports (traits), Erreurs          │
├──────────────────────────────────────────────┤
│  CRYPTO — sanctum-crypto                     │
│    AEAD, Noise, X3DH, Double Ratchet         │
└──────────────────────────────────────────────┘
```

La CLI est la **seule couche qui connaît tout le monde**. Elle importe domain, app, et infra. C'est ici que l'inversion de dépendances se matérialise : la CLI instancie les adapters concrets (infra) et les passe aux services (app) qui ne connaissent que les traits (domain).

---

## 3. Structure des fichiers

```
crates/sanctum-cli/
├── Cargo.toml
└── src/
    ├── main.rs                    ← Point d'entrée, Clap, signals
    ├── banner.rs                  ← ASCII art Sanctum
    ├── config.rs                  ← Configuration TOML + défauts
    └── commands/
        ├── mod.rs                 ← Re-exports
        ├── init.rs                ← sanctum init
        ├── identity.rs            ← sanctum identity *
        ├── host.rs                ← sanctum host *
        ├── join.rs                ← sanctum join
        ├── chat.rs                ← sanctum chat ★
        ├── room.rs                ← sanctum room *
        ├── send.rs                ← sanctum send
        ├── read.rs                ← sanctum read
        ├── status.rs              ← sanctum status
        └── export_manifest.rs     ← sanctum export-manifest
```

15 fichiers au total. Le `commands/` contient un fichier par sous-commande — c'est le pattern standard Clap.

---

## 4. Les dépendances

| Dépendance | Rôle |
|-----------|------|
| `sanctum-domain` | Entités (RoomId, Fingerprint, etc.) |
| `sanctum-app` | Services (RoomService, ChatSession, etc.) |
| `sanctum-infra` | Adapters (TorController, TerminalRenderer, etc.) |
| `clap` (derive) | Parsing CLI avec macros dérivées |
| `tokio` (full + signal) | Runtime async + gestion Ctrl-C |
| `tokio-util` | CancellationToken pour shutdown coordonné |
| `toml` | Parsing du fichier config.toml |
| `dirs` | Répertoire home portable (~/.sanctum/) |
| `tracing-subscriber` | Logging configurable |
| `crossterm` | Restauration terminal dans le panic hook |
| `serde` / `serde_json` | Sérialisation config et manifeste |

---

## 5. main.rs — Le point d'entrée

### 5.1 Le parsing Clap

Clap utilise le pattern **derive** : les structs Rust deviennent des parsers CLI automatiquement.

```rust
#[derive(Parser)]
struct Cli {
    #[arg(long, global = true)]
    config: Option<String>,       // --config /path/to/config.toml

    #[arg(short, long, global = true)]
    log_level: String,            // -l debug / --log-level warn

    #[arg(long, global = true)]
    no_banner: bool,              // --no-banner

    #[command(subcommand)]
    command: Commands,            // init | host | join | chat | ...
}
```

Les flags `global = true` sont disponibles pour toutes les sous-commandes :
```bash
sanctum --no-banner --log-level debug host create my-room
```

Les sous-commandes sont un enum :
```rust
enum Commands {
    Init { alias: Option<String> },
    Identity { action: IdentityAction },
    Host { action: HostAction },
    Join { token: String, no_chat: bool },
    Chat { room_id: String, backlog: u32 },
    Room { action: RoomAction },
    Send { room_id: String, message: String },
    Read { room_id: String, follow: bool, last: Option<u32>, json: bool },
    Status,
    ExportManifest,
}
```

Clap génère automatiquement le `--help`, la validation des arguments, et les messages d'erreur.

### 5.2 Le panic hook

Si Sanctum panique (bug), le terminal pourrait rester en mode raw (curseur invisible, pas d'écho). Le panic hook restaure le terminal avant d'afficher l'erreur :

```
Panic !
    │
    ▼
1. crossterm::disable_raw_mode()  → restaure l'écho
2. crossterm::cursor::Show        → rend le curseur visible
3. Affiche "[sanctum] fatal error — secrets may still be in memory"
4. Appelle le hook par défaut (stack trace)
```

Le message "secrets may still be in memory" est un rappel : en cas de panic, `zeroize` n'est pas garanti d'avoir été appelé sur toutes les clés.

### 5.3 Le signal handler

Ctrl-C (SIGINT) et SIGTERM sont interceptés pour un shutdown propre :

```rust
let shutdown = CancellationToken::new();
let shutdown_clone = shutdown.clone();
tokio::spawn(async move {
    tokio::signal::ctrl_c().await.ok();
    shutdown_clone.cancel();
});
```

Le même `CancellationToken` est passé à toutes les commandes. Quand l'utilisateur fait Ctrl-C :

```
Ctrl-C
  │
  ▼
Signal handler → shutdown.cancel()
  │
  ├──► host command : arrête le host, ferme les connexions
  ├──► chat command : ferme le ChatSession, restaure le terminal
  ├──► join command : annule la connexion en cours
  └──► toute commande async : sort de son await
```

### 5.4 Le runtime Tokio

La CLI construit un runtime multi-thread manuellement (pas `#[tokio::main]`) pour contrôler la séquence :

```
1. Parser les arguments (synchrone)
2. Installer le panic hook (synchrone)
3. Afficher le banner (synchrone)
4. Charger la config (synchrone)
5. Construire le runtime Tokio
6. Lancer la commande (async, dans le runtime)
7. Récupérer le résultat
8. Exit avec code 0 ou 1
```

Cette séquence garantit que le terminal est propre avant tout code async.

---

## 6. banner.rs — L'ASCII art

```
   █████████    █████████   ██████   █████   █████████  ███████████ █████  █████ ██████   ██████
  ███▒▒▒▒▒███  ███▒▒▒▒▒███ ▒▒██████ ▒▒███   ███▒▒▒▒▒███▒█▒▒▒███▒▒▒█▒▒███  ▒▒███ ▒▒██████ ██████ 
 ▒███    ▒▒▒  ▒███    ▒███  ▒███▒███ ▒███  ███     ▒▒▒ ▒   ▒███  ▒  ▒███   ▒███  ▒███▒█████▒███ 
 ▒▒█████████  ▒███████████  ▒███▒▒███▒███ ▒███             ▒███     ▒███   ▒███  ▒███▒▒███ ▒███ 
  ▒▒▒▒▒▒▒▒███ ▒███▒▒▒▒▒███  ▒███ ▒▒██████ ▒███             ▒███     ▒███   ▒███  ▒███ ▒▒▒  ▒███ 
  ███    ▒███ ▒███    ▒███  ▒███  ▒▒█████ ▒▒███     ███    ▒███     ▒███   ▒███  ▒███      ▒███ 
 ▒▒█████████  █████   █████ █████  ▒▒█████ ▒▒█████████     █████    ▒▒████████   █████     █████
  ▒▒▒▒▒▒▒▒▒  ▒▒▒▒▒   ▒▒▒▒▒ ▒▒▒▒▒    ▒▒▒▒▒   ▒▒▒▒▒▒▒▒▒     ▒▒▒▒▒      ▒▒▒▒▒▒▒▒   ▒▒▒▒▒     ▒▒▒▒▒ 
  encrypted group chat over Tor hidden services
```

Affiché au démarrage en cyan bold. Désactivable avec `--no-banner` ou `[ui] banner = false` dans la config.

---

## 7. config.rs — La configuration

### 7.1 Les sections

La config est structurée en 8 sections, chacune avec ses défauts :

| Section | Champs clés | Défauts |
|---------|------------|---------|
| `[identity]` | alias, pgp_key_id | "anon", "" |
| `[tor]` | control_port, socks_port | 9051, 9050 |
| `[network]` | ping_interval, timeout | 60s, 180s |
| `[host]` | default_mode, listen_port, max_connections | "ephemeral", 9738, 20 |
| `[storage]` | data_dir, db_max_size_mb | "~/.sanctum/data", 256 |
| `[logging]` | level, output | "off", "stdout" |
| `[chat]` | auto_chat_on_join, backlog_display, timestamp_format | true, 50, "%H:%M" |
| `[ui]` | banner, color | true, true |

Chaque champ a un défaut raisonnable. Un fichier config vide (ou absent) fonctionne parfaitement.

### 7.2 La précédence

```
CLI flags  >  Env vars (SANCTUM_*)  >  config.toml  >  défauts compilés
  (P0)            (P1)                    (P2)              (P3)
```

Exemple :
```bash
# Config dit socks_port = 9050
# Env dit SANCTUM_TOR_SOCKS_PORT=19050
# CLI dit --socks-port 29050

# Résultat : 29050 (CLI gagne)
```

Si le fichier config n'existe pas ou est invalide, les défauts compilés prennent le relais avec un warning.

### 7.3 Le fichier config.toml

Généré par `sanctum init`, stocké à `~/.sanctum/config.toml` avec permissions 0600 :

```toml
[identity]
alias = "alice"

[tor]
control_port = 9051
socks_port = 9050

[host]
default_mode = "ephemeral"
listen_port = 9738

[chat]
auto_chat_on_join = true
backlog_display = 50
```

---

## 8. Les commandes

### 8.1 init — Initialiser un profil

```bash
sanctum init [--alias alice]
```

Crée la structure de répertoire Sanctum :

```
~/.sanctum/           (0700)
├── config.toml       (0600)
├── keys/             (0700)
│   └── signing.key   (0600, après import)
└── data/             (0700)
    └── db.sqlite     (0600, mode persistant)
```

**Sécurité** : les permissions Unix sont strictes dès la création. Aucun autre utilisateur ne peut lire les fichiers.

Si le profil existe déjà, la commande refuse de l'écraser (un `--force` sera ajouté plus tard).

### 8.2 identity — Gérer les clés

```bash
sanctum identity import <keyfile>   # Importer une clé
sanctum identity show               # Afficher le fingerprint
sanctum identity generate           # Générer une identité de test
```

Le flux d'import :

```
keyfile (≥32 bytes)
    │
    ▼
Lecture du fichier
    │
    ▼
Extraction des 32 premiers bytes → signing key
    │
    ▼
IdentityAdapter::from_key(key)
    │
    ▼
Dérivation du fingerprint (SHA-256)
    │
    ▼
Stockage dans ~/.sanctum/keys/signing.key (0600)
    │
    ▼
Affiche : "[sanctum] key imported: [4A7B..5A6B]"
```

En production (v0.2), l'import parsera un vrai fichier PGP via sequoia-openpgp et extraira la sous-clé de signature Ed25519.

`identity generate` crée une identité aléatoire pour les tests — ce n'est pas une vraie clé PGP.

### 8.3 host — Héberger une room

```bash
sanctum host create my-room [options]
sanctum host status
sanctum host stop
```

Options de `host create` :

| Flag | Défaut | Description |
|------|--------|------------|
| `--mode` | ephemeral | ephemeral ou persistent |
| `--port` | 9738 | Port du hidden service |
| `--max-members` | 10 | Capacité max |
| `--backlog-max` | 500 | Messages backlog (persistent) |
| `--backlog-hours` | 72 | Âge max backlog |
| `--chat` | false | Ouvrir le chat interactif immédiatement |

Le flux de `host create` :

```
1. Créer le RoomConfig (valider, clamper les valeurs)
2. Créer le RoomService + Room (avec l'owner = host)
3. Initialiser le TorController
4. Créer le hidden service → obtenir l'adresse .onion
5. Démarrer le HostService (routage, connexions)
6. Si --chat : lancer la ChatSession interactive
7. Attendre le shutdown (Ctrl-C)
8. Détruire le hidden service
9. Cleanup
```

### 8.4 join — Rejoindre une room

```bash
sanctum join <invite_token> [--no-chat]
```

Par défaut, `join` ouvre automatiquement la session interactive après authentification réussie. C'est le comportement voulu dans 95% des cas.

`--no-chat` permet de rejoindre sans ouvrir le chat (pour les scripts ou le debug).

Le flux prévu :

```
1. Décoder le token base64url → InviteToken
2. Valider : fingerprint match, pas expiré
3. Connecter via Tor SOCKS5 à l'adresse .onion
4. Noise NK handshake (vérifier server_id)
5. PGP challenge-response (prouver son identité)
6. Recevoir l'AuthResult (rôle, room state, bundles)
7. X3DH avec chaque pair → établir les sessions ratchet
8. Si --chat (défaut) : lancer ChatSession
```

### 8.5 chat — Session interactive ★

```bash
sanctum chat <room_id> [--backlog 50]
```

C'est la commande **cœur** de Sanctum — l'expérience utilisateur principale. Elle crée un `ChatSession` avec un `TerminalLineRenderer` et lance les boucles async (input, network, render, maintenance).

```
sanctum chat abc123
    │
    ▼
Charger la room depuis le storage
    │
    ▼
Se connecter au host (si pas déjà connecté)
    │
    ▼
Créer SessionConfig + ChatSession<TerminalLineRenderer>
    │
    ▼
init_ui() → affiche le header
    │
    ▼
Démarrer les 4 boucles async :
    ├── input_loop (UiPort.read_input → parse → event_tx)
    ├── network_recv_loop (TransportPort → decrypt → event_tx)
    ├── render_loop (event_rx → UiPort.print_*)
    ├── maintenance_loop (GC backlog, si persistant)
    │
    ▼
[Session active — l'utilisateur chatte]
    │
    ▼
/exit ou Ctrl-C → shutdown.cancel()
    │
    ▼
cleanup_ui() → restaure le terminal
zeroize → efface les secrets
```

### 8.6 room — Gestion des rooms

```bash
sanctum room list                              # Lister les rooms connues
sanctum room members <room_id>                 # Lister les membres
sanctum room invite <room_id> <fp> [--role]    # Inviter
sanctum room revoke <room_id> <fp>             # Révoquer
```

Ces commandes sont non-interactives. Elles chargent la room depuis le storage, effectuent l'opération, et quittent.

L'invitation est **toujours hors session** : le token généré doit être transmis par un canal sécurisé (Signal, email chiffré, en personne).

### 8.7 send — Envoi non-interactif

```bash
sanctum send <room_id> "Hello from a script"
```

Mode one-shot pour les scripts et les bots. Connecte, envoie, déconnecte. Utilise `NullUiAdapter` (pas de rendu terminal).

### 8.8 read — Lecture non-interactif

```bash
sanctum read <room_id>                    # Derniers 50 messages
sanctum read <room_id> --last 100         # Derniers 100
sanctum read <room_id> --follow           # Streaming (comme tail -f)
sanctum read <room_id> --json             # Sortie JSON pour scripts
```

Modes :
- **Batch** (défaut) : affiche les N derniers messages du backlog et quitte
- **Follow** : reste connecté et affiche les messages en temps réel
- **JSON** : sortie structurée pour le piping Unix

Combinable : `sanctum read room --follow --json | jq '.content'`

### 8.9 status — Statut système

```bash
sanctum status
```

Affiche un résumé de l'état du système :

```
[sanctum] system status
  profile:  initialized
  home:     /home/alice/.sanctum
  alias:    alice
  identity: imported
  tor:      socks=127.0.0.1:9050, control=127.0.0.1:9051
  tor conn: connected ✓
  host:     port=9738, mode=ephemeral
```

### 8.10 export-manifest — Manifeste JSON

```bash
sanctum export-manifest
```

Produit un JSON structuré décrivant le build :

```json
{
  "name": "sanctum",
  "version": "0.1.0",
  "license": "AGPL-3.0",
  "features": {
    "encryption": "Noise NK + X3DH + Double Ratchet",
    "transport": "Tor v3 Hidden Services",
    "storage": "SQLite + AES-256-GCM"
  },
  "crates": ["sanctum-domain", "sanctum-crypto", "sanctum-app", "sanctum-infra", "sanctum-cli"]
}
```

Utile pour les releases, la documentation automatique, et l'intégration CI.

---

## 9. Le câblage des adapters

C'est le rôle le plus important de la CLI : connecter les implémentations concrètes aux traits abstraits. Voici comment chaque commande câble ses adapters :

```
sanctum host create --mode ephemeral
    │
    ▼
storage    = MemoryStorageAdapter::new(500)     ← infra
identity   = IdentityAdapter::from_key(key)     ← infra
tor        = TorController::new(config)          ← infra
ui         = TerminalLineRenderer::new()         ← infra
    │
    ▼
room_svc   = RoomService::new()                  ← app (utilise storage via trait)
host_svc   = HostService::new(room, event_tx)    ← app (utilise transport via trait)
chat       = ChatSession::new(config, ui, ...)   ← app (utilise ui via trait)
```

```
sanctum host create --mode persistent
    │
    ▼
storage    = SqliteStorageAdapter::open(path)    ← infra (seul changement !)
identity   = IdentityAdapter::from_key(key)      ← infra
tor        = TorController::new(config)           ← infra
ui         = TerminalLineRenderer::new()          ← infra
    │
    ▼
[même services app qu'en éphémère]
```

La seule différence entre éphémère et persistant au niveau du câblage : `MemoryStorageAdapter` vs `SqliteStorageAdapter`. Les services app ne changent pas une seule ligne.

```
sanctum send (non-interactif)
    │
    ▼
ui = NullUiAdapter        ← pas de terminal
[reste identique]
```

---

## 10. Flux utilisateur complet

Voici le parcours complet d'un utilisateur, de l'installation au chat :

```
ALICE (host)                               BOB (client)

$ sanctum init --alias alice               $ sanctum init --alias bob
  → ~/.sanctum/ créé                         → ~/.sanctum/ créé

$ sanctum identity import key.gpg          $ sanctum identity import key.gpg
  → fingerprint: [4A7B..5A6B]               → fingerprint: [8C3D..2E9F]

$ sanctum host create ops-room --chat
  → Room créée: ops-room (éphémère)
  → Tor HS: abc123...xyz.onion:9738
  → Session interactive ouverte
  │
  │  [Alice génère un invite pour Bob]
  │
  ├──► sanctum room invite ops-room 8C3D...2E9F
  │    → Token: eyJyb29tX2lkIjoiYWJj...
  │    → [Alice envoie le token à Bob via Signal]
  │
  │                                        $ sanctum join eyJyb29tX2lkIjoiYWJj...
  │                                          → Connexion Tor → abc123.onion
  │                                          → Noise NK handshake ✓
  │◄─────────────────────────────────────────  PGP auth challenge-response ✓
  │                                          → X3DH avec Alice ✓
  │                                          → Session interactive ouverte
  │                                          │
  │  ── bob a rejoint la room ──             │  Connected to ops-room (1 peer)
  │                                          │
  │  [14:30] alice: bienvenue bob !          │  [14:30] alice: bienvenue bob !
  │                                          │  [14:31] bob: merci !
  │  [14:31] bob: merci !                    │
  │                                          │
  │  /exit                                   │  /exit
  │  Session ended. Secrets cleared.         │  Session ended. Secrets cleared.
```

---

## 11. Résumé des tests

| Module | Tests | Ce qu'ils vérifient |
|--------|-------|-------------------|
| **config** | 4 | Défauts corrects, parsing TOML, fichier manquant → défauts, home dir contient "sanctum" |
| **banner** | 1 | Ne panique pas |
| **Total** | **5** | |

Les commandes elles-mêmes sont testées principalement par des tests d'intégration (Sprint 6) qui lancent le binaire et vérifient le comportement end-to-end.

### Compteur global du projet

| Crate | Tests |
|-------|-------|
| sanctum-domain | 23 |
| sanctum-crypto | 37 |
| sanctum-app | 46 |
| sanctum-infra | 45 |
| sanctum-cli | 5 |
| **Total** | **156** |
