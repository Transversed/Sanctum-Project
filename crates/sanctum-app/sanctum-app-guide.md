# Sanctum App — Documentation Complète

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Rôle dans l'architecture](#2-rôle-dans-larchitecture)
3. [Structure des fichiers](#3-structure-des-fichiers)
4. [Les dépendances](#4-les-dépendances)
5. [AuthService — L'authentification PGP](#5-authservice--lauthentification-pgp)
6. [RoomService — La gestion des rooms](#6-roomservice--la-gestion-des-rooms)
7. [MessageService — Le traitement des messages E2E](#7-messageservice--le-traitement-des-messages-e2e)
8. [HostService — Le relais central](#8-hostservice--le-relais-central)
9. [ClientService — La machine à états du client](#9-clientservice--la-machine-à-états-du-client)
10. [InputParser — L'interprétation des saisies](#10-inputparser--linterprétation-des-saisies)
11. [ChatSession — L'orchestrateur](#11-chatsession--lorchestateur)
12. [Comment les services interagissent](#12-comment-les-services-interagissent)
13. [Résumé des 46 tests](#13-résumé-des-46-tests)

---

## 1. Vue d'ensemble

Le crate `sanctum-app` est la **couche application** de Sanctum. Il orchestre les entités et les ports du domain en **use cases** concrets : authentifier un utilisateur, gérer une room, chiffrer et router un message, animer une session de chat interactive.

**Ce qu'il fait** :
- Coordonne les appels aux ports (CryptoPort, StoragePort, IdentityPort, etc.)
- Implémente la logique métier qui implique plusieurs entités
- Gère les machines à états (connexion, authentification, session)
- Orchestre les tâches async concurrentes (réseau, saisie, rendu, maintenance)

**Ce qu'il ne fait PAS** :
- Aucun accès direct au réseau (délégué à TransportPort)
- Aucune crypto concrète (délégué à CryptoPort via sanctum-crypto)
- Aucun stockage concret (délégué à StoragePort)
- Aucune interaction terminal (délégué à UiPort)

---

## 2. Rôle dans l'architecture

```
┌──────────────────────────────────────────────┐
│  CLI (sanctum-cli)                           │
│    Appelle les services, câble les adapters  │
├──────────────────────────────────────────────┤
│  APP (ici) — sanctum-app                     │
│    AuthService, RoomService, MessageService  │
│    HostService, ClientService, ChatSession   │
│    InputParser                               │
├──────────────────────────────────────────────┤
│  DOMAIN (sanctum-domain)                     │
│    Entities, Ports (traits), Errors, Events  │
├──────────────────────────────────────────────┤
│  CRYPTO (sanctum-crypto)                     │
│    AEAD, KDF, Noise, X3DH, Double Ratchet    │
├──────────────────────────────────────────────┤
│  INFRA (sanctum-infra)                       │
│    Adapters concrets (Tor, SQLite, PGP, etc.)│
└──────────────────────────────────────────────┘
```

La couche App ne dépend **que** du domain. Elle ne connaît pas sanctum-crypto ni sanctum-infra. Elle parle uniquement aux **traits** (CryptoPort, StoragePort, etc.) et c'est la couche CLI qui câble les implémentations concrètes au démarrage. C'est l'**inversion de dépendances** en action.

---

## 3. Structure des fichiers

```
crates/sanctum-app/
├── Cargo.toml
└── src/
    ├── lib.rs              ← Re-exports
    ├── auth_service.rs     ← Challenge-response PGP
    ├── room_service.rs     ← CRUD rooms, membres, invitations
    ├── message_service.rs  ← Enveloppes E2E, padding, anti-replay
    ├── host_service.rs     ← Relais central, routage, connexions
    ├── client_service.rs   ← Machine à états du client
    ├── input_parser.rs     ← Slash commands et parsing
    └── chat_session.rs     ← Orchestrateur session interactive
```

---

## 4. Les dépendances

| Dépendance | Rôle |
|-----------|------|
| `sanctum-domain` | Entités, ports, erreurs |
| `tokio` | Channels sync, timers (pas le runtime) |
| `tokio-util` | CancellationToken pour shutdown coordonné |
| `sha2` | SHA-256 pour le server_id |
| `rand` | Génération de nonces aléatoires |
| `tracing` | Logging |
| `serde` | Sérialisation |
| `zeroize` | Effacement des secrets en mémoire |

---

## 5. AuthService — L'authentification PGP

### 5.1 Le problème

Un client se connecte au host via Tor. Le tunnel Noise NK est établi (chiffré). Mais le host ne sait pas **qui** est derrière le tunnel. N'importe qui pourrait se connecter.

Il faut prouver son identité. Dans Sanctum, l'identité est le **fingerprint PGP**. L'authentification doit prouver que le client possède la clé privée PGP correspondant au fingerprint annoncé.

### 5.2 Le challenge-response en détail

```
Client                              Host
  │                                   │
  │   [Tunnel Noise NK établi]        │
  │                                   │
  │◄── AuthChallenge ─────────────────┤
  │    nonce (32 octets aléatoires)   │
  │    timestamp (Unix seconds)       │
  │    room_id (quelle room)          │
  │    server_id (SHA-256 de la       │
  │      clé Noise du host)           │
  │                                   │
  │    [Client vérifie server_id]     │
  │    [Client signe le challenge     │
  │     avec sa clé PGP privée]       │
  │                                   │
  ├── AuthResponse ──────────────────►│
  │    fingerprint (PGP)              │
  │    signature (sur le challenge)   │
  │    pgp_public_key                 │
  │    display_alias ("alice")        │
  │                                   │
  │    [Host vérifie :]               │
  │    1. Nonce pas déjà utilisé      │
  │    2. Timestamp ±120 secondes     │
  │    3. Fingerprint autorisé        │
  │    4. Signature PGP valide        │
  │                                   │
  │◄── AuthResult ────────────────────┤
  │    ok / fail                      │
  │    role, room_state, bundles      │
```

**Pourquoi un nonce ?** Si un attaquant intercepte une AuthResponse signée, il ne peut pas la réutiliser car le nonce est unique. Le host garde en mémoire les nonces déjà utilisés et refuse les doublons.

**Pourquoi un timestamp ?** Ça borne la fenêtre d'utilisation. Même si un attaquant capture un challenge, il ne peut l'utiliser que pendant 120 secondes.

### 5.3 Protection anti-relay (server_id)

Le `server_id` est le SHA-256 de la clé publique Noise statique du host. Le client le reçoit dans le challenge et le compare avec la clé Noise qu'il a reçue pendant le handshake.

Sans ça, un man-in-the-middle pourrait relayer le challenge du vrai host vers le client, récupérer la réponse signée, et la renvoyer au vrai host. Avec le `server_id`, le client vérifie que le challenge vient bien du host avec lequel il a fait le handshake Noise.

### 5.4 Protections intégrées

| Protection | Mécanisme |
|-----------|-----------|
| **Anti-replay** | Nonces stockés en mémoire, refus des doublons |
| **Anti-relay** | server_id = SHA-256(clé Noise du host) |
| **Anti-timing** | Timestamp ±120s (tolérance Tor) |
| **Anti-brute-force** | Maximum 3 tentatives par fingerprint |
| **Identité forgée** | La signature PGP prouve la possession de la clé privée |

### 5.5 Le code

```rust
pub struct AuthService {
    used_nonces: HashSet<Vec<u8>>,
    attempt_counts: HashMap<String, u32>,
}

pub fn create_challenge(room_id, host_noise_pubkey) -> AuthChallenge
pub fn challenge_to_bytes(challenge) -> Vec<u8>
pub fn verify_response(challenge, response, authorized) -> Result<()>
pub fn verify_server_id(challenge, host_noise_pubkey) -> Result<()>
```

La vérification de la signature PGP elle-même est déléguée à l'appelant via `IdentityPort`. AuthService ne sait pas comment PGP fonctionne — il ne fait que vérifier le nonce, le timestamp, et l'autorisation.

---

## 6. RoomService — La gestion des rooms

### 6.1 CRUD et permissions

Le RoomService est un wrapper autour de l'entité `Room` qui ajoute les **vérifications de permissions**. La Room du domain sait ajouter un membre, mais elle ne vérifie pas si l'appelant a le droit de le faire.

```
Opération         │  Minimum requis  │  Vérifié par
──────────────────┼──────────────────┼────────────────
Créer une room    │  —               │  Constructeur
Ajouter un membre │  Admin ou Owner  │  can_invite()
Révoquer un membre│  Admin ou Owner  │  can_kick()
Générer un invite │  Admin ou Owner  │  can_invite()
```

Quand `add_member()` est appelé :
1. Cherche le `caller_fingerprint` dans la room
2. Vérifie que son rôle a `can_invite()`
3. Si oui, délègue à `room.add_member()` (qui vérifie pas de doublon, pas plein)
4. Sinon, retourne `InsufficientPermissions`

### 6.2 Le système d'invitation

Les invitations sont **nominatives** et **signées** :

```
Owner/Admin veut inviter Bob :

1. generate_invite(inviter=alice, invited=bob, role=Member, ...)
   → Produit un InviteToken contenant :
     room_id, onion_address, port, host_noise_pubkey,
     inviter_fingerprint, invited_fingerprint,
     role, expires_at, signature (vide, l'appelant signe via IdentityPort)

2. Le token est signé PGP puis sérialisé en base64url
3. Transmis à Bob hors-bande (Signal, email, etc.)

Bob reçoit :
1. validate_invite(token, bob_fp)
   - Vérifie que le token est pour bob_fp (nominatif)
   - Vérifie que le token n'est pas expiré
2. Bob utilise les infos du token pour se connecter
```

### 6.3 Le code

```rust
pub struct RoomService { room: Option<Room> }

pub fn create_room(name, mode, config, owner...) -> Result<&Room>
pub fn load_room(room)
pub fn add_member(caller, new_member...) -> Result<()>
pub fn revoke_member(caller, target) -> Result<()>
pub fn generate_invite(inviter, invited, role...) -> Result<InviteToken>
pub fn validate_invite(token, local_fp) -> Result<()>
pub fn is_authorized(fingerprint) -> bool
```

---

## 7. MessageService — Le traitement des messages E2E

### 7.1 Le rôle du MessageService

Le MessageService est l'intermédiaire entre le ChatSession et le chiffrement. Il gère les sessions (anti-replay, séquences), le padding, les enveloppes, et la vérification. Il ne fait PAS le chiffrement lui-même — c'est le Double Ratchet.

### 7.2 Séquence d'envoi

```
Alice tape "Hello Bob"
        │
        ▼
1. message_service.pad_message("Hello Bob", crypto)
   → 256 octets paddés

2. ratchet_state.encrypt(padded)           ← sanctum-crypto
   → (ratchet_header, ciphertext)

3. message_service.prepare_envelope(sender, recipient, room, ct, header, crypto)
   → MessageEnvelope { sender, room_id, seq=1, nonce, timestamp, ct, header }

4. Sérialiser et envoyer via TransportPort
```

### 7.3 Séquence de réception

```
Bob reçoit un MessageEnvelope
        │
        ▼
1. message_service.process_received(envelope)
   - Valide l'enveloppe (seq > 0, nonce = 12 bytes)
   - Anti-replay : session.check_replay(seq)
   - Si replay → Err(ReplayDetected)

2. ratchet_state.decrypt(header, ciphertext)  ← sanctum-crypto
   → padded plaintext

3. message_service.unpad_message(padded, crypto)
   → "Hello Bob"
```

### 7.4 Le code

```rust
pub struct MessageService {
    sessions: HashMap<Fingerprint, Session>,
    padding_block_size: usize,
}

pub fn register_session(peer)
pub fn mark_established(peer)
pub fn prepare_envelope(...) -> Result<MessageEnvelope>
pub fn process_received(envelope) -> Result<()>
pub fn pad_message(plaintext, crypto) -> Vec<u8>
pub fn unpad_message(padded, crypto) -> Result<Vec<u8>>
```

---

## 8. HostService — Le relais central

### 8.1 Ce que le host fait et ne fait pas

| Le host FAIT | Le host NE FAIT PAS |
|-------------|-------------------|
| Accepter les connexions Tor | Déchiffrer les messages E2E |
| Vérifier l'authentification PGP | Lire le contenu des messages |
| Router les messages vers les destinataires | Stocker des clés privées |
| Stocker le backlog (ciphertexts opaques) | Modifier les messages |
| Gérer la liste des membres connectés | Forger des messages |

Le host est un **relais aveugle**. Il voit les métadonnées de routage (qui envoie, quelle room) mais le contenu est opaque.

### 8.2 Cycle de vie d'un client

```
Client se connecte
  → register_client(fingerprint, connection_id)
  → Vérifie fingerprint autorisé
  → Émet SanctumEvent::ClientConnected
  → client.ready = false

[X3DH avec tous les pairs]
  → mark_client_ready(fingerprint)
  → client.ready = true
  → Peut recevoir les messages routés

[Session active]

Déconnexion
  → remove_client(fingerprint)
  → Émet SanctumEvent::ClientDisconnected
```

### 8.3 Le routage

```
Alice (sender) ──→ Host ──→ Bob (ready)       ✓ routé
                        ──→ Charlie (ready)    ✓ routé
                        ──✗ Diana (pas ready)  ✗ exclu
                        ──✗ Alice (envoyeur)   ✗ exclu
```

`route_recipients(sender)` retourne les fingerprints connectés **et ready**, sauf l'envoyeur.

### 8.4 Le code

```rust
pub struct HostService {
    room: Room,
    connected_clients: HashMap<Fingerprint, ConnectedClient>,
    event_tx: broadcast::Sender<SanctumEvent>,
}

pub fn register_client(fingerprint, connection_id) -> Result<()>
pub fn mark_client_ready(fingerprint)
pub fn remove_client(fingerprint)
pub fn route_recipients(sender) -> Vec<Fingerprint>
pub fn is_connected(fingerprint) -> bool
pub fn connection_id_for(fingerprint) -> Option<u64>
```

---

## 9. ClientService — La machine à états du client

### 9.1 Les 5 états

```
Disconnected → Handshaking → Authenticating → Synchronizing → Ready
     ▲                                                          │
     └──────────────── disconnect() ◄───────────────────────────┘
```

| État | Signification | Peut envoyer ? |
|------|--------------|----------------|
| **Disconnected** | Pas de connexion | Non |
| **Handshaking** | Noise NK en cours | Non |
| **Authenticating** | PGP en cours | Non |
| **Synchronizing** | X3DH en cours | Non |
| **Ready** | Tout prêt | **Oui** |

### 9.2 Les transitions

```rust
begin_handshake(connection_id)     // Disconnected → Handshaking
handshake_complete()               // Handshaking → Authenticating
auth_complete(identity, room_id)   // Authenticating → Synchronizing
synchronization_complete()         // Synchronizing → Ready
disconnect()                       // Any → Disconnected
```

L'identité locale (`LocalIdentity` : fingerprint, alias, rôle) n'est disponible qu'après `auth_complete()`.

### 9.3 Le code

```rust
pub struct ClientService {
    state: ClientState,
    local_identity: Option<LocalIdentity>,
    room_id: Option<RoomId>,
    connection_id: Option<u64>,
}

pub fn state() -> ClientState
pub fn is_ready() -> bool
pub fn local_identity() -> Option<&LocalIdentity>
```

---

## 10. InputParser — L'interprétation des saisies

### 10.1 Messages vs commandes

| Saisie | Classification |
|--------|---------------|
| `Hello world` | `Input::Message("Hello world")` |
| `/exit` | `Input::Command(SlashCommand::Exit)` |
| ` ` (vide/espaces) | `Input::Empty` |
| `hello /world` | `Input::Message("hello /world")` |

Règle : commence par `/` → commande. Sinon → message. Un `/` au milieu ne déclenche rien.

### 10.2 Les slash commands

| Commande | Alias | Action |
|----------|-------|--------|
| `/exit` | `/quit`, `/q` | Quitter |
| `/help` | `/h`, `/?` | Aide |
| `/status` | — | Infos room |
| `/members` | `/who` | Liste connectés |
| `/invite <fp> [role]` | — | Inviter |
| `/kick <fp>` | — | Expulser |
| `/alias <n>` | `/nick` | Changer pseudo |

Les commandes sont **case-insensitive** (`/EXIT` = `/exit`). Les commandes inconnues retournent `SlashCommand::Unknown`.

### 10.3 Le code

```rust
pub fn parse_input(raw: &str) -> Input

pub enum Input { Message(String), Command(SlashCommand), Empty }
pub enum SlashCommand { Exit, Help, Status, Members, Invite{..}, Kick{..}, Alias{..}, Unknown(String) }
```

---

## 11. ChatSession — L'orchestrateur

### 11.1 Ce que ChatSession coordonne

Le `ChatSession` est le **cœur** de l'expérience utilisateur. Il coordonne 4 boucles asynchrones concurrentes qui tournent en parallèle via `tokio::select!` :

```
┌─────────────────────────────────────────────────┐
│                ChatSession                      │
│                                                 │
│  ┌──────────────┐    ┌──────────────────────┐   │
│  │ input_loop   │    │  network_recv_loop   │   │
│  │ UiPort       │    │ TransportPort        │   │
│  │ .read_input()│    │ .recv()              │   │
│  │      │       │    │      │               │   │
│  │      ▼       │    │      ▼               │   │
│  │ parse_input  │    │ decrypt + unpad      │   │
│  │      │       │    │      │               │   │
│  │      ▼       │    │      ▼               │   │
│  │ event_tx ────┼────┼─► event_tx           │   │
│  └──────────────┘    └──────────────────────┘   │
│                                                 │
│  ┌──────────────┐    ┌──────────────────────┐   │
│  │ render_loop  │    │  maintenance_loop    │   │
│  │              │    │  (persistant seul.)  │   │
│  │ event_rx ◄───┼────┼── event_tx           │   │
│  │      │       │    │                      │   │
│  │      ▼       │    │ Toutes les 15 min :  │   │
│  │ UiPort       │    │ purge backlog expiré │   │
│  │ .print_*()   │    │                      │   │
│  └──────────────┘    └──────────────────────┘   │
│                                                 │
│  Tous partagent un CancellationToken            │
└─────────────────────────────────────────────────┘
```

### 11.2 Les boucles async

**input_loop** : lit les saisies via `UiPort.read_input()`, les parse avec `InputParser`. Un message → `ChatEvent::OutgoingMessage`. Un `/exit` → `request_shutdown()`.

**network_recv_loop** : reçoit les `MessageEnvelope` du réseau, les passe au `MessageService` (anti-replay), les déchiffre via le ratchet → `ChatEvent::IncomingMessage`.

**render_loop** : écoute les `ChatEvent` sur le bus et les affiche via `UiPort.print_*()`. C'est la seule boucle qui écrit à l'écran — ça évite les conflits d'affichage entre messages reçus et saisie utilisateur.

**maintenance_loop** : uniquement en mode persistant. Purge le backlog expiré toutes les 15 minutes. En mode éphémère, cette boucle n'est pas démarrée (rien sur disque).

### 11.3 Le bus d'événements

Toutes les boucles communiquent via un `broadcast::channel<ChatEvent>` — un canal un-vers-plusieurs :

```
input_loop ──────┐
                 ├──► broadcast::Sender<ChatEvent>
network_recv ────┘           │
                             ├──► render_loop (Receiver)
                             └──► (autres consumers)
```

Les `ChatEvent` couvrent tout ce qui peut se passer :

| Catégorie | Événements |
|-----------|-----------|
| **Messages** | `IncomingMessage`, `OutgoingMessage` |
| **Pairs** | `PeerJoining`, `PeerReady`, `PeerLeft`, `PeerRevoked` |
| **Session** | `Connected`, `Disconnected` |
| **Backlog** | `BacklogStart`, `BacklogEnd` |
| **Système** | `RatchetReKeyed`, `BacklogPurged`, `TorStatusChanged`, `ProtocolError` |

Le render_loop dispatche chaque événement vers la bonne méthode UiPort :
- `IncomingMessage` → `ui.print_message()`
- `PeerJoining` → `ui.print_system("── charlie joining ──")`
- `Connected` → `ui.print_system("Connected to room-name (3 peers)")`
- etc.

### 11.4 Le shutdown coordonné

Sanctum utilise un `CancellationToken` de `tokio-util` :

```
Ctrl-C / /exit / erreur fatale
        │
        ▼
session.request_shutdown()
  → CancellationToken.cancel()
        │
        ├──► input_loop voit cancelled() → break
        ├──► network_recv_loop voit cancelled() → break
        ├──► render_loop voit cancelled() → break
        └──► maintenance_loop voit cancelled() → break

Toutes les boucles terminent proprement
        │
        ▼
cleanup_ui()  → restaure le terminal
zeroize       → efface les secrets en mémoire
disconnect    → ferme la connexion Tor
```

Chaque boucle utilise `tokio::select!` avec `shutdown.cancelled()` comme branche prioritaire. Dès que le token est annulé, toutes les boucles sortent proprement au prochain tick.

### 11.5 Le code

```rust
pub struct ChatSession<U: UiPort> {
    config: SessionConfig,
    ui: U,
    event_tx: broadcast::Sender<ChatEvent>,
    shutdown: CancellationToken,
}

pub fn new(config, ui, event_tx, shutdown) -> Self
pub fn event_tx() -> broadcast::Sender<ChatEvent>
pub fn shutdown_token() -> CancellationToken
pub fn build_status(peer_count, tor_connected) -> StatusInfo
pub fn init_ui() -> Result<()>
pub fn cleanup_ui() -> Result<()>
pub fn emit(event: ChatEvent)
pub fn request_shutdown()
pub fn is_shutdown_requested() -> bool
pub async fn render_loop(&self)
```

Le `ChatSession` est **générique** sur `U: UiPort`. En production, `U` = `TerminalLineRenderer`. En test, `U` = `MockUi` (capture les sorties dans des `Vec<String>`).

---

## 12. Comment les services interagissent

Voici le flux complet quand Alice exécute `sanctum join <token>` :

```
1. PARSE TOKEN
   InputParser n'intervient pas ici (c'est la CLI qui parse le token)
   Le token contient : onion_address, host_noise_pubkey, room_id

2. CONNEXION
   ClientService.begin_handshake(conn_id)
   État : Disconnected → Handshaking
   [Noise NK handshake via TransportPort — sanctum-crypto]
   ClientService.handshake_complete()
   État : Handshaking → Authenticating

3. AUTHENTIFICATION
   Host : AuthService.create_challenge(room_id, noise_pubkey)
           → envoie AuthChallenge via tunnel Noise
   Client : AuthService.verify_server_id(challenge, host_pubkey)
           → signe le challenge via IdentityPort
           → envoie AuthResponse
   Host : AuthService.verify_response(challenge, response, allowlist)
           → vérifie nonce, timestamp, fingerprint, signature
           → envoie AuthResult (ok, role, room_state, bundles)
   ClientService.auth_complete(identity, room_id)
   État : Authenticating → Synchronizing

4. SYNCHRONISATION (X3DH)
   Pour chaque pair dans bundles :
     x3dh::initiate(alice_ik, bob_bundle)
     → shared_secret
     ratchet::RatchetState::init_alice(shared_secret, bob_spk_pub)
     MessageService.register_session(bob_fp)
     MessageService.mark_established(bob_fp)
   ClientService.synchronization_complete()
   État : Synchronizing → Ready
   HostService.mark_client_ready(alice_fp)

5. SESSION INTERACTIVE
   ChatSession démarre les 4 boucles async :
   - input_loop : lit UiPort, parse, envoie
   - network_recv_loop : reçoit, déchiffre, affiche
   - render_loop : ChatEvent → UiPort
   - maintenance_loop : GC backlog (si persistant)

6. ALICE ENVOIE "Hello Bob"
   input_loop : UiPort.read_input() → "Hello Bob"
   InputParser : parse_input("Hello Bob") → Input::Message("Hello Bob")
   MessageService.pad_message("Hello Bob", crypto) → 256 octets
   RatchetState.encrypt(padded) → (header, ciphertext)
   MessageService.prepare_envelope(alice, bob, room, ct, header)
     → MessageEnvelope { seq=1, nonce, timestamp, ciphertext }
   TransportPort.send(envelope) → via tunnel Noise → Host
   ChatSession.emit(ChatEvent::OutgoingMessage { content, timestamp })
   render_loop : ui.print_own_message("alice", "Hello Bob", ts)

7. HOST ROUTE
   HostService reçoit le MessageEnvelope
   HostService.route_recipients(alice) → [bob_fp, charlie_fp]
   Pour chaque destinataire :
     TransportPort.send(envelope) vers connection_id
   HostService.emit_message_received(room, alice, seq=1)

8. BOB REÇOIT
   network_recv_loop : TransportPort.recv() → MessageEnvelope
   MessageService.process_received(envelope) → anti-replay OK
   RatchetState.decrypt(header, ciphertext) → padded
   MessageService.unpad_message(padded) → "Hello Bob"
   ChatSession.emit(ChatEvent::IncomingMessage { sender=alice, content="Hello Bob" })
   render_loop : ui.print_message("alice", "Hello Bob", ts)

9. SHUTDOWN (/exit ou Ctrl-C)
   input_loop : parse_input("/exit") → Input::Command(SlashCommand::Exit)
   ChatSession.request_shutdown() → CancellationToken.cancel()
   Toutes les boucles terminent
   ChatSession.cleanup_ui() → restaure le terminal
   Secrets zeroized, connexion fermée
```

---

## 13. Résumé des 46 tests

| Service | Tests | Ce qu'ils vérifient |
|---------|-------|-------------------|
| **auth_service** | 6 | Création de challenge, sérialisation déterministe, acceptation valide, rejet non-autorisé, rejet nonce replay, vérification server_id, max tentatives |
| **room_service** | 7 | Création room, ajout par owner, ajout par member refusé, révocation, révocation par member refusée, génération invite, validation invite (mauvais fp / expiré) |
| **message_service** | 3 | Séquence auto-incrémentée, anti-replay doublon, pad/unpad round-trip |
| **host_service** | 4 | Enregistrement client autorisé, client non-autorisé refusé, routage exclut sender et non-ready, suppression client |
| **client_service** | 2 | Transitions d'état complètes, identité disponible après auth |
| **input_parser** | 14 | Message, espaces, vide, /exit (3 alias), case-insensitive, /help, /status, /members, /invite (avec/sans rôle, args manquants), /kick, /alias, commande inconnue, unicode, slash au milieu |
| **chat_session** | 5 | Création, shutdown, handle incoming message, handle peer events, build status |
| **Total** | **46** | |