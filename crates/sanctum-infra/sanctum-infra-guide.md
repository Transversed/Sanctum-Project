# Sanctum Infra — Documentation Complète

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Rôle dans l'architecture](#2-rôle-dans-larchitecture)
3. [Structure des fichiers](#3-structure-des-fichiers)
4. [Les dépendances](#4-les-dépendances)
5. [Codec — Le protocole filaire](#5-codec--le-protocole-filaire)
   - 5.1 [Le format des trames](#51-le-format-des-trames)
   - 5.2 [Les types de messages](#52-les-types-de-messages)
   - 5.3 [Encode / Decode](#53-encode--decode)
   - 5.4 [Le code](#54-le-code)
6. [MemoryStorageAdapter — Le stockage éphémère](#6-memorystorageadapter--le-stockage-éphémère)
   - 6.1 [Pourquoi un storage RAM ?](#61-pourquoi-un-storage-ram)
   - 6.2 [Le backlog en mémoire](#62-le-backlog-en-mémoire)
   - 6.3 [Le code](#63-le-code)
7. [SqliteStorageAdapter — Le stockage persistant](#7-sqlitestorageadapter--le-stockage-persistant)
   - 7.1 [Le schéma de la base](#71-le-schéma-de-la-base)
   - 7.2 [Chiffrement au repos](#72-chiffrement-au-repos)
   - 7.3 [Hashing des fingerprints](#73-hashing-des-fingerprints)
   - 7.4 [Rétention et GC](#74-rétention-et-gc)
   - 7.5 [Migrations](#75-migrations)
   - 7.6 [Le code](#76-le-code)
8. [IdentityAdapter — La signature PGP](#8-identityadapter--la-signature-pgp)
   - 8.1 [Le rôle de l'identité](#81-le-rôle-de-lidentité)
   - 8.2 [L'implémentation actuelle vs production](#82-limplémentation-actuelle-vs-production)
   - 8.3 [Le code](#83-le-code)
9. [Transport — Les connexions réseau](#9-transport--les-connexions-réseau)
   - 9.1 [TransportConnection](#91-transportconnection)
   - 9.2 [InProcessTransport](#92-inprocesstransport)
   - 9.3 [Le code](#93-le-code)
10. [TorController — Le service caché](#10-torcontroller--le-service-caché)
    - 10.1 [Comment Tor Hidden Services fonctionnent](#101-comment-tor-hidden-services-fonctionnent)
    - 10.2 [Le control port protocol](#102-le-control-port-protocol)
    - 10.3 [Le code](#103-le-code)
11. [TerminalLineRenderer — L'affichage terminal](#11-terminallinerenderer--laffichage-terminal)
    - 11.1 [Le rendu ligne par ligne](#111-le-rendu-ligne-par-ligne)
    - 11.2 [NullUiAdapter](#112-nulluiadapter)
    - 11.3 [Le code](#113-le-code)
12. [Comment les adapters se branchent](#12-comment-les-adapters-se-branchent)
13. [Résumé des 45 tests](#13-résumé-des-45-tests)

---

## 1. Vue d'ensemble

Le crate `sanctum-infra` contient les **implémentations concrètes** des ports définis dans le domain. C'est ici que le code touche le monde réel : le réseau, le disque, le terminal, Tor.

Chaque adapter implémente (ou prépare l'implémentation de) un trait du domain :

```
Domain Port              │  Infra Adapter
─────────────────────────┼──────────────────────────────
StoragePort              │  MemoryStorageAdapter (RAM)
                         │  SqliteStorageAdapter (SQLite chiffré)
IdentityPort             │  IdentityAdapter (sign/verify)
TransportPort            │  TransportConnection (TCP framing)
                         │  InProcessTransport (channels mémoire)
TorPort                  │  TorController (hidden services)
UiPort                   │  TerminalLineRenderer (crossterm)
                         │  NullUiAdapter (mode non-interactif)
—                        │  Codec (framing wire protocol)
```

Le codec n'implémente pas un port — c'est un utilitaire de sérialisation que le transport utilise.

---

## 2. Rôle dans l'architecture

```
┌──────────────────────────────────────────────┐
│  CLI — câble les adapters aux services       │
├──────────────────────────────────────────────┤
│  APP — appelle les ports (traits)            │
├──────────────────────────────────────────────┤
│  DOMAIN — définit les ports (traits)         │
├──────────────────────────────────────────────┤
│  INFRA (ici) — implémente les ports          │
│    Codec, Memory/SQLite, Identity,           │
│    Transport, Tor, Terminal                  │
└──────────────────────────────────────────────┘
```

L'infra dépend du domain (pour les traits et entités) mais **pas** de l'app. C'est la CLI qui fait le lien entre app et infra au démarrage :

```rust
// Dans la CLI :
let storage = MemoryStorageAdapter::new(500);  // infra
let room_svc = RoomService::new();             // app
// room_svc utilise storage via le trait StoragePort
```

---

## 3. Structure des fichiers

```
crates/sanctum-infra/
├── Cargo.toml
└── src/
    ├── lib.rs                 ← Re-exports
    ├── codec.rs               ← Framing wire protocol
    ├── storage_memory.rs      ← StoragePort (RAM)
    ├── storage_sqlite.rs      ← StoragePort (SQLite chiffré)
    ├── identity_pgp.rs        ← IdentityPort (sign/verify)
    ├── transport.rs           ← Connexions + InProcessTransport
    ├── tor_control.rs         ← TorPort (hidden services)
    └── terminal_renderer.rs   ← UiPort (terminal)
```

---

## 4. Les dépendances

| Dépendance | Version | Rôle |
|-----------|---------|------|
| `bytes` | 1 | Buffers efficaces pour le codec |
| `rusqlite` | 0.31 (bundled) | SQLite embarqué, sans dépendance système |
| `crossterm` | 0.27 | Couleurs et attributs terminal, cross-platform |
| `tokio` | workspace | Channels, mutex async, réseau |
| `tokio-util` | 0.7 | Codec traits pour framing |
| `sha2` | 0.10 | SHA-256 pour hashing fingerprints |
| `rand` | 0.8 | Génération d'adresses .onion mock |
| `serde` / `serde_json` | workspace / 1 | Sérialisation des données stockées |
| `zeroize` | workspace | Effacement des clés en mémoire |
| `tempfile` | 3 (dev) | Fichiers temporaires pour tests SQLite |

`rusqlite` est en mode **bundled** : il compile SQLite directement dans le binaire. Aucune libsqlite3 système n'est nécessaire.

---

## 5. Codec — Le protocole filaire

### 5.1 Le format des trames

Chaque message sur le réseau est encadré dans une **trame** (frame) :

```
┌──────────────┬──────────┬──────────────────────┐
│ len: u32 BE  │ type: u8 │ payload: [u8; len-1] │
│ (4 octets)   │ (1 oct)  │ (len - 1 octets)     │
└──────────────┴──────────┴──────────────────────┘
```

- **len** : taille de (type + payload) en big-endian. N'inclut PAS ses propres 4 octets.
- **type** : identifiant du type de message (1 octet).
- **payload** : données sérialisées (protobuf en production).
- **Taille totale sur le fil** : `4 + len`.
- **Contrainte** : `1 ≤ len ≤ 65536` (64 KiB max). Un `len = 0` ou `len > 65536` ferme la connexion.

Pourquoi ce format ?

- **Simple** : pas de délimiteur à chercher, pas d'échappement. On lit 4 octets → on sait exactement combien lire ensuite.
- **Borné** : 64 KiB max empêche les attaques par messages géants.
- **Streamable** : compatible TCP et Tor (flux d'octets sans frontières de messages).

### 5.2 Les types de messages

Le byte `type` identifie la nature du message :

| Code | Nom | Direction | Phase |
|------|-----|-----------|-------|
| `0x01` | HandshakeInit | C→H | Connexion |
| `0x02` | HandshakeResp | H→C | Connexion |
| `0x03` | AuthChallenge | H→C | Auth |
| `0x04` | AuthResponse | C→H | Auth |
| `0x05` | AuthResult | H→C | Auth |
| `0x10` | RoomMessage | bidirectionnel | Session |
| `0x11` | RoomControl | bidirectionnel | Session |
| `0x12` | PeerReady | H→all | Session |
| `0x20` | RatchetKeyExchange | C↔C via H | Crypto |
| `0x21` | PublishBundle | C→H | Crypto |
| `0x22` | RequestBundle | C→H | Crypto |
| `0x23` | BundleResponse | H→C | Crypto |
| `0x24` | OPKDepleted | H→C | Crypto |
| `0x25` | RefreshOPK | C→H | Crypto |
| `0x30` | BacklogStart | H→C | Backlog |
| `0x31` | BacklogEnd | H→C | Backlog |
| `0x32` | BacklogAck | C→H | Backlog |
| `0xFE` | Ping | bidirectionnel | Keepalive |
| `0xFD` | Pong | bidirectionnel | Keepalive |
| `0xFF` | Error | bidirectionnel | Erreur |

Les codes sont groupés par plage :
- `0x01-0x05` : handshake et auth
- `0x10-0x12` : messages et contrôle de room
- `0x20-0x25` : échange de clés crypto
- `0x30-0x32` : backlog
- `0xFD-0xFF` : keepalive et erreurs

### 5.3 Encode / Decode

L'encodage est trivial :

```
Frame { type=0x10, payload=[1,2,3] }
  → len = 4 (1 type + 3 payload)
  → wire: [0,0,0,4, 0x10, 1,2,3]
```

Le décodage utilise un `BytesMut` (buffer à curseur) :

```
1. Lire 4 octets → len
2. Vérifier 1 ≤ len ≤ 65536
3. Si buf.len() < 4 + len → return None (attendre plus de données)
4. Lire 1 octet → type
5. Lire len-1 octets → payload
6. Avancer le curseur
```

Le `None` est important : sur TCP, les données arrivent par morceaux. On peut recevoir la moitié d'une trame, puis le reste au tour suivant. Le décodeur gère ça naturellement.

### 5.4 Le code

```rust
pub struct Frame { pub message_type: u8, pub payload: Vec<u8> }

pub fn encode_frame(frame: &Frame) -> Vec<u8>
pub fn decode_frame(buf: &mut BytesMut) -> Result<Option<Frame>, SanctumError>
pub fn ping_frame() -> Frame
pub fn pong_frame() -> Frame
pub fn error_frame(message: &str) -> Frame
```

---

## 6. MemoryStorageAdapter — Le stockage éphémère

### 6.1 Pourquoi un storage RAM ?

En mode éphémère, Sanctum ne doit **rien écrire sur le disque**. Pas de fichier SQLite, pas de log, pas de cache. Tout vit en RAM et disparaît quand le processus s'arrête.

Le `MemoryStorageAdapter` implémente la même interface que le SQLite adapter mais stocke tout dans des `HashMap` et `Vec` en mémoire. L'app ne sait pas lequel elle utilise — elle parle au trait `StoragePort`.

### 6.2 Le backlog en mémoire

Même en mode éphémère, le host peut bufferiser les messages pour les clients temporairement déconnectés (pendant un X3DH par exemple). Ce backlog est limité :

```
store_message(recipient, envelope)
  → Si le nombre de messages pour cette room ≥ max_messages_per_room :
    → Supprimer le plus ancien de cette room
  → Ajouter le message avec un timestamp

fetch_backlog(room_id, recipient, since_seq)
  → Retourner tous les messages pour ce destinataire avec seq > since_seq

purge_expired(max_age_secs)
  → Supprimer tous les messages stockés il y a plus de max_age_secs
```

L'éviction FIFO (First In First Out) empêche le backlog de grossir indéfiniment.

### 6.3 Le code

```rust
pub struct MemoryStorageAdapter {
    rooms: HashMap<String, Room>,
    messages: Vec<StoredMessage>,
    max_messages_per_room: u32,
}

pub fn store_room(room) -> Result<()>
pub fn load_room(id) -> Result<Option<Room>>
pub fn delete_room(id) -> Result<()>
pub fn store_message(recipient, envelope) -> Result<()>
pub fn fetch_backlog(room_id, recipient, since_seq) -> Result<Vec<MessageEnvelope>>
pub fn purge_expired(max_age_secs) -> Result<u64>
```

---

## 7. SqliteStorageAdapter — Le stockage persistant

### 7.1 Le schéma de la base

```
┌─────────────────┐     ┌─────────────────────┐
│     rooms       │     │      members        │
├─────────────────┤     ├─────────────────────┤
│ id TEXT PK      │◄────│ room_id TEXT FK     │
│ data BLOB       │     │ fingerprint_hash TEXT 
│ created_at INT  │     │ data BLOB           │
└─────────────────┘     └─────────────────────┘
        ▲
        │
┌───────┴─────────┐     ┌─────────────────────┐
│    messages     │     │       keys          │
├─────────────────┤     ├─────────────────────┤
│ id INT PK AUTO  │     │ key_type TEXT       │
│ room_id TEXT FK │     │ key_id TEXT         │
│ recipient_hash  │     │ data BLOB           │
│ sequence_number │     │ created_at INT      │
│ data BLOB       │     │ expires_at INT?     │
│ stored_at INT   │     │ PK(key_type, key_id)│
└─────────────────┘     └─────────────────────┘

┌─────────────────┐
│    metadata     │
├─────────────────┤
│ key TEXT PK     │
│ value TEXT      │  ← schema_version = "1"
└─────────────────┘
```

Cinq tables :
- **rooms** : données de room chiffrées
- **members** : membres par room (fingerprint hashé)
- **messages** : backlog de messages E2E (déjà chiffrés par l'expéditeur)
- **keys** : clés cryptographiques chiffrées (IK, SPK, OPK, Noise)
- **metadata** : version du schéma et configuration

### 7.2 Chiffrement au repos

Les colonnes `data` dans chaque table contiennent des **blobs chiffrés AES-256-GCM**. Le format de chaque blob :

```
┌──────────┬─────────────┬──────────┐
│ nonce    │ ciphertext  │ auth tag │
│ 12 bytes │ variable    │ 16 bytes │
└──────────┴─────────────┴──────────┘
```

Le chiffrement est fait par l'**appelant** (la couche app/CLI) avant de passer les données à l'adapter. L'adapter SQLite ne fait que stocker et retrouver des blobs opaques. Il ne connaît pas la clé de chiffrement.

La hiérarchie de clés pour le chiffrement au repos :

```
Master Passphrase
        │
   Argon2id(salt)
        │
        ▼
   Master Key (256 bits)
        │
   HKDF-SHA256
   ┌────┼────────┐
   ▼    ▼        ▼
RoomKey MsgKey  KeyStoreKey
```

Chaque type de donnée a sa propre sous-clé dérivée, de sorte que compromettre une clé ne révèle pas les autres.

### 7.3 Hashing des fingerprints

Les fingerprints PGP ne sont **jamais stockés en clair** dans la base. Ils sont hashés avec SHA-256 avant stockage :

```
fingerprint "4A7B3C2D..."
        │
   SHA-256
        │
        ▼
"a3f2b1c4..."  ← stocké dans fingerprint_hash
```

Pourquoi ? Si un attaquant accède au fichier SQLite (même sans la clé de chiffrement des blobs), il ne peut pas lister les fingerprints des membres. Il voit des hashs opaques.

Le hash est **déterministe** : le même fingerprint donne toujours le même hash, ce qui permet les lookups par fingerprint.

### 7.4 Rétention et GC

Deux mécanismes de purge :

**Par âge** (`purge_expired`) :
```sql
DELETE FROM messages WHERE stored_at < (now - max_age_secs)
```

**Par quantité** (`purge_excess`) :
```sql
DELETE FROM messages WHERE room_id = ?
  AND id NOT IN (
    SELECT id FROM messages WHERE room_id = ?
    ORDER BY sequence_number DESC LIMIT max_messages
  )
```

Le GC tourne toutes les 15 minutes en mode persistant (via la `maintenance_loop` du ChatSession).

### 7.5 Migrations

Le schéma est versionné via la table `metadata` (`schema_version`). Au démarrage, l'adapter vérifie la version et applique les migrations séquentiellement. Pour l'instant, seule la migration initiale (version 1) existe.

### 7.6 Le code

```rust
pub struct SqliteStorageAdapter { conn: Connection }

pub fn open(path) -> Result<Self>
pub fn open_in_memory() -> Result<Self>  // Pour tests
pub fn store_room(room_id, encrypted_data, created_at) -> Result<()>
pub fn load_room(room_id) -> Result<Option<Vec<u8>>>
pub fn store_member(room_id, fingerprint, encrypted_data) -> Result<()>
pub fn store_message(room_id, recipient, seq, data, stored_at) -> Result<()>
pub fn fetch_backlog(room_id, recipient, since_seq) -> Result<Vec<(u64, Vec<u8>)>>
pub fn purge_expired(max_age_secs) -> Result<u64>
pub fn purge_excess(room_id, max_messages) -> Result<u64>
pub fn store_key(key_type, key_id, data, created_at, expires_at) -> Result<()>
pub fn load_key(key_type, key_id) -> Result<Option<Vec<u8>>>
pub fn schema_version() -> Result<String>
```

---

## 8. IdentityAdapter — La signature PGP

### 8.1 Le rôle de l'identité

L'identité dans Sanctum repose sur PGP. Chaque utilisateur possède une clé PGP dont le **fingerprint** sert d'identifiant unique. Les opérations essentielles sont :

- **Signer** : prouver qu'on possède la clé privée (pour l'auth challenge-response)
- **Vérifier** : confirmer qu'une signature vient bien du bon fingerprint (pour les invitations, les bundles)
- **Dériver le fingerprint** : obtenir l'identifiant 40 hex chars depuis la clé

### 8.2 L'implémentation actuelle vs production

| Aspect | Actuel (v0.1 MVP) | Production (v0.2) |
|--------|-------------------|-------------------|
| **Signature** | HMAC-SHA256(key, data) | Ed25519 via sequoia-openpgp |
| **Vérification** | Recompute HMAC + constant-time compare | Vérification PGP standard |
| **Fingerprint** | SHA-256(key) tronqué 20 octets | Fingerprint PGP réel (20 octets) |
| **Clé** | 32 octets aléatoires | Sous-clé PGP Ed25519 |

L'API est identique dans les deux cas. Le swap vers sequoia-openpgp ne changera aucune signature de méthode — seule l'implémentation interne changera.

La raison de cette approche MVP : `sequoia-openpgp` a beaucoup de dépendances (nettle ou botan pour le backend crypto). En commençant par un placeholder, on peut développer et tester toute l'architecture sans cette complexité. Le trait `IdentityPort` garantit que le remplacement sera transparent.

### 8.3 Le code

```rust
pub struct IdentityAdapter {
    signing_key: Vec<u8>,     // Zeroize on Drop
    fingerprint: Fingerprint,
}

pub fn from_key(signing_key) -> Result<Self>  // Depuis une clé existante
pub fn generate() -> Self                     // Nouvelle identité aléatoire
pub fn fingerprint() -> &Fingerprint
pub fn public_key_bytes() -> Vec<u8>
pub fn sign(data) -> Result<Vec<u8>>
pub fn verify(peer_fp, data, signature, peer_key) -> Result<bool>
```

La clé de signature est effacée de la mémoire (`zeroize`) quand l'adapter est détruit.

---

## 9. Transport — Les connexions réseau

### 9.1 TransportConnection

Le `TransportConnection` encapsule une connexion réseau avec le codec de framing :

```
Réseau (TCP via Tor)
        │
        ▼
┌───────────────────────┐
│  TransportConnection  │
│                       │
│  read_buf (BytesMut)  │ ← feed_data() depuis le réseau
│  ┌──────────────┐     │
│  │   Codec      │     │ ← try_decode_frame() → Option<Frame>
│  └──────────────┘     │
│                       │
│  encode_frame(Frame)  │ → Vec<u8> à envoyer sur le réseau
│                       │
│  info: ConnectionInfo │
│    id: u64 (unique)   │
│    remote_addr        │
│    noise_established  │
└───────────────────────┘
```

Le pattern est celui du **buffer progressif** :

1. Le réseau donne des octets bruts → `feed_data(bytes)`
2. On essaie de décoder → `try_decode_frame()`
3. Si pas assez de données → `None`, on attend plus
4. Si une trame complète → `Some(Frame)`, on la traite
5. Les octets consommés sont retirés du buffer automatiquement

Chaque connexion a un **ID unique** (atomique, incrémenté globalement). C'est cet ID que le `HostService` utilise pour identifier à qui envoyer les messages.

### 9.2 InProcessTransport

Quand le host héberge une room, il est à la fois **relais ET participant**. Son propre ChatSession a besoin de communiquer avec le HostService, mais passer par TCP/Noise en loopback serait du gaspillage.

L'`InProcessTransport` résout ça avec des **channels Tokio** en mémoire :

```
HostService                    Host's ChatSession
     │                                │
     │   InProcessTransport (A)       │  InProcessTransport (B)
     │   tx → B.rx                    │  tx → A.rx
     │   rx ← B.tx                    │  rx ← A.tx
     │                                │
     └──── send(frame) ──────────────►│
     │◄─── recv() ◄───────────────────│
```

`InProcessTransport::pair()` crée deux transports croisés : ce que A envoie arrive dans B, et inversement. Les deux côtés ont `noise_established = true` par défaut (pas besoin de Noise en local).

Du point de vue du ChatSession, il ne sait pas s'il est local ou distant. Il appelle `send()` et `recv()` de la même façon.

### 9.3 Le code

```rust
// Connexion TCP
pub struct TransportConnection { info, read_buf, write_buf, closed }
pub fn new(remote_addr) -> Self
pub fn feed_data(bytes)
pub fn try_decode_frame() -> Result<Option<Frame>>
pub fn encode_frame(frame) -> Result<Vec<u8>>
pub fn close()

// Connexion in-process
pub struct InProcessTransport { tx, rx, info }
pub fn pair() -> (Self, Self)
pub async fn send(frame) -> Result<()>
pub async fn recv() -> Result<Frame>
```

---

## 10. TorController — Le service caché

### 10.1 Comment Tor Hidden Services fonctionnent

Un Hidden Service (HS) Tor permet d'exposer un serveur TCP sans révéler son adresse IP. Le flux :

```
Client (n'importe où)
  │
  │  Connaît l'adresse .onion
  │
  ├─► SOCKS5 proxy Tor local (127.0.0.1:9050)
  │       │
  │       ├─► Circuit Tor (3 relais)
  │       │       │
  │       │       ├─► Rendezvous Point
  │       │       │       │
  │       │       │       ├─► Circuit Tor du host
  │       │       │       │       │
  │       │       │       │       ▼
  │       │       │       │   Host local (127.0.0.1:9738)
  │       │       │       │
```

L'adresse `.onion` v3 est un identifiant cryptographique de 56 caractères (base32 d'une clé Ed25519). Personne — ni les relais Tor ni les observateurs — ne connaît l'IP du host.

### 10.2 Le control port protocol

Tor expose un **control port** (par défaut 9051) qui permet de gérer les services cachés dynamiquement :

```
Client → Tor Control Port :
  AUTHENTICATE "password"
  ADD_ONION NEW:ED25519-V3 Port=9738,127.0.0.1:9738

Tor → Client :
  250-ServiceID=abc123...xyz.onion
  250 OK
```

En production, `torut` (bibliothèque Rust) gère cette communication. L'implémentation actuelle est un **mock** qui simule le comportement :

- `create_hidden_service()` génère une fausse adresse .onion
- `destroy_hidden_service()` supprime le service
- `is_available()` indique si Tor est connecté

Le mock permet de développer et tester toute la logique sans avoir Tor installé.

### 10.3 Le code

```rust
pub struct TorController {
    config: TorConfig,
    active_service: Option<HiddenService>,
    available: bool,
}

pub fn new(config) -> Self
pub fn mock() -> Self                            // Pour tests
pub fn is_available() -> bool
pub async fn create_hidden_service() -> Result<HiddenService>
pub async fn destroy_hidden_service() -> Result<()>
pub fn active_service() -> Option<&HiddenService>
pub fn socks_addr() -> &str
```

---

## 11. TerminalLineRenderer — L'affichage terminal

### 11.1 Le rendu ligne par ligne

Le `TerminalLineRenderer` implémente `UiPort` avec un affichage simple et coloré :

```
[14:32] alice: Hello everyone!          ← print_message (cyan sender)
[14:32] you: Hey alice!                 ← print_own_message (green sender)
── bob joining (synchronizing...) ──    ← print_system (yellow)
── bob ready ──                         ← print_system (yellow)
── backlog (5 messages) ──              ← print_backlog_start
[14:30] charlie: Earlier message        ← print_message (backlog)
── end of backlog ──                    ← print_backlog_end
[test | ephemeral | Owner | 3 peers | 🧅] ← update_status
```

Les couleurs utilisées :
- **Cyan + Bold** : nom de l'expéditeur (messages reçus)
- **Green + Bold** : notre propre nom (messages envoyés)
- **Dark Yellow** : messages système (join, leave, backlog)
- **Dim** : timestamps et barre de statut

Le renderer utilise `crossterm` qui est cross-platform (Windows, macOS, Linux) et ne nécessite pas de mode raw ou d'alternate screen — c'est un simple rendu ligne par ligne au-dessus de stdout.

La lecture de l'input (`read_input`) est déléguée à un thread dédié via `std::io::stdin().read_line()` + `tokio::sync::oneshot`. Ça évite de bloquer le runtime Tokio avec une opération synchrone.

### 11.2 NullUiAdapter

Le `NullUiAdapter` est un UiPort qui ne fait rien. Il est utilisé pour les commandes non-interactives (`sanctum send`, `sanctum read`) où il n'y a pas de terminal :

```rust
impl UiPort for NullUiAdapter {
    fn print_message(..) {}   // Silencieux
    fn print_system(..) {}    // Silencieux
    fn read_input() -> Err()  // Toujours erreur (pas de terminal)
}
```

### 11.3 Le code

```rust
pub struct TerminalLineRenderer { stdout: Mutex<Stdout> }
pub fn new() -> Self

// Implémente UiPort :
fn read_input() -> Future<Result<String>>
fn print_message(role, sender, content, timestamp)
fn print_own_message(role, alias, content, timestamp)
fn print_system(text)
fn print_backlog_start(count)
fn print_backlog_end()
fn update_status(status)
fn init() -> Result<()>
fn cleanup() -> Result<()>

pub struct NullUiAdapter;  // Implémente UiPort silencieusement
```

---

## 12. Comment les adapters se branchent

Voici comment la CLI câble tout au démarrage :

```
sanctum host --ephemeral "my-room"
        │
        ▼
Mode éphémère :
  storage = MemoryStorageAdapter::new(500)
  identity = IdentityAdapter::from_key(pgp_key)
  tor = TorController::new(config)
  ui = TerminalLineRenderer::new()

        │
        ▼
Mode persistant :
  storage = SqliteStorageAdapter::open("~/.sanctum/db.sqlite")
  identity = IdentityAdapter::from_key(pgp_key)
  tor = TorController::new(config)
  ui = TerminalLineRenderer::new()

        │
        ▼
Côté host :
  hs = tor.create_hidden_service()        → .onion prêt
  host_svc = HostService::new(room, event_tx)

  Pour chaque client qui se connecte :
    conn = TransportConnection::new(addr)
    conn.feed_data(tcp_bytes)             → codec decode
    frame = conn.try_decode_frame()       → Frame
    // Noise handshake via sanctum-crypto
    // Auth challenge-response via AuthService
    host_svc.register_client(fp, conn.id())

Côté host-local (host est aussi participant) :
  (local_a, local_b) = InProcessTransport::pair()
  // local_a → HostService
  // local_b → ChatSession du host
  chat = ChatSession::new(config, ui, event_tx, shutdown)

Côté client distant :
  sanctum join <token>
  tor.connect_via_socks(onion_addr)       → TCP via Tor
  conn = TransportConnection::new(onion)
  // Noise + Auth + X3DH
  chat = ChatSession::new(config, ui, event_tx, shutdown)
```

Le point clé : **les services (app) ne savent pas** quel adapter ils utilisent. Un HostService qui route des messages ne sait pas si le message arrive de TCP/Tor ou d'un channel en mémoire. Un ChatSession ne sait pas si son UiPort est un vrai terminal ou un mock de test.

---

## 13. Résumé des 45 tests

| Module | Tests | Ce qu'ils vérifient |
|--------|-------|-------------------|
| **codec** | 8 | Round-trip simple, payload vide, données partielles, len=0 rejeté, frame trop grande rejetée, multi-frames dans un buffer, format wire exact, taille max acceptée |
| **storage_memory** | 7 | Store/load room, room inexistante, store/fetch messages, filtre par seq, éviction FIFO, purge par âge, delete room + messages |
| **storage_sqlite** | 8 | Schema version, store/load room, room inexistante, backlog store/fetch, purge expired, store/load key, key inexistante, store member, hash fingerprint déterministe |
| **identity_pgp** | 5 | Generate + fingerprint, sign/verify round-trip, mauvaises données rejetées, mauvaise clé rejetée, fingerprint déterministe, clé invalide rejetée |
| **transport** | 6 | Feed + decode, données partielles, connexion fermée, IDs uniques, InProcessTransport pair, bidirectionnel |
| **tor_control** | 5 | Create + destroy HS, indisponible → erreur, déjà actif → erreur, pas de service → erreur, format .onion |
| **terminal_renderer** | 4 | Format timestamp, NullAdapter fonctionne, init/cleanup, status bar |
| **Total** | **45** | |