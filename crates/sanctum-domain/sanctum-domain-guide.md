# Sanctum Domain — Documentation Complète

## Table des matières

1. Vue d'ensemble
2. Pourquoi un crate "domain" séparé ?
3. Structure des fichiers
4. Cargo.toml — les dépendances
5. lib.rs — le point d'entrée
6. Les Entités
7. Les Erreurs
8. Les Événements
9. Les Ports (Traits)
10. Concepts Rust utilisés
11. Pratiques de sécurité
12. Comment tout s'assemble

---

## 1. Vue d'ensemble

Le crate `sanctum-domain` est le **noyau** de l'application Sanctum. Il contient la logique métier pure : les structures de données, les règles métier et les interfaces (traits) que le reste du code doit respecter.

**Ce qu'il fait** :
- Définit ce qu'est une Room, un Member, un Message, etc.
- Définit les règles : "une room doit avoir au moins un Owner", "un fingerprint PGP fait 40 caractères hex", etc.
- Définit les contrats (traits) : "pour stocker des données, il faut implémenter ces méthodes"

**Ce qu'il ne fait PAS** :
- Aucun accès réseau
- Aucune lecture/écriture sur le disque
- Aucune cryptographie concrète
- Aucune interaction avec Tor
- Aucun affichage terminal

C'est volontaire. Le domain est pur — il ne dépend de rien d'externe. Ça le rend testable, portable et sûr.

---

## 2. Pourquoi un crate "domain" séparé ?

Sanctum suit l'architecture **Clean / Hexagonale**. L'idée centrale :

```
          ┌─────────────────────────────────────┐
          │           CLI (sanctum-cli)         │
          │                                     │
          │    ┌───────────────────────────┐    │
          │    │      App (sanctum-app)    │    │
          │    │                           │    │
          │    │   ┌───────────────────┐   │    │
          │    │   │                   │   │    │
          │    │   │  DOMAIN (ici)     │   │    │
          │    │   │                   │   │    │
          │    │   └───────────────────┘   │    │
          │    │                           │    │
          │    └───────────────────────────┘    │
          │                                     │
          │    Infra (sanctum-infra)            │
          │    Crypto (sanctum-crypto)          │
          └─────────────────────────────────────┘
```

Les flèches de dépendance pointent vers l'intérieur. Le CLI dépend de App, App dépend de Domain, Infra dépend de Domain. Mais Domain ne dépend de rien d'autre.

Pourquoi ? Parce que le domain définit des **traits** (interfaces). Par exemple, le domain dit "il existe un StoragePort avec une méthode store_message". Puis la couche Infra crée un SqliteStorageAdapter qui implémente ce trait. Le domain ne sait pas que SQLite existe.

Cargo enforce cette séparation : comme sanctum-domain n'a pas sanctum-infra dans ses dépendances, il est **physiquement impossible** d'importer du code infra depuis le domain.

---

## 3. Structure des fichiers

```
crates/sanctum-domain/
├── Cargo.toml                    ← Dépendances du crate
└── src/
    ├── lib.rs                    ← Point d'entrée, déclare les modules
    ├── errors.rs                 ← Enum d'erreurs centralisé
    ├── events.rs                 ← Événements système + session
    ├── entities/
    │   ├── mod.rs                ← Déclare les sous-modules
    │   ├── member.rs             ← Fingerprint, Role, DisplayAlias, Member
    │   ├── room.rs               ← RoomId, RoomMode, RoomConfig, Room
    │   ├── message.rs            ← MessageEnvelope, RatchetHeader
    │   ├── identity.rs           ← PreKeyBundle, Identity
    │   ├── session.rs            ← Session (anti-replay)
    │   └── invite.rs             ← InviteToken
    └── ports/
        ├── mod.rs                ← Déclare les sous-modules
        ├── transport.rs          ← TransportPort trait
        ├── storage.rs            ← StoragePort trait
        ├── crypto.rs             ← CryptoPort trait
        ├── identity.rs           ← IdentityPort trait
        ├── tor.rs                ← TorPort trait
        └── ui.rs                 ← UiPort trait
```

Deux dossiers principaux :
- `entities/` : les structures de données (ce que le système manipule)
- `ports/` : les interfaces (ce que le système peut faire)

---

## 4. Cargo.toml — les dépendances

| Dépendance | Rôle |
|-----------|------|
| `serde` | Sérialisation/désérialisation de structures |
| `uuid` | Génération d'identifiants uniques (UUID v4) |
| `zeroize` | Effacement sécurisé de la mémoire au drop |
| `thiserror` | Génération automatique de types d'erreurs |
| `tokio` | Types async (channels sync), PAS le runtime |
| `tracing` | Façade de logging (macros uniquement) |

Chaque dépendance est légère et ne fait aucun IO. Le domain reste pur.

`workspace = true` signifie "utilise la version définie dans le Cargo.toml racine". Tous les crates du projet utilisent la même version de chaque dépendance.

---

## 5. lib.rs — le point d'entrée

```rust
#![forbid(unsafe_code)]     // Interdit le code unsafe dans tout le crate
#![warn(missing_docs)]      // Avertit si un élément public n'est pas documenté
#![deny(dead_code)]         // Erreur si du code n'est jamais utilisé
#![deny(clippy::all)]       // Active toutes les règles du linter Clippy
```

`#![forbid(unsafe_code)]` est la ligne la plus importante. En Rust, `unsafe` contourne les garanties de sécurité mémoire. En l'interdisant, on garantit que ce crate ne peut jamais avoir de buffer overflow, use-after-free, etc.

Les `pub use` (re-exports) en bas du fichier permettent d'écrire `use sanctum_domain::Room` au lieu de `use sanctum_domain::entities::room::Room`.

---

## 6. Les Entités

### 6.1 member.rs — Fingerprint, Role, DisplayAlias, Member

#### Fingerprint — l'identité d'un utilisateur

```rust
pub struct Fingerprint(String);
```

Un fingerprint PGP = 40 caractères hexadécimaux. C'est l'identifiant unique de chaque utilisateur dans Sanctum.

**Pourquoi un type dédié plutôt qu'un String ?** C'est le **Newtype Pattern** :

```rust
// SANS newtype — bug silencieux
fn add_member(room_id: String, fingerprint: String) { }
add_member(fingerprint, room_id);  // Inversé mais compile !

// AVEC newtype — erreur de compilation
fn add_member(room_id: RoomId, fingerprint: Fingerprint) { }
add_member(fingerprint, room_id);  // Le compilateur refuse
```

Le constructeur `Fingerprint::new()` valide l'entrée : normalise en majuscules, retire les espaces, vérifie 40 chars hex. Retourne `Result` (pas de crash).

**Sécurité** : implémente `Zeroize` et `ZeroizeOnDrop`. Quand un Fingerprint est détruit, sa mémoire est écrasée avec des zéros. Empêche la récupération via dump mémoire.

**Display** : affiche `[4A7B..5A6B]` (tronqué) pour éviter de fuiter le fingerprint complet dans les logs. Le complet n'est accessible que via `.as_str()`.

#### Role — les permissions

```rust
pub enum Role {
    Member = 0,   // Envoyer/recevoir
    Admin = 1,    // + inviter et kick
    Owner = 2,    // + promouvoir, détruire la room
}
```

Les valeurs 0, 1, 2 avec `Ord` permettent `Role::Owner > Role::Admin > Role::Member`.

#### DisplayAlias — le pseudonyme

Newtype sur String. 1-20 caractères, `[a-zA-Z0-9_-]` uniquement. Purement cosmétique — l'identité réelle est le fingerprint.

#### Member — un participant

```rust
pub struct Member {
    fingerprint: Fingerprint,      // Qui (PGP)
    identity_key: Vec<u8>,         // Clé publique X25519
    display_alias: DisplayAlias,   // Pseudo affiché
    role: Role,                    // Permissions
    joined_at: u64,                // Timestamp
    status: MemberStatus,          // Active ou Revoked
}
```

Champs **privés**, accès via getters/méthodes. `identity_key` est une clé **publique** — les clés privées ne sont jamais dans le domain.

---

### 6.2 room.rs — RoomId, RoomMode, RoomConfig, Room

#### RoomId

Newtype sur UUID v4. Identifiant aléatoire de 128 bits, collision impossible en pratique.

#### RoomMode

```rust
pub enum RoomMode {
    Ephemeral,    // Tout en RAM, rien sur disque
    Persistent,   // SQLite chiffré, backlog, .onion stable
}
```

#### RoomConfig

```rust
pub struct RoomConfig {
    pub max_members: u16,            // Max 50
    pub backlog_max_messages: u32,   // Max 5000
    pub backlog_max_age_hours: u32,  // Max 720
    pub message_padding_block: u16,  // Puissance de 2
}
```

`validate()` borne les valeurs aux limites au lieu de rejeter.

#### Room

```rust
pub struct Room {
    id: RoomId,
    name: String,
    mode: RoomMode,
    config: RoomConfig,
    members: Vec<Member>,
}
```

**Invariants** (toujours vrais) :
1. Au moins un Owner (enforced par le constructeur qui prend un `owner` obligatoire)
2. Pas de fingerprints dupliqués actifs
3. Membres actifs ≤ max_members

`add_member()` et `revoke_member()` vérifient ces invariants et retournent `Err` si violation.

---

### 6.3 message.rs — MessageEnvelope

```rust
pub struct MessageEnvelope {
    sender_fingerprint: Fingerprint,  // En clair (routage)
    room_id: RoomId,                  // En clair (routage)
    sequence_number: u64,             // Anti-replay
    nonce: Vec<u8>,                   // 12 octets, unique
    timestamp: u64,                   // Unix seconds
    ciphertext: Vec<u8>,             // Opaque pour le host
    ratchet_header: RatchetHeader,    // Sync Double Ratchet
}
```

C'est ce qui transite via le host. Le host voit les métadonnées de routage mais le `ciphertext` est opaque — seul le destinataire peut déchiffrer.

`RatchetHeader` contient la clé publique DH actuelle et les compteurs de chaîne, nécessaires pour que le destinataire synchronise son état de ratchet.

---

### 6.4 identity.rs — PreKeyBundle, Identity

#### PreKeyBundle — clés publiques pour X3DH

```rust
pub struct PreKeyBundle {
    pub identity_key: Vec<u8>,              // IK permanente
    pub signed_prekey: Vec<u8>,             // SPK rotée 24-48h
    pub signed_prekey_signature: Vec<u8>,   // Preuve que SPK vient de IK
    pub signed_prekey_id: u32,
    pub one_time_prekey: Option<Vec<u8>>,   // Usage unique, peut être None
    pub one_time_prekey_id: Option<u32>,
}
```

Stocké sur le host, distribué aux membres. Tout est **public**. `Option` signifie "peut être absent" (pas de null en Rust).

#### Identity

Combine fingerprint PGP (auth) + PreKeyBundle (chiffrement). La carte d'identité publique d'un utilisateur.

---

### 6.5 session.rs — Session et Anti-Replay

```rust
pub struct Session {
    peer_fingerprint: Fingerprint,
    last_sent_sequence: u64,
    last_received_sequence: u64,
    replay_bitmap: u64,           // Fenêtre glissante 64 bits
    established: bool,
}
```

L'état crypto du Double Ratchet est opaque (géré par CryptoPort). Ici on ne stocke que les métadonnées.

**L'anti-replay** : `replay_bitmap` est un entier de 64 bits. Chaque bit = un message dans la fenêtre `[last_received - 63 .. last_received]`.

Quand un message arrive avec séquence `seq` :

| Cas | Action |
|-----|--------|
| `seq > last_received` | Nouveau, décaler la fenêtre, accepter |
| `seq` dans la fenêtre et bit = 0 | Hors-ordre mais pas vu, accepter |
| `seq` dans la fenêtre et bit = 1 | Déjà reçu = **replay, rejeter** |
| `seq` avant la fenêtre | Trop vieux, rejeter |

Ça tolère les messages hors-ordre (fréquent sur Tor) tout en détectant les replays.

---

### 6.6 invite.rs — InviteToken

```rust
pub struct InviteToken {
    pub room_id: RoomId,
    pub onion_address: String,
    pub port: u16,
    pub host_noise_pubkey: Vec<u8>,
    pub inviter_fingerprint: Fingerprint,
    pub invited_fingerprint: Fingerprint,   // Nominatif
    pub role: Role,
    pub expires_at: u64,
    pub signature: Vec<u8>,
}
```

**Auto-suffisant** : contient tout pour se connecter. Sérialisé en base64url, transmis hors-bande.

**Nominatif** : seul le détenteur de la clé PGP `invited_fingerprint` peut l'utiliser.

`signed_data()` calcule les octets couverts par la signature. Le destinataire vérifie l'intégrité.

---

## 7. Les Erreurs

```rust
pub enum SanctumError {
    VersionMismatch { got, min },
    AuthFailed { reason },
    InvalidSignature,
    ReplayDetected { seq, sender },
    RoomNotFound(RoomId),
    RoomFull { current, max },
    InsufficientPermissions { need, have },
    MemberAlreadyExists(Fingerprint),
    MemberNotFound(Fingerprint),
    MemberRevoked(Fingerprint),
    CannotRevokeOwner,
    DecryptionFailed,
    RatchetDesync { peer },
    TorUnavailable(String),
    ConnectionLost(String),
    StorageError(String),
    MalformedMessage(String),
    InvalidInviteToken(String),
    InviteTokenExpired,
}
```

Un seul enum pour toutes les erreurs. `thiserror` génère les messages via `#[error("...")]`.

En Rust, les erreurs sont des valeurs (`Result<T, E>`), pas des exceptions. L'appelant **doit** gérer l'erreur — le compilateur refuse sinon.

---

## 8. Les Événements

### SanctumEvent — événements internes

Utilisés entre services : `ClientConnected`, `RoomCreated`, `TorServiceReady`, etc. Ce sont des notifications d'infrastructure.

### ChatEvent — événements de session

Utilisés entre ChatSession et l'UI : `IncomingMessage`, `PeerJoining`, `PeerReady`, `Disconnected`, etc. Ce sont des notifications d'affichage.

Transitent via un `broadcast` channel Tokio : un émetteur, plusieurs récepteurs.

---

## 9. Les Ports (Traits)

Un port = un trait qui définit **quoi** faire sans dire **comment**.

```rust
// Le domain DÉFINIT :
pub trait StoragePort {
    fn store_message(&self, ...) -> ...;
}

// L'infra IMPLÉMENTE :
impl StoragePort for SqliteStorage { ... }

// Les tests MOCKENT :
impl StoragePort for MockStorage { ... }
```

`Send + Sync` sur chaque trait = utilisable dans un contexte async multi-threadé.

### Les 6 ports

| Port | Rôle | Implémentations prévues |
|------|------|------------------------|
| `TransportPort` | Envoyer/recevoir des frames réseau | NoiseTransport, InProcessTransport |
| `StoragePort` | Stocker rooms, messages, bundles | MemoryStorage, SqliteStorage |
| `CryptoPort` | Chiffrer, déchiffrer, padding, KDF | AesGcmCrypto |
| `IdentityPort` | Signer, vérifier (PGP) | SequoiaPgpIdentity |
| `TorPort` | Créer/détruire des Hidden Services | TorControlAdapter |
| `UiPort` | Lire saisie, afficher messages | TerminalRenderer, MockUi |

---

## 10. Concepts Rust utilisés

| Concept | Explication | Où dans le code |
|---------|------------|-----------------|
| **Newtype** | Wrapper un type pour la type safety | `Fingerprint(String)`, `RoomId(Uuid)` |
| **Enum avec données** | Tagged union, chaque variante a ses données | `SanctumError`, `ChatEvent` |
| **Result** | Retour Ok/Err au lieu d'exceptions | `add_member() -> Result<(), SanctumError>` |
| **Option** | Some/None au lieu de null | `one_time_prekey: Option<Vec<u8>>` |
| **Trait** | Interface (contrat sans implémentation) | `StoragePort`, `CryptoPort`, etc. |
| **derive** | Génération auto de code | `#[derive(Debug, Clone, Serialize)]` |
| **cfg(test)** | Code compilé uniquement pour les tests | `#[cfg(test)] mod tests { }` |
| **Champs privés + getters** | Encapsulation, invariants protégés | `Member`, `Room` |
| **forbid(unsafe_code)** | Interdit unsafe dans tout le crate | `lib.rs` ligne 1 |

---

## 11. Pratiques de sécurité

### `#![forbid(unsafe_code)]`

Aucun code unsafe dans le domain. Le compilateur le vérifie. Ça élimine toute une classe de bugs mémoire (buffer overflow, use-after-free, data races).

### Zeroize — effacement mémoire

`Fingerprint` implémente `ZeroizeOnDrop`. Quand la valeur est détruite (sort du scope), la mémoire est écrasée avec des zéros. Sans ça, un dump mémoire pourrait retrouver les fingerprints même après usage.

```rust
{
    let fp = Fingerprint::new("4A7B...").unwrap();
    // fp est en mémoire
}
// fp est détruit → la mémoire est remplie de 0x00
```

### Display tronqué

`Fingerprint` affiche `[4A7B..5A6B]` au lieu du fingerprint complet. Si un log est capturé par un attaquant, il ne récupère pas les fingerprints complets. Le complet n'est accessible que via `.as_str()` (appel explicite).

### Clés privées jamais dans le domain

`identity_key` dans `Member` = clé **publique**. `PreKeyBundle` = clés **publiques**. Les clés privées vivent uniquement dans l'implémentation du `CryptoPort`, jamais dans les entités.

### Validation à la construction

Impossible de créer un `Fingerprint` invalide, un `DisplayAlias` vide, ou une `Room` sans owner. Les constructeurs valident et retournent `Result` au lieu de crasher.

### Anti-replay bitmap

La fenêtre glissante de 64 bits dans `Session` détecte les messages rejoués même hors-ordre. Un attaquant qui capture et renvoie un message sera détecté.

### panic = "abort" en release

Dans le `Cargo.toml` racine, `panic = "abort"` empêche le stack unwinding sur panic. L'unwinding pourrait exposer des secrets en mémoire pendant le déroulement de la pile. Avec abort, le processus s'arrête immédiatement.

---

## 12. Comment tout s'assemble

Voici le flux d'un message de Alice vers Bob dans une room, du point de vue du domain :

```
Alice tape "Hello Bob"
    │
    ▼
ChatSession (couche App) reçoit le texte via UiPort.read_input()
    │
    ▼
ChatSession demande à CryptoPort.pad() puis CryptoPort.encrypt()
    │
    ▼
ChatSession crée un MessageEnvelope avec :
    - sender = Alice.fingerprint
    - room_id = la room
    - sequence = Session.next_send_sequence()
    - ciphertext = le résultat du chiffrement
    │
    ▼
ChatSession envoie via TransportPort.send()
    │
    ▼
Le Host reçoit le MessageEnvelope
    │
    ├─ Vérifie Room.is_authorized(alice)
    ├─ Stocke via StoragePort.store_message() (si persistant)
    ├─ Fan-out : envoie à Bob via TransportPort.send()
    │
    ▼
Bob reçoit le MessageEnvelope
    │
    ├─ Session.check_replay(seq) → true (pas un replay)
    ├─ CryptoPort.decrypt() → plaintext
    ├─ CryptoPort.unpad() → "Hello Bob"
    │
    ▼
ChatSession émet ChatEvent::IncomingMessage
    │
    ▼
UiPort.print_message() affiche "[14:32] Owner alice: Hello Bob"
```

Le domain fournit :
- Les types (`MessageEnvelope`, `Fingerprint`, `Room`, `Session`)
- Les règles (`is_authorized`, `check_replay`, validation)
- Les contrats (`TransportPort`, `CryptoPort`, `StoragePort`, `UiPort`)

Les couches extérieures fournissent les **implémentations concrètes** de ces contrats.

---

## Résumé des 23 tests

| Fichier | Tests | Ce qu'ils vérifient |
|---------|-------|-------------------|
| member.rs | 8 | Fingerprint valide/invalide, normalisation, display tronqué, rôles, alias, lifecycle membre |
| room.rs | 6 | Création avec owner, ajout membre, rejet doublon, room pleine, révocation, protection owner |
| session.rs | 6 | Incrémentation séquence, replay séquentiel/hors-ordre/vieux/zéro, gap large |
| **Total** | **23** | |

Tous passent. Le domain est validé.
