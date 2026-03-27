# SANCTUM — Dossier d'Architecture v0.1

```
  █████████    █████████   ██████   █████   █████████  ███████████ █████  █████ ██████   ██████
 ███▒▒▒▒▒███  ███▒▒▒▒▒███ ▒▒██████ ▒▒███   ███▒▒▒▒▒███▒█▒▒▒███▒▒▒█▒▒███  ▒▒███ ▒▒██████ ██████ 
▒███    ▒▒▒  ▒███    ▒███  ▒███▒███ ▒███  ███     ▒▒▒ ▒   ▒███  ▒  ▒███   ▒███  ▒███▒█████▒███ 
▒▒█████████  ▒███████████  ▒███▒▒███▒███ ▒███             ▒███     ▒███   ▒███  ▒███▒▒███ ▒███ 
 ▒▒▒▒▒▒▒▒███ ▒███▒▒▒▒▒███  ▒███ ▒▒██████ ▒███             ▒███     ▒███   ▒███  ▒███ ▒▒▒  ▒███ 
 ███    ▒███ ▒███    ▒███  ▒███  ▒▒█████ ▒▒███     ███    ▒███     ▒███   ▒███  ▒███      ▒███ 
▒▒█████████  █████   █████ █████  ▒▒█████ ▒▒█████████     █████    ▒▒████████   █████     █████
 ▒▒▒▒▒▒▒▒▒  ▒▒▒▒▒   ▒▒▒▒▒ ▒▒▒▒▒    ▒▒▒▒▒   ▒▒▒▒▒▒▒▒▒     ▒▒▒▒▒      ▒▒▒▒▒▒▒▒   ▒▒▒▒▒     ▒▒▒▒▒ 

         [ ARCHITECTURE DOSSIER — CLASSIFIÉ ]
```

**Version** : 0.1-draft  
**Date** : 2026-02-12  
**Statut** : En cours de validation  
**Classification** : Document technique interne

---

## Table des matières

1. [Vision Produit](#1-vision-produit)
2. [Modèle de Menaces](#2-modèle-de-menaces)
3. [Exigences de Sécurité](#3-exigences-de-sécurité)
4. [Conception du Protocole](#4-conception-du-protocole)
5. [Architecture Logicielle](#5-architecture-logicielle)
6. [Éphémère vs Persistant](#6-éphémère-vs-persistant)
7. [Stockage Chiffré](#7-stockage-chiffré)
8. [Gestion des Clés et Identités](#8-gestion-des-clés-et-identités)
9. [Logging / Observabilité](#9-logging--observabilité)
10. [Opérations Tor Hidden Service](#10-opérations-tor-hidden-service)
11. [UX Terminal](#11-ux-terminal)
12. [Roadmap](#12-roadmap)
13. [Plan de Dépendances Rust](#13-plan-de-dépendances-rust)
14. [Structure du Dépôt](#14-structure-du-dépôt)
15. [ADRs](#15-adrs)
16. [Tests d'Acceptance & DoD](#16-tests-dacceptance--dod)
17. [Plan d'Implémentation Fichier par Fichier](#17-plan-dimplémentation-fichier-par-fichier)
18. [CI, Release, Runbook](#18-ci-release-runbook)

---

## 1. Vision Produit

### 1.1 Énoncé

Sanctum est un outil de chat sécurisé, Tor-only, conçu pour des communications privées entre individus ou petits groupes. Il privilégie la confidentialité, l'anonymat et la souveraineté des données par-dessus tout.

### 1.2 Personas

| Persona | Description | Besoin principal |
|---------|-------------|-----------------|
| **Alice (Journaliste)** | Communique avec des sources sensibles | Anonymat, éphéméralité, aucune trace disque |
| **Bob (Administrateur)** | Héberge une room persistante sur un VPS/VM | Stabilité 24/7, backlog chiffré, contrôle d'accès |
| **Charlie (Activiste)** | Rejoint des rooms depuis des réseaux hostiles | Résistance à la censure, authentification forte |
| **Diana (Développeuse)** | Coordination technique en équipe restreinte | Petit groupe (5-10), fiabilité, CLI ergonomique |

### 1.3 Cas d'usage MVP

- **CU-1** : Alice crée une room éphémère, invite Bob. Ils échangent des messages. La session se termine, tout disparaît.
- **CU-2** : Bob héberge une room persistante sur un VPS. Charlie se connecte, récupère le backlog chiffré des messages envoyés pendant son absence.
- **CU-3** : Diana invite 5 collègues dans une room persistante. Un membre est révoqué par un admin.
- **CU-4** : Alice vérifie l'identité de Bob via PGP avant d'accepter l'invitation.

### 1.4 Non-objectifs (explicitement hors scope MVP)

- Support clearnet / WebSocket / HTTPS
- Interface graphique (GUI/Web)
- Transfert de fichiers (prévu v0.3)
- Appels audio/vidéo
- Fédération entre instances Sanctum
- Support mobile natif (prévu post-v1.0)
- Groupes > 30 personnes (optimisation MLS post-v1.0)

### 1.5 Périmètre MVP (v0.1)

| Fonctionnalité | Inclus | Notes |
|----------------|--------|-------|
| Création de room (éphémère/persistante) | ✅ | |
| Connexion via .onion | ✅ | |
| Auth PGP challenge-response | ✅ | |
| E2E Noise + Double Ratchet (pairwise) | ✅ | |
| Rôles owner/admin/member | ✅ | |
| Invitation par token signé | ✅ | |
| Révocation de membre | ✅ | |
| Backlog chiffré (persistant) | ✅ | 500 msgs / 72h défaut |
| CLI complète | ✅ | |
| Tor externe via Control Port | ✅ | |
| TUI (ratatui) | ❌ | v0.2 |
| Transfert fichiers | ❌ | v0.3 |
| Client auth Tor | ❌ | v0.2 |

---

## 2. Modèle de Menaces

### 2.1 Acteurs

| Acteur | Capacité | Motivation |
|--------|----------|------------|
| **Observateur réseau (ISP/État)** | Analyse de trafic, corrélation temporelle, DPI | Identifier les participants |
| **Compromission serveur** | Accès root au VPS hébergeant un host persistant | Lire les messages, identifier les membres |
| **Membre malveillant** | Accès légitime à une room | Exfiltrer du contenu, usurper une identité |
| **Attaquant actif (MITM)** | Interception/modification de trafic Tor | Injection, replay, downgrade |
| **Attaquant physique** | Accès physique à la machine d'un participant | Extraction de clés, lecture du disque |

### 2.2 Surfaces d'attaque

| Surface | Composant | Risque |
|---------|-----------|--------|
| **S1** Transport Tor | Liaison client↔host | Corrélation de trafic, timing attacks |
| **S2** Protocole d'authentification | Challenge-response PGP | Replay, impersonation si clé compromise |
| **S3** E2E chiffrement | Double Ratchet pairwise | Compromission de clé de session |
| **S4** Stockage persistant | SQLite chiffré | Accès physique, cold boot |
| **S5** Mémoire (RAM) | Clés en mémoire | Dump mémoire, swap leak |
| **S6** Métadonnées | Timestamps, tailles de messages | Analyse de pattern |
| **S7** Dépendances (supply chain) | Crates Rust | Backdoor, vulnérabilité non patchée |
| **S8** Tor Control Port | Interface de gestion Tor | Accès non autorisé au control port |

### 2.3 Scénarios prioritaires et mitigations

| # | Scénario | Impact | Probabilité | Mitigation | ADR |
|---|----------|--------|-------------|------------|-----|
| T1 | Compromission du VPS host | Critique | Moyenne | E2E : l'host ne voit que du ciphertext. Clés E2E jamais sur le host. | ADR-003 |
| T2 | Vol de clé PGP d'un membre | Élevé | Faible | PGP = auth seule, pas chiffrement. Révocation possible. Forward secrecy via Ratchet. | ADR-004 |
| T3 | Replay d'un message | Moyen | Moyenne | Nonces uniques + compteur monotone + fenêtre anti-replay | ADR-006 |
| T4 | Analyse de trafic / corrélation | Élevé | Élevée | Padding des messages, Tor comme seul transport | ADR-010 |
| T5 | Lecture du disque après saisie | Critique | Faible | Éphémère : zéro disque. Persistant : AES-256-GCM + Argon2id | ADR-007 |
| T6 | Swap/core dump leak | Élevé | Faible | `mlock()`, désactivation core dumps, `zeroize` | ADR-008 |
| T7 | Membre malveillant exfiltre | Moyen | Moyenne | Hors scope crypto. Mitigation : révocation rapide. | — |
| T8 | Downgrade du protocole | Critique | Faible | Version dans le handshake, refus strict, pas de fallback | ADR-006 |

### 2.4 Hypothèses explicites

- Tor fournit l'anonymat réseau attendu.
- L'utilisateur protège sa clé PGP avec une passphrase forte.
- Le système d'exploitation n'est pas compromis au moment du déploiement.
- Les crates Rust sont authentiques (mitigé par `cargo-deny` + `cargo-audit`).

### 2.5 Hors scope du modèle de menaces

- Attaques par canaux auxiliaires CPU (Spectre, etc.)
- Compromission du réseau Tor lui-même (guard discovery, Sybil)
- Ingénierie sociale pure
- Rubber-hose cryptanalysis

---

## 3. Exigences de Sécurité

### 3.1 Exigences fonctionnelles

| ID | Exigence | Priorité |
|----|----------|----------|
| SF-01 | Authentification par challenge-response PGP | P0 |
| SF-02 | Chiffrement E2E pairwise (X25519 + Double Ratchet) | P0 |
| SF-03 | Forward secrecy : compromission d'une clé ne révèle pas les messages passés | P0 |
| SF-04 | Protection anti-replay : nonce + compteur monotone | P0 |
| SF-05 | Gestion des membres : invitation, révocation, rôles | P0 |
| SF-06 | Backlog chiffré (persistant) : ciphertexts E2E stockés | P1 |
| SF-07 | Révocation : exclusion immédiate et rotation des clés de session | P0 |
| SF-08 | Padding des messages à taille fixe (blocs de 256 octets) | P1 |
| SF-09 | Version de protocole dans chaque handshake, refus de downgrade | P0 |
| SF-10 | Tor client authorization (optionnel, v0.2) | P2 |

### 3.2 Exigences non fonctionnelles

| ID | Exigence | Priorité |
|----|----------|----------|
| SNF-01 | Aucune écriture disque en mode éphémère (vérifiable) | P0 |
| SNF-02 | Logs désactivés par défaut ; aucun secret en clair même en debug | P0 |
| SNF-03 | Secrets en mémoire protégés (`mlock`, `zeroize`) | P0 |
| SNF-04 | Temps de handshake < 5s (hors latence Tor) | P1 |
| SNF-05 | Binaire statique, pas de dépendance runtime sauf Tor | P0 |
| SNF-06 | `cargo-deny` + `cargo-audit` en CI : zéro advisory non résolu | P0 |
| SNF-07 | Résilience : reconnexion automatique après perte Tor | P1 |
| SNF-08 | Vérification de la version du protocole, avertissement si obsolète | P2 |

---

## 4. Conception du Protocole

### 4.1 Transport Tor — Hypothèses et framing

**Transport** : Connexion TCP via Tor Hidden Service (v3 onion). Le host expose un `.onion` sur un port configurable (défaut : 9738). Les clients se connectent via le SOCKS5 proxy de Tor local.

**Framing des messages** :

```
┌──────────┬──────────┬──────────────────┐
│ len (4B) │ type(1B) │ payload (len-1 B)│
└──────────┴──────────┴──────────────────┘
```

- `len` : u32 big-endian, taille du payload + type (max 64 KiB)
- `type` : identifiant du type de message (enum)
- `payload` : protobuf sérialisé

**Types de messages** :

| Type | Code | Direction | Description |
|------|------|-----------|-------------|
| `HandshakeInit` | 0x01 | C→H | Initiation Noise |
| `HandshakeResp` | 0x02 | H→C | Réponse Noise |
| `AuthChallenge` | 0x03 | H→C | Challenge PGP |
| `AuthResponse` | 0x04 | C→H | Réponse signée PGP |
| `AuthResult` | 0x05 | H→C | Succès/échec |
| `RoomMessage` | 0x10 | C→H / H→C | Message E2E chiffré (relayé) |
| `RoomControl` | 0x11 | C→H / H→C | Opérations de room (invite, kick, etc.) |
| `RatchetKeyExchange` | 0x20 | C↔C (via H) | Échange de clés Double Ratchet |
| `Ping` | 0xFE | bidirectionnel | Keepalive |
| `Error` | 0xFF | bidirectionnel | Erreur protocolaire |

### 4.2 Authentification PGP Challenge-Response

**Séquence exacte** :

```
Client                          Host
  │                               │
  ├── HandshakeInit ─────────────►│  (clé publique Noise éphémère)
  │                               │
  │◄── HandshakeResp ─────────────┤  (handshake Noise NK complet)
  │                               │
  │    [Transport Noise NK établi]│
  │                               │
  │◄── AuthChallenge ─────────────┤  {nonce_32B, timestamp, room_id, server_id}
  │                               │
  │    [Client vérifie le challenge]
  │    [Client signe avec sa clé PGP]
  │                               │
  ├── AuthResponse ──────────────►│  {pgp_fingerprint, signature(challenge), pgp_public_key}
  │                               │
  │    [Host vérifie :]           │
  │    1. fingerprint autorisé    │
  │    2. signature valide        │
  │    3. nonce non rejouable     │
  │    4. timestamp ±120s         │
  │                               │
  │◄── AuthResult ────────────────┤  {ok, member_role, room_state}
```

**Détails critiques** :

- Challenge = `nonce(32B) ‖ timestamp(u64) ‖ room_id(16B) ‖ server_id(32B)`
- Fenêtre anti-replay de 120 secondes sur les nonces
- Timestamp tolérance ±120s (Tor n'offre pas NTP fiable)
- Clé publique PGP envoyée pour vérification, mais le fingerprint doit être pré-autorisé

### 4.3 Établissement de session E2E

**Architecture à deux couches** :

```
┌─────────────────────────────────────────────────┐
│ Couche Transport : Noise NK (client ↔ host)     │
│   Le host DÉCHIFFRE le transport pour router,    │
│   mais ne voit que des ciphertexts E2E.          │
├─────────────────────────────────────────────────┤
│ Couche E2E : Double Ratchet (client ↔ client)   │
│   Chaque paire maintient un ratchet indépendant. │
│   Le host ne possède jamais les clés E2E.        │
│   Forward secrecy message par message.           │
└─────────────────────────────────────────────────┘
```

**Noise NK** : Pattern NK, ChaChaPoly, X25519, SHA-256.

**Double Ratchet (pairwise)** — X3DH pour l'échange initial :

```
Alice                                    Bob
  │                                        │
  ├── X3DH Bundle Request ───────────────►│  (via host relay)
  │                                        │
  │◄── X3DH PreKey Bundle ────────────────┤  {IK_Bob, SPK_Bob, Sig(SPK), OPK_Bob}
  │                                        │
  │  DH1 = DH(IK_Alice, SPK_Bob)          │
  │  DH2 = DH(EK_Alice, IK_Bob)           │
  │  DH3 = DH(EK_Alice, SPK_Bob)          │
  │  DH4 = DH(EK_Alice, OPK_Bob)          │
  │  SK = KDF(DH1 ‖ DH2 ‖ DH3 [‖ DH4])   │
  │                                        │
  ├── Initial Message ───────────────────►│  {IK_Alice, EK_Alice, OPK_id, ciphertext}
  │                                        │
  │  [Double Ratchet initialisé]           │
```

**Clés X3DH** :

| Clé | Type | Durée de vie | Stockage |
|-----|------|-------------|----------|
| IK (Identity Key) | X25519 longue durée | Permanente | Fichier chiffré (persistant) / RAM (éphémère) |
| SPK (Signed PreKey) | X25519, signée par IK | 24-48h rotation | Idem |
| OPK (One-Time PreKey) | X25519 usage unique | Consommée | Pool de 10, rechargé quand < 3 |
| EK (Ephemeral Key) | X25519 éphémère | Une session X3DH | RAM uniquement |
| Clés de ratchet | Dérivées | Chaque message | RAM, effacées après usage |

**Pour un groupe de N membres** : N-1 sessions Double Ratchet par membre. Message chiffré N-1 fois. Acceptable pour N ≤ 30.

### 4.4 Modèle de Room et Membership

**Structure** :

```rust
Room {
    id: RoomId,          // UUID v4
    name: String,
    mode: Ephemeral | Persistent,
    config: RoomConfig {
        max_members: u16,            // défaut: 10, max: 50
        backlog_max_messages: u32,   // défaut: 500
        backlog_max_age_hours: u32,  // défaut: 72
        message_padding_block: u16,  // défaut: 256
    },
    members: Vec<Member>,
}

Member {
    pgp_fingerprint: Fingerprint,
    identity_key: X25519PublicKey,
    role: Owner | Admin | Member,
    joined_at: Timestamp,
    status: Active | Revoked,
}
```

**Système d'invitation** :

```rust
InviteToken {
    room_id: RoomId,
    onion_address: String,
    host_noise_pubkey: X25519PublicKey,
    inviter_pgp_fingerprint: Fingerprint,
    invited_pgp_fingerprint: Fingerprint,  // nominatif
    role: Member | Admin,
    expires_at: Timestamp,
    signature: PGPSignature,  // signée par l'inviter
}
// Sérialisé en base64url pour partage hors bande
```

**Révocation** :

1. Owner/Admin envoie `RoomControl::Revoke { target }`
2. Host supprime le membre, déconnecte le client
3. Broadcast `MemberRevoked` à tous
4. Tous les membres renouvellent leurs SPK et purgent la session avec le membre révoqué

### 4.5 Anti-Replay et Gestion d'Horloge

```rust
MessageEnvelope {
    sender_fingerprint: Fingerprint,
    sequence_number: u64,        // compteur monotone par expéditeur
    nonce: [u8; 12],             // nonce unique AEAD
    timestamp: u64,              // Unix timestamp (secondes)
    ciphertext: Vec<u8>,
    ratchet_header: RatchetHeader,
}
```

- **Compteur monotone** : seq incrémenté par envoi par room. Refus si seq ≤ dernier accepté (fenêtre de 32 msgs pour réordonnancement).
- **Fenêtre bitmap** : 64 bits glissante pour détecter les replays dans la fenêtre.
- **Nonce** : 12 octets dérivés du compteur + salt. Unicité garantie par le Double Ratchet.
- **Timestamp** : Tolérance ±120s. Utilisé pour expiration du backlog, PAS pour l'anti-replay.

### 4.6 Backlog / Messagerie Hors Ligne (Persistant)

1. Message arrive, destinataire hors ligne → host stocke le **ciphertext E2E** dans le backlog
2. Indexé par `(room_id, recipient_fingerprint, sequence_number)`
3. À la reconnexion : client demande depuis son dernier seq → host envoie puis supprime
4. Contraintes : 500 msgs/room défaut, 72h max, GC toutes les 15 min
5. **Mode éphémère** : PAS de backlog. Hors ligne = message perdu.
6. **Limitation** : Double Ratchet tolère max 256 messages sautés par chaîne

### 4.7 Gestion des Erreurs et Prévention de Downgrade

**Version du protocole** :

```rust
SANCTUM_PROTOCOL_VERSION: u16 = 1;

HandshakeInit {
    protocol_version: u16,
    min_supported_version: u16,
    noise_ephemeral_key: [u8; 32],
}
```

- Si version < min supportée : rejet immédiat `Error::VersionMismatch`
- Aucun mode dégradé, aucun fallback

**Table d'erreurs** :

| Erreur | Action | Réponse |
|--------|--------|---------|
| Version incompatible | Fermeture immédiate | `Error::VersionMismatch` |
| Auth échouée (3 tentatives) | Fermeture + ban 5 min | `Error::AuthFailed` |
| Message malformé | Ignorer, log safe | `Error::MalformedMessage` |
| Sequence number invalide | Ignorer | `Error::ReplayDetected` |
| Room pleine | Refuser | `Error::RoomFull` |
| Membre révoqué | Déconnexion | `Error::Revoked` |
| Ratchet désynchronisé | Re-keying (max 3×) | `Error::RatchetDesync` |

---

## 5. Architecture Logicielle (Clean / Hexagonal)

### 5.1 Vue d'ensemble

```
┌─────────────────────────────────────────────────────────────────┐
│                      Infrastructure                             │
│  ┌──────────┐ ┌───────────┐ ┌──────────┐ ┌─────────────────┐    │
│  │TorControl│ │SqliteStore│ │SequoiaPGP│ │ProtobufCodec    │    │
│  └─────┬────┘ └─────┬─────┘ └────┬─────┘ └────────┬────────┘    │
│════════╪════════════╪════════════╪════════════════╪═════════════│
│        │    Application (Use Cases / Services)    │             │
│  ┌─────▼────────────▼────────────▼────────────────▼──────────┐  │
│  │  HostService │ ClientService │ RoomService │ AuthService  │  │
│  └─────┬────────┴───────┬───────┴──────┬──────┴──────┬───────┘  │
│════════╪════════════════╪══════════════╪═════════════╪══════════│
│        │         Domain (Entities & Ports)           │          │
│  ┌─────▼────────────────▼──────────────▼─────────────▼───────┐  │
│  │  Room │ Member │ Message │ Identity │ Session │ Invite    │  │
│  │                                                           │  │
│  │  Ports (Traits) :                                         │  │
│  │  TransportPort, StoragePort, CryptoPort,                  │  │
│  │  IdentityPort, TorPort                                    │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### 5.2 Couche Domain (`sanctum-domain`)

**Entités** (structures pures, aucune dépendance externe sauf `serde`, `uuid`, `zeroize`) :

| Entité | Champs clés | Invariants |
|--------|-------------|------------|
| `RoomId` | UUID v4 | Non vide |
| `Room` | id, name, mode, config, members | Au moins 1 owner |
| `Member` | fingerprint, identity_key, role, status | Fingerprint unique par room |
| `Message` | sender, sequence, nonce, ciphertext, ratchet_header | seq > 0 |
| `Identity` | pgp_fingerprint, identity_key_pair, signed_prekeys, otp_prekeys | Clé valide |
| `Session` | peer_fingerprint, ratchet_state, last_sequence | Ratchet initialisé |
| `InviteToken` | room_id, onion, host_key, inviter, invited, role, expires, sig | Signature valide |

**Ports (Traits)** :

```rust
trait TransportPort {
    async fn listen(&self, config: &ListenConfig) -> Result<Listener>;
    async fn connect(&self, addr: &OnionAddress) -> Result<Connection>;
    async fn send(&self, conn: &Connection, frame: &Frame) -> Result<()>;
    async fn recv(&self, conn: &Connection) -> Result<Frame>;
}

trait StoragePort {
    async fn store_message(&self, room: &RoomId, msg: &EncryptedMessage) -> Result<()>;
    async fn fetch_backlog(&self, room: &RoomId, recipient: &Fingerprint, since: u64) -> Result<Vec<EncryptedMessage>>;
    async fn store_room(&self, room: &Room) -> Result<()>;
    async fn load_room(&self, id: &RoomId) -> Result<Option<Room>>;
    async fn purge_expired(&self, max_age: Duration) -> Result<u64>;
}

trait CryptoPort {
    fn noise_handshake_initiator(&self, remote_static: &[u8; 32]) -> Result<NoiseSession>;
    fn noise_handshake_responder(&self, keypair: &NoiseKeypair) -> Result<NoiseSession>;
    fn ratchet_encrypt(&self, state: &mut RatchetState, plaintext: &[u8]) -> Result<(RatchetHeader, Vec<u8>)>;
    fn ratchet_decrypt(&self, state: &mut RatchetState, header: &RatchetHeader, ct: &[u8]) -> Result<Vec<u8>>;
    fn x3dh_initiate(&self, our_ik: &IdentityKeypair, their_bundle: &PreKeyBundle) -> Result<(SharedSecret, EphemeralPublicKey)>;
    fn x3dh_respond(&self, our_bundle: &PreKeyBundlePrivate, their_ik: &[u8; 32], their_ek: &[u8; 32]) -> Result<SharedSecret>;
}

trait IdentityPort {
    fn sign(&self, data: &[u8]) -> Result<PgpSignature>;
    fn verify(&self, fp: &Fingerprint, data: &[u8], sig: &PgpSignature) -> Result<bool>;
    fn fingerprint(&self) -> &Fingerprint;
    fn public_key_bytes(&self) -> Vec<u8>;
}

trait TorPort {
    async fn create_hidden_service(&self, port: u16) -> Result<OnionAddress>;
    async fn destroy_hidden_service(&self, addr: &OnionAddress) -> Result<()>;
    async fn connect_via_socks(&self, addr: &OnionAddress, port: u16) -> Result<TcpStream>;
    fn is_available(&self) -> bool;
}
```

### 5.3 Couche Application (`sanctum-app`)

| Service | Responsabilité | Ports utilisés |
|---------|---------------|----------------|
| `HostService` | Démarre le host, accepte connexions, route messages | Transport, Storage, Tor, Crypto |
| `ClientService` | Connexion à un host, sessions E2E | Transport, Tor, Crypto, Identity |
| `AuthService` | Challenge-response PGP | Identity, Crypto |
| `RoomService` | CRUD rooms, membres, invitations, backlog | Storage |
| `MessageService` | Chiffrement/déchiffrement E2E, anti-replay, padding | Crypto |
| **`ChatSession`** | **★ Orchestration session interactive stateful** | **Tous via services ci-dessus + UiPort** |

**Modèle d'événements** :

```rust
enum SanctumEvent {
    ClientConnected { fingerprint: Fingerprint },
    ClientDisconnected { fingerprint: Fingerprint },
    AuthSucceeded { fingerprint: Fingerprint, role: Role },
    AuthFailed { fingerprint: Fingerprint, reason: AuthError },
    RoomCreated { room_id: RoomId },
    MemberJoined { room_id: RoomId, fingerprint: Fingerprint },
    MemberRevoked { room_id: RoomId, fingerprint: Fingerprint },
    MessageReceived { room_id: RoomId, sender: Fingerprint, seq: u64 },
    MessageDelivered { room_id: RoomId, recipient: Fingerprint, seq: u64 },
    BacklogDelivered { room_id: RoomId, recipient: Fingerprint, count: u32 },
    RatchetReKeyed { peer: Fingerprint },
    BacklogPurged { room_id: RoomId, purged: u64 },
    TorServiceReady { onion_address: OnionAddress },
    Error { context: String, error: SanctumError },
}
```

#### 5.3.1 `ChatSession` — Use case session interactive (ADR-016)

`ChatSession` est le **use case principal** de Sanctum côté client. Il orchestre une session de chat interactive en coordonnant des tâches async concurrentes.

**Responsabilités** : connecter/authentifier via `ClientService` + `AuthService`, démarrer les boucles async (réception, saisie, maintenance), router les événements entre réseau/crypto/UI, gérer le cycle de vie session et garantir le nettoyage des secrets au shutdown.

```rust
pub struct ChatSession<T, C, I, S, U>
where
    T: TransportPort, C: CryptoPort, I: IdentityPort, S: StoragePort, U: UiPort,
{
    client: ClientService<T, C, I>,
    messages: MessageService<C>,
    room: RoomService<S>,
    ui: U,
    event_tx: broadcast::Sender<ChatEvent>,
    shutdown: CancellationToken,
}
```

**Cycle de vie** :

```
sanctum chat <room_id>
      │
      ▼
┌─────────────────┐
│  Connect & Auth │  ClientService + AuthService
└────────┬────────┘
         ▼
┌─────────────────┐
│  Fetch Backlog  │  Si persistant : RoomService::fetch_backlog()
└────────┬────────┘
         ▼
┌──────────────────────────────────────────────┐
│         Boucle Principale (tokio::select!)   │
│                                              │
│  Task 1: network_recv_loop                   │
│    transport.recv → decrypt → event_tx       │
│                                              │
│  Task 2: input_loop                          │
│    ui.read_input → parse → encrypt → send    │
│                                              │
│  Task 3: maintenance_loop (persistant seul.) │
│    gc_interval → purge_expired               │
│                                              │
│  Task 4: render_loop                         │
│    event_rx → ui.print_*                     │
│                                              │
│  Tous partagent un CancellationToken         │
└──────────────────────────────────────────────┘
         │
    Ctrl-C / /exit / erreur fatale
         ▼
┌─────────────────┐
│ Shutdown        │  zeroize, restaurer terminal, disconnect
└─────────────────┘
```

En mode éphémère, la maintenance loop n'est **pas démarrée** (pas de storage, pas de GC). Aucune tâche ne touche le disque.

#### 5.3.2 Bus d'événements : `ChatEvent`

Le bus utilise un `tokio::sync::broadcast` channel. `ChatEvent` relie les tâches async au renderer UI.

```rust
enum ChatEvent {
    // Messages
    IncomingMessage { sender: Fingerprint, sender_display: String, content: String, timestamp: u64, seq: u64 },
    OutgoingMessage { content: String, timestamp: u64 },
    // Système
    PeerJoined { fingerprint: Fingerprint, display: String },
    PeerLeft { fingerprint: Fingerprint, display: String },
    PeerRevoked { fingerprint: Fingerprint, display: String },
    // Session
    Connected { room_id: RoomId, role: Role, peers: Vec<PeerInfo> },
    Disconnected { reason: String },
    BacklogStart { count: u32 },
    BacklogEnd,
    // Crypto & maintenance
    RatchetReKeyed { peer: Fingerprint },
    BacklogPurged { count: u64 },
    TorStatusChanged { connected: bool },
    ProtocolError(SanctumError),
}
```

#### 5.3.3 Port UI (`UiPort`)

Sixième port du domain, abstrait le rendu et la saisie :

```rust
trait UiPort: Send + Sync {
    async fn read_input(&self) -> Result<String>;
    fn print_message(&self, sender: &str, content: &str, timestamp: u64);
    fn print_own_message(&self, content: &str, timestamp: u64);
    fn print_system(&self, text: &str);
    fn print_backlog_start(&self, count: u32);
    fn print_backlog_end(&self);
    fn update_status(&self, status: &SessionStatus);
    fn init(&self) -> Result<()>;
    fn cleanup(&self) -> Result<()>;
}
```

**Adaptateurs** :

| Adaptateur | Implémente | Usage | Crate |
|-----------|-----------|-------|-------|
| `TerminalLineRenderer` | `UiPort` | MVP : rendu line-based interactif | `crossterm` |
| `RatatuiRenderer` | `UiPort` | v0.2 : TUI plein écran | `ratatui` + `crossterm` |
| `MockUiAdapter` | `UiPort` | Tests : capture événements dans un Vec | — |
| `NullUiAdapter` | `UiPort` | Mode non-interactif (`send`/`read`) | — |


### 5.4 Couche Infrastructure (`sanctum-infra`)

| Adaptateur | Implémente | Crate |
|-----------|-----------|-------|
| `TorControlAdapter` | `TorPort` | `torut` |
| `NoiseTransportAdapter` | `TransportPort` | `snow` |
| `SqliteStorageAdapter` | `StoragePort` | `rusqlite` + AES-256-GCM |
| `MemoryStorageAdapter` | `StoragePort` | RAM uniquement |
| `SequoiaIdentityAdapter` | `IdentityPort` | `sequoia-openpgp` |
| `RatchetCryptoAdapter` | `CryptoPort` | `x25519-dalek`, Double Ratchet custom |
| `ProtobufCodec` | sérialisation | `prost` |
| **`TerminalLineRenderer`** | **`UiPort`** | **`crossterm`** |

### 5.5 Modèle d'erreurs

```rust
#[derive(Debug, thiserror::Error)]
enum SanctumError {
    #[error("Version mismatch: got {got}, need >= {min}")]
    VersionMismatch { got: u16, min: u16 },
    #[error("Authentication failed: {reason}")]
    AuthFailed { reason: String },
    #[error("Replay detected: seq {seq} for {sender}")]
    ReplayDetected { seq: u64, sender: Fingerprint },
    #[error("Ratchet desynchronized with {peer}")]
    RatchetDesync { peer: Fingerprint },
    #[error("Room not found: {0}")]
    RoomNotFound(RoomId),
    #[error("Room full: {current}/{max}")]
    RoomFull { current: u16, max: u16 },
    #[error("Insufficient permissions: need {need:?}, have {have:?}")]
    InsufficientPermissions { need: Role, have: Role },
    #[error("Member revoked: {0}")]
    MemberRevoked(Fingerprint),
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Tor unavailable: {0}")]
    TorUnavailable(String),
    #[error("Storage error: {0}")]
    StorageError(String),
    #[error("Connection lost: {0}")]
    ConnectionLost(String),
    #[error("Malformed message: {0}")]
    MalformedMessage(String),
}
```

### 5.6 Stratégie de Test

| Niveau | Cible | Outil | Approche |
|--------|-------|-------|----------|
| Unitaire | Domain entities, crypto | `#[cfg(test)]` | Invariants, round-trip chiffrement |
| Intégration | Services + mocks | Ports mockés (`mockall`) | Scénarios auth, room lifecycle |
| E2E | Client ↔ Host réel | Tor loopback | Tests d'acceptance |
| Fuzzing | Parsing protobuf, framing | `cargo-fuzz` | Messages malformés |
| Property-based | Anti-replay, ratchet | `proptest` | Réordonnancement, messages manquants |

---

## 6. Éphémère vs Persistant — Deltas Exacts

### 6.1 Tableau comparatif

| Aspect | Mode Éphémère | Mode Persistant |
|--------|--------------|-----------------|
| **Écriture disque** | ❌ Strictement interdite | ✅ SQLite chiffré |
| **Stockage clés (IK, SPK, OPK)** | RAM uniquement | Fichier chiffré |
| **Backlog** | ❌ Messages perdus si offline | ✅ Avec limites |
| **Room state** | RAM | Persisté en BDD |
| **Membership** | RAM, perdu au redémarrage | Persisté |
| **Clé Noise host** | Régénérée → nouvelle .onion | Persistée → même .onion |
| **Adresse .onion** | Change à chaque session | Stable |
| **Logs** | Aucun (stdout max en debug) | Safe logging optionnel chiffré |
| **StoragePort impl** | `MemoryStorageAdapter` | `SqliteStorageAdapter` |
| **Au redémarrage** | Tout perdu | Reprend rooms, membres, backlog |

### 6.2 Garanties du mode éphémère

Vérification au démarrage :

1. `StoragePort` = `MemoryStorageAdapter` (assertion)
2. Aucun fichier créé dans le data dir
3. `mlock()` sur toutes les clés
4. Test d'intégration avec `strace` vérifie zéro `open(..., O_WRONLY)`

### 6.3 Redémarrage (persistant)

1. Reload rooms, membres, backlog depuis SQLite
2. Sessions Double Ratchet perdues (RAM only) → membres refont X3DH au reconnect
3. Adresse .onion restaurée
4. GC purge les messages expirés

---

## 7. Stockage Chiffré (Mode Persistant)

### 7.1 Backend : SQLite via `rusqlite`

| Option | Pour | Contre | Verdict |
|--------|------|--------|---------|
| **SQLite** | Mature, fiable, SQL, `rusqlite` | Chiffrement applicatif nécessaire | ✅ Choisi |
| sled | Rust natif | API instable, mainteneur unique | ❌ |
| RocksDB | Performant | Complexe, bindings C, overkill | ❌ |

### 7.2 Schéma

```sql
CREATE TABLE rooms (
    id TEXT PRIMARY KEY,
    data BLOB NOT NULL,          -- Room sérialisé + chiffré AES-256-GCM
    created_at INTEGER NOT NULL
);

CREATE TABLE members (
    room_id TEXT NOT NULL,
    fingerprint_hash TEXT NOT NULL,   -- SHA-256(fingerprint)
    data BLOB NOT NULL,               -- Member chiffré
    PRIMARY KEY (room_id, fingerprint_hash),
    FOREIGN KEY (room_id) REFERENCES rooms(id)
);

CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id TEXT NOT NULL,
    recipient_hash TEXT NOT NULL,
    sequence_number INTEGER NOT NULL,
    data BLOB NOT NULL,               -- Ciphertext E2E (déjà chiffré par expéditeur)
    stored_at INTEGER NOT NULL,
    FOREIGN KEY (room_id) REFERENCES rooms(id)
);

CREATE INDEX idx_messages_backlog ON messages(room_id, recipient_hash, sequence_number);
CREATE INDEX idx_messages_expiry ON messages(stored_at);

CREATE TABLE keys (
    key_type TEXT NOT NULL,
    key_id TEXT NOT NULL,
    data BLOB NOT NULL,               -- Clé chiffrée
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    PRIMARY KEY (key_type, key_id)
);

CREATE TABLE metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT INTO metadata (key, value) VALUES ('schema_version', '1');
```

### 7.3 Chiffrement au repos

```
Master Passphrase → Argon2id(salt) → Master Key (256b)
                                        │
                                   HKDF-SHA256
                                   ┌────┼────┐
                                   ▼    ▼    ▼
                               RoomKey MsgKey KeyStoreKey
```

- **Argon2id** : m=256MiB, t=4, p=2
- **AES-256-GCM** : nonce unique 12B par champ
- **Format blob** : `nonce(12B) ‖ ciphertext ‖ tag(16B)`
- Salt stocké en clair dans `metadata`
- Master Key en RAM avec `mlock` + `zeroize`

### 7.4 Rétention et GC

| Paramètre | Défaut | Plafond dur | Configurable |
|-----------|--------|-------------|-------------|
| `backlog_max_messages` | 500/room | 5000 | ✅ |
| `backlog_max_age_hours` | 72 | 720 (30j) | ✅ |
| `gc_interval_minutes` | 15 | — | ✅ |
| `db_max_size_mb` | 256 | 1024 | ✅ |

GC toutes les 15 min : purge par âge → purge par count → VACUUM si nécessaire.

### 7.5 Migrations

Fichiers `migrations/001_initial.sql`, `002_xxx.sql`, etc. Exécutés séquentiellement au démarrage selon `schema_version`.

---

## 8. Gestion des Clés et Identités

### 8.1 PGP : Sous-clé Dédiée Recommandée

L'utilisateur DEVRAIT utiliser une sous-clé PGP dédiée (signing only) pour Sanctum :

```bash
gpg --edit-key <KEY_ID>
> addkey  # Ed25519 sign only
> save
gpg --export-secret-subkeys <SUBKEY_ID>! > sanctum-signing-key.gpg
```

### 8.2 Stockage des clés

| Clé | Éphémère | Persistant |
|-----|----------|------------|
| PGP | RAM (depuis keyring) | Idem |
| Identity Key (X25519) | RAM, perdue au quit | Fichier chiffré |
| Signed PreKeys | RAM | Fichier chiffré, rotation auto |
| One-Time PreKeys | RAM, pool 10 | Fichier chiffré |
| Noise static (host) | RAM, régénérée | Fichier chiffré (même .onion) |

**Emplacement** : `~/.sanctum/keys/` (persistant).

**Protection** : Permissions `0600`, `mlock()` en RAM, `zeroize` au drop.

### 8.3 Rotation et Révocation

| Événement | Action |
|-----------|--------|
| SPK expirée (24-48h) | Auto-génération, publication nouveau bundle |
| OPK épuisées (< 3) | Rechargement du pool à 10 |
| Membre révoqué | Purge clés + sessions avec ce membre |
| Compromission IK | Régénérer, re-inviter, bannir l'ancienne |
| Compromission PGP | Révocation PGP standard, ré-auth avec nouvelle clé |

---

## 9. Logging / Observabilité

### 9.1 Politique

**Logs désactivés par défaut.** En mode debug : stdout uniquement (jamais disque en éphémère).

| Niveau | Contenu | Éphémère | Persistant |
|--------|---------|----------|------------|
| `OFF` (défaut) | Rien | ✅ | ✅ |
| `ERROR` | Erreurs sans détails sensibles | stdout | stdout / fichier chiffré |
| `WARN` | Auth échouée, replay | stdout | stdout / fichier chiffré |
| `INFO` | Connexions (fingerprint hashé) | stdout | stdout / fichier chiffré |
| `DEBUG` | Détails proto SANS secrets | stdout | stdout uniquement |
| `TRACE` | Interdit en production | ❌ | ❌ |

### 9.2 Règles de rédaction

**JAMAIS** : messages en clair, clés privées/publiques, passphrases, .onion complets, fingerprints complets.

**AUTORISÉ** : hash de fingerprint (tronqué), UUIDs, compteurs, codes d'erreur, événements de cycle de vie.

### 9.3 Panic Hook

```rust
std::panic::set_hook(Box::new(|info| {
    GLOBAL_KEY_STORE.zeroize();
    eprintln!("[SANCTUM PANIC] Secrets wiped. Location: {:?}", info.location());
    std::process::exit(1);
}));
```

---

## 10. Opérations Tor Hidden Service

### 10.1 Bootstrap

Prérequis : Tor installé, Control Port actif.

```toml
# torrc
ControlPort 9051
CookieAuthentication 1
```

**Démarrage host** :

1. Vérifier Tor via Control Port (`torut`)
2. `ADD_ONION` :
   - Éphémère : `ADD_ONION NEW:ED25519-V3 Port=9738,127.0.0.1:9738 Flags=DiscardPK`
   - Persistant : `ADD_ONION ED25519-V3:<saved_key> Port=9738,127.0.0.1:9738`
3. Attendre publication du descripteur (30-120s)
4. Écouter sur `127.0.0.1:9738`

### 10.2 Permissions

| Élément | Permissions |
|---------|------------|
| `~/.sanctum/` | `0700` |
| Config | `0600` |
| Clé HS Tor | `0600`, chiffrée en BDD |
| Cookie Tor | Lisible par l'utilisateur Sanctum |
| Control Port | Localhost uniquement |

### 10.3 Client Authorization (v0.2)

Automatisation via `TorPort` de la gestion des fichiers `.auth` pour HS v3.

### 10.4 Menaces Tor

| Menace | Mitigation |
|--------|------------|
| Corrélation de trafic | Padding, délais (post-MVP) |
| Guard discovery | Configuration Vanguards |
| HS enumeration | .onion = secret partagé via invitation |
| DoS | Rate limiting Sanctum (max connexions, ban temporaire) |

---


## 11. UX Terminal

### 11.1 Philosophie UX

Le workflow principal de Sanctum est une **session de chat interactive en temps réel** dans le terminal. L'utilisateur rejoint une room et entre immédiatement dans un mode conversationnel persistant, analogue à IRC/WeeChat, pas dans une succession de commandes one-shot.

**Hiérarchie des modes d'interaction** :

| Mode | Priorité | Usage |
|------|----------|-------|
| **Session interactive** (`sanctum chat`) | **Primaire** | Usage humain quotidien |
| Commandes one-shot (`send`, `read`) | Secondaire | Scripts, bots, debug, pipes unix |
| TUI plein écran (`ratatui`, v0.2) | Futur | Remplace le mode interactif CLI brut |

### 11.2 Commandes CLI MVP

```
# ─── Gestion du profil ────────────────────────────
sanctum init                              # Initialiser un profil (~/.sanctum/)
sanctum identity import <keyfile>         # Importer une clé PGP
sanctum identity show                     # Afficher fingerprint

# ─── Hébergement ──────────────────────────────────
sanctum host create <room_name>           # Créer et héberger une room
    --mode ephemeral|persistent           #   défaut: ephemeral
    --port 9738                           #   port HS
    --max-members 10
    --backlog-max 500                     #   persistant uniquement
    --backlog-hours 72
    --chat                                #   ouvrir la session interactive immédiatement

sanctum host status                       # Statut du host (non-interactif)
sanctum host stop                         # Arrêter le host

# ─── Rejoindre & Chatter (WORKFLOW PRINCIPAL) ─────
sanctum join <invite_token>               # Rejoindre une room
    --chat                                #   ouvrir session interactive après join (DÉFAUT)
    --no-chat                             #   rejoindre sans ouvrir la session

sanctum chat <room_id>                    # ★ OUVRIR UNE SESSION INTERACTIVE
    --backlog <n>                         #   afficher les n derniers msgs backlog (défaut: 50)

# ─── Commandes non-interactives (secondaires) ─────
sanctum send <room_id> <message>          # Envoyer un message (scripts/debug)
sanctum read <room_id>                    # Lire les messages (batch, scripts)
    --follow                              #   mode streaming (tail -f like)
    --last <n>                            #   n derniers messages
    --json                                #   sortie structurée pour scripts

# ─── Gestion des rooms ───────────────────────────
sanctum room list                         # Lister les rooms connues
sanctum room members <room_id>            # Lister les membres
sanctum room invite <room_id> <fp> [--role admin|member]
sanctum room revoke <room_id> <fp>
sanctum leave <room_id>                   # Quitter définitivement une room

# ─── Système ─────────────────────────────────────
sanctum status                            # Statut global (Tor, rooms, identité)
sanctum export-manifest                   # Manifeste NFO du release
```

**Comportement par défaut** :

- `sanctum join <token>` **ouvre automatiquement la session interactive** après authentification réussie (équivalent à `join --chat`). Raison : dans 95% des cas, l'utilisateur veut chatter immédiatement. `--no-chat` existe pour les cas scriptés.
- `sanctum host create ... --chat` permet à l'host d'entrer en mode interactif dans sa propre room immédiatement après création.
- `sanctum chat <room_id>` est la commande dédiée pour ouvrir (ou ré-ouvrir) une session interactive sur une room déjà rejointe.

### 11.3 Session Interactive — Spécification

#### 11.3.1 Layout terminal

```
┌─────────────────────────────────────────────────────────┐
│ SANCTUM │ #ops-room │ ephemeral │ 3 peers │ Tor: ✓      │  ← Status bar
├─────────────────────────────────────────────────────────┤
│                                                         │
│ [12:03] alice: rendez-vous à 14h                        │  ← Zone messages
│ [12:04] bob: reçu, je serai là                          │     (scrollback)
│ [12:05] ── charlie a rejoint la room ──                 │
│ [12:05] charlie: salut tout le monde                    │
│ [12:07] alice: charlie, bienvenue                       │
│                                                         │
├─────────────────────────────────────────────────────────┤
│ > _                                                     │  ← Ligne de saisie
└─────────────────────────────────────────────────────────┘
```

**Composants** :

| Zone | Contenu | Mise à jour |
|------|---------|------------|
| **Status bar** (ligne 1) | Nom room, mode (ephemeral/persistent), pairs connectés, santé Tor (✓/✗/⟳), rôle | Réactive (événements) |
| **Zone messages** | Messages horodatés, événements système (join/leave/revoke), backlog au connect | Temps réel (push via event bus) |
| **Ligne de saisie** | Prompt `> `, édition readline-like (historique, curseur), slash commands | Input utilisateur |

**Implémentation MVP** : Rendu **line-based** simple via `crossterm` (raw mode + gestion curseur). Quand un message arrive pendant la saisie, la ligne de saisie est temporairement effacée, le message imprimé, puis la ligne restaurée (technique standard IRC CLI).

#### 11.3.2 Slash commands (MVP minimal)

| Commande | Action |
|----------|--------|
| `/help` | Afficher les commandes disponibles |
| `/exit` ou `/quit` | Quitter la session (Ctrl-C fait la même chose) |
| `/who` | Lister les membres connectés et leurs rôles |
| `/status` | Afficher le statut (mode, Tor, backlog, pairs) |
| `/invite <fingerprint> [role]` | Inviter un membre (owner/admin) |
| `/kick <fingerprint>` | Révoquer un membre (owner/admin) |
| `/me <action>` | Message d'action (`* alice fait ceci`) |
| `/clear` | Effacer l'écran local |

**Hors MVP** (v0.2+) : `/nick`, `/topic`, `/mute`, `/export`.

#### 11.3.3 Comportement temps réel

- Messages entrants affichés **immédiatement** dès déchiffrement (latence = Tor + ~500ms).
- Événements système en **lignes système** : `── alice a quitté la room ──`.
- Backlog (persistant) affiché au connect avec séparateurs visuels :
  ```
  ── backlog (3 messages) ──────────────
  [hier 23:15] bob: message offline 1
  [hier 23:20] alice: réponse
  ── fin du backlog ─────────────────────
  ```
- Perte Tor : status bar `Tor: ✗`, message système, session reste ouverte.

#### 11.3.4 Sortie propre

1. `Ctrl-C`, `Ctrl-D`, `/exit` → shutdown graceful
2. Envoi message de déconnexion au host
3. `zeroize` toutes les clés ratchet en mémoire
4. Terminal restauré (raw mode off, curseur visible)
5. Message : `[sanctum] Session terminée. Secrets purgés.`

Signal SIGINT/SIGTERM interceptés pour le même shutdown.

### 11.4 Configuration (`~/.sanctum/config.toml`)

```toml
[identity]
pgp_key_id = "0xABCD1234"

[tor]
control_port = 9051
control_auth = "cookie"        # "cookie" | "password"
socks_port = 9050

[host]
default_mode = "ephemeral"
listen_port = 9738
max_connections = 20

[storage]
data_dir = "~/.sanctum/data"
db_max_size_mb = 256

[logging]
level = "off"
output = "stdout"

[chat]
auto_chat_on_join = true       # Session interactive après join (défaut: true)
backlog_display = 50           # Messages backlog affichés au connect
timestamp_format = "%H:%M"    # Format d'horodatage
show_system_events = true      # Afficher join/leave/revoke

[ui]
banner = true
color = true
```

**Précédence** : CLI flags > Env vars (`SANCTUM_*`) > config.toml > défauts.

### 11.5 TUI (v0.2)

Le TUI plein écran (`ratatui`) **remplacera** le mode interactif CLI line-based. Il utilisera le même `ChatSession` (couche Application), le même bus d'événements, et les mêmes ports. Seul l'adaptateur de rendu change : `TerminalLineRenderer` → `RatatuiRenderer` (les deux implémentent `UiPort`).

---

## 12. Roadmap

### v0.1 — MVP « Premier Contact »

| Critère d'acceptance |
|---------------------|
| `sanctum init` crée un profil avec permissions correctes |
| Import de clé PGP fonctionnel |
| `sanctum host create` crée un HS Tor éphémère |
| `sanctum join` avec token fonctionne |
| Auth PGP challenge-response réussie |
| Messages E2E (Noise + Double Ratchet) |
| Mode éphémère : zéro écriture disque vérifiée |
| Mode persistant : backlog chiffré SQLite |
| Invitation et révocation fonctionnelles |
| CLI complète |
| Tests unitaires > 80% couverture domain |
| Tests d'intégration auth + messaging |

### v0.2 — « Cercle Élargi »

- TUI (`ratatui`)
- Tor client authorization
- Groupes jusqu'à 30
- Notifications de présence
- Reconnexion automatique

### v0.3 — « Arsenal »

- Transfert fichiers chiffré (≤ 10 MiB)
- Messages auto-destructeurs (TTL)
- Audit log chiffré
- Packaging .deb, .rpm, AUR

### v1.0 — « Forteresse »

- Migration MLS pour grands groupes
- `arti` client Tor intégré (si HS prêt)
- Audit de sécurité externe
- Multi-plateforme (macOS, Windows)

---

## 13. Plan de Dépendances Rust

### 13.1 Dépendances principales

| Crate | Version | Usage | Audité | Risque |
|-------|---------|-------|--------|--------|
| `tokio` | 1.x | Runtime async | ✅ | Faible |
| `snow` | 0.9.x | Noise protocol | ✅ | Faible |
| `x25519-dalek` | 2.x | DH X25519 | ✅ | Faible |
| `ed25519-dalek` | 2.x | Signatures SPK | ✅ | Faible |
| `aes-gcm` | 0.10.x | Chiffrement stockage | ✅ | Faible |
| `chacha20poly1305` | 0.10.x | Chiffrement messages | ✅ | Faible |
| `argon2` | 0.5.x | KDF passphrase | ✅ | Faible |
| `hkdf` | 0.12.x | Dérivation de clés | ✅ | Faible |
| `sha2` | 0.10.x | Hashing | ✅ | Faible |
| `sequoia-openpgp` | 1.x | PGP operations | ✅ | Moyen (lourd) |
| `rusqlite` | 0.31.x | SQLite | ✅ | Faible |
| `prost` | 0.12.x | Protobuf | ✅ | Faible |
| `prost-build` | 0.12.x | Proto compiler | — | Faible (build) |
| `torut` | 0.2.x | Tor control | ❌ | Moyen (auditer) |
| `clap` | 4.x | CLI parser | ✅ | Faible |
| `toml` | 0.8.x | Config | ✅ | Faible |
| `serde` | 1.x | Serialization | ✅ | Faible |
| `thiserror` | 1.x | Error derive | ✅ | Faible |
| `tracing` | 0.1.x | Logging | ✅ | Faible |
| `zeroize` | 1.x | Secret wiping | ✅ | Faible |
| `secrecy` | 0.8.x | Secret wrapping | ✅ | Faible |
| `uuid` | 1.x | Room IDs | ✅ | Faible |
| `rand` | 0.8.x | CSPRNG | ✅ | Faible |
| `bytes` | 1.x | Buffers | ✅ | Faible |
| `crossterm` | 0.27.x | Raw mode terminal, input async, gestion curseur | ✅ (prérequis ratatui) | Faible |
| `tokio-util` | 0.7.x | CancellationToken (shutdown coordonné ChatSession) | ✅ | Faible |

### 13.2 Dev dependencies

`tokio-test`, `proptest`, `cargo-fuzz`, `mockall`, `assert_cmd`, `tempfile`

### 13.3 Supply Chain

- CI : `cargo-deny` (licences, advisories) + `cargo-audit` à chaque PR
- `Cargo.lock` versionné
- Features minimisées par crate
- Toute nouvelle dépendance crypto/réseau = ADR obligatoire

---

## 14. Structure du Dépôt (Workspace Rust)

### 14.1 Arborescence

```
sanctum/
├── Cargo.toml                    # Workspace root
├── Cargo.lock
├── README.md
├── LICENSE
├── SECURITY.md
├── NFO.md                        # Release manifest / branding
│
├── docs/
│   ├── architecture.md
│   ├── adrs/
│   │   ├── ADR-001-tor-only.md
│   │   ├── ADR-002-clean-hex.md
│   │   ├── ...
│   │   └── ADR-015-workspace.md
│   ├── threat-model.md
│   ├── protocol.md
│   └── runbook.md
│
├── proto/
│   └── sanctum.proto
│
├── crates/
│   ├── sanctum-domain/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── entities/
│   │       │   ├── mod.rs
│   │       │   ├── room.rs
│   │       │   ├── member.rs
│   │       │   ├── message.rs
│   │       │   ├── identity.rs
│   │       │   ├── session.rs
│   │       │   └── invite.rs
│   │       ├── ports/
│   │       │   ├── mod.rs
│   │       │   ├── transport.rs
│   │       │   ├── storage.rs
│   │       │   ├── crypto.rs
│   │       │   ├── identity.rs
│   │       │   ├── tor.rs
│   │       │   └── ui.rs
│   │       ├── errors.rs
│   │       └── events.rs
│   │
│   ├── sanctum-crypto/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── noise.rs
│   │       ├── ratchet.rs
│   │       ├── x3dh.rs
│   │       ├── aead.rs
│   │       ├── kdf.rs
│   │       └── padding.rs
│   │
│   ├── sanctum-app/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── host_service.rs
│   │       ├── client_service.rs
│   │       ├── auth_service.rs
│   │       ├── room_service.rs
│   │       ├── message_service.rs
│   │       ├── chat_session.rs
│   │       ├── chat_event.rs
│   │       └── input_parser.rs
│   │
│   ├── sanctum-infra/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── tor_control.rs
│   │       ├── transport.rs
│   │       ├── storage_sqlite.rs
│   │       ├── storage_memory.rs
│   │       ├── identity_pgp.rs
│   │       ├── codec.rs
│   │       └── terminal_renderer.rs
│   │
│   └── sanctum-cli/
│       ├── Cargo.toml
│       └── src/
│           ├── main.rs
│           ├── commands/
│           │   ├── mod.rs
│           │   ├── init.rs
│           │   ├── identity.rs
│           │   ├── host.rs
│           │   ├── join.rs
│           │   ├── chat.rs
│           │   ├── room.rs
│           │   ├── send.rs
│           │   ├── read.rs
│           │   ├── status.rs
│           │   └── export_manifest.rs
│           ├── config.rs
│           └── banner.rs
│
├── tests/
│   ├── integration/
│   │   ├── auth_test.rs
│   │   ├── messaging_test.rs
│   │   ├── room_lifecycle_test.rs
│   │   ├── backlog_test.rs
│   │   ├── ephemeral_no_disk_test.rs
│   │   ├── interactive_session_test.rs
│   │   └── chat_event_flow_test.rs
│   └── fuzz/
│       ├── fuzz_frame_parser.rs
│       └── fuzz_protobuf.rs
│
├── migrations/
│   └── 001_initial.sql
│
├── scripts/
│   ├── setup-tor.sh
│   └── check-no-disk-writes.sh
│
└── .github/
    └── workflows/
        └── ci.yml
```

### 14.2 Responsabilités et dépendances

| Crate | Dépend de | API publique |
|-------|-----------|-------------|
| `sanctum-domain` | Rien (sauf `serde`, `uuid`, `zeroize`) | Entities, Ports, Errors, Events |
| `sanctum-crypto` | `sanctum-domain` | NoiseSession, RatchetState, X3dh, Aead, Kdf |
| `sanctum-app` | `sanctum-domain` | HostService, ClientService, AuthService, RoomService, MessageService |
| `sanctum-infra` | `sanctum-domain`, `sanctum-crypto` | Tous les adaptateurs concrets |
| `sanctum-cli` | `sanctum-app`, `sanctum-infra` | Binaire (main) |

---

## 15. ADRs (Architecture Decision Records)

### ADR-001 : Transport Tor Only

**Contexte** : Choix du transport réseau.
**Décision** : Tor Hidden Services v3 uniquement. Aucun fallback clearnet.
**Options** : (1) Tor + clearnet fallback, (2) Tor only, (3) I2P.
**Conséquences** : Latence ~1-5s, dépendance Tor daemon, anonymat garanti par défaut.
**Suivi** : Évaluer `arti` quand HS serveur stable.

### ADR-002 : Architecture Clean / Hexagonale

**Contexte** : Architecture testable et extensible.
**Décision** : Clean Architecture avec inversion de dépendances via traits (ports).
**Options** : (1) Monolithique, (2) Clean/Hex, (3) Actor model.
**Conséquences** : Boilerplate initial, testabilité maximale, remplacement facile des adaptateurs.

### ADR-003 : Host comme Relais Aveugle

**Contexte** : L'host doit-il pouvoir lire les messages ?
**Décision** : Non. Host = relais aveugle. Messages E2E chiffrés entre clients.
**Options** : (1) Host trusted, (2) Host aveugle E2E.
**Conséquences** : Pas de modération contenu. Backlog = ciphertexts opaques. Fan-out N-1.

### ADR-004 : PGP pour Identité Uniquement

**Contexte** : Rôle de PGP.
**Décision** : PGP = auth + vérification d'identité. Chiffrement = X25519 + Double Ratchet.
**Options** : (1) PGP pour tout, (2) PGP identité + X25519 chiffrement.
**Conséquences** : Deux systèmes de clés, sécurité optimale, forward secrecy native.

### ADR-005 : Noise NK + Double Ratchet

**Contexte** : Protocole de chiffrement.
**Décision** : Noise NK (transport) + Double Ratchet pairwise (E2E).
**Options** : (1) Noise NK + DR, (2) Noise XX seul, (3) MLS.
**Conséquences** : Complexité d'implémentation DR, forward + post-compromise secrecy.
**Suivi** : MLS pour groupes > 30 en v1.0.

### ADR-006 : Anti-Replay par Compteur Monotone

**Contexte** : Prévention du replay.
**Décision** : Compteur monotone/expéditeur + fenêtre bitmap 64 + nonces uniques.
**Options** : (1) Timestamp seul, (2) Compteur + fenêtre, (3) Nonce random + set.
**Conséquences** : Persister dernier seq vu (persistant). Réordonnancement toléré dans fenêtre 64.

### ADR-007 : SQLite avec Chiffrement Applicatif

**Contexte** : Backend stockage persistant.
**Décision** : SQLite (`rusqlite`) + AES-256-GCM applicatif par champ.
**Options** : (1) SQLCipher, (2) SQLite + chiffrement applicatif, (3) sled.
**Conséquences** : Plus de code crypto, contrôle total, pas de dep C supplémentaire.

### ADR-008 : Protection Secrets en Mémoire

**Contexte** : Clés vulnérables en RAM.
**Décision** : `mlock()` + `zeroize` au drop + désactivation core dumps.
**Options** : (1) Aucune, (2) mlock + zeroize, (3) SGX.
**Conséquences** : Nécessite `CAP_IPC_LOCK`. Recommander désactivation swap en éphémère.

### ADR-009 : Protobuf (prost) pour Sérialisation

**Contexte** : Format wire.
**Décision** : Protocol Buffers via `prost`.
**Options** : (1) Protobuf, (2) MessagePack, (3) Bincode.
**Conséquences** : Fichier `.proto` à maintenir. Évolution via champs optionnels.

### ADR-010 : Padding des Messages

**Contexte** : Fuite de métadonnées via la taille.
**Décision** : Padding à blocs de 256 octets.
**Options** : (1) Pas de padding, (2) Blocs 256B, (3) Taille unique.
**Conséquences** : Overhead moyen ~128B. Messages max 64 KiB.

### ADR-011 : Tor Externe via Control Port

**Contexte** : Interaction avec Tor.
**Décision** : Tor daemon externe via Control Protocol. Trait `TorPort` pour migration arti.
**Options** : (1) arti embarqué, (2) Tor externe, (3) Hybride.
**Conséquences** : Dépendance runtime Tor. Runbook d'installation.
**Suivi** : Surveiller arti HS serveur.

### ADR-012 : TOML pour Configuration

**Contexte** : Format config.
**Décision** : TOML.
**Conséquences** : Idiomatique Rust, bien supporté serde.

### ADR-013 : Rôles Owner/Admin/Member

**Contexte** : Modèle d'autorisation rooms.
**Décision** : 3 rôles hiérarchiques. Owner + Admins invitent/révoquent.
**Options** : (1) Flat, (2) Owner seul, (3) Rôles hiérarchiques.
**Conséquences** : Promotion/demotion réservée à l'owner.

### ADR-014 : Binaire Statique MVP

**Contexte** : Distribution.
**Décision** : Binaire statique `musl`. Docker en v0.2.
**Conséquences** : Target `x86_64-unknown-linux-musl`. Pas de dep runtime sauf Tor.

### ADR-015 : Workspace Rust Multi-Crates

**Contexte** : Organisation code.
**Décision** : 5 crates : domain, crypto, app, infra, cli.
**Conséquences** : Séparation enforcée par Cargo. Compilation incrémentale.

### ADR-016 : Session Chat Interactive comme UX Principale

**Contexte** : Le design initial proposait des commandes CLI one-shot (`send`, `read`) comme mode d'interaction principal. Cela ne correspond pas à l'usage naturel d'un outil de chat.
**Décision** : Introduire `ChatSession` comme use case central dans la couche Application. La commande `sanctum chat <room_id>` ouvre une session interactive line-based. `sanctum join` lance cette session par défaut. Les commandes `send`/`read` restent pour scripts/debug. Ajout du port `UiPort` et de l'adaptateur `TerminalLineRenderer` (`crossterm`).
**Options** : (1) One-shot uniquement — UX inadaptée. (2) TUI plein écran immédiat (`ratatui`) — trop lourd pour MVP. (3) ★ Session interactive CLI line-based — compromis optimal, `UiPort` permet migration transparente vers ratatui en v0.2.
**Conséquences** : +1 port (`UiPort`), +1 use case (`ChatSession`), +1 adaptateur (`TerminalLineRenderer`), +1 dépendance (`crossterm`, prérequis ratatui, bien audité). Bus d'événements `ChatEvent` via `broadcast` channel. Tests interactifs via `MockUiAdapter`.
**Suivi** : v0.2 → remplacer `TerminalLineRenderer` par `RatatuiRenderer` via le même `UiPort`.

---

## 16. Tests d'Acceptance & Définitions de Done

### 16.1 Tests d'Acceptance MVP

#### Tests Interactifs (workflow principal)

```
AT-01: Initialisation du Profil
  GIVEN un système sans profil Sanctum
  WHEN  `sanctum init`
  THEN  ~/.sanctum/ créé avec config.toml
  AND   permissions 0700 (répertoire) / 0600 (fichiers)

AT-02: Import d'Identité PGP
  GIVEN un profil initialisé
  WHEN  `sanctum identity import <keyfile>`
  THEN  clé chargée, fingerprint affiché, sous-clé signing identifiée

AT-03: Création de Room Éphémère
  GIVEN profil avec identité PGP, Tor accessible
  WHEN  `sanctum host create test-room --mode ephemeral`
  THEN  Hidden Service Tor créé, .onion affiché
  AND   AUCUN fichier dans ~/.sanctum/data/
  AND   token d'invitation généré

AT-04: Connexion, Auth et Entrée en Session Interactive
  GIVEN room éphémère active, Client possède token valide
  WHEN  `sanctum join <token>` (--chat est le défaut)
  THEN  handshake Noise NK OK, challenge PGP signé/vérifié
  AND   Client entre en SESSION INTERACTIVE
  AND   status bar affiche: nom room, mode, peers, Tor ✓
  AND   prompt de saisie `> ` visible

AT-05: Réception de Message en Temps Réel (Interactif)
  GIVEN Alice et Bob en session interactive dans la même room
  WHEN  Alice tape "Hello Bob" + Entrée
  THEN  Bob voit `[HH:MM] alice: Hello Bob` en temps réel
  AND   délai ≤ latence Tor + 500ms
  AND   le host N'A PAS accès au plaintext
  AND   la ligne de saisie de Bob est préservée

AT-05b: Envoi/Réception Non-Interactif (Secondaire)
  GIVEN Alice en session interactive, Bob utilise `sanctum read --follow`
  WHEN  Alice envoie "Hello Bob"
  THEN  Bob voit le message sur stdout en streaming
  GIVEN Bob utilise `sanctum send <room> "Reply"`
  THEN  Alice voit le message dans sa session interactive

AT-06: Forward Secrecy
  GIVEN Alice et Bob ont échangé des messages
  WHEN  la clé ratchet actuelle est capturée
  THEN  les messages PASSÉS ne sont PAS déchiffrables

AT-07: Zéro Écriture Disque en Session Interactive (Éphémère)
  GIVEN Sanctum en mode éphémère
  WHEN  session interactive complète :
        init → host create → join → chat (10 messages) → /exit
  THEN  strace montre AUCUN open(..., O_WRONLY|O_CREAT) sur data dir
  AND   aucun fichier temporaire créé par crossterm

AT-08: Backlog Affiché au Connect (Persistant)
  GIVEN room persistante, Bob hors ligne
  WHEN  Alice envoie 3 messages, Bob exécute `sanctum chat <room_id>`
  THEN  Bob voit séparateur "── backlog (3 messages) ──"
  AND   les 3 messages avec timestamps originaux
  AND   séparateur "── fin du backlog ──"
  AND   puis les nouveaux messages en temps réel

AT-09: Révocation via Session Interactive
  GIVEN Alice (owner) en session, Bob et Charlie connectés
  WHEN  Alice tape `/kick <bob_fp>`
  THEN  Bob déconnecté, sa session affiche "[sanctum] Vous avez été révoqué."
  AND   Charlie voit "── bob a été révoqué ──"
  AND   Bob ne peut plus se reconnecter

AT-10: Invitation Nominative
  GIVEN token pour Bob (fingerprint spécifique)
  WHEN  Charlie (fingerprint différent) tente join
  THEN  auth ÉCHOUE (fingerprint mismatch)

AT-11: Anti-Replay
  GIVEN message capturé par un observateur
  WHEN  message renvoyé au host
  THEN  rejeté (sequence déjà vue)

AT-12: Prévention Downgrade
  GIVEN client avec protocol_version=0
  WHEN  handshake
  THEN  refusé avec Error::VersionMismatch

AT-13: GC du Backlog
  GIVEN backlog avec messages > 72h
  WHEN  GC s'exécute
  THEN  messages expirés supprimés

AT-14: Persistence au Redémarrage
  GIVEN room persistante avec membres et backlog
  WHEN  host redémarre
  THEN  room rechargée, même .onion, backlog disponible

AT-15: Sortie Propre (Ctrl-C / /exit)
  GIVEN utilisateur en session interactive
  WHEN  Ctrl-C ou /exit
  THEN  message de déconnexion envoyé au host
  AND   secrets zeroize-és
  AND   terminal restauré (raw mode off, curseur visible)
  AND   "[sanctum] Session terminée. Secrets purgés."
  AND   les autres membres voient "── user a quitté la room ──"

AT-16: Slash Command /who
  GIVEN 3 utilisateurs en session interactive
  WHEN  Alice tape `/who`
  THEN  liste affichée: fingerprint (tronqué), rôle, statut
  AND   la liste n'est PAS envoyée sur le réseau (locale)

AT-17: Perte de Connexion Tor en Session Interactive
  GIVEN utilisateur en session interactive
  WHEN  Tor se déconnecte temporairement
  THEN  status bar passe à Tor: ✗
  AND   message système "── connexion Tor perdue ──"
  AND   session reste ouverte
  AND   aucun crash, aucun leak de secrets
```

### 16.2 Définitions de Done

**DoD Sécurité** : Toutes les clés utilisent `zeroize` + `mlock` ; aucun secret dans les logs ; AES-256-GCM nonces uniques ; Argon2id m=256M t=4 p=2 ; anti-replay vérifié proptest ; pas de `unsafe` injustifié ; `cargo-deny` + `cargo-audit` OK ; shutdown graceful zeroize même si panic/Ctrl-C.

**DoD QA** : Tests unitaires > 80% couverture domain/crypto ; AT-01→AT-17 passent ; fuzzing 1h sans crash ; clippy -D warnings OK ; fmt OK ; session interactive testée avec MockUiAdapter.

**DoD OPSEC** : Mode éphémère vérifié strace **pendant session interactive** (AT-07) ; permissions 0700/0600 ; pas de .onion/fingerprint complet dans les logs ; panic hook wipe secrets + restaure terminal ; binaire musl statique ; `crossterm` ne crée aucun fichier temporaire.

---

## 17. Plan d'Implémentation Fichier par Fichier

### 17.1 Ordre d'implémentation (inside-out)

**Phase A — Domain** : A1-A18 (entities, ports incl. UiPort, errors, events)
**Phase B — Crypto** : B1-B8 (aead, kdf, noise, x3dh, ratchet, padding)
**Phase C — Application** : C1-C10 (services + ChatSession + ChatEvent + InputParser)
**Phase D — Infra** : D1-D9 (adaptateurs + TerminalLineRenderer)
**Phase E — Proto** : E1-E2 (sanctum.proto, build.rs)
**Phase F — CLI** : F1-F15 (main, banner, config, commandes incl. `chat`)
**Phase G — Tests** : G1-G9 (intégration + fuzz + tests interactifs)
**Phase H — Ops** : H1-H11 (workspace root, migrations, scripts, CI, docs)

### 17.2 Détail par fichier

#### Phase A — Domain (18 fichiers)

| # | Fichier | Types/Fonctions clés | Tests | ADR |
|---|---------|---------------------|-------|-----|
| A1 | `sanctum-domain/Cargo.toml` | deps: serde, uuid, zeroize | — | 015 |
| A2 | `sanctum-domain/src/lib.rs` | re-exports | — | — |
| A3 | `entities/mod.rs` | re-exports | — | — |
| A4 | `entities/room.rs` | Room, RoomId, RoomConfig, RoomMode | invariants, max members | 003,013 |
| A5 | `entities/member.rs` | Member, Role, Fingerprint | permissions par rôle | 013 |
| A6 | `entities/message.rs` | MessageEnvelope, RatchetHeader | serde round-trip | 006,010 |
| A7 | `entities/identity.rs` | Identity, PreKeyBundle | validité clés | 004 |
| A8 | `entities/session.rs` | Session (opaque) | — | 005 |
| A9 | `entities/invite.rs` | InviteToken | encode/decode round-trip | 013 |
| A10 | `ports/mod.rs` | re-exports | — | 002 |
| A11 | `ports/transport.rs` | TransportPort trait | — | 001 |
| A12 | `ports/storage.rs` | StoragePort trait | — | 007 |
| A13 | `ports/crypto.rs` | CryptoPort trait | — | 005 |
| A14 | `ports/identity.rs` | IdentityPort trait | — | 004 |
| A15 | `ports/tor.rs` | TorPort trait | — | 011 |
| **A16** | **`ports/ui.rs`** | **UiPort trait** | **—** | **016** |
| A17 | `errors.rs` | SanctumError enum | Display/Debug | — |
| A18 | `events.rs` | SanctumEvent enum | serde | — |

#### Phase B — Crypto (8 fichiers, inchangé)

| # | Fichier | Types/Fonctions | Tests | ADR |
|---|---------|----------------|-------|-----|
| B1 | `sanctum-crypto/Cargo.toml` | deps: aes-gcm, chacha, argon2, hkdf, snow, x25519-dalek | — | 015 |
| B2 | `src/lib.rs` | re-exports | — | — |
| B3 | `src/aead.rs` | encrypt, decrypt (AES-256-GCM + ChaChaPoly) | round-trip, mauvaise clé | 007 |
| B4 | `src/kdf.rs` | derive_master_key (Argon2id), derive_subkey (HKDF) | déterminisme | 007 |
| B5 | `src/noise.rs` | NoiseInitiator, NoiseResponder | handshake round-trip | 005 |
| B6 | `src/x3dh.rs` | x3dh_initiate, x3dh_respond | shared secret match | 005 |
| B7 | `src/ratchet.rs` | RatchetState, encrypt, decrypt | round-trip, out-of-order, FS | 005 |
| B8 | `src/padding.rs` | pad, unpad | round-trip, taille correcte | 010 |

#### Phase C — Application (10 fichiers, +3)

| # | Fichier | Fonctions | Tests | ADR |
|---|---------|-----------|-------|-----|
| C1 | `sanctum-app/Cargo.toml` | dep: sanctum-domain, tokio | — | 015 |
| C2 | `src/lib.rs` | re-exports | — | — |
| C3 | `src/auth_service.rs` | create_challenge, verify_response, sign_challenge | replay refusé, timestamp hors fenêtre | 004 |
| C4 | `src/room_service.rs` | create_room, add/remove_member, generate/validate_invite | permissions, invite nominative | 013 |
| C5 | `src/message_service.rs` | prepare_message, process_received, check_replay | round-trip E2E, replay, padding | 005,006,010 |
| C6 | `src/host_service.rs` | start, accept_client, route_message, run_gc | routing, GC, rejet non-autorisé | 003 |
| C7 | `src/client_service.rs` | connect, authenticate, send/receive_message | connexion, auth, E2E | 001,005 |
| **C8** | **`src/chat_session.rs`** | **★ ChatSession::start(), ::shutdown(), network_recv_loop, input_loop, render_loop, maintenance_loop** | **Round-trip via MockUi, shutdown propre, zéro disque éphémère** | **016** |
| **C9** | **`src/chat_event.rs`** | **ChatEvent enum, SystemEventKind, conversions** | **Sérialisation, conversion depuis SanctumEvent** | **016** |
| **C10** | **`src/input_parser.rs`** | **parse_input() → Input::Message / SlashCommand / Exit** | **Tous slash commands, edge cases, unicode** | **—** |

#### Phase D — Infra (9 fichiers, +1)

| # | Fichier | Implémente | Tests | ADR |
|---|---------|-----------|-------|-----|
| D1 | `sanctum-infra/Cargo.toml` | deps (+ crossterm) | — | 015 |
| D2 | `src/lib.rs` | re-exports | — | — |
| D3 | `src/codec.rs` | Framing + Protobuf | round-trip, max size | 009 |
| D4 | `src/storage_memory.rs` | StoragePort (RAM) | CRUD, backlog, purge | 007 |
| D5 | `src/storage_sqlite.rs` | StoragePort (SQLite+AES) | CRUD, chiffrement, GC, migration | 007 |
| D6 | `src/identity_pgp.rs` | IdentityPort (sequoia) | sign/verify round-trip | 004 |
| D7 | `src/transport.rs` | TransportPort (Noise+TCP) | handshake, send/recv | 005 |
| D8 | `src/tor_control.rs` | TorPort (torut) | création/destruction HS (mock) | 011 |
| **D9** | **`src/terminal_renderer.rs`** | **UiPort (TerminalLineRenderer)** | **Tests avec crossterm test backend** | **016** |

#### Phase E — Proto (2 fichiers, inchangé)

| # | Fichier | Purpose |
|---|---------|---------|
| E1 | `proto/sanctum.proto` | Tous les types de messages |
| E2 | `sanctum-infra/build.rs` | Compilation proto→Rust |

#### Phase F — CLI (15 fichiers, +1, révisé)

| # | Fichier | Commande | Tests acceptance |
|---|---------|----------|-----------------|
| F1 | `sanctum-cli/Cargo.toml` | — | — |
| F2 | `src/main.rs` | entry point, panic hook, signal handler | AT-15 |
| F3 | `src/banner.rs` | ASCII art | — |
| F4 | `src/config.rs` | Config::load, merge_env (incl. [chat]) | précédence |
| F5 | `commands/mod.rs` | re-exports | — |
| F6 | `commands/init.rs` | `sanctum init` | AT-01 |
| F7 | `commands/identity.rs` | `sanctum identity *` | AT-02 |
| F8 | `commands/host.rs` | `sanctum host *` (incl. --chat) | AT-03, AT-14 |
| F9 | `commands/join.rs` | `sanctum join` (--chat défaut, lance chat) | AT-04 |
| **F10** | **`commands/chat.rs`** | **★ `sanctum chat <room_id>`** | **AT-04, AT-05, AT-15, AT-16, AT-17** |
| F11 | `commands/room.rs` | `sanctum room *` | AT-09, AT-10 |
| F12 | `commands/send.rs` | `sanctum send` (non-interactif) | AT-05b |
| F13 | `commands/read.rs` | `sanctum read` (non-interactif) | AT-05b, AT-08 |
| F14 | `commands/status.rs` | `sanctum status` | — |
| F15 | `commands/export_manifest.rs` | `sanctum export-manifest` | — |

#### Phase G — Tests (9 fichiers, +2)

| # | Fichier | Couvre |
|---|---------|-------|
| G1 | `tests/integration/auth_test.rs` | AT-04, AT-10, AT-12 |
| G2 | `tests/integration/messaging_test.rs` | AT-05, AT-05b, AT-06, AT-11 |
| G3 | `tests/integration/room_lifecycle_test.rs` | AT-03, AT-09 |
| G4 | `tests/integration/backlog_test.rs` | AT-08, AT-13 |
| G5 | `tests/integration/ephemeral_no_disk_test.rs` | AT-07 (session interactive complète) |
| G6 | `tests/fuzz/fuzz_frame_parser.rs` | Fuzzing framing |
| G7 | `tests/fuzz/fuzz_protobuf.rs` | Fuzzing protobuf |
| **G8** | **`tests/integration/interactive_session_test.rs`** | **AT-05, AT-15, AT-16, AT-17** |
| **G9** | **`tests/integration/chat_event_flow_test.rs`** | **Flux ChatSession→UiPort avec MockUi** |

#### Phase H — Ops (11 fichiers, inchangé)

| # | Fichier |
|---|---------|
| H1 | `Cargo.toml` (workspace root) |
| H2 | `migrations/001_initial.sql` |
| H3 | `proto/sanctum.proto` |
| H4 | `scripts/setup-tor.sh` |
| H5 | `scripts/check-no-disk-writes.sh` |
| H6 | `.github/workflows/ci.yml` |
| H7 | `README.md` |
| H8 | `SECURITY.md` |
| H9 | `NFO.md` |
| H10 | `docs/adrs/*.md` (16 fichiers, +ADR-016) |
| H11 | `docs/runbook.md` |

### 17.3 Carte des APIs Internes (résumé)

| Module | Trait/Struct | Méthodes publiques | Utilisé par |
|--------|-------------|-------------------|-------------|
| `domain::entities::room` | `Room` | new, add/remove_member, is_full | app::room_service, app::host_service |
| `domain::entities::member` | `Member`, `Role` | new, can_invite, can_revoke | app::room_service |
| `domain::entities::message` | `MessageEnvelope` | new, validate | app::message_service |
| `domain::entities::invite` | `InviteToken` | new, encode, decode, verify | app::room_service, cli::join |
| `domain::ports::*` | 6 traits (incl. UiPort) | voir §5.2 | app + infra |
| **`domain::ports::ui`** | **`UiPort`** | **read_input, print_message/own/system, backlog, status, init, cleanup** | **app::chat_session** |
| `crypto::*` | Aead, Kdf, Noise*, Ratchet*, X3dh, Padding | voir Phase B | infra (via CryptoPort) |
| `app::*` | 6 services (incl. ChatSession) | voir Phase C | cli |
| **`app::chat_session`** | **`ChatSession`** | **start, shutdown** | **cli::chat, cli::join, cli::host** |
| **`app::chat_event`** | **`ChatEvent`** | **— (enum)** | **app::chat_session, infra::terminal_renderer** |
| **`app::input_parser`** | **`parse_input()`** | **parse → Input enum** | **app::chat_session** |
| `infra::*` | 7 adaptateurs (incl. TerminalLineRenderer) | voir Phase D | cli |
| **`infra::terminal_renderer`** | **`TerminalLineRenderer`** | **impl UiPort** | **cli** |


---

## 18. CI, Release, Runbook

### 18.1 Pipeline CI (`.github/workflows/ci.yml`)

```yaml
name: Sanctum CI
on: [push, pull_request]

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy

      # Format
      - name: Format check
        run: cargo fmt --all -- --check

      # Clippy
      - name: Clippy
        run: cargo clippy --workspace --all-targets -- -D warnings

      # Tests
      - name: Unit tests
        run: cargo test --workspace

      # Supply chain audit
      - name: Install cargo-deny
        run: cargo install cargo-deny
      - name: Licenses & advisories
        run: cargo deny check

      - name: Install cargo-audit
        run: cargo install cargo-audit
      - name: Security audit
        run: cargo audit

  build-musl:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: x86_64-unknown-linux-musl
      - name: Install musl tools
        run: sudo apt-get install -y musl-tools
      - name: Build static binary
        run: cargo build --release --target x86_64-unknown-linux-musl
      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: sanctum-linux-x86_64
          path: target/x86_64-unknown-linux-musl/release/sanctum
```

### 18.2 Checklist de Release

**Avant la release** :

- [ ] Tous les tests passent (unit + integration)
- [ ] `cargo deny check` OK
- [ ] `cargo audit` OK
- [ ] `cargo clippy -- -D warnings` OK
- [ ] `cargo fmt --check` OK
- [ ] Tests d'acceptance AT-01 à AT-14 passent
- [ ] Mode éphémère vérifié (strace)
- [ ] Binaire musl compilé et testé

**OPSEC Release** :

- [ ] Aucun secret hardcodé dans le code
- [ ] Aucun .onion de test dans le code
- [ ] Metadata git : pas d'emails personnels dans les commits
- [ ] Le binaire ne contient pas de chemins locaux (`strings` check)
- [ ] `NFO.md` mis à jour avec le numéro de version
- [ ] `SECURITY.md` à jour
- [ ] Tag git signé (`git tag -s`)

### 18.3 Runbook Opérationnel

#### Installation

```bash
# 1. Installer Tor
sudo apt install tor

# 2. Configurer Tor pour le Control Port
sudo tee -a /etc/tor/torrc << EOF
ControlPort 9051
CookieAuthentication 1
EOF
sudo systemctl restart tor

# 3. Donner accès au cookie Tor
sudo usermod -aG debian-tor $USER
# (se reconnecter pour que le groupe prenne effet)

# 4. Installer Sanctum
# Option A : binaire pré-compilé
chmod +x sanctum-linux-x86_64
sudo mv sanctum-linux-x86_64 /usr/local/bin/sanctum

# Option B : compilation depuis les sources
cargo build --release --target x86_64-unknown-linux-musl
sudo cp target/x86_64-unknown-linux-musl/release/sanctum /usr/local/bin/
```

#### Configuration initiale

```bash
# Initialiser le profil
sanctum init

# Importer une clé PGP (sous-clé de signature recommandée)
sanctum identity import ~/.gnupg/sanctum-signing-key.gpg
sanctum identity show
```

#### Héberger une Room

```bash
# Room éphémère (rien sur disque)
sanctum host create "ops-room" --mode ephemeral

# Room persistante (backlog chiffré)
sanctum host create "base-camp" --mode persistent --backlog-max 500 --backlog-hours 72
# Sanctum demandera une passphrase pour chiffrer le stockage

# Vérifier le statut
sanctum host status

# Générer une invitation pour Bob
sanctum room invite <room_id> <bob_pgp_fingerprint>
# → copier le token et l'envoyer à Bob par un canal sûr
```

#### Rejoindre une Room

```bash
# Coller le token d'invitation
sanctum join <invite_token_base64>

# Lire les messages
sanctum read <room_id>

# Envoyer un message
sanctum send <room_id> "Message sécurisé"
```

#### Troubleshooting

| Problème | Diagnostic | Solution |
|----------|-----------|----------|
| `TorUnavailable` | Tor n'est pas lancé ou control port inaccessible | `sudo systemctl status tor`, vérifier `torrc` |
| `AuthFailed` | Fingerprint non autorisé ou clé incorrecte | Vérifier `sanctum identity show`, vérifier le token |
| Connexion lente | Normal : Tor ajoute 1-5s de latence | Patience. Vérifier la connectivité Tor (`tor --verify-config`) |
| `StorageError` | Passphrase incorrecte ou BDD corrompue | Retenter la passphrase. Backup : `~/.sanctum/data/sanctum.db` |
| `RatchetDesync` | Sessions Double Ratchet désynchronisées | Automatique : re-keying (3 tentatives). Si échec : quitter et rejoindre la room |
| Mode éphémère + fichiers sur disque | Bug critique | Reporter immédiatement. Vérifier avec `strace` |

#### Mode Sécurisé (Recommandations Opérationnelles)

```bash
# Désactiver le swap (éphémère)
sudo swapoff -a

# Vérifier que core dumps sont désactivés
ulimit -c 0

# Lancer avec mlock autorisé
# Option 1 : setcap
sudo setcap cap_ipc_lock=ep /usr/local/bin/sanctum

# Option 2 : ulimit
ulimit -l unlimited

# Vérifier les permissions
ls -la ~/.sanctum/
# drwx------ (0700)

# Vérifier zéro écriture disque (éphémère)
strace -e trace=open,openat,creat -f sanctum host create test --mode ephemeral 2>&1 | grep -v RDONLY
```

---

## Annexe A — MVP Backlog (User Stories)

| ID | Story | Priorité | Critère d'acceptance |
|----|-------|----------|---------------------|
| US-01 | En tant qu'utilisateur, je veux initialiser un profil Sanctum | P0 | AT-01 |
| US-02 | En tant qu'utilisateur, je veux importer ma clé PGP | P0 | AT-02 |
| US-03 | En tant qu'host, je veux créer une room éphémère | P0 | AT-03 |
| US-04 | En tant qu'host, je veux créer une room persistante | P0 | AT-14 |
| US-05 | En tant que client, je veux rejoindre une room via token | P0 | AT-04 |
| US-06 | En tant qu'utilisateur, je veux envoyer un message E2E | P0 | AT-05 |
| US-07 | En tant qu'utilisateur, je veux recevoir un message E2E | P0 | AT-05 |
| US-08 | En tant que client offline, je veux récupérer le backlog | P0 | AT-08 |
| US-09 | En tant qu'owner, je veux inviter un membre | P0 | AT-10 |
| US-10 | En tant qu'owner, je veux révoquer un membre | P0 | AT-09 |
| US-11 | En tant qu'utilisateur, je veux vérifier le statut du système | P1 | — |
| US-12 | En tant qu'host, je veux que le GC purge le backlog | P1 | AT-13 |
| US-13 | En tant qu'utilisateur, je veux que le mode éphémère n'écrive RIEN sur disque | P0 | AT-07 |
| US-14 | En tant qu'utilisateur, je veux que les messages aient du forward secrecy | P0 | AT-06 |
| US-15 | En tant qu'utilisateur, je veux que les replays soient détectés | P0 | AT-11 |

---

*Fin du Dossier d'Architecture Sanctum v0.1*

```
┌──────────────────────────────────────┐
│     "Privacy is no more a Myth"      │
│          — Sanctum Project           │
└──────────────────────────────────────┘
```
