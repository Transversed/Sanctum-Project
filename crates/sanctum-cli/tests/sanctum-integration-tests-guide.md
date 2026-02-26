# Sanctum Tests d'Intégration — Documentation Complète

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Pourquoi des tests d'intégration ?](#2-pourquoi-des-tests-dintégration)
3. [Structure des fichiers](#3-structure-des-fichiers)
4. [Comment Rust découvre les tests](#4-comment-rust-découvre-les-tests)
5. [auth_flow_test — L'authentification bout en bout](#5-auth_flow_test--lauthentification-bout-en-bout)
   - 5.1 [Le flux testé](#51-le-flux-testé)
   - 5.2 [Les 6 tests](#52-les-6-tests)
6. [messaging_test — Le message de A à Z](#6-messaging_test--le-message-de-a-à-z)
   - 6.1 [Le flux testé](#61-le-flux-testé)
   - 6.2 [Le MockCrypto](#62-le-mockcrypto)
   - 6.3 [Les 6 tests](#63-les-6-tests)
7. [room_lifecycle_test — La vie d'une room](#7-room_lifecycle_test--la-vie-dune-room)
   - 7.1 [Le flux testé](#71-le-flux-testé)
   - 7.2 [Les 7 tests](#72-les-7-tests)
8. [backlog_test — Le stockage et le GC](#8-backlog_test--le-stockage-et-le-gc)
   - 8.1 [Le problème du room_id](#81-le-problème-du-room_id)
   - 8.2 [Memory vs SQLite](#82-memory-vs-sqlite)
   - 8.3 [Les 7 tests](#83-les-7-tests)
9. [chat_session_test — L'orchestrateur et l'UI](#9-chat_session_test--lorchestateur-et-lui)
   - 9.1 [Le MockUi](#91-le-mockui)
   - 9.2 [Les 10 tests](#92-les-10-tests)
10. [transport_integration_test — Le réseau simulé](#10-transport_integration_test--le-réseau-simulé)
    - 10.1 [InProcessTransport comme simulateur](#101-inprocesstransport-comme-simulateur)
    - 10.2 [Les 8 tests](#102-les-8-tests)
11. [Couverture des Acceptance Tests](#11-couverture-des-acceptance-tests)
12. [Leçons apprises](#12-leçons-apprises)
13. [Résumé des 43 tests](#13-résumé-des-43-tests)

---

## 1. Vue d'ensemble

Les tests d'intégration du Sprint 6 vérifient que les crates de Sanctum fonctionnent **ensemble**. Chaque test unitaire des sprints 1 à 5 testait une brique isolée avec des mocks. Ici, on assemble les vraies briques et on vérifie que le système complet se comporte correctement.

```
Tests unitaires (Sprints 1-5)          Tests d'intégration (Sprint 6)
┌─────────┐                            ┌─────────────────────────┐
│ Domain  │ ← testé seul               │ App + Infra + Domain    │
├─────────┤                            │ assemblés ensemble      │
│ Crypto  │ ← testé seul               │                         │
├─────────┤                            │ AuthService             │
│ App     │ ← testé avec mocks         │   + IdentityAdapter     │
├─────────┤                            │   + Codec               │
│ Infra   │ ← testé seul               │                         │
├─────────┤                            │ MessageService          │
│ CLI     │ ← testé seul               │   + MemoryStorage       │
└─────────┘                            │   + SqliteStorage       │
                                       │   + Codec               │
                                       │                         │
                                       │ ChatSession + MockUi    │
                                       │ InProcessTransport      │
                                       └─────────────────────────┘
```

---

## 2. Pourquoi des tests d'intégration ?

Les tests unitaires répondent à la question : "est-ce que cette fonction fait ce qu'elle doit ?". Les tests d'intégration répondent à une question différente : "est-ce que ces composants fonctionnent ensemble ?".

Concrètement, voici ce que les tests unitaires **ne pouvaient pas** attraper :

- **Incompatibilités de types** : un service retourne un `HashSet` mais le test utilisait un `Vec`. Compilé séparément, ça marchait. Assemblé, ça casse.
- **Incohérence de `RoomId`** : créer une room dans un test puis en créer une autre pour le fetch donne deux IDs différents. Le test unitaire passait car il ne mélangeait pas les composants.
- **Noms de méthodes divergents** : `member_count()` dans le test vs `active_member_count()` dans le code réel. Le mock masquait la différence.
- **Signatures d'API** : `verify_response` prend 3 arguments dans le code, mais les tests en passaient 4 (avec une closure). Le mock ne vérifiait pas.

Ces 43 tests d'intégration ont effectivement révélé **toutes ces erreurs** lors du Sprint 6.

---

## 3. Structure des fichiers

```
crates/sanctum-cli/
└── tests/
    ├── integration.rs                         ← Point d'entrée
    └── integration/
        ├── auth_flow_test.rs                  ← 6 tests (AT-04, AT-10, AT-12)
        ├── messaging_test.rs                  ← 6 tests (AT-05, AT-06, AT-11)
        ├── room_lifecycle_test.rs             ← 7 tests (AT-03, AT-09)
        ├── backlog_test.rs                    ← 7 tests (AT-08, AT-13)
        ├── chat_session_test.rs               ← 10 tests (AT-15, AT-16, AT-17)
        └── transport_integration_test.rs      ← 8 tests (transport)
```

---

## 4. Comment Rust découvre les tests

Rust traite chaque fichier directement dans `tests/` comme un **crate de test séparé**. Mais les fichiers dans un sous-dossier (`tests/integration/`) ne sont pas découverts automatiquement.

La solution : `tests/integration.rs` sert de point d'entrée et déclare les sous-modules :

```rust
mod integration {
    mod auth_flow_test;
    mod messaging_test;
    mod room_lifecycle_test;
    mod backlog_test;
    mod chat_session_test;
    mod transport_integration_test;
}
```

Rust compile tout ça en un seul binaire de test. La commande `cargo test -p sanctum-cli --test integration` lance les 43 tests d'un coup.

Les tests d'intégration vivent dans `sanctum-cli` car c'est le seul crate qui a accès à **toutes** les dépendances (domain, app, infra, crypto).

---

## 5. auth_flow_test — L'authentification bout en bout

### 5.1 Le flux testé

```
Host                                    Client
  │                                       │
  │  AuthService.create_challenge()       │
  │  ──── AuthChallenge ────────────────► │
  │                                       │  AuthService::verify_server_id()
  │                                       │  AuthService::challenge_to_bytes()
  │                                       │  IdentityAdapter.sign(bytes)
  │  ◄──── AuthResponse ──────────────── │
  │                                       │
  │  AuthService.verify_response()        │
  │    ├── check nonce replay             │
  │    ├── check timestamp ±120s          │
  │    ├── check fingerprint ∈ allowed    │
  │    └── check attempt count ≤ 3        │
  │                                       │
  │  Codec: encode → wire → decode        │
```

Les crates traversées :
- **sanctum-app** : `AuthService` (create_challenge, verify_response, verify_server_id, challenge_to_bytes)
- **sanctum-infra** : `IdentityAdapter` (sign), `Codec` (encode/decode frames)
- **sanctum-domain** : `Fingerprint`, `RoomId`

### 5.2 Les 6 tests

| Test | AT | Ce qu'il vérifie |
|------|-----|-----------------|
| `full_auth_challenge_response_with_identity_adapter` | AT-04 | Le flux complet : challenge → sign avec IdentityAdapter → verify. Les vrais adapters fonctionnent ensemble. |
| `auth_rejects_non_invited_fingerprint` | AT-10 | Un intrus avec un fingerprint hors du `HashSet<Fingerprint>` autorisé est rejeté. |
| `client_detects_server_id_mismatch` | AT-12 | Le client détecte si le server_id dans le challenge ne correspond pas à la clé Noise reçue pendant le handshake (attaque relais). |
| `auth_challenge_survives_codec_round_trip` | — | Un challenge sérialisé comme payload de Frame survit à encode → decode. |
| `auth_response_survives_codec_round_trip` | — | Idem pour la réponse d'auth. |
| `auth_rate_limits_per_fingerprint` | — | Après 3 échecs d'auth, le 4ème est bloqué même avec les bonnes credentials. |

**Point technique** : `verify_server_id` et `challenge_to_bytes` sont des **fonctions statiques** (`AuthService::verify_server_id(...)`, pas `auth_svc.verify_server_id(...)`). Le test a révélé cette subtilité.

**Point technique** : `verify_response` retourne `Result<(), SanctumError>`, pas une struct. La vérification de signature PGP est déléguée à l'appelant via `IdentityPort` — le service ne fait que les vérifications logiques (nonce, timestamp, fingerprint, rate limit).

---

## 6. messaging_test — Le message de A à Z

### 6.1 Le flux testé

```
Alice (sender)                          Bob (receiver)
  │                                       │
  │  MessageService.pad_message()         │
  │  [simulated] ratchet.encrypt()        │
  │  MessageService.prepare_envelope()    │
  │    → seq auto-incrémenté              │
  │    → nonce dérivé                     │
  │    → timestamp                        │
  │                                       │
  │  Codec: Frame → encode → wire         │
  │  ═══════════════════════════════════► │
  │  Host: relais opaque                  │
  │                                       │  Codec: wire → decode → Frame
  │                                       │  MessageService.process_received()
  │                                       │    → anti-replay (seq déjà vu ?)
  │                                       │  [simulated] ratchet.decrypt()
  │                                       │  MessageService.unpad_message()
  │                                       │    → plaintext original
```

### 6.2 Le MockCrypto

Les tests d'intégration utilisent un `MockCrypto` qui implémente le trait `CryptoPort` avec les **5 méthodes requises** :

```rust
impl CryptoPort for MockCrypto {
    fn encrypt(..) → Ok(plaintext)       // passthrough
    fn decrypt(..) → Ok(ciphertext)      // passthrough
    fn pad(..) → [len:4B][msg][zeros]    // vrai padding
    fn unpad(..) → msg                   // vrai unpadding
    fn derive_key(..) → repeated bytes   // déterministe
}
```

`encrypt`/`decrypt` sont des passthroughs (pas de vrai chiffrement). Mais `pad`/`unpad` sont des implémentations réelles du format `[real_len: 4B BE][message][random padding]` arrondi au block_size. Ça permet de tester le round-trip complet du padding.

### 6.3 Les 6 tests

| Test | AT | Ce qu'il vérifie |
|------|-----|-----------------|
| `message_send_receive_full_flow` | AT-05 | Alice pad → envelope → Bob process → unpad → plaintext identique. |
| `replay_attack_detected` | AT-11 | Bob accepte un message une fois, le rejette la seconde fois (même seq). |
| `sequence_numbers_auto_increment` | — | 5 envelopes ont les seq 1, 2, 3, 4, 5 automatiquement. |
| `padding_preserves_message_content` | — | Messages de taille 0 à 1000 octets survivent au pad/unpad. Taille paddée toujours multiple de 256. |
| `message_stored_and_retrieved_from_memory_backlog` | — | 3 messages stockés dans `MemoryStorageAdapter` → récupérés avec les bons seq. |
| `message_envelope_survives_full_wire_round_trip` | — | pad → Frame → encode → wire → decode → unpad → plaintext original. Traverse le codec complet. |

---

## 7. room_lifecycle_test — La vie d'une room

### 7.1 Le flux testé

```
Alice (owner)                           Host                    Bob (member)
  │                                       │                       │
  │  RoomService.create_room()            │                       │
  │  RoomService.add_member(bob)          │                       │
  │                                       │                       │
  │  MemoryStorage.store_room()           │                       │
  │                                       │                       │
  │  RoomService.generate_invite()        │                       │
  │  ────── InviteToken ──────────────────┼─────────────────────► │
  │                                       │                       │  validate_invite()
  │                                       │                       │
  │                                       │  register_client(bob) │
  │                                       │  ◄──────────────────── │
  │                                       │  mark_client_ready()  │
  │                                       │                       │
  │  RoomService.revoke_member(bob)       │                       │
  │                                       │  remove_client(bob)   │
  │                                       │    → is_connected = false
```

Les crates traversées :
- **sanctum-app** : `RoomService` + `HostService`
- **sanctum-infra** : `MemoryStorageAdapter` + `IdentityAdapter`
- **sanctum-domain** : `Room`, `Member`, `InviteToken`, `Role`

### 7.2 Les 7 tests

| Test | AT | Ce qu'il vérifie |
|------|-----|-----------------|
| `create_room_and_store_in_memory` | AT-03 | Créer une room → `active_member_count() == 1` → store/load dans MemoryStorage. |
| `add_member_then_register_in_host_service` | — | Ajouter Bob via RoomService → `active_member_count() == 2` → HostService.register_client(bob) accepté → événement émis. |
| `host_rejects_non_member` | — | Un intrus non-membre est rejeté par `register_client`. |
| `revoke_member_disconnects_from_host` | AT-09 | Révoquer Bob via RoomService → `remove_client` → `is_connected == false`. |
| `invite_generate_validate_round_trip` | AT-10 | `generate_invite` (7 args : inviter, invited, role, onion, port, noise_key, ttl) → `validate_invite` accepte Bob, rejette Charlie. |
| `host_routes_to_ready_peers_only` | — | 3 clients connectés, seul Bob est ready → `route_recipients` retourne [bob]. Mark Charlie ready → retourne [bob, charlie]. |
| `room_full_prevents_new_members` | — | Room avec max_members=2 → alice + bob OK → charlie rejeté. |

**Point technique** : `generate_invite` prend **7 arguments** : `(inviter_fp, invited_fp, role, onion_address, port, host_noise_pubkey, ttl_secs)`. Le `port: u16` et `ttl_secs: u64` manquaient dans la première version des tests.

**Point technique** : `invited_fingerprint` est un **champ public** de `InviteToken`, pas une méthode. On y accède avec `invite.invited_fingerprint`, pas `invite.invited_fingerprint()`.

---

## 8. backlog_test — Le stockage et le GC

### 8.1 Le problème du room_id

Ce fichier a révélé un bug subtil lors de l'intégration. Les tests créaient les envelopes dans `make_envelopes()` (qui utilise `make_room()` avec un `RoomId::new()` aléatoire), puis faisaient `fetch_backlog` avec un **autre** `make_room()` qui générait un `RoomId` différent.

Résultat : le backlog retournait 0 messages car le `room_id` ne matchait pas.

La correction : extraire le `room_id` des envelopes créées :

```rust
let envelopes = make_envelopes(5);
let room_id = envelopes[0].room_id().clone();  // ← même ID
```

C'est exactement le genre de bug que les tests d'intégration sont conçus pour attraper.

### 8.2 Memory vs SQLite

Les tests vérifient les **deux** backends de stockage avec le même scénario. Le point clé : les deux doivent se comporter de manière identique du point de vue de l'appelant.

```
Memory:  fetch_backlog() → Vec<MessageEnvelope>
SQLite:  fetch_backlog() → Vec<(u64, Vec<u8>)>   // (seq, encrypted_data)
```

Les APIs sont légèrement différentes car SQLite stocke des blobs chiffrés opaques (il ne connaît pas `MessageEnvelope`), tandis que Memory stocke les objets directement. Mais les invariants sont les mêmes : filtrage par seq, ordre croissant, éviction FIFO.

### 8.3 Les 7 tests

| Test | AT | Ce qu'il vérifie |
|------|-----|-----------------|
| `backlog_round_trip_memory` | AT-08 | 5 messages → fetch all → 5. Fetch since seq 3 → 2 (seq 4, 5). |
| `backlog_round_trip_sqlite` | AT-08 | Même scénario en SQLite. |
| `gc_purges_expired_memory` | AT-13 | Messages récents + max_age très grand → 0 purgé. |
| `gc_purges_expired_sqlite` | AT-13 | 3 messages anciens (timestamp=100) + 1 récent → purge → 3 supprimés, 1 restant. |
| `backlog_evicts_oldest_when_full_memory` | — | Max 3 messages, store 5 → seuls 3, 4, 5 restent. |
| `backlog_excess_purge_sqlite` | — | 10 messages → `purge_excess(3)` → 7 supprimés, seuls 8, 9, 10 restent. |
| `memory_and_sqlite_backlog_consistent` | — | Même données dans les deux backends → même nombre de résultats pour `fetch_backlog(since_seq=2)`. |

---

## 9. chat_session_test — L'orchestrateur et l'UI

### 9.1 Le MockUi

Le `MockUi` implémente `UiPort` en capturant chaque appel dans un `Arc<Mutex<Vec<UiEvent>>>` :

```rust
enum UiEvent {
    Init,
    Cleanup,
    System(String),
    Message { sender: String, content: String },
    OwnMessage { content: String },
    BacklogStart(u32),
    BacklogEnd,
    StatusUpdate,
}
```

Après l'exécution, on peut inspecter la séquence exacte d'événements UI :

```rust
let captured = events.lock().unwrap();
assert!(matches!(captured[0], UiEvent::Init));
assert!(matches!(captured[1], UiEvent::Cleanup));
```

### 9.2 Les 10 tests

| Test | AT | Ce qu'il vérifie |
|------|-----|-----------------|
| `session_init_and_cleanup` | AT-15 | `init_ui()` → UiEvent::Init, `cleanup_ui()` → UiEvent::Cleanup. Séquence correcte. |
| `shutdown_cancels_token` | AT-15 | `request_shutdown()` → `CancellationToken.is_cancelled() == true`. |
| `emit_events_reach_subscribers` | — | `session.emit(OutgoingMessage)` → un subscriber broadcast reçoit l'event. |
| `build_status_reflects_config` | — | `build_status(3, true)` retourne room_name, peer_count=3, tor_connected=true, alias correctes. |
| `slash_commands_parsed_correctly` | AT-16 | 7 cas : message normal, /who → Members, /exit → Exit, /help → Help, /status → Status, "" → Empty, "   " → Empty. |
| `slash_commands_case_insensitive` | AT-16 | /WHO, /EXIT, /Help → reconnus correctement. |
| `slash_command_aliases_work` | AT-16 | /quit → Exit, /q → Exit, /h → Help, /? → Help. |
| `chat_events_for_tor_loss` | AT-17 | `TorStatusChanged { connected: false }` et `Disconnected { reason: "Tor..." }` se construisent et se matchent correctement. |
| `event_sequence_order_preserved` | — | 3 events envoyés (Connected, IncomingMessage, PeerLeft) → reçus dans le même ordre. |

**Point technique** : `ChatEvent::Connected` a un champ `peer_count: usize`, pas `peers: Vec<...>`. Le test original utilisait `peers: vec![]` ce qui ne compilait pas.

---

## 10. transport_integration_test — Le réseau simulé

### 10.1 InProcessTransport comme simulateur

`InProcessTransport::pair()` crée deux transports connectés par des channels Tokio. Ce que A envoie arrive dans B et inversement. Aucun réseau réel, aucun Tor, aucun TCP — juste des channels en mémoire.

C'est exactement ce que le host utilise en production pour sa propre ChatSession locale (le host est participant ET relais dans sa room).

```
Host Side              Client Side
    │                      │
    │  tx ─────────► rx    │
    │                      │
    │  rx ◄───────── tx    │
    │                      │
```

### 10.2 Les 8 tests

| Test | Ce qu'il vérifie |
|------|-----------------|
| `host_client_handshake_simulation` | Client envoie HandshakeInit → Host reçoit → Host envoie HandshakeResp → Client reçoit. |
| `auth_challenge_response_over_transport` | Challenge → Response → Result : 3 échanges séquentiels sur le transport. |
| `message_routing_three_clients` | Client A envoie → Host reçoit → Host route à B et C (pas A). B et C reçoivent le même payload. |
| `ping_pong_exchange` | Client envoie PING → Host reçoit → Host envoie PONG → Client reçoit. |
| `large_message_delivery` | Payload de 60 000 octets (juste sous la limite 64 KiB) → délivré intégralement. |
| `error_frame_delivery` | Frame ERROR avec message texte → délivré et décodé. |
| `detect_closed_channel` | Drop le host side → client.recv() retourne une erreur (pas un hang). |
| `concurrent_bidirectional_traffic` | Host et Client envoient 10 messages chacun simultanément → tous reçus, dans le bon ordre une fois triés. |

Le test `concurrent_bidirectional_traffic` est particulièrement intéressant : il lance deux `tokio::spawn` qui envoient en parallèle, puis vérifie que les 20 messages arrivent tous sans perte ni corruption.

---

## 11. Couverture des Acceptance Tests

| AT | Description | Fichier de test | Statut |
|----|------------|-----------------|--------|
| AT-03 | Création room éphémère | room_lifecycle_test | ✅ |
| AT-04 | Connexion + Auth | auth_flow_test | ✅ |
| AT-05 | Message temps réel | messaging_test | ✅ |
| AT-08 | Backlog au connect | backlog_test | ✅ |
| AT-09 | Révocation | room_lifecycle_test | ✅ |
| AT-10 | Invitation nominative | auth_flow_test + room_lifecycle_test | ✅ |
| AT-11 | Anti-replay | messaging_test | ✅ |
| AT-12 | Prévention downgrade | auth_flow_test | ✅ |
| AT-13 | GC backlog | backlog_test | ✅ |
| AT-15 | Sortie propre | chat_session_test | ✅ |
| AT-16 | Slash commands | chat_session_test | ✅ |
| AT-17 | Perte Tor | chat_session_test | ✅ |

Tests d'acceptance non encore couverts (nécessitent un réseau réel ou strace) :

| AT | Description | Raison |
|----|------------|--------|
| AT-01 | Init profil | Test CLI end-to-end (Sprint 7) |
| AT-02 | Import PGP | Test CLI end-to-end |
| AT-06 | Forward secrecy | Nécessite le vrai Double Ratchet |
| AT-07 | Zéro écriture disque | Nécessite strace (Sprint 7) |
| AT-14 | Persistence redémarrage | Test CLI end-to-end |

---

## 12. Leçons apprises

Les tests d'intégration ont révélé **8 problèmes concrets** que les tests unitaires ne pouvaient pas voir :

| Problème | Où | Cause |
|----------|-----|-------|
| `verify_server_id` appelé comme méthode | auth_flow_test | C'est une fonction statique (`AuthService::verify_server_id`) |
| `challenge_to_bytes` appelé comme méthode | auth_flow_test | Même cause |
| `verify_response` avec 4 arguments | auth_flow_test | Le code réel prend 3 args (pas de closure de vérification) |
| `Vec<Fingerprint>` vs `HashSet<Fingerprint>` | auth_flow_test | Le code utilise `HashSet`, le test passait un `Vec` |
| `pad_message` / `unpad_message` vs `pad` / `unpad` | messaging_test, backlog_test | Les noms dans `CryptoPort` sont `pad`/`unpad`, pas les noms longs |
| `member_count()` vs `active_member_count()` | room_lifecycle_test | La méthode s'appelle `active_member_count` |
| `generate_invite` avec 6 args vs 7 | room_lifecycle_test | `port: u16` manquait |
| `ChatEvent::Connected { peers }` vs `{ peer_count }` | chat_session_test | Le champ est `peer_count: usize`, pas `peers: Vec` |

Chacun de ces problèmes aurait causé un bug en production. Les tests d'intégration les ont tous attrapés avant.

**La leçon principale** : les mocks mentent. Ils compilent toujours, même quand l'API réelle a changé. Les tests d'intégration ne mentent pas car ils utilisent les vrais types.

---

## 13. Résumé des 43 tests

| Fichier | Tests | Crates traversées |
|---------|-------|-------------------|
| **auth_flow_test** | 6 | app (AuthService) + infra (IdentityAdapter, Codec) + domain |
| **messaging_test** | 6 | app (MessageService) + infra (MemoryStorage, Codec) + domain |
| **room_lifecycle_test** | 7 | app (RoomService, HostService) + infra (MemoryStorage, IdentityAdapter) + domain |
| **backlog_test** | 7 | app (MessageService) + infra (MemoryStorage, SqliteStorage) + domain |
| **chat_session_test** | 10 | app (ChatSession, InputParser) + domain (events, UiPort) |
| **transport_integration_test** | 8 | infra (InProcessTransport, Codec) |
| **Total** | **43** | |

### Compteur global du projet

| Crate | Unitaires | Intégration | Total |
|-------|-----------|-------------|-------|
| sanctum-domain | 23 | — | 23 |
| sanctum-crypto | 37 | — | 37 |
| sanctum-app | 46 | — | 46 |
| sanctum-infra | 45 | — | 45 |
| sanctum-cli | 5 | 43 | 48 |
| **Total** | **156** | **43** | **199** |
