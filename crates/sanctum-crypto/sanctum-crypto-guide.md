# Sanctum Crypto — Documentation Complète

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Pourquoi un crate crypto séparé ?](#2-pourquoi-un-crate-crypto-séparé)
3. [Structure des fichiers](#3-structure-des-fichiers)
4. [Les dépendances et pourquoi elles](#4-les-dépendances-et-pourquoi-elles)
5. [AEAD — Le chiffrement des données](#5-aead--le-chiffrement-des-données)
   - 5.1 [C'est quoi AEAD ?](#51-cest-quoi-aead)
   - 5.2 [AES-256-GCM vs ChaCha20-Poly1305](#52-aes-256-gcm-vs-chacha20-poly1305)
   - 5.3 [Le code : aead.rs](#53-le-code-aeadrs)
6. [KDF — La dérivation de clés](#6-kdf--la-dérivation-de-clés)
   - 6.1 [Argon2id — Passphrase vers clé maître](#61-argon2id--passphrase-vers-clé-maître)
   - 6.2 [HKDF-SHA256 — Clé maître vers sous-clés](#62-hkdf-sha256--clé-maître-vers-sous-clés)
   - 6.3 [Le code : kdf.rs](#63-le-code-kdfrs)
7. [Padding — Cacher la taille des messages](#7-padding--cacher-la-taille-des-messages)
   - 7.1 [Pourquoi le padding ?](#71-pourquoi-le-padding)
   - 7.2 [Le schéma choisi](#72-le-schéma-choisi)
   - 7.3 [Le code : padding.rs](#73-le-code-paddingrs)
8. [Noise NK — Le tunnel de transport](#8-noise-nk--le-tunnel-de-transport)
   - 8.1 [C'est quoi Noise ?](#81-cest-quoi-noise)
   - 8.2 [Pourquoi NK ?](#82-pourquoi-nk)
   - 8.3 [Le handshake en détail](#83-le-handshake-en-détail)
   - 8.4 [Le code : noise.rs](#84-le-code-noisers)
9. [X3DH — L'échange de clés entre pairs](#9-x3dh--léchange-de-clés-entre-pairs)
   - 9.1 [Le problème que X3DH résout](#91-le-problème-que-x3dh-résout)
   - 9.2 [Les clés impliquées](#92-les-clés-impliquées)
   - 9.3 [Le protocole pas à pas](#93-le-protocole-pas-à-pas)
   - 9.4 [Le code : x3dh.rs](#94-le-code-x3dhrs)
10. [Double Ratchet — Le secret par message](#10-double-ratchet--le-secret-par-message)
    - 10.1 [Pourquoi pas juste X3DH ?](#101-pourquoi-pas-juste-x3dh)
    - 10.2 [Les trois ratchets](#102-les-trois-ratchets)
    - 10.3 [Forward secrecy et break-in recovery](#103-forward-secrecy-et-break-in-recovery)
    - 10.4 [Messages hors-ordre](#104-messages-hors-ordre)
    - 10.5 [Le code : ratchet.rs](#105-le-code-ratchetrs)
11. [CryptoPort — L'adaptateur qui relie tout](#11-cryptoport--ladaptateur-qui-relie-tout)
12. [Comment tout s'enchaîne](#12-comment-tout-senchaîne)
13. [Choix de protocoles : pourquoi ceux-là ?](#13-choix-de-protocoles--pourquoi-ceux-là)
14. [Résumé des 37 tests](#14-résumé-des-37-tests)

---

## 1. Vue d'ensemble

Le crate `sanctum-crypto` fournit toutes les opérations cryptographiques de Sanctum. Il ne fait aucun IO réseau ou disque — il prend des octets en entrée et retourne des octets en sortie.

Il contient **6 briques** qui s'empilent les unes sur les autres :

```
┌─────────────────────────────────────────┐
│          Double Ratchet (ratchet.rs)    │  ← Secret unique par message
│  ┌─────────────────────────────────┐    │
│  │       X3DH (x3dh.rs)            │    │  ← Établissement du premier secret
│  └─────────────────────────────────┘    │
├─────────────────────────────────────────┤
│       Noise NK (noise.rs)               │  ← Tunnel de transport chiffré
├─────────────────────────────────────────┤
│  AEAD (aead.rs) │ KDF (kdf.rs) │ Pad    │  ← Primitives de base
└─────────────────────────────────────────┘
```

Les couches basses (AEAD, KDF, Padding) sont des primitives pures. Les couches hautes (Noise, X3DH, Double Ratchet) sont des protocoles qui combinent ces primitives.

---

## 2. Pourquoi un crate crypto séparé ?

Dans l'architecture Clean, le domain définit le **contrat** (`CryptoPort` trait) et le crate crypto fournit l'**implémentation concrète**. Cette séparation permet de :

- **Auditer** la crypto indépendamment du reste du code
- **Tester** avec des mocks (fausses implémentations) dans les autres crates
- **Remplacer** un algorithme sans toucher au domain ni à l'app
- **Isoler** les dépendances lourdes (les crates crypto) dans un seul endroit

Le domain ne sait pas que AES-256-GCM existe. Il sait juste qu'il peut appeler `encrypt()` et `decrypt()`.

---

## 3. Structure des fichiers

```
crates/sanctum-crypto/
├── Cargo.toml
└── src/
    ├── lib.rs              ← Point d'entrée, déclare les modules
    ├── aead.rs             ← AES-256-GCM + ChaCha20-Poly1305
    ├── kdf.rs              ← Argon2id + HKDF-SHA256
    ├── padding.rs          ← Padding à taille fixe
    ├── noise.rs            ← Noise NK handshake
    ├── x3dh.rs             ← X3DH key agreement
    ├── ratchet.rs          ← Double Ratchet
    └── crypto_adapter.rs   ← Implémentation du CryptoPort trait
```

---

## 4. Les dépendances et pourquoi elles

| Dépendance | Version | Rôle | Pourquoi celle-là |
|-----------|---------|------|------------------|
| `aes-gcm` | 0.10 | Chiffrement AES-256-GCM | RustCrypto, audité, pure Rust |
| `chacha20poly1305` | 0.10 | Chiffrement ChaCha20-Poly1305 | RustCrypto, constant-time, pas besoin d'AES-NI |
| `hkdf` | 0.12 | Dérivation de sous-clés | Standard IETF (RFC 5869) |
| `sha2` | 0.10 | Hashing SHA-256 | Base pour HKDF et HMAC |
| `argon2` | 0.5 | KDF depuis passphrase | Vainqueur du Password Hashing Competition |
| `x25519-dalek` | 2 | Diffie-Hellman sur Curve25519 | Réf. impl. Rust, audité par NCC |
| `ed25519-dalek` | 2 | Signatures Ed25519 | Pour signer les SPK |
| `snow` | 0.9 | Noise protocol framework | Impl. complète et auditée |
| `rand` | 0.8 | CSPRNG | OsRng = source d'aléa du système |
| `zeroize` | 1 | Effacement mémoire | Empêche les fuites de secrets |

Toutes ces dépendances sont en **pure Rust** (pas de code C sous-jacent), auditées, et largement utilisées dans l'écosystème.

---

## 5. AEAD — Le chiffrement des données

### 5.1 C'est quoi AEAD ?

**AEAD** = Authenticated Encryption with Associated Data. C'est un mode de chiffrement qui garantit **deux choses en même temps** :

1. **Confidentialité** : seul celui qui a la clé peut lire le message
2. **Intégrité** : si quelqu'un modifie ne serait-ce qu'un bit du ciphertext, le déchiffrement échoue

Le "Associated Data" (AAD) est un bonus : des données qui ne sont pas chiffrées mais qui sont authentifiées. Par exemple, on peut mettre le `room_id` en AAD : il reste lisible (le host en a besoin pour le routage) mais si quelqu'un le modifie, le déchiffrement échoue.

```
┌──────────────────────────────────────────────┐
│  AAD (non chiffré mais authentifié)          │
│  ex: room_id, sender_fingerprint             │
├──────────────────────────────────────────────┤
│  Ciphertext (chiffré + authentifié)          │
│  ex: le contenu du message                   │
├──────────────────────────────────────────────┤
│  Auth Tag (16 octets, preuve d'intégrité)    │
└──────────────────────────────────────────────┘
```

Sans AEAD, un attaquant pourrait modifier le ciphertext et l'envoyer à quelqu'un qui le déchiffrerait en un message corrompu sans s'en rendre compte. Avec AEAD, toute modification est détectée.

### 5.2 AES-256-GCM vs ChaCha20-Poly1305

Sanctum utilise **deux** algorithmes AEAD :

| | AES-256-GCM | ChaCha20-Poly1305 |
|---|---|---|
| **Usage dans Sanctum** | Chiffrement du stockage SQLite | Chiffrement des messages E2E |
| **Performance** | Très rapide avec AES-NI (instruction CPU) | Rapide partout, même sans AES-NI |
| **Timing attacks** | Vulnérable sans AES-NI hardware | Constant-time par design |
| **Taille de clé** | 256 bits | 256 bits |
| **Taille de nonce** | 96 bits (12 octets) | 96 bits (12 octets) |
| **Auth tag** | 128 bits (16 octets) | 128 bits (16 octets) |

**Pourquoi deux ?** Le stockage SQLite tourne sur la machine locale où on contrôle le hardware — AES-NI est disponible et c'est le plus rapide. Les messages E2E transitent via Tor et peuvent être traités sur n'importe quel hardware — ChaCha20 est le choix sûr car il est constant-time sans instruction spéciale.

### 5.3 Le code : aead.rs

```rust
pub fn encrypt(cipher, key, nonce, plaintext, aad) -> Result<Vec<u8>, SanctumError>
pub fn decrypt(cipher, key, nonce, ciphertext, aad) -> Result<Vec<u8>, SanctumError>
pub fn generate_nonce() -> [u8; 12]
pub fn generate_key() -> [u8; 32]
```

Les fonctions sont simples : elles prennent une clé (32 octets), un nonce (12 octets), des données, et retournent le résultat. Le premier paramètre `cipher` choisit entre AES-256-GCM et ChaCha20-Poly1305.

**Le nonce** (Number used ONCE) est critique : il doit être unique pour chaque opération de chiffrement avec la même clé. Si on réutilise un nonce, la sécurité s'effondre totalement. Dans Sanctum, le nonce est soit généré aléatoirement (via `generate_nonce()` qui utilise le CSPRNG du système), soit dérivé du compteur de messages dans le Double Ratchet.

---

## 6. KDF — La dérivation de clés

### 6.1 Argon2id — Passphrase vers clé maître

**Problème** : l'utilisateur tape une passphrase ("correct horse battery staple"). On a besoin d'une clé de 256 bits avec une entropie maximale. On ne peut pas utiliser la passphrase directement car elle est trop prévisible (mots du dictionnaire, patterns humains).

**Solution** : Argon2id est une fonction de hachage de mots de passe qui est volontairement **lente** et **gourmande en mémoire** :

```
Passphrase  ──→  Argon2id(64 MiB RAM, 3 itérations)  ──→  Clé 256 bits
    +
   Salt (aléatoire, 32 octets)
```

Pourquoi lent et gourmand ?

- **Un utilisateur légitime** appelle Argon2id une seule fois au lancement. 0.5 seconde d'attente est acceptable.
- **Un attaquant** qui brute-force doit appeler Argon2id pour **chaque tentative**. À 0.5s et 64 MiB par tentative, tester 1 milliard de mots de passe prendrait 16 ans et nécessiterait un datacenter de RAM.

**Argon2id** combine les avantages de Argon2i (résistant aux attaques side-channel) et Argon2d (résistant aux attaques GPU/ASIC). C'est le vainqueur du Password Hashing Competition (2015) et la recommandation OWASP.

Le **salt** est un aléa unique stocké avec les données chiffrées. Il empêche les rainbow tables (tables précalculées de hash → mot de passe).

### 6.2 HKDF-SHA256 — Clé maître vers sous-clés

**Problème** : on a un secret partagé (issu de X3DH ou du Double Ratchet). On a besoin de **plusieurs** clés différentes : une pour chiffrer, une pour le MAC, une pour le prochain ratchet, etc. On ne peut pas réutiliser la même clé partout.

**Solution** : HKDF (HMAC-based Key Derivation Function, RFC 5869) dérive des sous-clés à partir d'une clé maître :

```
Secret partagé  ──→  HKDF-SHA256(info="room_key")   ──→  Clé pour la room
                ──→  HKDF-SHA256(info="msg_key")    ──→  Clé pour le message
                ──→  HKDF-SHA256(info="chain_key")  ──→  Clé pour la chaîne
```

Le paramètre `info` est une chaîne de contexte qui rend chaque sous-clé unique. Même secret + info différent = clés totalement différentes et indépendantes.

HKDF fonctionne en deux phases :
1. **Extract** : compresse le secret d'entrée (qui peut avoir une distribution non uniforme) en un pseudorandom key
2. **Expand** : étend cette clé en autant de sous-clés que nécessaire

### 6.3 Le code : kdf.rs

```rust
pub fn derive_master_key(passphrase, salt) -> Result<[u8; 32], SanctumError>  // Argon2id
pub fn derive_subkey(master_key, salt, info, output_len) -> Result<Vec<u8>, SanctumError>  // HKDF
pub fn generate_salt() -> [u8; 32]
```

`derive_master_key` est utilisé une seule fois au démarrage (déverrouillage du stockage persistant). `derive_subkey` est utilisé partout dans le Double Ratchet pour dériver les clés de message.

---

## 7. Padding — Cacher la taille des messages

### 7.1 Pourquoi le padding ?

Même avec un chiffrement parfait, la **taille** du ciphertext révèle la taille du plaintext (à 16 octets près à cause du tag AEAD). Un attaquant qui observe le réseau Tor peut :

- Distinguer "ok" (2 octets → ~18 octets chiffrés) de "Je serai au point de rendez-vous à 14h" (38 octets → ~54 octets chiffrés)
- Faire de l'analyse de trafic sur la longueur des messages
- Corréler des messages entre rooms par leur pattern de taille

C'est une fuite de métadonnées que le chiffrement seul ne résout pas.

### 7.2 Le schéma choisi

On padde chaque message à un multiple d'un **block_size** (256 octets par défaut) :

```
Message original : "Hello" (5 octets)

Après padding (bloc de 256) :
┌──────────┬───────────────────┬──────────────────────────────┐
│ Longueur │     Message       │      Padding aléatoire       │
│ 4 octets │     5 octets      │       247 octets             │
│ 00000005 │     Hello         │     (bruit aléatoire)        │
└──────────┴───────────────────┴──────────────────────────────┘
                    = 256 octets au total
```

Résultat : tous les messages de 0 à 252 octets font exactement 256 octets après padding. Les messages de 253 à 508 font 512 octets, etc.

Le padding est **aléatoire** (pas des zéros) pour éviter qu'un attaquant ne détecte le pattern de padding dans le ciphertext.

### 7.3 Le code : padding.rs

```rust
pub fn pad(plaintext, block_size) -> Vec<u8>     // Ajoute le padding
pub fn unpad(padded) -> Result<Vec<u8>, SanctumError>  // Retire le padding
```

Le format est simple : 4 octets de longueur (big-endian) + message + bruit aléatoire. L'unpadding lit les 4 premiers octets pour savoir combien d'octets de message réel extraire.

---

## 8. Noise NK — Le tunnel de transport

### 8.1 C'est quoi Noise ?

**Noise** est un framework pour construire des protocoles de handshake cryptographiques. C'est utilisé par WhatsApp, WireGuard, Lightning Network, et beaucoup d'autres.

Contrairement à TLS qui est énorme et complexe (avec certificats X.509, négociation de cipher suites, etc.), Noise est minimaliste : tu choisis un **pattern** de handshake et Noise génère un protocole sécurisé spécifique à ton cas d'usage.

### 8.2 Pourquoi NK ?

Un pattern Noise est décrit par les lettres des clés échangées. "NK" signifie :

- **N** : l'initiateur (client) n'a **No** clé statique dans le handshake Noise. Il est anonyme au niveau transport.
- **K** : le répondeur (host) a une clé statique **Known** à l'avance (elle est dans le token d'invitation).

```
Client (N)                        Host (K)
   │                                 │
   │  Connaît la clé publique        │  A une clé statique
   │  du host (via invite token)     │  (générée au host)
   │                                 │
   │──── msg1: ephemeral key ───────→│  Client génère une clé éphémère
   │                                 │
   │←─── msg2: encrypted payload ────│  Host répond avec le tunnel chiffré
   │                                 │
   │  Tunnel chiffré établi          │
   │  (ChaCha20-Poly1305)            │
```

**Pourquoi pas une authentification mutuelle dans Noise ?** Parce que Sanctum authentifie le client ensuite via **PGP** (challenge-response avec le fingerprint). Noise NK ne fait qu'établir un canal chiffré vers le bon host — l'authentification de l'identité se fait à un niveau supérieur.

C'est une séparation de responsabilités : Noise gère le chiffrement du transport, PGP gère l'identité.

### 8.3 Le handshake en détail

Le pattern NK en 2 messages :

**Message 1 (Client → Host)** :
1. Client génère une clé éphémère (aléatoire, usage unique)
2. Client envoie sa clé publique éphémère + un payload optionnel
3. Le tout est partiellement chiffré avec la clé publique du host

**Message 2 (Host → Client)** :
1. Host génère sa propre clé éphémère
2. Host fait un Diffie-Hellman avec la clé éphémère du client
3. Host envoie sa réponse chiffrée

Après ces 2 messages, les deux côtés ont un `TransportState` qui chiffre/déchiffre tout le trafic suivant avec ChaCha20-Poly1305. Chaque message a un compteur anti-replay intégré.

**Sécurité** : même si un attaquant enregistre tout le trafic et vole plus tard la clé statique du host, il ne peut pas déchiffrer les sessions passées car les clés éphémères ont été détruites (forward secrecy du transport).

### 8.4 Le code : noise.rs

```rust
pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>), SanctumError>
pub fn responder(static_private) -> Result<HandshakeState, SanctumError>
pub fn initiator(remote_static_public) -> Result<HandshakeState, SanctumError>
pub fn write_message(state, payload) -> Result<Vec<u8>, SanctumError>
pub fn read_message(state, message) -> Result<Vec<u8>, SanctumError>
pub fn into_transport(state) -> Result<TransportState, SanctumError>
pub fn transport_encrypt(transport, plaintext) -> Result<Vec<u8>, SanctumError>
pub fn transport_decrypt(transport, ciphertext) -> Result<Vec<u8>, SanctumError>
```

L'API est volontairement découpée en petites fonctions pour que la couche infra puisse orchestrer le handshake pas à pas (envoyer msg1, attendre msg2, etc.) au-dessus du réseau TCP/Tor.

---

## 9. X3DH — L'échange de clés entre pairs

### 9.1 Le problème que X3DH résout

Alice veut envoyer un message chiffré à Bob. Mais ils n'ont jamais communiqué. Comment établir un secret partagé ?

La solution classique (Diffie-Hellman simple) nécessite que les deux soient en ligne en même temps. X3DH résout ça : Bob publie à l'avance un **PreKey Bundle** (un ensemble de clés publiques), et Alice peut initier une session même si Bob est hors ligne.

### 9.2 Les clés impliquées

Bob publie son PreKey Bundle sur le host :

| Clé | Nom | Durée de vie | Rôle |
|-----|-----|-------------|------|
| **IK** | Identity Key | Permanente | Identité long-terme de Bob |
| **SPK** | Signed Pre-Key | 24-48h | Clé semi-éphémère, signée par IK |
| **OPK** | One-Time Pre-Key | Usage unique | Clé jetable (optionnelle, meilleure sécurité) |

Alice a sa propre IK permanente et génère une clé **EK** éphémère (jetable, usage unique pour cette session).

### 9.3 Le protocole pas à pas

```
Alice (initiateur)                    Bob (répondeur)
═══════════════════                   ═══════════════
Possède :                             A publié :
- IK_alice (permanent)                - IK_bob (permanent)
- EK_alice (éphémère, générée now)    - SPK_bob (semi-éphémère)
                                      - OPK_bob (jetable, optionnel)

Calcule 3 (ou 4) Diffie-Hellman :

DH1 = IK_alice × SPK_bob    ← Prouve qu'Alice possède sa clé permanente
DH2 = EK_alice × IK_bob     ← Lie la session à l'identité de Bob
DH3 = EK_alice × SPK_bob    ← Forward secrecy via la clé éphémère
DH4 = EK_alice × OPK_bob    ← (optionnel) Sécurité supplémentaire

Secret = HKDF(DH1 || DH2 || DH3 [|| DH4])

Alice envoie à Bob :
- EK_alice (clé publique éphémère)
- Quel SPK_bob et OPK_bob elle a utilisés

Bob recalcule les mêmes DH de son côté :
DH1 = SPK_bob × IK_alice    ← Même résultat (DH est commutatif)
DH2 = IK_bob × EK_alice
DH3 = SPK_bob × EK_alice
DH4 = OPK_bob × EK_alice

Secret = HKDF(DH1 || DH2 || DH3 [|| DH4])  ← Identique !
```

**Pourquoi 3 DH et pas 1 ?** Chaque DH apporte une propriété différente :

- **DH1** (IK_alice × SPK_bob) : prouve qu'Alice est bien Alice (authentification)
- **DH2** (EK_alice × IK_bob) : lie la session à Bob
- **DH3** (EK_alice × SPK_bob) : forward secrecy (si IK est compromise plus tard, les sessions passées sont sûres car EK a été détruite)
- **DH4** (EK_alice × OPK_bob) : one-time security boost (l'OPK n'est utilisable qu'une fois)

### 9.4 Le code : x3dh.rs

```rust
pub struct X25519Keypair { secret, public }

pub fn initiate(alice_ik, bob_ik_pub, bob_spk_pub, bob_opk_pub)
    -> Result<X3dhInitResult { shared_secret, ephemeral_public }, ...>

pub fn respond(bob_ik, bob_spk, bob_opk, alice_ik_pub, alice_ek_pub)
    -> Result<X3dhRespondResult { shared_secret }, ...>
```

"Alice" et "Bob" sont des noms conventionnels en crypto. Dans Sanctum, n'importe quel utilisateur est "Alice" quand il initie une session et "Bob" quand il la reçoit. Si tu fais `sanctum join` tu es Alice ; si quelqu'un rejoint ta room tu es Bob.

Le `shared_secret` de 32 octets est ensuite passé au Double Ratchet pour démarrer le chiffrement par message.

---

## 10. Double Ratchet — Le secret par message

### 10.1 Pourquoi pas juste X3DH ?

X3DH produit **un seul** secret partagé. Si on l'utilise directement pour chiffrer tous les messages, un attaquant qui obtient ce secret peut déchiffrer **toute** la conversation (passée et future). C'est catastrophique.

Le Double Ratchet résout ça en dérivant une **clé unique pour chaque message**. Après usage, la clé est détruite. Résultat :

- Compromission d'une clé de message → un seul message déchiffré
- Compromission du secret X3DH initial → rien, car le ratchet a évolué depuis

### 10.2 Les trois ratchets

Le Double Ratchet combine en fait **trois mécanismes** qui "avancent" les clés :

```
                    ┌──────────────────┐
                    │   DH Ratchet     │  ← Avance quand le tour de parole change
                    │  (asymétrique)   │     Génère une nouvelle paire DH à chaque fois
                    └────────┬─────────┘
                             │
                     root_key évolue
                             │
              ┌──────────────┴──────────────┐
              │                             │
    ┌─────────▼──────────┐       ┌──────────▼──────────┐
    │  Sending Chain     │       │  Receiving Chain    │
    │  (symétrique)      │       │  (symétrique)       │
    │                    │       │                     │
    │  chain_key ──→ msg_key_1   │  chain_key ──→ msg_key_1
    │  chain_key ──→ msg_key_2   │  chain_key ──→ msg_key_2
    │  chain_key ──→ msg_key_3   │  chain_key ──→ msg_key_3
    └────────────────────┘       └─────────────────────┘
```

**1. Le DH Ratchet** (asymétrique) : chaque fois qu'Alice envoie un message après avoir reçu un message de Bob, elle génère une **nouvelle paire de clés DH**. Un Diffie-Hellman avec la clé de Bob produit un nouveau secret, qui fait évoluer la `root_key`. C'est ce qui apporte la **break-in recovery** : même si un attaquant compromet l'état actuel, dès qu'un nouveau DH a lieu, il est exclu.

**2. La Sending Chain** (symétrique) : pour chaque message envoyé, la `chain_key` est dérivée en une `message_key` (pour chiffrer ce message) et une nouvelle `chain_key` (pour le prochain message). La `message_key` est utilisée puis détruite.

**3. La Receiving Chain** (symétrique) : identique mais pour les messages reçus.

### 10.3 Forward secrecy et break-in recovery

| Propriété | Signification | Comment le Double Ratchet l'assure |
|-----------|--------------|-----------------------------------|
| **Forward secrecy** | Compromission des clés actuelles → les messages passés restent sûrs | Les message_keys sont dérivées d'une chaîne unidirectionnelle. On ne peut pas remonter. |
| **Break-in recovery** | Compromission temporaire → les messages futurs redeviennent sûrs | Le DH Ratchet génère un nouveau secret à chaque tour de parole. L'attaquant doit aussi compromettre les nouvelles clés DH. |

C'est la combinaison des deux qui rend le Double Ratchet puissant. TLS n'a que la forward secrecy (via les clés éphémères du handshake). Le Double Ratchet a les deux.

### 10.4 Messages hors-ordre

Sur Tor, les messages peuvent arriver dans le désordre. Le Double Ratchet gère ça avec un mécanisme de **clés sautées** (skipped keys) :

```
Alice envoie msg1, msg2, msg3

Bob reçoit msg3 en premier :
  → Il dérive et stocke les clés de msg1 et msg2 (sans les utiliser)
  → Il déchiffre msg3 avec sa clé

Bob reçoit msg1 :
  → Il retrouve la clé stockée pour msg1
  → Il déchiffre msg1
  → Il supprime la clé stockée

Limite : max 256 messages sautés par chaîne (protection contre le DoS)
```

### 10.5 Le code : ratchet.rs

```rust
pub struct RatchetState { ... }  // État complet d'une session (privé, zeroize on drop)

impl RatchetState {
    pub fn init_alice(shared_secret, bob_ratchet_pub) -> Result<Self, ...>  // Initiateur
    pub fn init_bob(shared_secret, bob_spk_secret, bob_spk_public) -> Self // Répondeur
    pub fn encrypt(&mut self, plaintext) -> Result<(Header, Vec<u8>), ...>
    pub fn decrypt(&mut self, header, ciphertext) -> Result<Vec<u8>, ...>
}
```

`RatchetState` implémente `Drop` manuellement pour zeroize tous les secrets (root_key, chain_keys, skipped_keys) quand la session se termine.

Le `Header` envoyé avec chaque message contient :
- `dh_public` : la clé publique DH actuelle de l'envoyeur
- `prev_chain_len` : combien de messages dans la chaîne précédente (pour que le récepteur sache combien de clés stocker)
- `msg_num` : le numéro de ce message dans la chaîne actuelle

---

## 11. CryptoPort — L'adaptateur qui relie tout

`crypto_adapter.rs` implémente le trait `CryptoPort` défini dans le domain :

```rust
impl CryptoPort for SanctumCryptoProvider {
    fn encrypt(...)  → aead::encrypt(ChaCha20Poly1305, ...)
    fn decrypt(...)  → aead::decrypt(ChaCha20Poly1305, ...)
    fn pad(...)      → padding::pad(...)
    fn unpad(...)    → padding::unpad(...)
    fn derive_key(.) → kdf::derive_subkey(...)
}
```

C'est un simple câblage : le domain appelle `crypto.encrypt()`, ça arrive ici, et on délègue aux bonnes fonctions avec les bons algorithmes. Si demain on voulait remplacer ChaCha20 par un autre algorithme, on ne changerait que ce fichier.

---

## 12. Comment tout s'enchaîne

Voici le flux complet quand Alice rejoint une room et envoie un message à Bob :

```
1. CONNEXION (Noise NK)
   Alice connaît la clé publique du host (via invite token)
   ──→ noise::initiator(host_pub_key)
   ──→ Handshake 2 messages
   ──→ Tunnel chiffré établi (transport_encrypt/decrypt)

2. AUTHENTIFICATION (PGP, hors de ce crate)
   Le host envoie un challenge via le tunnel Noise
   Alice signe avec sa clé PGP
   Le host vérifie la signature

3. ÉTABLISSEMENT DE SESSION E2E (X3DH)
   Alice récupère le PreKey Bundle de Bob (via le host)
   ──→ x3dh::initiate(alice_ik, bob_ik_pub, bob_spk_pub, bob_opk_pub)
   ──→ shared_secret + ephemeral_public
   Alice envoie son ephemeral_public à Bob (via le host)

4. INITIALISATION DU RATCHET
   Alice : ratchet::RatchetState::init_alice(shared_secret, bob_spk_pub)
   Bob   : ratchet::RatchetState::init_bob(shared_secret, bob_spk_secret, bob_spk_pub)

5. ENVOI D'UN MESSAGE
   Alice tape "Hello Bob"
   ──→ padding::pad("Hello Bob", 256)        → 256 octets
   ──→ ratchet.encrypt(padded)               → (header, ciphertext)
   ──→ Construit un MessageEnvelope
   ──→ Sérialisé, envoyé via le tunnel Noise

6. RÉCEPTION
   Bob reçoit le MessageEnvelope via le tunnel Noise
   ──→ ratchet.decrypt(header, ciphertext)   → padded plaintext
   ──→ padding::unpad(padded)                → "Hello Bob"
   ──→ Affiché dans le terminal
```

Chaque couche ne voit que ce qui la concerne :
- **Noise** voit des octets bruts sur le réseau
- **X3DH** voit des clés publiques et produit un secret
- **Double Ratchet** voit un plaintext et produit un (header + ciphertext)
- **Padding** voit un message et produit un bloc de taille fixe
- **AEAD** voit une clé + nonce + données et chiffre/déchiffre

---

## 13. Choix de protocoles : pourquoi ceux-là ?

### Pourquoi pas TLS ?

TLS est conçu pour le web : il gère les certificats X.509, les autorités de certification, la négociation de cipher suites, etc. Tout ça est inutile et dangereux pour Sanctum :
- Pas de CA (autorité de certification) — on est sur Tor, décentralisé
- La négociation de cipher suite ouvre la porte aux attaques de downgrade
- TLS n'offre pas de forward secrecy par message (seulement par session)

Noise NK est plus simple, plus sûr pour notre cas, et n'a pas de négociation (un seul cipher fixe).

### Pourquoi pas Signal Protocol directement ?

Le Signal Protocol = X3DH + Double Ratchet, exactement ce qu'on implémente. Mais la librairie `libsignal` officielle est en C/Java et difficile à intégrer en Rust proprement. On utilise les mêmes **protocoles** (conçus par Trevor Perrin et Moxie Marlinspike) mais implémentés avec des crates Rust auditées.

### Pourquoi X25519 et pas RSA ?

| | X25519 (Curve25519) | RSA-4096 |
|---|---|---|
| Taille de clé | 32 octets | 512 octets |
| Performance | ~150 000 DH/sec | ~1 000 opérations/sec |
| Sécurité | ~128 bits | ~128 bits (à 4096 bits) |
| Design | Modern (2005), constant-time | Legacy (1977), timing attacks possibles |

X25519 est plus rapide, plus compact, et plus sûr (constant-time by design). RSA est trop lent pour faire du DH à chaque message (Double Ratchet).

### Pourquoi Argon2id et pas bcrypt/scrypt ?

Argon2id est le plus récent et le plus résistant :
- **bcrypt** : pas de paramètre mémoire (vulnérable aux GPU)
- **scrypt** : paramètre mémoire mais vulnérable aux attaques timing side-channel
- **Argon2id** : combine résistance mémoire (anti-GPU) et résistance side-channel

### Pourquoi ChaCha20-Poly1305 pour les messages ?

ChaCha20 est constant-time sur **tout** hardware. AES-GCM ne l'est que si le CPU a l'instruction AES-NI. Sur un vieux laptop ou un Raspberry Pi, AES-GCM en software a des fuites de timing exploitables. Pour des messages E2E qui transitent entre machines inconnues, ChaCha20 est le choix sûr.

---

## 14. Résumé des 37 tests

| Fichier | Tests | Ce qu'ils vérifient |
|---------|-------|-------------------|
| aead.rs | 7 | Round-trip AES-GCM et ChaCha20, mauvaise clé, ciphertext altéré, mauvais AAD, clé/nonce invalides |
| kdf.rs | 7 | Argon2id déterministe, passphrase/salt différents, salt trop court, HKDF déterministe, info différent, longueurs variées |
| padding.rs | 9 | Round-trip, alignement bloc, minimum 1 bloc, messages courts/longs, multi-blocs, données invalides, message vide, tailles de bloc variées |
| noise.rs | 3 | Handshake complet + transport bidirectionnel, payload dans handshake, mauvaise clé détectée |
| x3dh.rs | 3 | Secret partagé identique des deux côtés, avec OPK, clés différentes → secrets différents |
| ratchet.rs | 5 | Round-trip, messages multiples, bidirectionnel, hors-ordre, forward secrecy (clé consommée) |
| crypto_adapter.rs | 3 | CryptoPort round-trip, pad/unpad, derive_key |
| **Total** | **37** | |
