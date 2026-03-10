# Sanctum Ops — Documentation Complète

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Pourquoi un sprint Ops ?](#2-pourquoi-un-sprint-ops)
3. [Structure des fichiers](#3-structure-des-fichiers)
4. [README.md — La porte d'entrée](#4-readmemd--la-porte-dentrée)
5. [SECURITY.md — Le contrat de sécurité](#5-securitymd--le-contrat-de-sécurité)
   - 5.1 [Ce que Sanctum protège](#51-ce-que-sanctum-protège)
   - 5.2 [Ce que Sanctum ne protège PAS](#52-ce-que-sanctum-ne-protège-pas)
   - 5.3 [Les primitives crypto](#53-les-primitives-crypto)
   - 5.4 [Les invariants de sécurité](#54-les-invariants-de-sécurité)
6. [NFO.md — Le manifeste de release](#6-nfomd--le-manifeste-de-release)
7. [migrations/001_initial.sql — Le schéma SQLite](#7-migrations001_initialsql--le-schéma-sqlite)
   - 7.1 [Les 5 tables](#71-les-5-tables)
   - 7.2 [Les index](#72-les-index)
   - 7.3 [Pourquoi des migrations versionnées](#73-pourquoi-des-migrations-versionnées)
8. [scripts/setup-tor.sh — L'installation Tor](#8-scriptssetup-torsh--linstallation-tor)
   - 8.1 [Ce que le script fait](#81-ce-que-le-script-fait)
   - 8.2 [Détection multi-distro](#82-détection-multi-distro)
   - 8.3 [Vérification de la connectivité](#83-vérification-de-la-connectivité)
9. [scripts/check-no-disk-writes.sh — La vérification éphémère](#9-scriptscheck-no-disk-writessh--la-vérification-éphémère)
   - 9.1 [Le principe de strace](#91-le-principe-de-strace)
   - 9.2 [Ce que le script vérifie](#92-ce-que-le-script-vérifie)
   - 9.3 [Lien avec AT-07](#93-lien-avec-at-07)
10. [.github/workflows/ci.yml — L'intégration continue](#10-githubworkflowsciyml--lintégration-continue)
    - 10.1 [Les 5 jobs](#101-les-5-jobs)
    - 10.2 [Pourquoi chaque job](#102-pourquoi-chaque-job)
11. [docs/runbook.md — Le guide opérationnel](#11-docsrunbookmd--le-guide-opérationnel)
12. [docs/adrs/ — Les décisions d'architecture](#12-docsadrs--les-décisions-darchitecture)
    - 12.1 [Qu'est-ce qu'un ADR ?](#121-quest-ce-quun-adr)
    - 12.2 [Les 16 ADRs de Sanctum](#122-les-16-adrs-de-sanctum)
    - 12.3 [Les ADRs les plus importants](#123-les-adrs-les-plus-importants)
13. [Intégration dans le repo](#13-intégration-dans-le-repo)
14. [Résumé du Sprint 7](#14-résumé-du-sprint-7)

---

## 1. Vue d'ensemble

Le Sprint 7 ne produit aucun code Rust. Il produit tout ce qui **entoure** le code : la documentation, les scripts, la CI, et les décisions d'architecture formalisées. C'est le sprint qui transforme un projet de développeur en un projet open-source présentable.

Avant ce sprint, quelqu'un qui clone le repo voit 5 crates Rust sans contexte. Après ce sprint, il voit un README qui explique le projet, un SECURITY.md qui documente les garanties, des ADRs qui expliquent les choix, une CI qui valide chaque push, et des scripts qui l'aident à démarrer.

---

## 2. Pourquoi un sprint Ops ?

Un projet de sécurité sans documentation est un projet dangereux. Si personne ne comprend le modèle de menaces, personne ne peut vérifier que les garanties sont respectées. L'auditabilité — valeur fondamentale de Sanctum — commence par la documentation.

Concrètement, ce sprint répond à 5 questions :

| Question | Fichier qui répond |
|----------|-------------------|
| "C'est quoi ce projet ?" | README.md |
| "Quelles sont les garanties de sécurité ?" | SECURITY.md |
| "Pourquoi ce choix technique ?" | docs/adrs/*.md |
| "Comment j'installe et je diagnostique ?" | docs/runbook.md, scripts/ |
| "Comment je contribue sans casser ?" | .github/workflows/ci.yml |

---

## 3. Structure des fichiers

```
Sanctum-Project/
├── README.md                            ← Page d'accueil
├── SECURITY.md                          ← Contrat de sécurité
├── NFO.md                               ← Manifeste release
├── migrations/
│   └── 001_initial.sql                  ← Schéma SQLite v1
├── scripts/
│   ├── setup-tor.sh                     ← Installation Tor
│   └── check-no-disk-writes.sh          ← Vérification AT-07
├── .github/
│   └── workflows/
│       └── ci.yml                       ← Pipeline CI
├── docs/
│   ├── architecture.md                  ← (existant, Sprint 0)
│   ├── runbook.md                       ← Guide opérationnel
│   └── adrs/
│       ├── ADR-001-tor-only.md
│       ├── ADR-002-clean-hex.md
│       ├── ADR-003-host-blind-relay.md
│       ├── ADR-004-pgp-identity-only.md
│       ├── ADR-005-noise-nk-ratchet.md
│       ├── ADR-006-anti-replay.md
│       ├── ADR-007-sqlite-app-encryption.md
│       ├── ADR-008-memory-protection.md
│       ├── ADR-009-protobuf.md
│       ├── ADR-010-message-padding.md
│       ├── ADR-011-tor-external.md
│       ├── ADR-012-toml-config.md
│       ├── ADR-013-roles.md
│       ├── ADR-014-static-binary.md
│       ├── ADR-015-workspace.md
│       └── ADR-016-interactive-session.md
└── crates/                              ← (existant, Sprints 1-6)
```

24 fichiers au total. Aucun n'est du code Rust.

---

## 4. README.md — La porte d'entrée

Le README est la première chose qu'un visiteur voit sur GitHub. Il doit répondre en 30 secondes à "qu'est-ce que c'est et pourquoi je devrais m'y intéresser".

**Structure du README** :

```
1. Titre + tagline          → "Encrypted group chat over Tor hidden services"
2. Features (6 puces)       → E2E, Tor-only, deux modes, PGP, forward secrecy, interactive
3. Quick Start (6 lignes)   → setup-tor → init → identity → host → join → chat
4. Architecture (schéma)    → Les 5 crates en ASCII
5. Commands (table)         → Toutes les commandes avec descriptions
6. Building                 → cargo build, release, musl
7. Tests                    → 199 tests, commande pour lancer
8. License                  → AGPL-3.0 avec explication
```

**Choix importants** :

- Le Quick Start montre le workflow complet en 6 commandes. Quelqu'un peut copier-coller et avoir un chat fonctionnel.
- L'architecture est un schéma ASCII de 5 lignes, pas un paragraphe de texte. Visuel > verbal.
- La licence AGPL est expliquée en termes humains : "vous pouvez tout faire, mais si vous modifiez et distribuez, publiez vos modifications".

---

## 5. SECURITY.md — Le contrat de sécurité

Pour un outil de sécurité, le SECURITY.md est aussi important que le code. Il documente trois choses : comment rapporter une vulnérabilité, ce que l'outil protège, et ce qu'il ne protège pas.

### 5.1 Ce que Sanctum protège

| Menace | Mitigation |
|--------|------------|
| Host lit les messages | E2E — le host ne voit que des ciphertexts |
| Observateur réseau | Tout le trafic passe par Tor |
| Analyse de trafic | Padding 256 octets |
| Compromission de clé (passé) | Forward secrecy via Double Ratchet |
| Replay | Compteur monotone + fenêtre bitmap |
| Forensique disque (éphémère) | Zéro écriture disque |
| Forensique disque (persistant) | AES-256-GCM par champ |
| Forensique mémoire | `zeroize` + `mlock` |
| Brute-force auth | Rate limiting (3 tentatives) |
| Downgrade protocole | Version stricte dans le handshake |

### 5.2 Ce que Sanctum ne protège PAS

C'est la section la plus importante du SECURITY.md. Un outil qui prétend tout protéger est un outil dangereux car il crée une fausse confiance.

| Limitation | Pourquoi |
|-----------|---------|
| Machine compromise | Si votre OS est rooté, rien ne peut vous sauver |
| Adversaire global (état) | La corrélation de trafic Tor est hors scope |
| Membership du groupe | Le host connaît les fingerprints et alias des membres |
| Timing des messages | Le host voit quand les messages passent |
| Disponibilité | Le host est un point unique de défaillance |
| Vérification des clés | La vérification PGP est out-of-band (responsabilité utilisateur) |

Documenter ces limitations est un acte de transparence. Un utilisateur qui connaît les limites peut prendre des décisions éclairées. Un utilisateur qui ne les connaît pas est en danger.

### 5.3 Les primitives crypto

La table des primitives liste chaque usage avec sa primitive et sa bibliothèque :

```
Transport       → Noise NK (snow)
Key agreement   → X3DH (x25519-dalek)
Messages        → Double Ratchet (aes-gcm)
Identity        → Ed25519 (ed25519-dalek)
Key derivation  → HKDF-SHA256 (hkdf)
Password hash   → Argon2id m=256M t=4 p=2 (argon2)
Storage         → AES-256-GCM 12B nonce (aes-gcm)
Padding         → Block 256B (custom)
```

Chaque choix est justifié par un ADR correspondant. Un auditeur peut tracer chaque primitive jusqu'à sa justification.

### 5.4 Les invariants de sécurité

5 invariants qui doivent être vrais à tout moment :

1. **Pas de `unsafe`** — vérifié par `#![forbid(unsafe_code)]` dans chaque crate et par le job CI `no-unsafe`
2. **Tous les secrets `zeroize`d** — les structs contenant des clés implémentent `Drop` avec `zeroize`
3. **Pas de secrets dans les logs** — les fingerprints sont tronqués, les clés ne sont jamais loggées
4. **Nonces uniques** — basés sur des compteurs, jamais réutilisés
5. **Permissions strictes** — `~/.sanctum/` est 0700, les fichiers sont 0600

---

## 6. NFO.md — Le manifeste de release

Le NFO est une tradition du monde de la release logicielle. C'est un fichier texte qui accompagne un binaire et résume ce qu'il contient. Le NFO de Sanctum inclut :

- Le banner ASCII (identité visuelle)
- Le nom de la release : v0.1.0 — "Premier Contact"
- Un résumé non-technique en 3 phrases
- Les specs techniques (table)
- Les statistiques par crate (lignes, tests, rôle)
- Les requirements runtime

Le NFO est aussi ce que produit `sanctum export-manifest` en JSON. Le fichier Markdown est la version humaine.

---

## 7. migrations/001_initial.sql — Le schéma SQLite

### 7.1 Les 5 tables

```sql
rooms         → Rooms sérialisées et chiffrées
members       → Membres par room (fingerprint hashé)
messages      → Backlog (ciphertexts E2E opaques)
keys          → Clés de session (chiffrées au repos)
metadata      → Métadonnées (schema_version, salt, etc.)
```

Chaque table a un rôle précis dans l'architecture :

**`rooms`** : stocke les `Room` sérialisées. Le champ `data` est un blob chiffré AES-256-GCM contenant la configuration, le nom, et les paramètres de la room. Le `id` est le RoomId en clair (nécessaire pour les requêtes).

**`members`** : ne stocke **pas** les fingerprints en clair. Le champ `fingerprint_hash` contient `SHA-256(fingerprint)`. C'est une mesure de privacy : si la base de données est volée, les fingerprints PGP réels ne sont pas exposés. Les données du membre (rôle, alias, clé publique) sont dans le blob `data` chiffré.

**`messages`** : le backlog pour le mode persistant. Le champ `data` contient le ciphertext E2E tel que l'expéditeur l'a chiffré. Le host ne peut pas le déchiffrer — il le stocke opaque et le retransmet au destinataire quand il se reconnecte. Le `recipient_hash` est `SHA-256(fingerprint_destinataire)` pour router sans exposer l'identité.

**`keys`** : stocke les PreKey Bundles, les clés de session ratchet, etc. Le champ `data` est chiffré avec la KeyStoreKey dérivée du Master Key. Le `expires_at` permet la rotation automatique.

**`metadata`** : paires clé-valeur pour le versionnement du schéma et le sel Argon2id.

### 7.2 Les index

```sql
idx_messages_backlog  ON messages(room_id, recipient_hash, sequence_number)
idx_messages_expiry   ON messages(stored_at)
```

Le premier index accélère `fetch_backlog` : "donne-moi les messages de cette room pour ce destinataire après ce numéro de séquence". C'est la requête la plus fréquente (chaque reconnexion d'un client).

Le second index accélère le GC : "supprime les messages plus vieux que N secondes". Exécuté toutes les 15 minutes.

### 7.3 Pourquoi des migrations versionnées

Le fichier s'appelle `001_initial.sql`, pas juste `schema.sql`. C'est le pattern des migrations séquentielles :

```
001_initial.sql         → v0.1 : schéma initial
002_add_read_status.sql → v0.2 : ajout d'un champ (hypothétique)
003_add_reactions.sql   → v0.3 : nouvelle table (hypothétique)
```

Au démarrage, `SqliteStorageAdapter` lit `metadata.schema_version` et applique séquentiellement les migrations manquantes. Le fichier `001_initial.sql` utilise `CREATE TABLE IF NOT EXISTS` et `INSERT OR IGNORE` pour être idempotent — on peut le relancer sans erreur.

---

## 8. scripts/setup-tor.sh — L'installation Tor

### 8.1 Ce que le script fait

```
1. Détecter le package manager (apt, dnf, pacman, brew)
2. Installer Tor
3. Démarrer le service
4. Activer le control port (9051) avec cookie auth
5. Vérifier que l'utilisateur peut lire le cookie
6. Vérifier la connectivité SOCKS5
7. Afficher un résumé
```

### 8.2 Détection multi-distro

Le script utilise `command -v` pour détecter le package manager :

```bash
if command -v apt-get &>/dev/null; then       # Debian/Ubuntu
elif command -v dnf &>/dev/null; then          # Fedora/RHEL
elif command -v pacman &>/dev/null; then       # Arch
elif command -v brew &>/dev/null; then         # macOS
else
    echo "install Tor manually"
fi
```

C'est plus fiable que de détecter la distribution via `/etc/os-release` car certaines distributions dérivées n'ont pas les mêmes fichiers mais ont le même package manager.

### 8.3 Vérification de la connectivité

Le script vérifie deux choses :

**Le cookie auth** : Tor utilise un fichier cookie (`/var/lib/tor/control_auth_cookie`) pour l'authentification au control port. L'utilisateur doit pouvoir le lire. Sur Debian/Ubuntu, ça nécessite d'être dans le groupe `debian-tor`.

**Le proxy SOCKS5** : un `curl --socks5` vers `check.torproject.org` vérifie que le trafic sort bien par Tor. Si la réponse contient `"IsTor":true`, tout fonctionne.

---

## 9. scripts/check-no-disk-writes.sh — La vérification éphémère

### 9.1 Le principe de strace

`strace` est un outil Linux qui intercepte tous les appels système d'un processus. En filtrant sur les appels de fichiers (`open`, `openat`, `creat`, `write`, `rename`, `unlink`), on peut vérifier qu'aucune écriture n'a lieu dans le répertoire de données.

```bash
strace -f -e trace=open,openat,creat,write,rename,unlink \
    -o "$TRACE_FILE" \
    "$SANCTUM_BIN" --no-banner status
```

Le flag `-f` suit les threads et processus enfants. Le flag `-o` écrit la trace dans un fichier pour analyse.

### 9.2 Ce que le script vérifie

Deux vérifications :

1. **Zéro opération sur le data dir** : `grep "$DATA_DIR" "$TRACE_FILE"` ne doit retourner aucune ligne. Toute mention de `~/.sanctum/data/` est un FAIL.

2. **Pas de fichiers temporaires** : vérifier que ni `crossterm` ni aucune autre dépendance ne crée de fichiers dans `/tmp/sanctum` ou `.sanctum/`.

### 9.3 Lien avec AT-07

Ce script est l'implémentation de l'acceptance test AT-07 :

```
AT-07: Zéro Écriture Disque en Session Interactive (Éphémère)
  GIVEN Sanctum en mode éphémère
  WHEN  session interactive complète
  THEN  strace montre AUCUN open(..., O_WRONLY|O_CREAT) sur data dir
  AND   aucun fichier temporaire créé par crossterm
```

En CI, ce script tourne avec le binaire release après chaque build. Si une régression introduit une écriture disque en mode éphémère, le script échoue et bloque le merge.

---

## 10. .github/workflows/ci.yml — L'intégration continue

### 10.1 Les 5 jobs

```
Push/PR sur main ou dev
         │
         ▼
    ┌─────────┐
    │  check   │ → cargo check + clippy
    └────┬────┘
         │ (si OK)
         ▼
    ┌─────────┐
    │  test    │ → cargo test --workspace
    └─────────┘
    ┌─────────┐
    │  fmt     │ → cargo fmt --check
    └─────────┘
    ┌─────────┐
    │  audit   │ → cargo deny check advisories
    └─────────┘
    ┌─────────┐
    │no-unsafe │ → grep -rn "unsafe" crates/
    └─────────┘
```

Les jobs `fmt`, `audit`, et `no-unsafe` tournent en parallèle. Le job `test` attend que `check` passe (pas la peine de tester si ça ne compile pas).

### 10.2 Pourquoi chaque job

**check + clippy** : vérifie que le code compile sans warnings. `RUSTFLAGS="-D warnings"` transforme les warnings en erreurs. Clippy attrape les anti-patterns Rust (unwrap inutiles, allocations évitables, etc.).

**test** : lance les 199 tests (unitaires + intégration). Si un test échoue, le PR est bloqué.

**fmt** : vérifie que le code est formaté selon `rustfmt`. Pas de débat de style — c'est automatique. `--check` ne modifie pas le code, il échoue si le formatage ne correspond pas.

**audit** : `cargo deny` vérifie les dépendances contre la base de données RustSec. Si une dépendance a une vulnérabilité connue, le build échoue. C'est critique pour un outil de sécurité — une dépendance vulnérable compromet tout.

**no-unsafe** : grep le code source pour tout usage de `unsafe`. Chaque crate a `#![forbid(unsafe_code)]` mais ce job est une vérification supplémentaire au niveau CI. Si quelqu'un ajoute un `#![allow(unsafe_code)]` puis du `unsafe`, le grep le détecte.

---

## 11. docs/runbook.md — Le guide opérationnel

Le runbook est le guide "comment faire" pour les opérations courantes. Il couvre :

**Installation** (4 étapes) :
1. Installer Tor (via script ou manuellement)
2. Builder Sanctum (debug ou release musl)
3. Initialiser un profil (`sanctum init`)
4. Importer une clé PGP

**Hébergement** :
- Room éphémère : `sanctum host create --mode ephemeral --chat`
- Room persistante : avec backlog, max messages, max age
- Invitation : `sanctum room invite` + transmission out-of-band

**Diagnostics** : une table de 7 symptômes courants avec leurs causes et solutions :

| Symptôme | Cause | Solution |
|----------|-------|---------|
| "Tor unavailable" | Daemon pas lancé | `systemctl start tor` |
| "cookie auth failed" | Permissions | Ajouter l'user au groupe debian-tor |
| "connection refused :9738" | Firewall | Ouvrir localhost:9738 |
| "nonce already used" | Replay ou clock skew | Vérifier `timedatectl` |
| "fingerprint not authorized" | Pas invité | Vérifier le token |
| "room full" | max_members | Augmenter la limite |
| Terminal cassé | Raw mode | Taper `reset` |

**Maintenance** : purge manuelle du backlog SQL, réinitialisation de profil, mise à jour.

Le runbook est le document qu'un opérateur consulte à 3h du matin quand quelque chose ne marche pas. Il doit être concis, actionnable, et couvrir les cas courants.

---

## 12. docs/adrs/ — Les décisions d'architecture

### 12.1 Qu'est-ce qu'un ADR ?

Un ADR (Architecture Decision Record) est un document court qui capture une décision technique importante : le contexte, les options considérées, la décision prise, et ses conséquences. Le format est standardisé :

```markdown
# ADR-NNN: Titre

**Status**: Accepted / Superseded / Deprecated
**Date**: YYYY-MM

## Context
Pourquoi cette décision est nécessaire.

## Decision
Ce qui a été décidé.

## Options considered
Les alternatives et pourquoi elles n'ont pas été retenues.

## Consequences
Ce que cette décision implique (positif et négatif).
```

L'intérêt des ADRs est triple :

1. **Pour les contributeurs** : comprendre pourquoi un choix a été fait, sans demander à l'auteur original.
2. **Pour les auditeurs** : vérifier que chaque choix de sécurité est délibéré et justifié.
3. **Pour le futur** : quand on se demande "pourquoi on a fait ça ?", l'ADR répond.

### 12.2 Les 16 ADRs de Sanctum

| ADR | Titre | Résumé de la décision |
|-----|-------|----------------------|
| 001 | Transport Tor Only | Tor HS v3 exclusivement, aucun fallback clearnet |
| 002 | Clean / Hexagonal | Architecture hexagonale avec inversion de dépendances via traits |
| 003 | Host Blind Relay | Le host ne peut pas lire les messages (E2E) |
| 004 | PGP Identity Only | PGP pour auth uniquement, pas pour chiffrement |
| 005 | Noise NK + Ratchet | Noise NK transport + X3DH + Double Ratchet E2E |
| 006 | Anti-Replay | Compteur monotone + fenêtre bitmap 64 |
| 007 | SQLite App Encryption | SQLite + AES-256-GCM applicatif par champ |
| 008 | Memory Protection | mlock + zeroize + désactivation core dumps |
| 009 | Protobuf | prost pour la sérialisation wire |
| 010 | Message Padding | Blocs de 256 octets |
| 011 | Tor External | Tor daemon externe via Control Port |
| 012 | TOML Config | TOML pour la configuration |
| 013 | Roles | Owner > Admin > Member hiérarchique |
| 014 | Static Binary | Binaire musl statique, zero deps runtime |
| 015 | Workspace | 5 crates dans un workspace Cargo |
| 016 | Interactive Session | ChatSession comme UX principale, pas one-shot |

### 12.3 Les ADRs les plus importants

**ADR-001 (Tor Only)** est la décision fondatrice. En refusant tout fallback clearnet, Sanctum rend l'anonymat obligatoire. Un fallback serait utilisé "juste une fois" et compromettrait tout le modèle. C'est une décision d'UX autant que de sécurité : si l'anonymat est opt-in, personne ne l'active.

**ADR-003 (Host Blind Relay)** définit le modèle de confiance. Le host est un relais, pas un serveur de confiance. Il route des ciphertexts opaques. Ça signifie pas de modération de contenu possible côté host — c'est un compromis assumé. Cependant, le host connaît les métadonnées (qui est dans la room, quand les messages passent) — c'est documenté dans le SECURITY.md comme limitation explicite.

**ADR-005 (Noise NK + Double Ratchet)** est le cœur crypto. Noise NK (pas XX) parce que le client connaît la clé publique du host à l'avance (via le token d'invitation). Le Double Ratchet pairwise (pas MLS) parce que pour des groupes ≤10, la complexité N*(N-1)/2 est acceptable et l'implémentation est plus simple à auditer.

**ADR-016 (Interactive Session)** est la décision UX la plus récente. Elle a émergé pendant le développement quand il est devenu clair que des commandes one-shot ne correspondent pas à l'usage d'un outil de chat. L'introduction du `UiPort` trait permet de migrer vers ratatui en v0.2 sans toucher la logique métier.

---

## 13. Intégration dans le repo

Tous les fichiers vont à la **racine** du repo, pas dans un crate :

```bash
# Depuis la racine du workspace Sanctum-Project/
# Copier les fichiers téléchargés :

cp README.md .
cp SECURITY.md .
cp NFO.md .
mkdir -p migrations scripts .github/workflows docs/adrs

cp 001_initial.sql migrations/
cp setup-tor.sh scripts/
cp check-no-disk-writes.sh scripts/
cp ci.yml .github/workflows/
cp runbook.md docs/
cp ADR-*.md docs/adrs/

# Rendre les scripts exécutables
chmod +x scripts/setup-tor.sh
chmod +x scripts/check-no-disk-writes.sh
```

Aucune modification de Cargo.toml ou de code Rust n'est nécessaire.

---

## 14. Résumé du Sprint 7

| Catégorie | Fichiers | Rôle |
|-----------|----------|------|
| **Documentation** | README.md, SECURITY.md, NFO.md | Présentation, sécurité, release |
| **Base de données** | migrations/001_initial.sql | Schéma SQLite (5 tables, 2 index) |
| **Scripts** | setup-tor.sh, check-no-disk-writes.sh | Installation Tor, vérification éphémère |
| **CI/CD** | .github/workflows/ci.yml | 5 jobs (check, test, fmt, audit, no-unsafe) |
| **Opérations** | docs/runbook.md | Guide diagnostique et maintenance |
| **Architecture** | docs/adrs/ADR-001 à ADR-016 | 16 décisions documentées |
| **Total** | **24 fichiers** | |

### Bilan global du projet après 7 sprints

| Sprint | Livrable | Tests |
|--------|----------|-------|
| 1 — Domain | sanctum-domain (7 fichiers) | 23 |
| 2 — Crypto | sanctum-crypto (7 fichiers) | 37 |
| 3 — App | sanctum-app (8 fichiers) | 46 |
| 4 — Infra | sanctum-infra (9 fichiers) | 45 |
| 5 — CLI | sanctum-cli (15 fichiers) | 5 |
| 6 — Intégration | tests/ (7 fichiers) | 43 |
| 7 — Ops | docs, scripts, CI (24 fichiers) | — |
| **Total** | **77 fichiers** | **199 tests** |
