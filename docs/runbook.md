# Sanctum — Runbook (v0.1.1)

Guide opérationnel : installer, utiliser et diagnostiquer Sanctum.
**Ne lancez jamais `sanctum` avec `sudo`.**

## 1. Installation

### Tor

```bash
./scripts/setup-tor.sh          # installe Tor, configure le control port
```

Ou à la main (Debian/Ubuntu) :

```bash
sudo apt install tor
# /etc/tor/torrc doit contenir :
#   ControlPort 9051
#   CookieAuthentication 1
#   CookieAuthFileGroupReadable 1
sudo systemctl restart tor
sudo usermod -aG debian-tor "$USER"   # puis se déconnecter / reconnecter
```

Sanctum s'authentifie au control port en **SAFECOOKIE** et refuse un control port
sans authentification.

### Sanctum

```bash
sudo apt install protobuf-compiler    # requis pour compiler
cargo build --release                 # Rust ≥ 1.89
install -m 0755 target/release/sanctum ~/.local/bin/
```

## 2. Identité

```bash
sanctum init --alias alice
```

Crée `~/.sanctum/` (0700) avec une clé Ed25519 **chiffrée** par une passphrase
(Argon2id + ChaCha20-Poly1305, 8 caractères minimum, demandée deux fois).
`host`, `join` et `room invite` redemandent la passphrase. Pour un script, la
variable `SANCTUM_PASSPHRASE` évite la saisie ; elle est visible des autres
processus du même utilisateur : à réserver aux tests.

```bash
sanctum identity show       # affiche le fingerprint (sans passphrase)
sanctum status              # état du profil
```

Clé créée par une version antérieure (non chiffrée) :

```bash
sanctum identity protect    # la chiffre avec une passphrase
```

## 3. Héberger une room

```bash
sanctum host create ops-room --chat
```

L'hôte crée un service onion éphémère (adresse nouvelle à chaque lancement),
affiche votre fingerprint et ouvre le chat en tant qu'owner. Le mode persistant
n'existe pas encore (`--mode persistent` est refusé).

### Inviter un membre

1. Le membre vous transmet son fingerprint (`sanctum identity show`) par un canal sûr.
2. Dans le chat owner : `/invite <fingerprint> [heures]` (24 h par défaut, 168 max).
3. Transmettez le jeton affiché hors bande. Il est signé, nominatif, valable pour
   cette session d'hôte uniquement, et **à usage unique**.

Hors du chat (autre terminal, même identité owner) :

```bash
sanctum room invite <fingerprint> --room-onion <onion> --room-port <port> \
    --room-id <room_id> --host-key <host_key>
```

(la commande exacte est affichée au lancement de l'hôte).

### Retirer un membre

Dans le chat owner : `/kick <alias|fingerprint>`. Le membre est déconnecté
(« vous avez été retiré de la room par son owner »), les autres voient
« a quitté la room » et suppriment sa session. Toutes les invitations émises
pour lui **avant** le retrait deviennent invalides, y compris un jeton encore
en attente. Pour le réadmettre, émettre un nouveau jeton avec `/invite`
(au moins une seconde après le retrait). Le retrait vaut pour la session
d'hôte en cours : en mode éphémère, un redémarrage repart d'une room vide.

## 4. Rejoindre et discuter

```bash
sanctum join <jeton>
```

| Commande | Effet |
|----------|-------|
| `/who` | membres connectés et état du chiffrement (🔒 / ⏳) |
| `/verify <alias>` | safety number à comparer de vive voix |
| `/invite <fp> [h]` | (owner) émettre une invitation |
| `/kick <alias\|fp>` | (owner) retirer un membre et révoquer ses invitations |
| `/help`, `/exit` | aide, quitter |

Un message n'est envoyé qu'aux membres avec qui le chiffrement est établi ; s'il
n'y en a aucun, il n'est pas envoyé.

## 5. Test local sans Tor

```bash
sanctum host create test --local --chat          # terminal 1
sanctum join <jeton>                             # terminal 2 (autre HOME/utilisateur)
```

Pour simuler plusieurs utilisateurs sur une machine : `HOME=/tmp/u2 sanctum init`,
puis `HOME=/tmp/u2 sanctum join …`.

## 6. Test de bout en bout sur le vrai réseau Tor

### Sur une machine (automatisé)

```bash
cargo build --release
./scripts/tor-smoke-test.sh target/release/sanctum
```

Le script crée trois identités jetables (owner, alice, bob), héberge une room en
service onion, émet deux invitations par `/invite`, fait rejoindre les membres
**à travers Tor** (SOCKS 9050, avec 3 tentatives le temps que le descripteur
onion se propage), attend les sessions chiffrées puis vérifie que chacun déchiffre
les messages des deux autres. Il affiche la durée de chaque étape et conserve les
journaux en cas d'échec (`--keep` pour les garder toujours, `--local` pour tester
le script sans Tor). Il refuse de tourner en root.

### Sur deux machines (manuel)

| # | Machine A (hôte) | Machine B (membre) | Attendu |
|---|------------------|--------------------|---------|
| 1 | `sanctum init --alias a` | `sanctum init --alias b` | deux fingerprints |
| 2 | `sanctum host create test --chat` | | `hidden service: <x>.onion:9738`, pas d'erreur SAFECOOKIE |
| 3 | | envoyer son fingerprint à A (canal sûr) | |
| 4 | `/invite <fp de b>` | | un jeton |
| 5 | | `sanctum join <jeton>` | `authenticated` en moins de 2 min |
| 6 | `/who` | `/who` | l'autre membre en 🔒 |
| 7 | `/verify b` | `/verify a` | **le même safety number des deux côtés** |
| 8 | échanger des messages | | reçus des deux côtés |
| 9 | `/exit`, relancer l'hôte, réutiliser l'ancien jeton | | refusé : `another host session` |

Notez pour chaque étape la durée et toute erreur : c'est ce qui permet d'ajuster
les timeouts (30 s pour le handshake côté hôte, 90 s pour `join`).

## 7. Diagnostic

| Symptôme | Cause probable | Solution |
|----------|----------------|----------|
| `cannot read the Tor cookie` | utilisateur hors du groupe Tor | `sudo usermod -aG debian-tor $USER`, se reconnecter |
| `does not offer SAFECOOKIE` / `unauthenticated` | torrc sans `CookieAuthentication 1` | corriger torrc, redémarrer Tor |
| `could not prove it knows the cookie` | faux control port sur 9051 | vérifier quel processus écoute (`ss -ltnp`) |
| `wrong passphrase or corrupted identity file` | passphrase erronée | ressaisir ; sinon restaurer `~/.sanctum/keys` |
| `stored unencrypted` | clé d'une ancienne version | `sanctum identity protect` |
| `not a member of this room and no invitation` | pas encore invité | demander un jeton à l'owner |
| `invitation already used` / `expired` | jeton consommé ou périmé | demander un nouveau jeton |
| `invitation revoked by the owner` | membre retiré par `/kick` après l'émission du jeton | demander un nouveau jeton à l'owner |
| `vous avez été retiré de la room par son owner` | `/kick` de l'owner | voir avec l'owner |
| `invitation is for another host session` | l'hôte a redémarré (nouvelle clé Noise) | nouveau jeton |
| `refusing to connect … not a .onion address` | jeton pointant vers une IP publique | refusé par conception (pas de clearnet) |
| `⏳` qui ne passe pas à `🔒` | pair parti ou échange de clés rejeté | `/who`, faire reconnecter le pair |
| Déconnexion après 2 minutes | client bloqué (pas de PING) | relancer `sanctum join` |

Journaux : `sanctum --log-level debug …` (stderr). Ils ne contiennent ni
fingerprint, ni alias, ni adresse, ni contenu.

## 8. Hygiène de la machine hôte

- Désactiver le swap et les core dumps (`swapoff -a`, `ulimit -c 0`) : `mlock`
  n'est pas encore utilisé.
- Système à jour, Tor à jour, aucun autre service exposé.
- Vérifier régulièrement que le mode éphémère n'écrit rien :
  `./scripts/check-no-disk-writes.sh target/release/sanctum`.
