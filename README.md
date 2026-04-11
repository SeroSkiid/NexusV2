# 🗨️ Nexus

Application de chat sécurisé en temps réel — **serveur + client** Windows (WinForms / C#/.NET).

---

## 📋 Présentation

NexusChat est un système de messagerie instantanée multi-salons avec une couche de sécurité complète (TLS 1.2, chiffrement AES-256 applicatif, échange de clé RSA-2048). Il se compose de deux applications indépendantes :

- **Nexus Server** (`ChatServerGUI`) — serveur avec interface d'administration graphique
- **Nexus Client** (`ChatClientGUI`) — client avec interface de chat moderne

---

## ✨ Fonctionnalités

### Communication
- Messagerie en temps réel dans des **salons de discussion** multiples
- Salon par défaut `général` créé automatiquement
- Historique des 100 derniers messages par salon (persistant côté serveur)
- **Messages privés (DM)** entre utilisateurs, accessibles via un onglet dédié ou la commande `/pm`
- Diffusion de messages globaux depuis l'interface serveur (broadcast admin)

### Sécurité & Chiffrement
| Couche | Mécanisme |
|---|---|
| Transport | TLS 1.2 via `SslStream` + certificat auto-signé RSA-2048 |
| Échange de clé | RSA-2048 OAEP — clé de session AES-256 négociée à chaque connexion |
| Chiffrement applicatif | AES-256 CBC avec IV aléatoire 16 octets préfixé à chaque paquet |
| Framing réseau | Payload préfixé sur 4 octets (big-endian), limité à 64 Ko par message |
| Stockage mots de passe | PBKDF2-SHA256, 100 000 itérations, sel aléatoire 32 octets par compte |
| Préférences client | Mot de passe sauvegardé chiffré via **Windows DPAPI** (`ProtectedData`) |

> Si la génération du certificat TLS échoue (PowerShell non disponible), le serveur bascule automatiquement en mode chiffrement applicatif AES-256 pur.

### Authentification & Comptes
- Inscription (`REGISTER`) et connexion (`LOGIN`)
- Noms d'utilisateur : 2–20 caractères, sans espaces
- Mots de passe : 4–64 caractères, supportant tous les caractères spéciaux (y compris `:`)
- **Verrouillage de compte** après 5 mauvais mots de passe consécutifs (5 min)
- **Ban IP temporaire** après 10 échecs d'authentification depuis la même IP (5 min)
- Limite configurable de connexions simultanées par IP (défaut : 5)
- Suppression de compte depuis le client

### Heartbeat & Reconnexion automatique (client)
| Mécanisme | Comportement |
|---|---|
| PING client | Envoyé toutes les **25 secondes** au serveur |
| Timeout PONG | Si aucun PONG reçu en **10 secondes** → connexion déclarée morte |
| Reconnexion auto | Jusqu'à **8 tentatives** avec délai exponentiel (2s → 4s → 8s … plafonné à 30s) |
| Annulation | Pas de reconnexion si kick, ban, ou déconnexion volontaire |

### Heartbeat (serveur)
- PING envoyé toutes les **30 secondes** à chaque client authentifié
- Déconnexion automatique si aucun PONG reçu en **45 secondes** (ghost connection)

---

## 🖥️ Interface client

L'interface est organisée en deux onglets principaux :

**Chat** — fenêtre principale avec :
- Zone de messages colorisée (ses messages en bleu, les autres en noir)
- Barre de saisie avec envoi par `Entrée` ou bouton `Send ›`
- Support des [commandes slash](#-commandes-client)

**DM (Messages Privés)** — onglet avec :
- Liste des conversations ouvertes dans une sidebar
- Fenêtre de conversation dédiée par contact
- Badge de notification `📩` lorsqu'un nouveau MP arrive

**Sidebar commune** :
- Liste des **salons** (double-clic pour rejoindre)
- Liste des **utilisateurs connectés** (double-clic ou clic droit → message privé)
- Bouton `↻ Refresh` pour actualiser la liste

---

## ⌨️ Commandes client

| Commande | Description |
|---|---|
| `/join <salon>` | Rejoindre ou créer un salon |
| `/pm <pseudo> <message>` | Envoyer un message privé |
| `/mkroom <nom>` | Créer un nouveau salon |
| `/users` | Rafraîchir la liste des utilisateurs |
| `/help` | Afficher l'aide |

---

## 🛠️ Interface serveur (administration)

| Onglet | Contenu |
|---|---|
| **Journal** | Logs en temps réel, broadcast, port configurable |
| **Utilisateurs** | Liste des connectés, kick, ban pseudo + IP, gestion des salons |
| **Sécurité** | Bans actifs, débannissement, synthèse des mesures actives |
| **Paramètres** | Limite connexions/IP, chemins des fichiers, compteur de trafic réseau |

---

## 🔧 Prérequis

- **Windows** (WinForms, .NET Framework 4.x ou .NET 6+ Windows)
- **PowerShell** (pour la génération automatique du certificat TLS au 1er démarrage du serveur)
- Aucune dépendance NuGet externe

---

## 🚀 Démarrage rapide

### Serveur
1. Compiler et lancer `ChatServerGUI.exe`
2. Choisir un port (défaut : **8888**) dans l'onglet Journal
3. Cliquer sur **▶ Démarrer le serveur**
4. Au premier démarrage, le certificat `nexuschat_server.pfx` est généré automatiquement via PowerShell

### Client
1. Compiler et lancer `ChatClientGUI.exe`
2. Saisir l'IP du serveur et le port
3. Entrer un nom d'utilisateur et un mot de passe
4. Cliquer sur **Connexion** — choisir entre connexion ou inscription
5. Les préférences (IP, port, utilisateur, mot de passe chiffré DPAPI) sont sauvegardées automatiquement dans `client_prefs.json`

---

## 📁 Fichiers de données

### Serveur
| Fichier | Contenu |
|---|---|
| `users.json` | Comptes (nom, hash PBKDF2, sel, compteur d'échecs, verrouillage) |
| `rooms.json` | Salons et historique des messages (100 derniers par salon) |
| `bans.json` | IPs et pseudos bannis avec table de correspondance IP ↔ pseudo |
| `nexuschat_server.pfx` | Certificat TLS auto-signé (RSA-2048 / SHA-256, valide 10 ans) |

### Client
| Fichier | Contenu |
|---|---|
| `client_prefs.json` | Dernière IP, port, utilisateur et mot de passe chiffré (DPAPI) |

> Tous les fichiers JSON sont écrits de manière **atomique** (`.tmp` → renommage + `.bak`) pour éviter toute corruption en cas de crash.

---

## 🌐 Protocole réseau

```
Client                          Serveur
  │                                │
  │── Connexion TCP ──────────────▶│
  │◀─ Clé publique RSA (XML) ──────│
  │── Clé AES-256 chiffrée RSA ───▶│  (handshake applicatif)
  │                                │
  │      [TLS 1.2 établi]          │
  │                                │
  │── AUTH:LOGIN:user:pass ────────▶│  (chiffré AES)
  │◀─ OK:LOGIN:USER ────────────────│
  │                                │
  │── MSG:<texte> ─────────────────▶│
  │◀─ MSG:<from>:<room>:<texte> ───│  (broadcast salon)
  │                                │
  │── PM:<pseudo>:<texte> ─────────▶│
  │◀─ PM:<from>:<texte> ────────────│
  │                                │
  │◀─ PING (serveur, toutes 30s) ───│
  │── PONG ────────────────────────▶│
  │                                │
  │── PING (client, toutes 25s) ───▶│
  │◀─ PONG ─────────────────────────│
```

Tous les paquets utilisent un **framing préfixé longueur sur 4 octets** (big-endian), suivi du payload `[IV 16 octets | cipher AES-256 CBC]`.

---

## 🛡️ Thread-safety

Toutes les structures partagées sont protégées par des locks dédiés :

| Lock | Structure protégée |
|---|---|
| `_usersLock` | `registeredUsers` |
| `_bansLock` | `bannedIPs`, `bannedUsernames`, `bannedUsernameToIP` |
| `_authLock` | `ipAuthFails`, `ipBanExpiry` |
| `clientsLock` | `connectedClients` |
| `roomsLock` | `rooms` |
| `_trafficLock` | Compteurs de trafic réseau |
| `lock(clientStream)` | Écriture réseau côté client |

---

## 🗺️ Structure du code

### Serveur — `ChatServerGUI/Form1.cs`
| Classe / Méthode | Rôle |
|---|---|
| `UserAccount` | Modèle de compte utilisateur |
| `ConnectedClient` | État d'une connexion active (TLS, AES, heartbeat) |
| `ChatRoom` | Salon avec historique limité à 100 messages |
| `BanEntry` / `BanType` | Entrée de ban (IP, pseudo, temporaire) |
| `HandleClientComm()` | Boucle de traitement par client (thread dédié) |
| `PerformServerHandshake()` | Échange RSA → clé de session AES |
| `SendEncrypted()` / `ReadFramedPacket()` | Chiffrement/déchiffrement AES-256 CBC |
| `EnsureTlsCertificate()` | Génération/chargement du certificat PFX via PowerShell |
| `WriteJsonAtomic()` | Écriture JSON sans corruption (tmp → rename) |
| `StartHeartbeat()` | Ping/pong serveur toutes les 30s |

### Client — `ChatClientGUI/Form1.cs`
| Classe / Méthode | Rôle |
|---|---|
| `DoConnect()` / `DoRegister()` | Connexion et inscription au serveur |
| `PerformClientHandshake()` | Réception clé RSA publique, envoi de la clé AES chiffrée |
| `ReceiveLoop()` | Thread de réception des messages serveur |
| `HandleServerMessage()` | Dispatch des messages entrants (MSG, PM, ROOMS, ERR…) |
| `HandleCommand()` | Traitement des commandes `/join`, `/pm`, `/mkroom`… |
| `SendPacket()` / `ReadPacket()` | Chiffrement/déchiffrement AES-256 CBC |
| `StartHeartbeat()` | Ping toutes les 25s + détection timeout PONG |
| `TryAutoReconnect()` | Reconnexion exponentielle jusqu'à 8 tentatives |
| `SavePrefs()` / `LoadPrefs()` | Persistance des préférences avec DPAPI |

---

