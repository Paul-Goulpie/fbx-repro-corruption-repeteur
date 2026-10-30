# [FS#41234](https://dev.freebox.fr/bugs/task/41234) – Corruption de données TCP via le répéteur Wi-Fi Freebox (fbxwmr-r3, fw 2.9.3)

Complément au ticket : architecture du réseau de test (anonymisée), chemins testés,
résultats et script permettant de rejouer le défaut.

## 1. Architecture réseau

```
                              Internet (FTTH)
                                     │
                 ┌───────────────────┴───────────────────┐
                 │            Freebox Server             │
                 │   Freebox v8 (fbxgw8-r1), fw 4.13.1   │
                 │   mode routeur – LAN 192.168.x.0/24   │
                 │   Wi-Fi 7 5 GHz 160 MHz, MLO off      │
                 └──┬──────────────┬─────────────────┬───┘
                    │              ┆                 ┆
         Ethernet 1G│     backhaul ┆ Wi-Fi 5 GHz     ┆ backhaul Wi-Fi 5 GHz
                    │     (ou Ethernet 100M, test 3) ┆
          ┌─────────┴──────┐ ┌─────┴──────────┐ ┌────┴───────────┐
          │ Serveur Linux  │ │  Répéteur A    │ │  Répéteur B    │
          │ (destination)  │ │  fbxwmr-r3     │ │  fbxwmr-r3     │
          │ NIC RTL8168h   │ │  fw 2.9.3      │ │  fw 2.9.3      │
          │ socat + cmp    │ │  bh -55 dBm    │ │  bh -68 dBm    │
          └────────────────┘ └─────┬──────────┘ └────┬───────────┘
                                   ┆ fronthaul        ┆ fronthaul
                                   ┆ Wi-Fi 5 GHz      ┆ Wi-Fi 5 GHz
                                   ┆ 160 MHz          ┆ 160 MHz
                                   ┆ -58 dBm          ┆ -80 dBm
                            ┌──────┴──────────────────┴──────┐
                            │        PC portable Linux       │
                            │   (source : générateur, socat) │
                            │   Intel Wi-Fi 7 (iwlwifi) ou   │
                            │   dongle USB Realtek (rtw89)   │
                            └────────────────────────────────┘

   │  lien Ethernet          ┆  lien Wi-Fi
```

Le PC portable est associé, selon le test, directement à la Freebox Server, au
répéteur A ou au répéteur B (BSSID forcé). Le serveur est toujours relié en Ethernet
à la Freebox Server. Le flux de test va du PC portable vers le serveur.

## 2. Chemins testés

| # | Chemin du flux | Backhaul répéteur | Résultat |
|---|----------------|-------------------|----------|
| 1 | PC portable ┆ Freebox Server │ serveur | – | **0 erreur** (> 9 Gio) |
| 2 | PC portable ┆ répéteur A ┆ Freebox Server │ serveur | Wi-Fi 5 GHz | **corruption** (1 transfert de 2 Gio sur 2 à 4) |
| 3 | PC portable ┆ répéteur A │ Freebox Server │ serveur | Ethernet (100 Mbit/s) | **0 erreur** (8 × 2 Gio, 16 Gio) |
| 4 | PC portable ┆ répéteur B ┆ Freebox Server │ serveur | Wi-Fi 5 GHz | **corruption** dès le 1er transfert de 2 Gio |

Réglages Freebox Server essayés sur le chemin 2, sans supprimer le défaut : MLO
activé/désactivé, `vht_max_mpdu_len` 11454/défaut, largeur 160/80 MHz, déplacement
du répéteur (backhaul -78 → -55 dBm), redémarrage de la box et du répéteur.

Mis hors de cause : le client (deux cartes Wi-Fi différentes, offload de checksum TX
désactivé), le serveur (offload RX et GRO désactivés, `TcpInCsumErrors` = 0), SSH
(reproduit en TCP brut), IPv4/IPv6 (les deux affectés).

## 3. Conclusion

- Le défaut apparaît **uniquement quand le trafic traverse le backhaul Wi-Fi d'un
  répéteur**, et il touche **les deux répéteurs** : il ne s'agit pas d'un défaut
  matériel d'un exemplaire, mais vraisemblablement du firmware 2.9.3.
- Avec un backhaul Ethernet, le même répéteur, avec le même fronthaul, ne corrompt plus rien.
- Les données altérées arrivent avec un **checksum TCP valide**. Seuls les protocoles
  qui vérifient eux-mêmes l'intégrité (SSH, TLS) détectent le problème. Les transferts
  non chiffrés (SMB, NFS, HTTP, FTP) sont corrompus silencieusement.

## 4. Signature de la corruption

À chaque fois, un bloc contigu de 64 octets (parfois 128) du flux est remplacé.

Répéteur A : fragment d'en-tête TCP (`01 01 08 0a` = options NOP, NOP, Timestamp),
plages de zéros, puis données du même flux émises environ 8,5 Mo plus tôt.

Répéteur B : en-tête IPv6 + TCP **complet d'un autre flux**, inséré dans la charge utile :

```
00000000                              4 octets à zéro
6005c9ea 00200640                     IPv6, payload 32, next header TCP, hop limit 64
fd0fbabe b119b00b 00000000 00000001   source      fd0f:babe:b119:b00b::1
fd0fbabe b119b00b 00000000 00000004   destination fd0f:babe:b119:b00b::4
075bd560 c5e63207 f23632d9 801001eb   TCP 1883 (MQTT) -> 54624, ACK
9ba70000
```

Ce préfixe n'est pas celui du LAN. Il s'agit vraisemblablement du réseau interne de
gestion box ↔ répéteurs : un paquet de ce flux de contrôle se retrouve dans une
connexion utilisateur. Cela évoque une réutilisation de tampon dans le chemin
d'agrégation ou de resegmentation du backhaul, avec un impact en sécurité (fuite
de données entre flux).

## 5. Rejouer le défaut

Script joint : [repro_corruption_repeteur.sh](repro_corruption_repeteur.sh).

Il génère un flux pseudo-aléatoire déterministe (ChaCha20) sur le PC portable,
l'envoie en TCP brut (socat, sans chiffrement) vers le serveur, qui régénère la même
référence et compare les deux octet par octet. En cas d'écart, il affiche les blocs
altérés et un dump hexadécimal, et conserve la copie corrompue sur le serveur.

Prérequis :

- PC portable : `bash`, `socat`, `openssl`, `ssh`, `iw` ; `nmcli` pour forcer un BSSID ;
- serveur : `socat`, `openssl`, `cmp`, `od`, `ss`, accès SSH par clé depuis le PC portable,
  et 2 × la taille d'un transfert en espace libre (4 Gio pour 2G) dans le dossier
  personnel du serveur, ou dans le dossier indiqué par `-d`.

Exemple, PC portable forcé sur le BSSID 5 GHz du répéteur, 8 transferts de 2 Gio :

```bash
./repro_corruption_repeteur.sh \
    -s user@serveur -a 192.168.x.y \
    -i wlan0 -c "<connexion NetworkManager>" -b <BSSID 5 GHz du répéteur> \
    -n 8 -z 2G -f
```

Options utiles :

| Option | Rôle |
|--------|------|
| `-s` | cible SSH du serveur filaire |
| `-a` | adresse IPv4 LAN du serveur pour le flux de test (facultatif : déduite de `-s` si c'est une adresse privée ; obligatoire si le nom SSH pointe vers l'adresse publique) |
| `-i` | interface Wi-Fi du PC portable (le flux y est lié) |
| `-b` / `-c` | BSSID à forcer et connexion NetworkManager correspondante, restaurée à la fin |
| `-n` / `-z` | nombre et taille des transferts (défaut : 8 × 2G) |
| `-d` | dossier de travail sur le serveur (défaut : `$HOME` ; éviter un `/tmp` en tmpfs) |
| `-f` | ouvre temporairement le port dans firewalld sur le serveur |

Code de sortie : `0` = aucune corruption, `1` = corruption reproduite, `2` = erreur
d'utilisation ou d'exécution (aucun résultat).

Exemple de sortie en cas de corruption :

```
[09:18:02] run 1/8: 64 bytes differ, 2147483648/2147483648 bytes received in 447s (~4 MB/s) [bssid=... signal=-78 dBm ...]
[09:18:02] CORRUPTION DETECTED - altered blocks (stream offset, length):
  offset 286336292, 64 bytes
```

Pour une contre-épreuve, relancer le script en forçant le BSSID de la Freebox Server
(chemin 1) ou avec le répéteur relié en Ethernet (chemin 3) : aucun écart attendu.
