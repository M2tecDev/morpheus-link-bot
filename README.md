# URL-Filter-Bot für Matrix — v2.6.3
[![Made for Matrix](https://img.shields.io/badge/Made%20for%20Matrix-000000?logo=matrix&logoColor=white)](https://matrix.org/)

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Maubot](https://img.shields.io/badge/maubot-%3E%3D0.4.0-green)
![License](https://img.shields.io/github/license/M2tecDev/morpheus-link-bot?color=brightgreen)
![Release](https://img.shields.io/github/v/release/M2tecDev/morpheus-link-bot)
![Last Commit](https://img.shields.io/github/last-commit/M2tecDev/morpheus-link-bot)
![Issues](https://img.shields.io/github/issues/M2tecDev/morpheus-link-bot)
![Stars](https://img.shields.io/github/stars/M2tecDev/morpheus-link-bot?style=social)


Ein Maubot-Plugin, das eingehende Nachrichten in Matrix-Räumen auf URLs scannt und diese gegen konfigurierbare Blacklists und Whitelists prüft. Unbekannte Links werden automatisch zur Moderatorenüberprüfung weitergeleitet. Enthält automatischen Spam-Schutz mit optionalem Stummschalten, eine vollständig datenbankgestützte Persistenz und DSGVO-konforme Datenhaltung.

> **Neu in v2.6.3:** Wildcard-Einträge (`*.domain.com`) werden jetzt persistent in der Datenbank gespeichert und überleben Bot-Neustarts.

---

## Inhaltsverzeichnis

1. [Funktionsübersicht](#funktionsübersicht)
2. [Verfügbare Befehle](#verfügbare-befehle)
3. [Wie der Bot URLs erkennt](#wie-der-bot-urls-erkennt)
4. [Wildcard-Einträge](#wildcard-einträge)
5. [Konfigurationsoptionen](#konfigurationsoptionen)
6. [Installation mit Docker](#installation-mit-docker)
7. [Paketerstellung und Deployment](#paketerstellung-und-deployment)
8. [Anforderungen](#anforderungen)
9. [Änderungsprotokoll](#änderungsprotokoll)

---

## Funktionsübersicht

**Automatische URL-Filterung** — Der Bot überwacht alle Textnachrichten in überwachten Räumen. Enthält eine Nachricht eine URL oder Domain, prüft er diese sofort gegen Blacklist und Whitelist.

**Drei-Wege-Routing** — Jede erkannte Domain landet in einer von drei Kategorien: Whitelist (erlaubt), Blacklist (gesperrt) oder Unbekannt (zur Überprüfung). Die Spezifität bestimmt die Priorität: Exakte Treffer > Wildcard-Treffer > Apex-Treffer. Bei gleicher Spezifität hat Whitelist Vorrang vor Blacklist.

**Moderationsworkflow** — Unbekannte Domains werden automatisch an einen konfigurierten Moderationsraum weitergeleitet. Moderatoren entscheiden dort per Emoji-Reaktion (✅ / ❌) oder Textbefehl. Die Entscheidung wird sofort aktiv und in der Datenbank sowie in der jeweiligen `custom.txt` gespeichert.

**Datenbankgestützte Persistenz** — Alle Runtime-Moderationsentscheidungen (Whitelist, Blacklist, Wildcards, Ignore-Vorschauen) sowie offene Moderationsanfragen werden in Maubots nativer Datenbank gespeichert. Bot-Neustarts sind dadurch vollständig stateful — kein Datenverlust bei Neustarts.

**DSGVO / Privacy by Design** — Matrix-Nutzer-IDs werden ausschließlich als `SHA-256(secret_salt:user_id)`-Hash gespeichert, niemals im Klartext. Ein Hintergrund-Retention-Loop löscht Verstoßdaten automatisch nach 24 Stunden. Der `secret_salt` ist ein Pflichtfeld in der Konfiguration.

**Befehlsraum-Einschränkung** — Über den Konfigurationsschlüssel `command_rooms` kann festgelegt werden, in welchen Räumen der Bot auf Befehle reagiert. Der Moderationsraum und Direktnachrichten sind immer erlaubt, unabhängig von dieser Liste.

**Wildcard-Unterstützung** — Einträge wie `*.boese-seite.com` sperren alle Subdomains auf einmal. Funktioniert in Blacklist und Whitelist gleichermaßen.

**Apex-Domain-Matching** — Ist `evil.com` direkt in der Blacklist eingetragen, werden Subdomains wie `sub.evil.com` oder `api.sub.evil.com` automatisch mitgeblockt — ohne gesonderten Wildcard-Eintrag. Gilt spiegelbildlich auch für die Whitelist.

**URL-Shortener-Auflösung** — Bekannte Kurzlink-Dienste (bit.ly, t.co, tinyurl.com u.a.) werden via HEAD-Request aufgelöst. Die finale Ziel-Domain wird geprüft statt des Shortener-Hosts selbst. Ist der Shortener-Host selbst bereits gesperrt, entfällt der Netzwerkzugriff vollständig.

**Spam-Schutz & Auto-Mute** — Ein konfigurierbarer Warn-Cooldown verhindert Notification Flooding: Nachrichten werden immer sofort gelöscht, aber eine öffentliche Warnmeldung wird pro Nutzer nur einmal innerhalb des Cooldown-Intervalls gepostet. Optional können Nutzer bei Erreichen eines konfigurierbaren Verstoß-Schwellenwerts innerhalb des Beobachtungsfensters automatisch stummgeschaltet (Powerlevel -1) werden. Verstöße werden datenbankgestützt mit Sliding-Window-Logik gezählt.

**Linkvorschauen** — Für freigegebene URLs kann der Bot optional Open-Graph-Metadaten abrufen und eine kurze Vorschau (Titel + Beschreibung) im Raum posten.

**Event-ID-Deduplizierung** — Ein interner LRU-Cache (1.000 Einträge) verhindert Doppelverarbeitung bei Matrix-Sync-Replays nach Bot-Neustarts oder Netzwerkproblemen.

---

## Verfügbare Befehle

### Öffentliche Befehle (für alle Nutzer)

| Befehl | Beschreibung |
|--------|-------------|
| `!urlstatus <domain>` | Zeigt ob eine Domain whitelisted, blacklisted oder unbekannt ist — inklusive Wildcard- und Apex-Treffern, mit identischer Priorität wie der Haupt-Filter (Exakt > Wildcard > Apex). Akzeptiert auch vollständige URLs: `!urlstatus https://example.com/` wird automatisch auf `example.com` normalisiert. |
| `!stats` | Gibt die Anzahl geladener Domains sowie Wildcards und offene Überprüfungen aus. |
| `!hilfe` | Zeigt die vollständige Befehlsübersicht — **nur per Direktnachricht (DM)**. In Gruppenräumen reagiert der Bot vollständig lautlos auf diesen Befehl. |
| `!status` | Zeigt den aktuellen Bot-Status inkl. Datenbankverbindung, Uptime und Version. |

### Moderationsbefehle (erfordern Berechtigung)

Ein Nutzer gilt als Moderator, wenn sein Powerlevel im Moderationsraum mindestens `min_power_level` (Standard: 50) beträgt oder seine Nutzer-ID in `allowed_users` eingetragen ist.

| Befehl | Beschreibung |
|--------|-------------|
| `!allow <domain>` | Domain sofort whitelisten. Unterstützt Wildcards: `!allow *.vertrauenswuerdig.de` — löst automatisch alle zugehörigen offenen Überprüfungen auf. |
| `!unallow <domain>` | Domain oder Wildcard-Eintrag aus der Whitelist entfernen (nur aus `custom.txt` und DB). |
| `!block <domain>` | Domain sofort blacklisten. Unterstützt Wildcards: `!block *.boese-seite.com` |
| `!unblock <domain>` | Domain oder Wildcard-Eintrag aus der Blacklist entfernen (nur aus `custom.txt` und DB). |
| `!reloadlists` | Alle `.txt`-Dateien neu einlesen — kein Neustart nötig. Nützlich nach manuellen Änderungen. |
| `!pending` | Zeigt alle Domains, die aktuell auf eine Moderationsentscheidung warten — mit menschenlesbaren Zeitangaben (z.B. „10 Minuten", „2 Stunden"). |
| `!sendpending` | Sendet alle offenen Überprüfungsalarme erneut in den Mod-Raum. Nützlich nach einem Bot-Neustart oder wenn Alarme verloren gegangen sind. |
| `!mute <@nutzer:server> [-t Minuten]` | Nutzer manuell stummschalten (Powerlevel -1). Optionaler `-t`-Parameter setzt die Dauer in Minuten; ohne `-t` gilt `mute_duration_minutes`. Nur wenn `mute_commands_enabled: true`. |
| `!unmute <@nutzer:server>` | Stummschaltung eines Nutzers manuell aufheben. Nur wenn `mute_commands_enabled: true`. |
| `!ignore <domain>` | Domain zur Vorschau-Ignore-Liste hinzufügen — Nachrichten mit dieser Domain werden weiterhin gefiltert, aber keine Linkvorschau mehr erzeugt. |
| `!unignore <domain>` | Domain von der Vorschau-Ignore-Liste entfernen. |

### Emoji-Reaktionen im Moderationsraum

Wenn eine unbekannte Domain erkannt wird, postet der Bot eine Alarmmeldung im Moderationsraum mit zwei Reaktionsknöpfen:

- **✅** — Domain zur Whitelist hinzufügen und Originalnachricht genehmigen.
- **❌** — Domain zur Blacklist hinzufügen.

Reaktionen von Nutzern ohne ausreichende Berechtigung werden still ignoriert.

---

## Wie der Bot URLs erkennt

Der Bot verwendet vier Stufen, die nacheinander auf jede Nachricht angewendet werden:

**Stufe 0 — Matrix-ID-Bereinigung:** Matrix-Nutzer-IDs (`@nutzer:homeserver`) und Raum-IDs (`!raum:homeserver`) werden aus dem Nachrichtentext entfernt, bevor die URL-Erkennung greift. Verhindert, dass Homeserver-Namen fälschlicherweise als URLs erkannt werden — z.B. wenn ein Nutzer `!stats @kori:mein-homeserver.net` schreibt.

**Stufe 1 — HTML-Links:** Matrix-Clients senden formatierte Nachrichten mit `<a href="...">`. Diese Links werden als erstes und zuverlässigste Quelle ausgewertet.

**Stufe 2 — Klassische URLs:** Explizite URLs mit `http://`, `https://` oder `www.`-Präfix werden per Regex erkannt.

**Stufe 3 — Nackte Domains:** Domains ohne Protokoll wie `example.com` werden erkannt, sofern ihre TLD (z.B. `.com`, `.de`, `.io`) zu einem bekannten Satz von ~230 gültigen Top-Level-Domains gehört. Das verhindert Falschpositive: `hallo.du` wird ignoriert (`.du` ist keine TLD), `banned.com` wird korrekt erkannt. E-Mail-Adressen wie `user@example.com` werden dabei nicht als Domain ausgewertet. Bekannte Missbrauchs-gTLDs wie `.zip`, `.mov` und `.phd` sind ebenfalls enthalten.

**Unicode-Normalisierung:** Alle extrahierten Domains werden vor dem Listen-Vergleich normalisiert — Vollbreite-Zeichen (`ｇｏｏｇｌｅ.com` → `google.com`) sowie Unicode-Domains werden per IDNA in ihre Punycode-Form umgewandelt, sodass Blacklist-Einträge in beiden Schreibweisen greifen.

---

## Wildcard-Einträge

Mit dem Präfix `*.` lassen sich ganze Domain-Familien auf einmal erfassen:

```
!block *.boese-seite.com     → sperrt sub.boese-seite.com, api.boese-seite.com, ...
!allow *.vertrauenswuerdig.de → whitelisted alle Subdomains
```

| Geprüfte Domain | Eintrag | Match? |
|-----------------|---------|--------|
| `sub.banned.com` | `*.banned.com` | ✅ Ja — Wildcard |
| `api.banned.com` | `*.banned.com` | ✅ Ja — Wildcard |
| `banned.com` | `*.banned.com` | ❌ Nein — Wildcard deckt nur Subdomains ab |
| `sub.banned.com` | `banned.com` (exakt) | ✅ Ja — Apex-Match |
| `a.b.banned.com` | `banned.com` (exakt) | ✅ Ja — Apex-Match |

Soll auch die Hauptdomain selbst gesperrt werden, müssen `banned.com` und `*.banned.com` als zwei separate Einträge angelegt werden. Ist `banned.com` direkt in der Blacklist (ohne Wildcard), werden alle Subdomains automatisch miterfasst.

Wildcards können genau wie reguläre Domains mit `!unblock` / `!unallow` wieder entfernt werden.

---

## Konfigurationsoptionen

Diese Optionen werden in `base-config.yaml` definiert und können pro Instanz im Maubot-Dashboard überschrieben werden.

### Grundkonfiguration

| Parameter | Standard | Beschreibung |
|-----------|----------|-------------|
| `blacklist_dir` | `/data/blacklists/` | Verzeichnis mit den Blacklist-`.txt`-Dateien. Absoluter Pfad empfohlen. |
| `whitelist_dir` | `/data/whitelists/` | Verzeichnis mit den Whitelist-`.txt`-Dateien. |
| `mod_room_id` | *(Pflichtfeld)* | Matrix-Raum-ID des Moderationsraums (Format: `!xxx:homeserver`). |
| `mod_permissions.min_power_level` | `50` | Mindest-Powerlevel für Moderationsaktionen. `100` = nur Admin, `0` = jeder. |
| `mod_permissions.allowed_users` | `[]` | Nutzer-IDs mit fester Moderationsberechtigung, unabhängig vom Powerlevel. Muss ein YAML-Array sein. Beispiel: `["@alice:matrix.org"]` |
| `command_rooms` | `[]` | Liste von Raum-IDs oder -Aliasen, in denen der Bot auf Befehle reagiert. Leer = keine Einschränkung. `mod_room_id` und DMs sind immer erlaubt. |

> ⚠️ **Konfigurationshinweis:** `allowed_users` muss als YAML-Array angegeben werden (eckige Klammern). Eine einzelne ID als String (`allowed_users: "@alice:server"`) wird aus Sicherheitsgründen als ungültig behandelt und ignoriert — der Bot gibt eine Warnung ins Log aus.

### Datenschutz / DSGVO

| Parameter | Standard | Beschreibung |
|-----------|----------|-------------|
| `secret_salt` | *(Pflichtfeld)* | Zufälliger Geheimschlüssel für SHA-256-Nutzer-Hashing. Matrix-IDs werden **niemals** im Klartext gespeichert. Generierung: `python3 -c "import secrets; print(secrets.token_hex(32))"` — **nach Erstkonfiguration nicht mehr ändern!** |

### Linkvorschauen

| Parameter | Standard | Beschreibung |
|-----------|----------|-------------|
| `enable_link_previews` | `true` | Linkvorschauen (Titel + Beschreibung) für whitelisted URLs aktivieren. |
| `link_preview_timeout` | `5` | HTTP-Timeout in Sekunden für Vorschau-Abrufe. |

### Spam-Schutz & Auto-Mute

| Parameter | Standard | Beschreibung |
|-----------|----------|-------------|
| `warn_cooldown` | `60` | Warn-Cooldown in Sekunden. Nach einer Warnmeldung wartet der Bot diese Zeit, bevor er für denselben Nutzer eine neue Warnung postet. Nachrichten werden weiterhin sofort gelöscht — nur die öffentliche Benachrichtigung wird gedrosselt. |
| `mute_enabled` | `false` | Automatisches Stummschalten aktivieren. Wenn `true`, wird ein Nutzer auf Powerlevel -1 gesetzt, sobald er `mute_threshold` Verstöße innerhalb des konfigurierten `mute_window_minutes`-Fensters angehäuft hat. Verstöße werden datenbankgestützt und DSGVO-konform erfasst. Der Bot benötigt ein höheres Powerlevel als der Zielnutzer. |
| `mute_threshold` | `5` | Anzahl der Verstöße innerhalb des Beobachtungsfensters, die eine automatische Stummschaltung auslösen. |
| `mute_window_minutes` | `5` | Beobachtungsfenster (Minuten), innerhalb dessen Verstöße eines Nutzers gezählt werden. |
| `mute_duration_minutes` | `60` | Dauer der automatischen Stummschaltung (Minuten). `0` = unbegrenzt. Ein Hintergrund-Task hebt die Stummschaltung nach Ablauf automatisch auf. |
| `mute_commands_enabled` | `true` | Manuelle `!mute`- und `!unmute`-Befehle aktivieren. Auf `false` setzen, wenn mehrere Moderations-Bots gleichzeitig im Raum aktiv sind. Betrifft **nicht** das automatische Stummschalten. |
| `global_mute` | `true` | Globales Stummschalten. Wenn `true`, wird ein Nutzer bei einem Verstoß oder einem `!mute`-Befehl in **allen** Räumen stummgeschaltet, in denen der Bot ein höheres Powerlevel als der Zielnutzer hat. |

### Leistungsoptimierung

| Parameter | Standard | Beschreibung |
|-----------|----------|-------------|
| `loader_threads` | `null` | Worker-Threads für paralleles Datei-Laden. `null` = automatisch (os.cpu_count). Auf speicherkonstrained Servern reduzieren. |
| `min_domain_length` | `4` | Minimale Domain-Länge beim Parsen (kürzere Einträge werden übersprungen). |
| `max_domain_length` | `253` | Maximale Domain-Länge (RFC-Maximum für FQDNs). |

---

## Installation mit Docker

### Voraussetzungen

- Maubot läuft in Docker (Standard-Image: `dock.mau.dev/maubot/maubot`)
- Maubot läuft standardmäßig als **UID/GID 1337** im Container

### Schritt 1 — Plugin paketieren

```bash
cd /pfad/zum/plugin
zip -r url_filter.mbp \
    maubot.yaml base-config.yaml main.py \
    blacklists/custom.txt blacklists/ignore.txt whitelists/custom.txt
```

### Schritt 2 — Plugin hochladen

1. Maubot-Dashboard aufrufen: `https://dein-server/_matrix/maubot/#/plugins`
2. **"Upload plugin"** klicken und die `.mbp`-Datei hochladen.
3. Neue Instanz erstellen, Bot-Client zuweisen und speichern.

### Schritt 3 — Verzeichnisstruktur anlegen

```bash
mkdir -p ./data/blacklists ./data/whitelists
touch ./data/blacklists/custom.txt
touch ./data/whitelists/custom.txt
```

### Schritt 4 — Blacklist-Dateien ablegen

Hostfile-formatierte `.txt`-Dateien in `./data/blacklists/` ablegen. Geeignete Quellen:

- [oisd.nl](https://oisd.nl/) — verschiedene Kategorien
- [StevenBlack/hosts](https://github.com/StevenBlack/hosts) — konsolidierte Listen
- [The Block List Project](https://blocklistproject.github.io/Lists/) — nach Kategorie sortiert

Beispielstruktur:

```
./data/blacklists/
├── malware.txt
├── phishing.txt
├── scam.txt
└── custom.txt      ← vom Bot verwaltet
```

### Schritt 5 — Berechtigungen setzen ⚠️

Da Maubot im Container als **UID 1337** läuft, müssen die Verzeichnisse diesem Nutzer gehören. Ohne korrekte Berechtigungen kann der Bot nicht in `custom.txt` schreiben.

```bash
chown -R 1337:1337 ./data/blacklists ./data/whitelists
```

> **Hinweis:** Es ist weder notwendig noch empfohlen, `chmod -R 777` auf dem `data`-Ordner auszuführen. Nur die `blacklists`- und `whitelists`-Unterverzeichnisse müssen angepasst werden.

### Schritt 6 — Instanz konfigurieren

Im Maubot-Dashboard mindestens folgende Werte setzen:

```yaml
blacklist_dir: /data/blacklists/
whitelist_dir: /data/whitelists/
mod_room_id: "!DEIN_MOD_RAUM_ID:homeserver.example"
secret_salt: "dein-zufaelliger-salt-hier"  # python3 -c "import secrets; print(secrets.token_hex(32))"
```

Moderatoren konfigurieren:

```yaml
mod_permissions:
  min_power_level: 50
  allowed_users:
    - "@alice:matrix.org"
    - "@bob:mein-server.de"
```

Auto-Mute aktivieren (optional):

```yaml
mute_enabled: true
mute_threshold: 3
warn_cooldown: 30
```

### Schritt 7 — Bot in Räume einladen

1. Bot in alle zu überwachenden Räume einladen.
2. Bot in diesen Räumen auf **Powerlevel 50** (Moderator) setzen, damit er Nachrichten löschen kann.
3. Bot in den Moderationsraum einladen und dort Schreibrechte erteilen.
4. Wenn Auto-Mute verwendet wird: Bot auf **Powerlevel 100** (Admin) setzen, damit er Powerlevel anderer Nutzer ändern kann.

### Fehlerbehebung

**Bot schreibt nicht in custom.txt** — Berechtigungen auf dem Host korrigieren:
```bash
chown -R 1337:1337 ./data/blacklists ./data/whitelists
```

**Bot kann keine Nachrichten löschen** — Bot im betreffenden Raum auf Powerlevel 50 setzen.

**Auto-Mute funktioniert nicht** — Bot benötigt ein höheres Powerlevel als der Zielnutzer (empfohlen: PL 100).

**Bot sendet nicht in den Moderationsraum** — Prüfen ob der Bot eingeladen wurde und Schreibrechte hat.

**Keine .txt-Dateien beim Start gefunden** — Verzeichnis und Dateien anlegen (Schritt 3), Berechtigungen setzen (Schritt 5).

**`!botstatus` meldet DB-Fehler** — Sicherstellen, dass `database: true` und `database_type: asyncpg` in `maubot.yaml` gesetzt sind und die Maubot-Instanz korrekt gestartet ist.

**Warnung „secret_salt ist nicht gesetzt"** — Den `secret_salt` in der Instanzkonfiguration auf einen sicheren Zufallswert setzen (siehe Schritt 6). Ohne gültigen Salt werden keine Verstöße in die Datenbank geschrieben.

---

## Paketerstellung und Deployment

Nach Änderungen an den Quelldateien neu paketieren:

```bash
zip -r url_filter.mbp \
    maubot.yaml base-config.yaml main.py \
    blacklists/custom.txt blacklists/ignore.txt whitelists/custom.txt
```

Das aktualisierte `.mbp` im Maubot-Dashboard hochladen und die Instanz neu starten.

**Listen manuell aktualisieren:** Neue `.txt`-Dateien in `./data/blacklists/` ablegen, Berechtigungen prüfen, dann `!reloadlists` im Moderationsraum eingeben — kein Neustart nötig.

---

## Anforderungen

| Komponente | Mindestversion |
|------------|---------------|
| Maubot | >= 0.4.0 |
| mautrix-python | >= 0.20.0 |
| Python | >= 3.10 |

---

## Dokumentation / Documentation
- Die zweisprachige Dokumentation für Morpheus Link Bot ist unter https://m2tecdev.github.io/morpheus-link-bot/ erreichbar.

---

## Änderungsprotokoll

Siehe das vollständige [Änderungsprotokoll (CHANGELOG.md)](CHANGELOG.md) für alle Versionen und detaillierten Änderungen.

*Erstellt von Kori — Lizenz: AGPL-3.0-or-later*
