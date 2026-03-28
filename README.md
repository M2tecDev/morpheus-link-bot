# URL-Filter-Bot für Matrix — v2.1.0

Ein Maubot-Plugin, das eingehende Nachrichten in Matrix-Räumen auf URLs scannt und diese gegen konfigurierbare Blacklists und Whitelists prüft. Unbekannte Links werden automatisch zur Moderatorenüberprüfung weitergeleitet. Enthält automatischen Spam-Schutz mit optionalem Stummschalten.

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

---

## Funktionsübersicht

**Automatische URL-Filterung** — Der Bot überwacht alle Textnachrichten in überwachten Räumen. Enthält eine Nachricht eine URL oder Domain, prüft er diese sofort gegen Blacklist und Whitelist.

**Drei-Wege-Routing** — Jede erkannte Domain landet in einer von drei Kategorien: Whitelist (erlaubt), Blacklist (gesperrt) oder Unbekannt (zur Überprüfung). Die Whitelist hat immer Vorrang, auch gegenüber einem gleichzeitigen Blacklist-Eintrag.

**Moderationsworkflow** — Unbekannte Domains werden automatisch an einen konfigurierten Moderationsraum weitergeleitet. Moderatoren entscheiden dort per Emoji-Reaktion (✅ / ❌) oder Textbefehl. Die Entscheidung wird sofort aktiv und in der jeweiligen `custom.txt` gespeichert.

**Wildcard-Unterstützung** — Einträge wie `*.boese-seite.com` sperren alle Subdomains auf einmal. Funktioniert in Blacklist und Whitelist gleichermaßen.

**Spam-Schutz & Auto-Mute** — Ein konfigurierbarer Warn-Cooldown verhindert Notification Flooding: Nachrichten werden immer sofort gelöscht, aber eine öffentliche Warnmeldung wird pro Nutzer nur einmal innerhalb des Cooldown-Intervalls gepostet. Optional können Nutzer bei Erreichen eines konfigurierbaren Verstoß-Schwellenwerts innerhalb von 5 Minuten automatisch stummgeschaltet (Powerlevel -1) werden.

**Linkvorschauen** — Für freigegebene URLs kann der Bot optional Open-Graph-Metadaten abrufen und eine kurze Vorschau (Titel + Beschreibung) im Raum posten.

**Persistente Entscheidungen** — Alle Moderationsentscheidungen überstehen Bot-Neustarts, da sie in `blacklists/custom.txt` bzw. `whitelists/custom.txt` geschrieben werden.

**Event-ID-Deduplizierung** — Ein interner LRU-Cache (1.000 Einträge) verhindert Doppelverarbeitung bei Matrix-Sync-Replays nach Bot-Neustarts oder Netzwerkproblemen. Kein doppeltes Löschen, kein doppelter Mod-Raum-Alarm.

---

## Verfügbare Befehle

### Öffentliche Befehle (für alle Nutzer)

| Befehl | Beschreibung |
|--------|-------------|
| `!urlstatus <domain>` | Zeigt ob eine Domain whitelisted, blacklisted oder unbekannt ist — inklusive Wildcard-Treffern. |
| `!liststats` | Gibt die Anzahl geladener Domains sowie Wildcards und offene Überprüfungen aus. |
| `!hilfe` | Zeigt die vollständige Befehlsübersicht — nur per Direktnachricht (DM), damit Modinfos in öffentlichen Räumen verborgen bleiben. |

### Moderationsbefehle (erfordern Berechtigung)

Ein Nutzer gilt als Moderator, wenn sein Powerlevel im Moderationsraum mindestens `min_power_level` (Standard: 50) beträgt oder seine Nutzer-ID in `allowed_users` eingetragen ist.

| Befehl | Beschreibung |
|--------|-------------|
| `!allow <domain>` | Domain sofort whitelisten. Unterstützt Wildcards: `!allow *.vertrauenswuerdig.de` |
| `!unallow <domain>` | Domain oder Wildcard-Eintrag aus der Whitelist entfernen (nur aus `custom.txt`). |
| `!block <domain>` | Domain sofort blacklisten. Unterstützt Wildcards: `!block *.boese-seite.com` |
| `!unblock <domain>` | Domain oder Wildcard-Eintrag aus der Blacklist entfernen (nur aus `custom.txt`). |
| `!reloadlists` | Alle `.txt`-Dateien neu einlesen — kein Neustart nötig. Nützlich nach manuellen Änderungen. |
| `!pending` | Zeigt alle Domains, die aktuell auf eine Moderationsentscheidung warten. |

### Emoji-Reaktionen im Moderationsraum

Wenn eine unbekannte Domain erkannt wird, postet der Bot eine Alarmmeldung im Moderationsraum mit zwei Reaktionsknöpfen:

- **✅** — Domain zur Whitelist hinzufügen und Originalnachricht genehmigen.
- **❌** — Domain zur Blacklist hinzufügen.

Reaktionen von Nutzern ohne ausreichende Berechtigung werden still ignoriert.

---

## Wie der Bot URLs erkennt

Der Bot verwendet drei Erkennungsstufen, die nacheinander auf jede Nachricht angewendet werden:

**Stufe 1 — HTML-Links:** Matrix-Clients senden formatierte Nachrichten mit `<a href="...">`. Diese Links werden als erstes und zuverlässigste Quelle ausgewertet.

**Stufe 2 — Klassische URLs:** Explizite URLs mit `http://`, `https://` oder `www.`-Präfix werden per Regex erkannt.

**Stufe 3 — Nackte Domains:** Domains ohne Protokoll wie `example.com` werden erkannt, sofern ihre TLD (z.B. `.com`, `.de`, `.io`) zu einem bekannten Satz von ~200 gültigen Top-Level-Domains gehört. Das verhindert Falschpositive: `hallo.du` wird ignoriert (`.du` ist keine TLD), `banned.com` wird korrekt erkannt. E-Mail-Adressen wie `user@example.com` werden dabei nicht als Domain ausgewertet.

---

## Wildcard-Einträge

Mit dem Präfix `*.` lassen sich ganze Domain-Familien auf einmal erfassen:

```
!block *.boese-seite.com     → sperrt sub.boese-seite.com, api.boese-seite.com, ...
!allow *.vertrauenswuerdig.de → whitelisted alle Subdomains
```

| Geprüfte Domain | Eintrag | Match? |
|-----------------|---------|--------|
| `sub.banned.com` | `*.banned.com` | ✅ Ja |
| `api.banned.com` | `*.banned.com` | ✅ Ja |
| `banned.com` | `*.banned.com` | ❌ Nein — Apex-Domain ist nicht abgedeckt |

Soll auch die Hauptdomain selbst gesperrt werden, müssen `banned.com` und `*.banned.com` als zwei separate Einträge angelegt werden.

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
| `mod_permissions.allowed_users` | `[]` | Nutzer-IDs mit fester Moderation-Berechtigung, unabhängig vom Powerlevel. Beispiel: `["@alice:matrix.org"]` |

### Linkvorschauen

| Parameter | Standard | Beschreibung |
|-----------|----------|-------------|
| `enable_link_previews` | `true` | Linkvorschauen (Titel + Beschreibung) für whitelisted URLs aktivieren. |
| `link_preview_timeout` | `5` | HTTP-Timeout in Sekunden für Vorschau-Abrufe. |

### Spam-Schutz & Auto-Mute

| Parameter | Standard | Beschreibung |
|-----------|----------|-------------|
| `warn_cooldown` | `60` | Warn-Cooldown in Sekunden. Nach einer Warnmeldung wartet der Bot diese Zeit, bevor er für denselben Nutzer eine neue Warnung postet. Nachrichten werden weiterhin sofort gelöscht — nur die öffentliche Benachrichtigung wird gedrosselt. |
| `mute_enabled` | `false` | Automatisches Stummschalten aktivieren. Wenn `true`, wird ein Nutzer auf Powerlevel -1 gesetzt, sobald er `mute_threshold` Verstöße innerhalb von 5 Minuten angehäuft hat. Der Bot benötigt ein höheres Powerlevel als der Zielnutzer. |
| `mute_threshold` | `5` | Anzahl der Verstöße innerhalb von 5 Minuten, die eine automatische Stummschaltung auslösen. |

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
    blacklists/custom.txt whitelists/custom.txt
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

**Doppelte Alarme im Mod-Raum** — Seit v2.1.0 durch Event-ID-Deduplizierung behoben. Sicherstellen, dass die neuste Version installiert ist.

---

## Paketerstellung und Deployment

Nach Änderungen an den Quelldateien neu paketieren:

```bash
zip -r url_filter.mbp \
    maubot.yaml base-config.yaml main.py \
    blacklists/custom.txt whitelists/custom.txt
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

*Erstellt von Kori — Lizenz: AGPL-3.0-or-later*
