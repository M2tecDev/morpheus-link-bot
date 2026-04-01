# URL-Filter-Bot für Matrix — v2.3.0

Ein Maubot-Plugin, das eingehende Nachrichten in Matrix-Räumen auf URLs scannt und diese gegen konfigurierbare Blacklists und Whitelists prüft. Unbekannte Links werden automatisch zur Moderatorenüberprüfung weitergeleitet. Enthält Link-Protokollierung mit Statistikabfragen, automatischen Spam-Schutz mit optionalem Stummschalten und eine umfassende Sicherheitshärtung.

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

**Drei-Wege-Routing** — Jede erkannte Domain landet in einer von drei Kategorien: Whitelist (erlaubt), Blacklist (gesperrt) oder Unbekannt (zur Überprüfung). Die Whitelist hat immer Vorrang, auch gegenüber einem gleichzeitigen Blacklist-Eintrag.

**Moderationsworkflow** — Unbekannte Domains werden automatisch an einen konfigurierten Moderationsraum weitergeleitet. Moderatoren entscheiden dort per Emoji-Reaktion (✅ / ❌) oder Textbefehl. Die Entscheidung wird sofort aktiv und in der jeweiligen `custom.txt` gespeichert.

**Link-Protokollierung & Statistiken** — Alle nicht genehmigten (unbekannten) Links werden in einer plugin-eigenen Datenbank gespeichert. Wird ein Link freigegeben, wird er automatisch aus der Protokolldatenbank entfernt. Der Befehl `!stats` ermöglicht Administratoren die Abfrage der offenen Link-Anzahl pro Nutzer.

**Befehlsraum-Einschränkung (neu in v2.3.0)** — Über den neuen Konfigurationsschlüssel `command_rooms` kann festgelegt werden, in welchen Räumen der Bot auf Befehle reagiert. Der Moderationsraum und Direktnachrichten sind immer erlaubt, unabhängig von dieser Liste.

**Automatische Datenbankbereinigung (neu in v2.2.1)** — Ein nicht-blockierender Hintergrund-Task löscht periodisch veraltete Einträge aus der Link-Log-Datenbank. Interval und Aufbewahrungsdauer sind konfigurierbar. Der Task läuft einmal beim Bot-Start und danach alle 24 Stunden, ohne den Matrix-Sync-Loop zu beeinträchtigen.

**Wildcard-Unterstützung** — Einträge wie `*.boese-seite.com` sperren alle Subdomains auf einmal. Funktioniert in Blacklist und Whitelist gleichermaßen.

**Spam-Schutz & Auto-Mute** — Ein konfigurierbarer Warn-Cooldown verhindert Notification Flooding: Nachrichten werden immer sofort gelöscht, aber eine öffentliche Warnmeldung wird pro Nutzer nur einmal innerhalb des Cooldown-Intervalls gepostet. Optional können Nutzer bei Erreichen eines konfigurierbaren Verstoß-Schwellenwerts innerhalb von 5 Minuten automatisch stummgeschaltet (Powerlevel -1) werden.

**Linkvorschauen** — Für freigegebene URLs kann der Bot optional Open-Graph-Metadaten abrufen und eine kurze Vorschau (Titel + Beschreibung) im Raum posten.

**Persistente Entscheidungen** — Alle Moderationsentscheidungen überstehen Bot-Neustarts, da sie in `blacklists/custom.txt` bzw. `whitelists/custom.txt` geschrieben werden.

**Event-ID-Deduplizierung** — Ein interner LRU-Cache (1.000 Einträge) verhindert Doppelverarbeitung bei Matrix-Sync-Replays nach Bot-Neustarts oder Netzwerkproblemen.

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
| `!allow <domain>` | Domain sofort whitelisten. Unterstützt Wildcards: `!allow *.vertrauenswuerdig.de` — löscht automatisch alle zugehörigen Link-Log-Einträge. |
| `!unallow <domain>` | Domain oder Wildcard-Eintrag aus der Whitelist entfernen (nur aus `custom.txt`). |
| `!block <domain>` | Domain sofort blacklisten. Unterstützt Wildcards: `!block *.boese-seite.com` |
| `!unblock <domain>` | Domain oder Wildcard-Eintrag aus der Blacklist entfernen (nur aus `custom.txt`). |
| `!reloadlists` | Alle `.txt`-Dateien neu einlesen — kein Neustart nötig. Nützlich nach manuellen Änderungen. |
| `!pending` | Zeigt alle Domains, die aktuell auf eine Moderationsentscheidung warten — mit menschenlesbaren Zeitangaben (z.B. „10 Minuten", „2 Stunden"). |
| `!sendpending` | Sendet alle offenen Überprüfungsalarme erneut in den Mod-Raum. Nützlich nach einem Bot-Neustart oder wenn Alarme verloren gegangen sind. |
| `!mute <@nutzer:server> [-t Minuten]` | Nutzer manuell stummschalten (Powerlevel -1). Optionaler `-t`-Parameter setzt die Dauer in Minuten; ohne `-t` gilt `mute_duration_minutes`. Nur wenn `mute_commands_enabled: true`. |
| `!unmute <@nutzer:server>` | Stummschaltung eines Nutzers manuell aufheben. Nur wenn `mute_commands_enabled: true`. |
| `!ignore <domain>` | Domain zur Vorschau-Ignore-Liste hinzufügen — Nachrichten mit dieser Domain werden weiterhin gefiltert, aber keine Linkvorschau mehr erzeugt. |
| `!unignore <domain>` | Domain von der Vorschau-Ignore-Liste entfernen. |

### Admin-Befehle (nur für `allowed_users`)

Der folgende Befehl ist **ausschließlich** für Nutzer verfügbar, die explizit in `mod_permissions.allowed_users` eingetragen sind. Ein ausreichendes Powerlevel im Mod-Raum genügt hier **nicht**.

| Befehl | Beschreibung |
|--------|-------------|
| `!stats <@nutzer:homeserver>` | Zeigt die Anzahl der aktuell protokollierten (noch nicht genehmigten) Links für den angegebenen Nutzer. Erwartet eine vollständige Matrix-ID im Format `@nutzer:homeserver`. |

Beispiel: `!stats @alice:matrix.org`

#### Wie `!stats` funktioniert

Der Befehl liest aus der `link_log`-Datenbanktabelle, die der Bot intern pflegt:

- **Eintrag entsteht**, wenn eine Nachricht eine unbekannte Domain enthält und der Nutzer die Nachricht zur Überprüfung eingereicht hat.
- **Eintrag wird gelöscht**, sobald die Domain per `!allow` oder ✅-Reaktion genehmigt wird — automatisch, ohne manuellen Eingriff.
- **Eintrag altert heraus**, wenn die automatische Bereinigung aktiv ist (`cleanup_enabled: true`) und der Eintrag älter als `cleanup_after_days` Tage ist.

**Berechtigungsanforderung:** Der aufrufende Nutzer muss in `mod_permissions.allowed_users` (YAML-Array) eingetragen sein. Ein Powerlevel von 50+ im Mod-Raum allein genügt nicht. Die Matrix-ID muss im Format `@localpart:homeserver` angegeben werden — ungültige Formate werden mit einer Fehlermeldung abgelehnt.

### Emoji-Reaktionen im Moderationsraum

Wenn eine unbekannte Domain erkannt wird, postet der Bot eine Alarmmeldung im Moderationsraum mit zwei Reaktionsknöpfen:

- **✅** — Domain zur Whitelist hinzufügen, Originalnachricht genehmigen und Link-Log-Einträge für diese Domain löschen.
- **❌** — Domain zur Blacklist hinzufügen.

Reaktionen von Nutzern ohne ausreichende Berechtigung werden still ignoriert.

---

## Wie der Bot URLs erkennt

Der Bot verwendet vier Stufen, die nacheinander auf jede Nachricht angewendet werden:

**Stufe 0 — Matrix-ID-Bereinigung (neu in v2.2):** Matrix-Nutzer-IDs (`@nutzer:homeserver`) und Raum-IDs (`!raum:homeserver`) werden aus dem Nachrichtentext entfernt, bevor die URL-Erkennung greift. Verhindert, dass Homeserver-Namen fälschlicherweise als URLs erkannt werden — z.B. wenn ein Nutzer `!stats @kori:mein-homeserver.net` schreibt.

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
| `mod_permissions.allowed_users` | `[]` | Nutzer-IDs mit fester Moderation- **und** `!stats`-Berechtigung, unabhängig vom Powerlevel. Muss ein YAML-Array sein. Beispiel: `["@alice:matrix.org"]` |
| `command_rooms` | `[]` | Liste von Raum-IDs oder -Aliasen, in denen der Bot auf Befehle reagiert. Leer = keine Einschränkung. `mod_room_id` und DMs sind immer erlaubt. |

> ⚠️ **Konfigurationshinweis:** `allowed_users` muss als YAML-Array angegeben werden (eckige Klammern). Eine einzelne ID als String (`allowed_users: "@alice:server"`) wird aus Sicherheitsgründen als ungültig behandelt und ignoriert — der Bot gibt eine Warnung ins Log aus.

### Linkvorschauen

| Parameter | Standard | Beschreibung |
|-----------|----------|-------------|
| `enable_link_previews` | `true` | Linkvorschauen (Titel + Beschreibung) für whitelisted URLs aktivieren. |
| `link_preview_timeout` | `5` | HTTP-Timeout in Sekunden für Vorschau-Abrufe. |

### Spam-Schutz & Auto-Mute

| Parameter | Standard | Beschreibung |
|-----------|----------|-------------|
| `warn_cooldown` | `60` | Warn-Cooldown in Sekunden. Nach einer Warnmeldung wartet der Bot diese Zeit, bevor er für denselben Nutzer eine neue Warnung postet. Nachrichten werden weiterhin sofort gelöscht — nur die öffentliche Benachrichtigung wird gedrosselt. |
| `mute_enabled` | `false` | Automatisches Stummschalten aktivieren. Wenn `true`, wird ein Nutzer auf Powerlevel -1 gesetzt, sobald er `mute_threshold` Verstöße innerhalb des konfigurierten `mute_window_minutes`-Fensters angehäuft hat. Der Bot benötigt ein höheres Powerlevel als der Zielnutzer. |
| `mute_threshold` | `5` | Anzahl der Verstöße innerhalb des Beobachtungsfensters, die eine automatische Stummschaltung auslösen. |
| `mute_window_minutes` | `5` | Beobachtungsfenster (Minuten), innerhalb dessen Verstöße eines Nutzers gezählt werden. |
| `mute_duration_minutes` | `60` | Dauer der automatischen Stummschaltung (Minuten). `0` = unbegrenzt. Ein Hintergrund-Task hebt die Stummschaltung nach Ablauf automatisch auf. |
| `mute_commands_enabled` | `true` | Manuelle `!mute`- und `!unmute`-Befehle aktivieren. Auf `false` setzen, wenn mehrere Moderations-Bots gleichzeitig im Raum aktiv sind. Betrifft **nicht** das automatische Stummschalten. |

### Datenbank-Bereinigung (Link-Log)

| Parameter | Standard | Beschreibung |
|-----------|----------|-------------|
| `cleanup_enabled` | `true` | Automatische Bereinigung des Link-Logs aktivieren. Wenn `true`, läuft beim Start und danach alle 24 Stunden ein nicht-blockierender Hintergrund-Task, der alte Einträge löscht. |
| `cleanup_after_days` | `30` | Alter in Tagen, nach dem ein Link-Log-Eintrag gelöscht wird. Muss eine positive ganze Zahl sein. Empfohlen: 30–90. |

> **Hinweis:** Die Bereinigung läuft vollständig nicht-blockierend im asyncio-Event-Loop und beeinflusst die Nachrichtenverarbeitung nicht. Der Cut-off-Zeitpunkt wird in Python berechnet und als parametrisierter Bindungsparameter übergeben — kein SQL-String-Zusammenbau, kompatibel mit PostgreSQL und SQLite.

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
```

Admins für `!stats`-Befehl und direkte Moderationsrechte konfigurieren:

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

**`!stats`-Befehl meldet keine Berechtigung** — Sicherstellen, dass die eigene Matrix-ID als Array-Eintrag in `mod_permissions.allowed_users` steht (z.B. `["@alice:matrix.org"]`). Ein einzelner String-Wert wird aus Sicherheitsgründen abgelehnt.

**Doppelte Alarme im Mod-Raum** — Seit v2.1.0 durch Event-ID-Deduplizierung behoben. Sicherstellen, dass die neuste Version installiert ist.

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

## Änderungsprotokoll

### v2.3.0

**Sicherheitshärtung**
- Fix #1: `_is_mod()` prüft Powerlevel ausschließlich im konfigurierten `mod_room_id` — DM-Eskalation durch Einladen des Bots in einen eigenen Raum mit erhöhten Rechten ist nicht mehr möglich.
- Fix #5: `on_message` überspringt den URL-Filter vollständig, wenn eine Nachricht mit einem bekannten Bot-Befehlsnamen beginnt — verhindert unbeabsichtigte Filterung eigener Befehle.

**Neue Befehle**
- Fix #10: `!mute <@nutzer:server> [-t Minuten]` — manuelles Stummschalten mit optionaler Zeitangabe.
- Fix #10: `!unmute <@nutzer:server>` — manuelle Entstummschaltung.
- Fix #11: `!sendpending` — sendet alle offenen Überprüfungsalarme neu in den Mod-Raum.
- `!ignore` / `!unignore` — Domain zur/von der Vorschau-Ignore-Liste hinzufügen/entfernen.

**Neue Konfigurationsoptionen**
- Fix #2: `command_rooms` — Liste erlaubter Befehlsräume; leer = keine Einschränkung.
- Fix #8: `mute_window_minutes` — konfigurierbares Beobachtungsfenster für Verstöße (Standard: 5 Minuten).
- Fix #8: `mute_duration_minutes` — Dauer der automatischen Stummschaltung; `0` = unbegrenzt.
- Fix #18: `mute_commands_enabled` — manuelle `!mute`/`!unmute`-Befehle aktivieren/deaktivieren.

**Verbesserungen**
- Fix #3: `_edit_notice()` erzeugt spec-konformes `m.new_content`-Format mit Retry-Mechanismus.
- Fix #4: `!allow`/`!block` räumen `pending_reviews` auf, inklusive Wildcard-Sweep.
- Fix #6: `!allow`, `!block`, `!unallow`, `!unblock`, `!urlstatus` akzeptieren mehrere Domains gleichzeitig (Leerzeichen-getrennt).
- Fix #7: Semikolon gilt als Domain-Trennzeichen — `1.com;2.com;3.com` wird korrekt in drei Domains aufgeteilt.
- Fix #9: `!pending` zeigt menschenlesbare Wartezeiten („10 Minuten", „2 Stunden").
- Fix #8: Auto-Unmute-Hintergrund-Task (`_auto_unmute_loop`) hebt abgelaufene Stummschaltungen automatisch auf.
- Fix #12: Bearbeitete Nachrichten aktualisieren bestehende Linkvorschauen anstatt neue zu erstellen; Vorschauen werden als Reply gesendet.
- Fix #13: Alle whitelisteten Links in einer Nachricht erhalten jeweils eine eigene Vorschau — inkl. Thread-Support.
- Fix #14: Aufeinanderfolgende Punkte (z.B. `achso...ne`) werden nicht mehr als Domain erkannt.

**Paketierung**
- `blacklists/ignore.txt` als Seed-Datei in das `.mbp`-Archiv aufgenommen (`maubot.yaml` → `extra_files`).

### v2.2.1

**Neues Feature: Automatische Datenbank-Bereinigung**
- Neuer Hintergrund-Task `_cleanup_loop` / `_run_link_log_cleanup` — löscht periodisch veraltete `link_log`-Einträge.
- Läuft einmalig beim Plugin-Start und danach im 24-Stunden-Takt via `asyncio.sleep` — kein Blocking des Matrix-Sync-Loops.
- Cut-off-Zeitpunkt wird mit `datetime.timedelta` in Python berechnet und als `$1`-Parameter übergeben — 100% parametrisiert, keine datenbankspezifische `INTERVAL`-Syntax, kompatibel mit PostgreSQL und SQLite/aiosqlite.
- Sauberes Lebenszyklusmanagement: `stop()` bricht den Task mit `cancel()` ab und wartet auf vollständige Beendigung.
- Zwei neue Konfigurationsschlüssel in `base-config.yaml`: `cleanup_enabled` (bool) und `cleanup_after_days` (int).

**Dokumentation**
- README um dedizierte `!stats`-Erklärung erweitert (Berechtigungsmodell, Eintrag-Lebenszyklus).
- Neue Konfigurationstabelle für Datenbank-Bereinigung.
- Fehlerbehebungseintrag für `!stats`-Berechtigungsprobleme ergänzt.

### v2.2.0

**Bugfix**
- Matrix-Nutzer-IDs (`@nutzer:homeserver`) und Raum-IDs (`!raum:homeserver`) wurden fälschlicherweise als URLs erkannt, wenn ihr Homeserver-Teil einer bekannten TLD entsprach. Betroffen war z.B. `!stats @kori:mein-server.net`, das `mein-server.net` als unbekannte Domain einstufte. Behoben durch vorgelagerte Bereinigung (Schritt 0 in der Extraktionspipeline) via `_MATRIX_ID_RE`.

**Sicherheitshärtung**
- SQL-Migration (`upgrade_v1`): F-String-Interpolation durch vollständig statische SQL-Strings ersetzt — ein Branch pro Datenbanktyp (PostgreSQL / SQLite). Kein nutzerkontrollierter Wert fließt mehr in den DDL-Code.
- Berechtigungsprüfung (`_is_mod`, `cmd_link_stats`): `isinstance`-Guards verhindern, dass ein als String statt als Array konfiguriertes `allowed_users` zu einem unbeabsichtigten Substring-Vergleich führt. Fehlerhafte Konfigurationen werden geloggt und safe-fail auf leere Liste normalisiert.
- Eingabevalidierung (`!stats`): Der `<user>`-Parameter wird auf gültiges Matrix-ID-Format (`@localpart:homeserver`) validiert, bevor er in Datenbankabfragen und Antwortnachrichten verwendet wird. Verhindert unerwartete Ausgabeformatierung durch ungültige Strings.

**Neue Features**
- Link-Protokollierung: Unbekannte URLs werden in einer plugin-eigenen Datenbank (`link_log`-Tabelle) gespeichert. Datenbank-Schema wird automatisch via `UpgradeTable` (mautrix async_db) beim Start migriert — kein manuelles SQL nötig.
- Neuer Befehl `!stats <@nutzer:homeserver>`: Zeigt die Anzahl protokollierter (nicht genehmigter) Links für einen bestimmten Nutzer. Ausschließlich für Einträge in `allowed_users` zugänglich (Powerlevel genügt nicht).
- Automatische Bereinigung: Wird eine Domain per `!allow` oder ✅-Reaktion freigegeben, werden alle zugehörigen `link_log`-Einträge automatisch gelöscht.

### v2.1.0

- Event-ID-Deduplizierung (LRU-Cache, 1.000 Einträge) — verhindert Doppelverarbeitung bei Matrix-Sync-Replays.
- Emoji-Reaktions-Moderationsworkflow (✅ / ❌ direkt im Mod-Raum).
- Automatisches Stummschalten (Auto-Mute) bei konfiguriertem Verstoß-Schwellenwert.
- Wildcard-Unterstützung (`*.domain.com`) in Blacklist und Whitelist.

### v2.0.0

- Nicht-blockierender Start via `asyncio.ThreadPoolExecutor` — Matrix-Sync-Loop läuft während des Listenladens weiter.
- Generator-basiertes Datei-Parsen — konstanter RAM-Verbrauch unabhängig von Listengröße.
- O(1)-Lookups via Python-`set` für Blacklist und Whitelist.
- ReDoS-sichere Regex-Architektur (flache Zeichenklassen, begrenzte Quantifizierer).

---

*Erstellt von Kori — Lizenz: AGPL-3.0-or-later*
