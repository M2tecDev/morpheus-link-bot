# Änderungsprotokoll

Alle wichtigen Änderungen am **morpheus-link-bot** werden hier dokumentiert.  
Das Format orientiert sich an [Keep a Changelog](https://keepachangelog.com/de/1.0.0/) und [Semantic Versioning](https://semver.org/lang/de/).

## [2.3.1] - 2026-04-02

**Sicherheitshärtung**
- Fix #16: NFKC-Unicode-Normalisierung + IDNA/Punycode-Konvertierung aller extrahierten Domains — Vollbreite-Zeichen (`ｇｏｏｇｌｅ.com` → `google.com`) und Unicode-Domains werden vor dem Listen-Vergleich normalisiert.
- Fix #17: Apex-Domain-Matching — ist `evil.com` in der Blacklist, werden `sub.evil.com` und tiefer verschachtelte Subdomains automatisch mitgeblockt, ohne gesonderten Wildcard-Eintrag. Gilt spiegelbildlich für die Whitelist. `!urlstatus` zeigt Apex-Treffer als eigene Kategorie an.
- Fix #18: URL-Shortener-Auflösung — bekannte Kurzlink-Dienste (bit.ly, t.co, tinyurl.com u.a.) werden via HEAD-Request aufgelöst; die finale Ziel-Domain wird geprüft statt des Shortener-Hosts.

**TLD-Liste erweitert**
- `.zip`, `.mov`, `.phd`, `.foo`, `.nexus` und weitere bekannte Missbrauchs-gTLDs ergänzt (betrifft ausschließlich Erkennung nackter Domains ohne `https://`-Präfix).

**Performance**
- Wildcard-Prüfung (`_matches_wildcards`) auf Set-Split-Lookup optimiert — O(Domain-Tiefe) statt O(Anzahl Wildcards), unabhängig von der Listengröße.

**Logging**
- Blacklist-Treffer und unbekannte Domains werden mit Raum-ID und Absender im Konsolen-Log ausgegeben.
- `!reloadlists` und `!sendpending` protokollieren den aufrufenden Nutzer.

## [2.3.0] - 2026-04-01

**Sicherheitshärtung**
- Fix #1: `_is_mod()` prüft Powerlevel ausschließlich im konfigurierten `mod_room_id` — DM-Eskalation durch Einladen des Bots in einen eigenen Raum mit erhöhten Rechten ist nicht mehr möglich.
- Fix #5: `on_message` überspringt den URL-Filter vollständig, wenn eine Nachricht mit einem bekannten Bot-Befehlsnamen beginnt — verhindert unbeabsichtigte Filterung eigener Befehle.

**Neue Befehle**
- `!mute <@nutzer:server> [-t Minuten]` — manuelles Stummschalten mit optionaler Zeitangabe.
- `!unmute <@nutzer:server>` — manuelle Entstummschaltung.
- `!sendpending` — sendet alle offenen Überprüfungsalarme neu in den Mod-Raum.
- `!ignore` / `!unignore` — Domain zur/von der Vorschau-Ignore-Liste hinzufügen/entfernen.

**Neue Konfigurationsoptionen**
- `command_rooms` — Liste erlaubter Befehlsräume (leer = keine Einschränkung).
- `mute_window_minutes`, `mute_duration_minutes`, `mute_commands_enabled`.

**Verbesserungen**
- `!allow`/`!block`/`!unallow`/`!unblock`/`!urlstatus` akzeptieren mehrere Domains gleichzeitig (Leerzeichen-getrennt).
- Semikolon (`;`) gilt als zusätzlicher Domain-Trenner.
- `!pending` zeigt menschenlesbare Wartezeiten („10 Minuten“, „2 Stunden“).
- Automatisches Unmute im Hintergrund (`_auto_unmute_loop`).
- Bearbeitete Nachrichten aktualisieren bestehende Vorschauen (spec-konform mit `m.new_content`).
- Thread-Support und mehrere Whitelist-Links pro Nachricht.
- Aufeinanderfolgende Punkte (`achso...ne`) werden nicht mehr als Domain erkannt.
- `blacklists/ignore.txt` wird jetzt ins `.mbp`-Paket mit eingebunden.

**Paketierung**
- `maubot.yaml` → `extra_files` für Seed-Dateien.

## [2.2.1] - 2025 (genaues Datum nicht dokumentiert)

**Neues Feature: Automatische Datenbank-Bereinigung**
- Neuer Hintergrund-Task `_cleanup_loop`.
- Neue Config-Optionen: `cleanup_enabled` und `cleanup_after_days`.

**Dokumentation**
- Erweiterte `!stats`-Erklärung in der README.

## [2.2.0]

**Link-Protokollierung & `!stats`-Befehl**
- Automatische Speicherung unbekannter Links in `link_log`.
- Neuer Befehl `!stats <@nutzer:homeserver>`.
- Matrix-ID-Erkennung stark verbessert.

**Sicherheit**
- Statische SQL-Migrationen (keine F-Strings mehr).
- Strengere Berechtigungs- und Eingabevalidierung.

## [2.1.0]

- Emoji-Reaktions-Workflow (✅/❌).
- Automatisches Stummschalten.
- Wildcard-Unterstützung (`*.domain.com`).

## [2.0.0]

- Nicht-blockierender Start.
- O(1)-Lookups mit Python-Sets.
- ReDoS-sichere Regex-Architektur.

---
