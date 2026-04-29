# Änderungsprotokoll

Alle wichtigen Änderungen am **morpheus-link-bot** werden hier dokumentiert.
Das Format orientiert sich an [Keep a Changelog](https://keepachangelog.com/de/1.0.0/) und [Semantic Versioning](https://semver.org/lang/de/).

## [2.6.2] - 2026-04-29

**Bugfixes**

- **`!urlstatus`-Priorität Exakt > Wildcard > Apex** — Die Prüfreihenfolge in `!urlstatus` wich von der des Haupt-Filters ab. War z. B. `sub.example.com` explizit in der Blacklist und `example.com` in der Whitelist, meldete `!urlstatus sub.example.com` fälschlicherweise `whitelisted (Apex)`, weil der Apex-Whitelist-Check vor dem exakten Blacklist-Check stattfand. Die Reihenfolge ist jetzt identisch zum Haupt-Filter: Exakt (Whitelist/Blacklist) → Wildcard → Apex.

---

## [2.6.1] - 2026-04-28

**Bugfixes**

- **Priorität Exakt > Wildcard > Apex (Fix #22)** — Domains werden jetzt in der korrekten Reihenfolge geprüft: Exakte Treffer haben Vorrang vor Wildcards, Wildcards vor Apex-Matches. Ein exakter Blacklist-Eintrag (`sub.example.com`) wird nicht mehr von einem Apex-Whitelist-Eintrag (`example.com`) überschrieben.
- **Keine Mute-Operationen in Direct Messages (Fix #23)** — `_get_mute_target_rooms()` filtert jetzt Räume mit ≤2 Mitgliedern (DM-Räume) aus. Ebenso werden keine "entstummt"-Nachrichten in DMs gesendet. Verhindert verwirrende Benachrichtigungen und unnötige plübergreifende Raumbley-Änderungen.

---

## [2.6.0] - 2026-04-26

**Neues Feature: Globales Stummschalten**

- **`global_mute`-Option (true/false, Standard: true)** — Wenn aktiviert, wird ein Nutzer bei einem automatischen Verstoß oder einem manuellen `!mute`-Befehl in **allen** Räumen stummgeschaltet, in denen der Bot aktiv ist und ein höheres Powerlevel als der Zielnutzer hat. Bei `false` gilt das bisherige Verhalten: nur der Raum des Verstoßes bzw. Befehls wird betroffen.
- **`_get_mute_target_rooms()`** — Neue Hilfsfunktion, die alle beigetretenen Räume parallel via `asyncio.gather` prüft und nur jene zurückgibt, in denen der Bot PL > 0 und PL > Zielnutzer hat. Blockiert den Event-Loop nicht.
- **`_mute_user_global()` / `_unmute_user_global()`** — Neue Orchestrierungsfunktionen, die den room-übergreifenden Mute-/Unmute-Vorgang verwalten und die Anzahl der betroffenen Räume zurückgeben.
- **Umstrukturiertes `_active_mutes`** — Das interne State-Dictionary wurde von `Dict[Tuple[str, str], float]` auf `Dict[str, List[Dict[str, Any]]]` umgestellt, um mehrere Räume pro Nutzer zu verfolgen.
- **`_mute_user()` / `_do_unmute_user()` als pure API-Wrapper** — Diese Funktionen manipulieren `_active_mutes` nicht mehr selbst; die Zeiterfassung erfolgt ausschließlich in `_mute_user_global()`.
- **Angepasste Rückmeldungen** — `!mute`, `!unmute` und automatische Verstöße melden die Anzahl der betroffenen Räume (z. B. „in 4 Räumen stummgeschaltet"), wenn mehr als ein Raum betroffen ist.

---

## [2.5.0] - 2026-04-19

**Bugfixes & Verbesserungen**

- **Kein Netzwerkzugriff nach Redaktion (Fix #19)** — Wenn eine Nachricht eine gesperrte Domain enthält, bricht der Bot die weitere Verarbeitung sofort nach der Redaktion ab (`return`). Linkvorschauen und alle sonstigen nachgelagerten Operationen werden nicht mehr ausgeführt. Zusätzlich werden bekannte URL-Shortener, die selbst auf der Blacklist stehen, vor dem Auflösen geprüft — ein unnötiger HEAD-Request an gesperrte Domains entfällt dadurch.
- **`!hilfe` ist in Gruppenräumen vollständig stumm (Fix #20)** — Bisher antwortete der Bot in öffentlichen Räumen mit einer Hinweismeldung (`„Nur per DM verfügbar"`). Ab v2.5.0 reagiert er in Nicht-DM-Räumen gar nicht mehr auf den Befehl — kein Reply, kein Hinweis. Das verhindert, dass Moderationsinfos versehentlich in überwachten Räumen sichtbar werden.
- **URL-Normalisierung für `!urlstatus` (Fix #21)** — `!urlstatus https://facebook.com/` lieferte bisher `unbekannt`, obwohl `facebook.com` whitelisted ist. Protokollpräfixe (`http://`, `https://`) und Pfadanteile werden jetzt vor dem Lookup automatisch abgeschnitten. `https://www.facebook.com/`, `www.facebook.com` und `facebook.com` werden einheitlich behandelt.

---

## [2.4.0] - 2026-04-03

**Datenbankarchitektur — komplett neu (Privacy by Design / DSGVO)**
- Vollständig neue DB-Schicht mit 4 Tabellen: `domain_rule`, `domain_stats`, `user_violation`, `pending_review` — ersetzt die frühere dateibasierte und RAM-basierte Speicherung.
- Alle Runtime-Moderationsentscheidungen (allow/block/ignore-preview) werden in `domain_rule` persistiert — bot-Neustarts sind jetzt stateful.
- Offene Moderationsanfragen werden in `pending_review` gespeichert und beim Start wiederhergestellt (`_load_pending_reviews_from_db()`).
- Domain-Whitelist und Blacklist werden beim Start aus der DB in den RAM-Cache geladen (`_load_domain_rules_cache()`).

**DSGVO-Konformität**
- Matrix-Nutzer-IDs werden ausschließlich als `SHA-256(secret_salt:user_id)` gespeichert — niemals im Klartext.
- Neues Pflichtfeld `secret_salt` in der Konfiguration.
- Neuer DSGVO-Retention-Loop (`_retention_loop`): Verstoßdaten in `user_violation` werden automatisch nach 24 Stunden gelöscht.
- `_record_violation()` ist jetzt `async` und schreibt direkt in die DB (Sliding-Window-Logik via SQL statt in-memory Deque).

**Neue Hilfsfunktionen**
- `_hash_user()` — SHA-256-Hashing mit Salt für DSGVO-konforme Nutzer-ID-Speicherung.
- `_sanitize_domain_for_storage()` — Bereinigung und Normalisierung von Domains vor DB-Speicherung.
- `!botstatus` — Neuer Health-Check-Befehl; zeigt DB-Verbindung, Listengröße und Bot-Status.

**Entfernt**
- `link_log`-Tabelle und alle zugehörigen Funktionen (`_log_link`, `_delete_logged_links_for_domain`, `_run_link_log_cleanup`, `_cleanup_loop`) — ersetzt durch datenschutzkonforme DB-Strukturen.
- `cmd_link_stats` (`!stats <@nutzer:homeserver>`) — entfernt, da auf rohen Nutzerdaten basierend (nicht DSGVO-konform).
- Config-Parameter `cleanup_enabled` und `cleanup_after_days` — nicht mehr benötigt.

**Sicherheit / Konfigurationsschutz**
- Hard-Stop beim Start wenn `secret_salt` noch den Standardwert enthält: Der Bot verweigert den Start mit einem `CRITICAL`-Log-Eintrag. Verhindert, dass die Datenbank mit dem falschen Salt befüllt wird und ein späterer Salt-Wechsel den Mute-Verlauf korrumpiert.

**Sonstiges**
- `requirements.txt` neu angelegt (`maubot >= 0.4.0`, `mautrix >= 0.20.0`).
- CI-Workflow bereinigt (Pyright-Step entfernt, Ruff-Step vereinheitlicht).
- Code-Formatierung via Ruff (E702 u.a.) durchgehend angewendet.

---

## [2.3.1] - 2026-04-02

**Sicherheitshärtung**
- NFKC-Unicode-Normalisierung + IDNA/Punycode-Konvertierung aller extrahierten Domains — Vollbreite-Zeichen und Unicode-Domains werden vor dem Listen-Vergleich normalisiert.
- Apex-Domain-Matching — ist `evil.com` in der Blacklist, werden alle Subdomains automatisch mitgeblockt. Gilt spiegelbildlich für die Whitelist.
- URL-Shortener-Auflösung — bekannte Kurzlink-Dienste werden via HEAD-Request aufgelöst; die finale Ziel-Domain wird geprüft.

**TLD-Liste erweitert**
- `.zip`, `.mov`, `.phd`, `.foo`, `.nexus` und weitere Missbrauchs-gTLDs ergänzt.

**Performance**
- Wildcard-Prüfung auf Set-Split-Lookup optimiert — O(Domain-Tiefe) statt O(Anzahl Wildcards).

## [2.3.0] - 2026-04-01

**Sicherheitshärtung**
- `_is_mod()` prüft Powerlevel ausschließlich im konfigurierten `mod_room_id` — DM-Eskalation nicht mehr möglich.
- `on_message` überspringt den URL-Filter vollständig bei bekannten Bot-Befehlsnamen.

**Neue Befehle**
- `!mute` / `!unmute` — manuelles Stummschalten mit optionaler Zeitangabe.
- `!sendpending` — offene Überprüfungsalarme neu in den Mod-Raum senden.
- `!ignore` / `!unignore` — Domain zur/von der Vorschau-Ignore-Liste.

**Neue Konfigurationsoptionen**
- `command_rooms`, `mute_window_minutes`, `mute_duration_minutes`, `mute_commands_enabled`.

**Verbesserungen**
- `!allow`/`!block`/`!unallow`/`!unblock`/`!urlstatus` akzeptieren mehrere Domains gleichzeitig.
- Automatisches Unmute im Hintergrund.
- Bearbeitete Nachrichten aktualisieren bestehende Vorschauen.
- Thread-Support und mehrere Whitelist-Links pro Nachricht.

## [2.2.1]

**Neues Feature**
- Automatischer Hintergrund-Task zur Bereinigung der Link-Log-Datenbank (`cleanup_enabled`, `cleanup_after_days`).

## [2.2.0]

**Link-Protokollierung & `!stats`-Befehl**
- Automatische Speicherung unbekannter Links in `link_log`.
- Matrix-ID-Erkennung verbessert; statische SQL-Migrationen.

## [2.1.0]

- Emoji-Reaktions-Workflow (✅/❌).
- Automatisches Stummschalten.
- Wildcard-Unterstützung (`*.domain.com`).

## [2.0.0]

- Nicht-blockierender Start.
- O(1)-Lookups mit Python-Sets.
- ReDoS-sichere Regex-Architektur.

---
