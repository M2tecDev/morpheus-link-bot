# Änderungsprotokoll

Alle wichtigen Änderungen am **morpheus-link-bot** werden hier dokumentiert.
Das Format orientiert sich an [Keep a Changelog](https://keepachangelog.com/de/1.0.0/) und [Semantic Versioning](https://semver.org/lang/de/).

## [2.7.1] - 2026-06-08

**Bugfix: matrix.to-Links mit `?via=…`-Parametern erzeugten Linkpreviews für die Via-Server**

- **Root Cause** — Continuwuity (und Matrix v12 / MSC4291) senden Raum-IDs in matrix.to-Links ohne `:server`-Suffix, z. B. `https://matrix.to/#/!Jos2YAuOg…?via=matrix.org&via=tchncs.de&via=nope.chat`. Die bisherige Heuristik `_looks_like_matrix_identifier` verlangte für die Sigille `@!#` zwingend einen Doppelpunkt im Token und stufte solche Raum-IDs daher als „kein Matrix-Bezeichner" ein. In der Folge griff `_strip_matrix_to_deeplinks` nicht, die naked-domain-Erkennung lief über die URL hinweg und zog die hinter `via=` stehenden Servernamen als eigenständige Domains heraus — der Bot postete Linkvorschauen für `matrix.org`, `tchncs.de` und `nope.chat`.
- **Fix in `_looks_like_matrix_identifier` ([main.py](main.py))** — `!`-Raum-IDs werden jetzt auch im serverlosen Format akzeptiert (Opaque-Identifier-Charset `[A-Za-z0-9._=+/-]+`). `@`-User-IDs und `#`-Raum-Aliase bleiben unverändert strikt mit `:server`-Suffix, da die Matrix-Spezifikation dort kein serverloses Format kennt. Alle nachgelagerten Pfade (`_is_matrix_to_deeplink`, `_strip_matrix_to_deeplinks`, `_extract_domains`, `_find_url_for_domain`) profitieren automatisch.
- **Tests** — 21 neue Tests in [tests/test_helpers.py](tests/test_helpers.py): direkte Tests für `_looks_like_matrix_identifier` und `_is_matrix_to_deeplink` (klassisches + serverloses Format, User/Alias-Regressionen) sowie Integrationstests durch `URLFilterBot._extract_domains` mit dem konkreten Bugreport-Body (inkl. Reply-Quote mit `<mx-reply>`).

---

## [2.7.0] - 2026-05-11

**Neues Feature: Auto-Block für .onion-Adressen (Tor Hidden Services)**

- **`.onion`-Erkennung in allen Extraktions-Pfaden** — Hidden-Service-Adressen (RFC 7686) werden jetzt aus `href`-Links, vollständigen URLs (`http(s)://…`) und nackten Domain-Erwähnungen (`abc.onion`) erkannt. Bisher fiel `.onion` durch alle Filter, weil `onion` nicht in der TLD-Whitelist enthalten war.
- **Automatische Blockierung ohne Mod-Review** — `.onion`-Treffer werden vor der Whitelist/Blacklist-/Unknown-Aufteilung erkannt und sofort redaktiert. Es gibt keinen Mod-Raum-Alert, keinen Google-Safe-Browsing-Check und keine Linkvorschau — eine Reputationsprüfung von Hidden Services aus dem Clearnet ist nicht möglich.
- **Eigener Handler `_handle_onion()`** — Spiegelt das Verhalten von `_handle_blacklisted()`: Nachricht löschen, throttled User-Warnung (`warn_cooldown`), DomainStats-Inkrement, Verstoß zählen (Auto-Mute greift bei Wiederholungstätern).
- **`!urlstatus <foo.onion>`** — Liefert „🧅 Tor Hidden Service — wird immer blockiert" statt „unbekannt".

**Neues Feature: Google Safe Browsing v5-Integration**

- **`url_safety_check`-Option (opt-in, Standard: false)** — Unbekannte Domains werden vor der Mod-Raum-Weiterleitung gegen die Google Safe Browsing v5 API geprüft. Das Ergebnis (✅ sauber / ⚠️ GEFÄHRLICH / 🟡 verdächtig / ❓ Fehler) erscheint direkt im Moderations-Alert.
- **Privacy-Preserving Hash Lookup (v5)** — Statt die URL im Klartext an Google zu senden (v4), wird nur ein 4-Byte SHA-256-Präfix übertragen. Google sieht niemals die echte Domain.
- **`_check_url_safety()` + `_validate_gsb_config()`** — Canonicalization, SHA-256-Hashing, Base64-Kodierung, GSB-API-Call, lokaler Full-Hash-Vergleich. Beim Start wird die GSB-Konfiguration via Test-Request validiert; ein ungültiger API-Key bricht den Plugin-Start hart ab, statt schweigend zu scheitern.
- **Konfiguration** — Neuer Block `url_safety_check:` in `base-config.yaml` mit `enabled`, `api_key`, `timeout`.

**Härtung: `!block` / `!allow` lehnen Matrix-IDs ab**

- **MXID-Schutz für Moderationsbefehle** — `!block @opfer:home.tld` (sowie Varianten mit `!`, `#`, `$`) werden mit einer expliziten Fehlermeldung abgelehnt, statt den Homeserver des Nutzers als Domain in die Blacklist zu schreiben. Schützt vor versehentlicher Sperre und vor Missbrauch durch einen kompromittierten Mod-Account. Dieselbe Prüfung greift in `!allow`. Bei Mehrfacheingaben wird nur das MXID-artige Token übersprungen, gültige Domains werden weiterhin verarbeitet.

**Robustheit: Klassen-weite Event-Deduplizierung**

- Zusätzlicher `_global_seen_event_ids`-Cache (5 000 Einträge) als Fallback, falls Maubot den Handler nach Hot-Reload doppelt registriert. Verhindert doppelt redaktierte Nachrichten und doppelte Mod-Alerts.

---

## [2.6.3] - 2026-05-07

**Bugfixes**

- **Wildcard-Einträge werden jetzt persistent gespeichert** — Domains, die per `!allow *.domain.com` oder `!block *.domain.com` hinzugefügt wurden, gingen nach einem Bot-Neustart verloren, weil sie ausschließlich im RAM gehalten wurden. Ab v2.6.3 werden Wildcard-Einträge wie reguläre Domains in der Datenbank (`domain_rule`-Tabelle) mit dem Präfix `*.` gespeichert. `_load_domain_rules_cache()` und der Reload-Pfad (`_reload_lists()`) erkennen das Präfix beim Laden und routen die Einträge korrekt in die Wildcard-Sets. `!unallow` und `!unblock` löschen Wildcard-Einträge jetzt ebenfalls aus der DB.

---

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
