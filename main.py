"""
URL-Filter-Bot — Hochleistungsedition  (v2)
============================================
Maubot-Plugin, das URL-Richtlinien in Matrix-Räumen gegen einen Korpus von
ca. 6,5 Millionen gesperrten Domains aus 13 großen Hostfile-formatierten
Listen durchsetzt.

Designziele
-----------
1. **Nicht-blockierender Start**: Alle Datei-E/A laufen im asyncio-ThreadPool
   via `loop.run_in_executor`, sodass der Matrix-/sync-Loop niemals blockiert wird.
2. **Generator-basiertes Parsen**: Jede Datei wird zeilenweise durch einen
   Python-Generator gestreamt. Kein vollständiger Dateitext wird im RAM gehalten;
   Domains werden einzeln dem Set hinzugefügt, sodass der GC Zeilenstrings sofort
   zurückfordern kann.
3. **O(1)-Lookups**: Sowohl die Blacklist als auch die Whitelist sind Python-`set`-Objekte.
   Der Mitgliedschaftstest ist ein einzelner Hash-Vergleich unabhängig von der Setgröße.
4. **ReDoS-sicherer Regex**: Der URL-Extraktions-Regex verwendet eine einzige, flache
   Zeichenklasse ohne geschachtelte Quantifizierer oder überlappende Alternativen, was
   katastrophales Backtracking mathematisch unmöglich macht.
5. **Threadsicheres Schreiben**: Ein einziges `asyncio.Lock` serialisiert alle Anhänge
   an die Runtime-`custom.txt`-Dateien.

Siehe SELBSTAUDIT-Abschnitt (Abschnitt 21) am Ende dieser Datei für eine detaillierte
Analyse von Speicherbedarf, Threadsicherheit, Fehlerbehandlung und Regex-Sicherheit.

Abhängigkeiten
--------------
  maubot    >= 0.4.0
  mautrix   >= 0.20.0
  aiohttp   (mit maubot gebündelt)
  Python    >= 3.10

Autor: Kori <korinator21@gmail.com>
"""

from __future__ import annotations

# ===========================================================================
# ABSCHNITT 1 — STANDARD-BIBLIOTHEKEN
# ===========================================================================

import asyncio
import concurrent.futures
import os
import re
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Generator, List, Optional, Set
from urllib.parse import urlparse

# ===========================================================================
# ABSCHNITT 2 — DRITTANBIETER-BIBLIOTHEKEN
# ===========================================================================

import aiohttp

# ===========================================================================
# ABSCHNITT 3 — MAUBOT / MAUTRIX IMPORTE
# ===========================================================================

from maubot import Plugin, MessageEvent
from maubot.handlers import command, event
from mautrix.types import (
    EventID,
    EventType,
    Format,
    MessageType,
    PowerLevelStateEventContent,
    RoomID,
    TextMessageEventContent,
    UserID,
)
from mautrix.util.config import BaseProxyConfig, ConfigUpdateHelper


# ===========================================================================
# ABSCHNITT 4 — REGEX-KONSTANTEN  (ReDoS-sicheres Design — siehe SELBSTAUDIT §4)
# ===========================================================================
#
# WARUM DIESER REGEX SICHER VOR ReDoS IST
# -----------------------------------------
# ReDoS (Regular Expression Denial of Service) entsteht, wenn die Regex-Engine
# aufgrund mehrdeutiger Muster bei adversariellen Eingaben exponentiell zurückverfolgt.
# Klassisch gefährliche Muster:
#
#   GEFÄHRLICH:  (a+)+       geschachtelte Quantifizierer  → O(2^n) Backtracking
#   GEFÄHRLICH:  (a|aa)+     überlappende Alternation      → O(2^n) Backtracking
#   GEFÄHRLICH:  (\w+\s*)+   mehrdeutige Gruppengrenze     → katastrophal
#
# Dieser Regex vermeidet ALL jene Muster:
#
#   1. Der URL-Körper verwendet EINE einzige flache Zeichenklasse [valid-url-chars]+.
#      Eine Zeichenklasse wird als Bitset-Lookup ausgewertet — deterministisch,
#      niemals intern zurückverfolgt. Ein Zeichen, eine Entscheidung.
#
#   2. Das führende Präfix (?:https?://|www\.) liegt außerhalb der wiederholten Gruppe.
#      Es passt entweder vollständig und verankert den Scan, oder es passt überhaupt
#      nicht — keine Mehrdeutigkeit für den wiederholten Teil.
#
#   3. Das abschließende negative Lookbehind (?<![.,;:!?)\]]) ist fest (genau
#      1 Zeichen). Pythons `re` wertet feste Lookbehinds in O(1) aus — kein
#      Backtracking.
#
#   4. re.ASCII beschränkt die Zeichenklasse auf 7-Bit-ASCII, vermeidet Unicode-
#      Kategorie-Scanning-Verlangsamungen bei emoji-schweren Nachrichten.
#
#   Schlechtester Fall: O(n) wobei n = Nachrichtenlänge. Immer linear.
#
# ZEICHENKLASSEN-ABDECKUNG (RFC 3986 konform):
#   a-z A-Z 0-9  — alphanumerisch
#   \-           — Bindestriche in Domain-Labels
#   .            — Domain-Trennzeichen
#   _            — Unterstriche (gültig in Pfaden/Subdomains)
#   ~            — nicht reserviert (RFC 3986)
#   : @ ! $ &    — Autorität, Benutzerinfo, Sonderzeichen
#   ' ( ) * + ,  — Sub-Trennzeichen
#   ; = ? / # %  — Query, Fragment, Prozent-Kodierung
#   [ ]          — IPv6-Klammern

_URL_RE: re.Pattern = re.compile(
    r"(?:https?://|www\.)"
    r"[a-zA-Z0-9\-._~:@!$&'()*+,;=/?#%\[\]]+"
    r"(?<![.,;:!?\])])",
    re.ASCII | re.IGNORECASE,
)

# Hostfile-IP-Präfixe, die beim Parsen verworfen werden
_LOOPBACK: frozenset = frozenset({"0.0.0.0", "127.0.0.1"})

# Gültige Hostfile-Token, die KEINE echten externen Domains sind
_SKIP_DOMAINS: frozenset = frozenset({
    "localhost", "broadcasthost", "local",
    "0.0.0.0", "127.0.0.1", "255.255.255.255",
    "ip6-localhost", "ip6-loopback",
})

# Emoji-Schlüssel, die als Moderations-Reaktionsknöpfe im Mod-Raum verwendet werden
_EMOJI_ALLOW = "✅"
_EMOJI_BLOCK  = "❌"

# ---------------------------------------------------------------------------
# BEKANNTE TOP-LEVEL-DOMAINS — Kuratiertes Set zur Falsch-Positiv-Prävention
# ---------------------------------------------------------------------------
# Dieses Set enthält gültige TLDs aus der IANA-Datenbank.
# Es dient als Torwächter für die "Naked-Domain"-Erkennung:
# Nur Domains mit einer TLD aus diesem Set werden als echte Links behandelt.
# Beispiel: "hallo.du" wird NICHT erkannt ("du" ∉ Set),
# aber "bannedurl.com" wird erkannt ("com" ∈ Set).
_COMMON_TLDS: frozenset = frozenset({
    # Generische TLDs (gTLDs)
    "com", "net", "org", "info", "biz", "edu", "gov", "mil", "int", "name",
    # Häufig genutzte neue gTLDs (inkl. bekannter Missbrauchs-TLDs)
    "io", "co", "app", "dev", "xyz", "online", "site", "club", "top", "pro",
    "store", "shop", "tech", "live", "news", "media", "cloud", "link", "click",
    "download", "win", "bid", "loan", "work", "space", "agency", "digital",
    "network", "services", "solutions", "systems", "group", "global", "world",
    "today", "center", "support", "tools", "email", "social", "chat", "game",
    "web", "pw", "cc", "tv", "mobi", "tel", "coop", "aero", "museum", "jobs",
    # Länder-TLDs (ccTLDs) — vollständige IANA-Liste der 2-Zeichen-Codes
    "ac", "ad", "ae", "af", "ag", "ai", "al", "am", "ao", "aq", "ar", "as",
    "at", "au", "aw", "ax", "az", "ba", "bb", "bd", "be", "bf", "bg", "bh",
    "bi", "bj", "bm", "bn", "bo", "br", "bs", "bt", "bw", "by", "bz", "ca",
    "cd", "cf", "cg", "ch", "ci", "ck", "cl", "cm", "cn", "cr", "cu", "cv",
    "cw", "cx", "cy", "cz", "de", "dj", "dk", "dm", "do", "dz", "ec", "ee",
    "eg", "er", "es", "et", "eu", "fi", "fj", "fk", "fm", "fo", "fr", "ga",
    "gb", "gd", "ge", "gf", "gg", "gh", "gi", "gl", "gm", "gn", "gp", "gq",
    "gr", "gs", "gt", "gu", "gw", "gy", "hk", "hm", "hn", "hr", "ht", "hu",
    "id", "ie", "il", "im", "in", "iq", "ir", "is", "it", "je", "jm", "jo",
    "jp", "ke", "kg", "kh", "ki", "km", "kn", "kp", "kr", "kw", "ky", "kz",
    "la", "lb", "lc", "li", "lk", "lr", "ls", "lt", "lu", "lv", "ly", "ma",
    "mc", "md", "me", "mg", "mh", "mk", "ml", "mm", "mn", "mo", "mp", "mq",
    "mr", "ms", "mt", "mu", "mv", "mw", "mx", "my", "mz", "na", "nc", "ne",
    "nf", "ng", "ni", "nl", "no", "np", "nr", "nu", "nz", "om", "pa", "pe",
    "pf", "pg", "ph", "pk", "pl", "pm", "pn", "pr", "ps", "pt", "pw", "py",
    "qa", "re", "ro", "rs", "ru", "rw", "sa", "sb", "sc", "sd", "se", "sg",
    "sh", "si", "sk", "sl", "sm", "sn", "so", "sr", "ss", "st", "sv", "sx",
    "sy", "sz", "tc", "td", "tf", "tg", "th", "tj", "tk", "tl", "tm", "tn",
    "to", "tr", "tt", "tv", "tw", "tz", "ua", "ug", "uk", "um", "us", "uy",
    "uz", "va", "vc", "ve", "vg", "vi", "vn", "vu", "wf", "ws", "ye", "yt",
    "za", "zm", "zw",
})

# ---------------------------------------------------------------------------
# HREF-REGEX — Extrahiert Ziel-URLs aus HTML-<a>-Tags im formatted_body
# ---------------------------------------------------------------------------
# Matrix-Clients (z.B. Element) senden bei formatierten Nachrichten ein
# `formatted_body`-Feld mit HTML-Links wie <a href="https://example.com">.
# Diese Links sind die zuverlässigste Quelle, da der Client sie selbst geparst hat.
# Zeichenlänge auf 2048 begrenzt — verhindert ReDoS, deckt alle echten URLs ab.
_HREF_RE: re.Pattern = re.compile(
    r'href=["\']([^"\']{1,2048})["\']',
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# NAKED-DOMAIN-REGEX — Erkennt Domains ohne http:// oder www. Präfix
# ---------------------------------------------------------------------------
# Erkennt Domain-ähnliche Zeichenketten wie "bannedurl.com" direkt im Text.
# Die TLD-Validierung via _COMMON_TLDS verhindert Falsch-Positive:
#   "hallo.du"   → "du" ∉ _COMMON_TLDS → IGNORIERT
#   "example.de" → "de" ∈ _COMMON_TLDS → ERKANNT
#
# REDOS-SICHERHEIT:
#   Die innere Zeichenklasse [a-zA-Z0-9\-\.] ist ein Bitset-Lookup (O(1)/Zeichen).
#   Der Quantifizierer {1,200} ist nach oben begrenzt — kein unendliches Backtracking.
#   Das negative Lookbehind und Lookahead sind jeweils 1 Zeichen breit (O(1)).
#   Worst-Case-Komplexität: O(n) für Nachrichtenlänge n. ✓
#
# LOOKBEHIND-LOGIK: Keine Übereinstimmung, wenn dem ersten Zeichen vorangeht:
#   /  → Domain ist Teil einer URL (https://example.com → "example" wird ignoriert)
#   \w → Domain ist Teil eines Wortes oder bereits erkannten Tokens
#   -  → Bindestrich-Präfix (Dateiname o.ä.)
#   *  → Wildcard-Präfix aus Listendateien
#   .  → Punkt-Präfix (Subdomain-Kontexte)
#   @  → E-Mail-Adresse (user@example.com → "example.com" wird ignoriert)
_NAKED_DOMAIN_RE: re.Pattern = re.compile(
    r'(?<![/\w\-\*\.@])'
    r'([a-zA-Z0-9][a-zA-Z0-9\-\.]{1,200}[a-zA-Z0-9])'
    r'(?![a-zA-Z0-9\-\.])',
    re.ASCII,
)


# ===========================================================================
# ABSCHNITT 5 — KONFIGURATION
# ===========================================================================

class Config(BaseProxyConfig):
    """
    Kapselt mautrix BaseProxyConfig. do_update() wird aufgerufen, wenn ein Operator
    die Instanzkonfiguration über das Maubot-Dashboard speichert. Es kopiert jeden
    Schlüssel aus der neuen Konfiguration in die aktive Konfiguration und behält
    die base-config-Standardwerte für fehlende Schlüssel bei.
    """

    def do_update(self, helper: ConfigUpdateHelper) -> None:
        helper.copy("blacklist_dir")
        helper.copy("whitelist_dir")
        helper.copy("mod_room_id")
        helper.copy("mod_permissions")
        helper.copy("enable_link_previews")
        helper.copy("link_preview_timeout")
        helper.copy("loader_threads")
        helper.copy("min_domain_length")
        helper.copy("max_domain_length")


# ===========================================================================
# ABSCHNITT 6 — DATENSTRUKTUREN
# ===========================================================================

@dataclass
class PendingReview:
    """
    Erfasst alle Kontextinformationen, die zur Auflösung einer Moderationsüberprüfung
    benötigt werden.

    Instanzen werden in URLFilterBot.pending_reviews gespeichert, indexiert nach der
    EventID der eigenen Alarmmeldung des Bots im Moderationsraum.
    """
    domain:               str
    original_event_id:    EventID
    original_room_id:     RoomID
    sender:               UserID
    submitted_at:         float = field(default_factory=time.monotonic)
    whitelist_reaction_id: Optional[EventID] = field(default=None)
    blacklist_reaction_id: Optional[EventID] = field(default=None)


@dataclass
class LoadResult:
    """Rückgabewert des synchronen Datei-Parser-Workers pro Datei."""
    filename:          str
    domains:           Set[str]
    wildcards:         Set[str]   # Subdomain-Wildcards: "*.banned.com" → "banned.com"
    lines_read:        int
    domains_accepted:  int
    wildcards_found:   int
    elapsed_ms:        float


# ===========================================================================
# ABSCHNITT 7 — HAUPTKLASSE DES PLUGINS
# ===========================================================================

class URLFilterBot(Plugin):
    """
    Haupt-Plugin-Klasse. Maubot erstellt eine Instanz pro konfiguriertem Bot und
    ruft start() / stop() rund um den Plugin-Lebenszyklus auf.

    Laufzeitzustand (initialisiert in start()):
      blacklist_set     — Set gesperrter Domains          (ca. 6,5 Mio. Einträge)
      whitelist_set     — Set erlaubter Domains           (typischerweise klein)
      pending_reviews   — offene Moderationsanfragen      (Dict)
      _pending_domains  — O(1)-Set bereits wartender Domains
                          (verhindert doppelte Mod-Raum-Alarme pro Domain)
      _seen_events      — LRU-Set kürzlich verarbeiteter Event-IDs
                          (verhindert Mehrfachverarbeitung bei Matrix-Sync-Replays)
      _seen_events_q    — Deque-Spiegel von _seen_events für FIFO-Verdrängung
      _file_lock        — asyncio.Lock für Datei-Schreibzugriffe
      _loader_pool      — ThreadPoolExecutor für Parser-Threads
    """

    # Maximale Anzahl zu merkender Event-IDs für die Deduplizierung.
    # Bei ca. 80 Byte pro ID sind 1.000 Einträge ≈ 80 KB — vernachlässigbar.
    _SEEN_EVENTS_MAX: int = 1_000

    # ------------------------------------------------------------------
    # Maubot-Lebenszyklus
    # ------------------------------------------------------------------

    @classmethod
    def get_config_class(cls) -> type[BaseProxyConfig]:
        return Config

    async def start(self) -> None:
        """
        Plugin-Einstiegspunkt. Initialisiert den gesamten Laufzeitzustand und startet
        dann den Hochleistungs-Async-Listenlader. Der Matrix-Sync-Loop verarbeitet
        Ereignisse normal weiter, während das Parsen im Hintergrund in Threads läuft.
        """
        await super().start()
        self.config.load_and_update()

        # O(1)-Lookup-Sets — einmalig beim Start befüllt, bei Mod-Aktionen aktualisiert
        self.blacklist_set: Set[str] = set()
        self.whitelist_set: Set[str] = set()

        # Wildcard-Sets für "*.domain.com"-Muster aus den Listendateien.
        # Speichern das Suffix nach Entfernung von "*.": "*.banned.com" → "banned.com".
        # Die Prüfung erfolgt per endswith()-Schleife in _matches_wildcards().
        self.blacklist_wildcards: Set[str] = set()
        self.whitelist_wildcards: Set[str] = set()

        # Offene Moderationsanfragen: alert_event_id → PendingReview
        self.pending_reviews: Dict[EventID, PendingReview] = {}

        # O(1)-Wächter: Domains, die bereits eine offene Überprüfung im Mod-Raum haben.
        # Verhindert, dass der Bot N doppelte Alarme + 2N Reaktionen postet, wenn
        # dieselbe unbekannte Domain mehrfach geteilt wird, bevor ein Mod entscheidet.
        self._pending_domains: Set[str] = set()

        # ── Event-ID-Deduplizierungs-Cache ────────────────────────────────────
        # WARUM NÖTIG:
        # Das Matrix-/sync-Protokoll kann Ereignisse, die während der Bot-Offline-Zeit
        # ankamen, erneut zusenden (z.B. nach Neustart oder Netzwerkproblem). Ohne
        # Seen-Event-Cache kann eine einzelne Nutzernachricht on_message() 2–3-mal
        # auslösen und doppelte Hinweise sowie doppelte Mod-Raum-Alarme erzeugen.
        #
        # IMPLEMENTIERUNG:
        # _seen_events   — Set für O(1)-Mitgliedschaftsprüfung
        # _seen_events_q — Deque für O(1)-FIFO-Verdrängung bei vollem Cache
        # Zusammen bilden sie einen gebundenen LRU-Cache ohne Drittanbieter-Bibliothek.
        self._seen_events: Set[EventID] = set()
        self._seen_events_q: Deque[EventID] = deque()

        # Lock zur Serialisierung von custom.txt-Anhängen (siehe SELBSTAUDIT §2-C)
        self._file_lock: asyncio.Lock = asyncio.Lock()

        # Dedizierter ThreadPoolExecutor, damit Datei-E/A nicht mit aiohttp
        # um den Standard-Executor konkurriert
        max_workers = self.config.get("loader_threads", None) or None
        self._loader_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="urlfilter_loader",
        )

        await self._reload_lists()

    async def stop(self) -> None:
        """Geordnetes Herunterfahren — gibt den Thread-Pool frei."""
        self._loader_pool.shutdown(wait=False, cancel_futures=True)
        await super().stop()
        self.log.info("URLFilterBot wurde beendet.")


    # ===========================================================================
    # ABSCHNITT 8 — HOCHLEISTUNGS-DATEIPARSER
    # ===========================================================================

    def _domain_generator(
        self,
        filepath: str,
        min_len: int,
        max_len: int,
    ) -> Generator[str, None, None]:
        """
        Kern-Generator — liefert einen Domain-String nach dem anderen aus einer Datei.

        SPEICHERSTRATEGIE
        -----------------
        Die Verwendung von `yield` statt Sammeln in eine Liste bedeutet, dass diese
        Funktion niemals mehr als EINE Rohzeile gleichzeitig im Speicher hält. Jeder
        gelieferte String wird sofort von set.add() in _load_one_file verbraucht,
        wodurch der intermediäre Zeilenstring sofort für den GC freigegeben werden kann.

        Für eine 500-K-Zeilen-Datei (ca. 30 MB auf der Festplatte) liegt der RAM-Overhead
        des Generators unter 1 KB. Die resultierenden Domain-Strings im Set kosten jeweils
        ca. 70 Byte (49-Byte-CPython-str-Header + durchschn. 20-Zeichen-Körper).

        PARSE-REGELN (der Reihe nach für Geschwindigkeit):
        1.  Leerzeichen von der Rohzeile entfernen.
        2.  Leere Zeilen überspringen (erstes `not line` ist O(1)).
        3.  Kommentarzeilen überspringen (erstes Zeichen == '#' ist O(1)).
        4.  Inline-Kommentare (' #' Suffix) entfernen.
        5.  Auf Leerzeichen aufteilen — max. 2 Token via split(None, 2).
        6.  Wenn erstes Token ein Loopback-IP ist, Token[1] verwenden; sonst Token[0].
        7.  Domain in Kleinbuchstaben umwandeln.
        8.  Einträge in _SKIP_DOMAINS überspringen (frozenset-Lookup = O(1)).
        9.  Einträge ohne '.' überspringen (kein FQDN).
        10. Einträge außerhalb [min_len, max_len] überspringen.
        """
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                for raw_line in fh:
                    line = raw_line.strip()

                    if not line or line[0] == "#":
                        continue

                    # Inline-Kommentar-Suffix entfernen
                    ci = line.find(" #")
                    if ci != -1:
                        line = line[:ci].rstrip()
                        if not line:
                            continue

                    # Domain-Token effizient extrahieren
                    parts = line.split(None, 2)
                    if not parts:
                        continue

                    if len(parts) >= 2 and parts[0] in _LOOPBACK:
                        domain = parts[1].lower()
                    else:
                        domain = parts[0].lower()

                    # Validierungstor
                    if (
                        domain in _SKIP_DOMAINS
                        or "." not in domain
                        or not (min_len <= len(domain) <= max_len)
                    ):
                        continue

                    yield domain

        except OSError as exc:
            # Pro-Datei protokollieren, damit der Aufrufer ein Teilergebnis erhält
            self.log.error("Datei '%s' kann nicht gelesen werden: %s", filepath, exc)

    def _load_one_file(
        self,
        filepath: str,
        min_len: int,
        max_len: int,
    ) -> LoadResult:
        """
        Synchroner Worker — läuft in einem Thread des ThreadPoolExecutors.

        Erstellt ein neues Set pro Datei durch Verbrauch von _domain_generator.
        Die Rückgabe eines Sets pro Datei vermeidet gemeinsamen Zustand zwischen
        Threads (kein Lock während der Ladephase nötig). Der asynchrone Koordinator
        führt sie danach zusammen.

        WARUM PRO-DATEI-SETS?
        Jeder Worker erhält sein eigenes Set. Würden wir ein gemeinsames globales Set
        nutzen, würde jeder set.add()-Aufruf über alle 13 Threads hinweg am GIL plus
        dem internen Resize-Lock des Sets konkurrieren — was das Laden effektiv
        serialisieren würde. Pro-Datei-Sets werden in einem einzigen set.update() im
        Haupt-Thread nach Abschluss aller Worker zusammengeführt, was insgesamt viel
        schneller ist.
        """
        filename = os.path.basename(filepath)
        t0 = time.monotonic()
        self.log.info("  ⏳  Lade %s ...", filename)

        domains:   Set[str] = set()
        wildcards: Set[str] = set()
        lines_read = 0

        for raw_entry in self._domain_generator(filepath, min_len, max_len):
            # WILDCARD-ERKENNUNG:
            # _domain_generator liefert Roheinträge unverändert.
            # "*.banned.com" — Zeilen, die mit "*." beginnen, sind Subdomain-Wildcards.
            # Wir speichern das Suffix (ohne "*.") separat und zählen sie NICHT als
            # reguläre Domains, da der exakte String "*.banned.com" keiner echten
            # Domain entspricht und niemals zu einem Lookup-Treffer führen würde.
            if raw_entry.startswith("*."):
                suffix = raw_entry[2:]          # "*.banned.com" → "banned.com"
                if suffix and "." in suffix:
                    wildcards.add(suffix)
            else:
                domains.add(raw_entry)
                lines_read += 1

        elapsed_ms = (time.monotonic() - t0) * 1_000
        self.log.info(
            "  ✅  %s — %d Domains + %d Wildcards aus %d Zeilen (%.0f ms)",
            filename, len(domains), len(wildcards), lines_read, elapsed_ms,
        )
        return LoadResult(
            filename=filename,
            domains=domains,
            wildcards=wildcards,
            lines_read=lines_read,
            domains_accepted=len(domains),
            wildcards_found=len(wildcards),
            elapsed_ms=elapsed_ms,
        )

    async def _reload_lists(self) -> None:
        """
        Asynchroner Koordinator — übermittelt alle Datei-Loader an den ThreadPoolExecutor
        und wartet sie gleichzeitig ab, OHNE den Matrix-Sync-Loop zu blockieren.

        PARALLELITÄTSMODELL
        -------------------
        loop.run_in_executor() gibt für jede Datei ein Future zurück.
        asyncio.gather() plant alle Futures gleichzeitig und suspendiert DIESE
        Coroutine, bis sie fertig sind — der Event-Loop kann Matrix-Ereignisse,
        WebSocket-Pings und Reaktionen die ganze Zeit verarbeiten.

        Auf einem 4-Kern-Server mit 13 Dateien:
          Wandzeit ≈ ceil(13/4) × avg_einzeldatei_zeit  (E/A-gebunden)
          Typisch:   15–25 s gesamt vs. ca. 60 s sequentiell

        ATOMARER AUSTAUSCH
        ------------------
        Neue Sets werden in lokale Variablen (new_bl, new_wl) aufgebaut und erst
        self.blacklist_set / self.whitelist_set zugewiesen, nachdem ALLE Dateien
        geladen sind. Das bedeutet:
          a) Beim ersten Start: alle Nachrichten werden als "unbekannt" → Mod-Queue geleitet.
          b) Bei !reloadlists: alte Listen bleiben gültig bis zum Tausch.
        Der Referenz-Tausch ist auf CPython-Ebene atomar (GIL), daher ist kein
        zusätzliches Lock nötig.
        """
        loop = asyncio.get_event_loop()
        min_len = int(self.config.get("min_domain_length", 4))
        max_len = int(self.config.get("max_domain_length", 253))

        bl_dir = self.config["blacklist_dir"]
        wl_dir = self.config["whitelist_dir"]

        bl_files = _list_txt_files(bl_dir)
        wl_files = _list_txt_files(wl_dir)

        if not bl_files and not wl_files:
            self.log.warning(
                "Keine .txt-Dateien in blacklist_dir='%s' oder whitelist_dir='%s' gefunden. "
                "Alle URLs werden als unbekannt behandelt.",
                bl_dir, wl_dir,
            )
            return

        total = len(bl_files) + len(wl_files)
        self.log.info(
            "🚀 Starte Listen-Ladevorgang: %d Dateien gesamt (bl=%d  wl=%d)",
            total, len(bl_files), len(wl_files),
        )
        t_start = time.monotonic()

        # Jede Datei an den Thread-Pool übermitteln
        bl_futures = [
            loop.run_in_executor(self._loader_pool, self._load_one_file, fp, min_len, max_len)
            for fp in bl_files
        ]
        wl_futures = [
            loop.run_in_executor(self._loader_pool, self._load_one_file, fp, min_len, max_len)
            for fp in wl_files
        ]

        # Alle gleichzeitig abwarten; return_exceptions=True bedeutet, eine fehlerhafte
        # Datei bricht den Rest nicht ab
        all_results: List = await asyncio.gather(
            *bl_futures, *wl_futures, return_exceptions=True,
        )

        # In neue Sets zusammenführen (Domains + Wildcards getrennt)
        new_bl:    Set[str] = set()
        new_wl:    Set[str] = set()
        new_bl_wc: Set[str] = set()
        new_wl_wc: Set[str] = set()
        n_bl = len(bl_futures)
        total_lines = 0
        total_domains = 0

        for i, result in enumerate(all_results):
            if isinstance(result, BaseException):
                self.log.error("Datei-Loader-Ausnahme: %s", result)
                continue
            total_lines   += result.lines_read
            total_domains += result.domains_accepted
            if i < n_bl:
                new_bl.update(result.domains)
                new_bl_wc.update(result.wildcards)
            else:
                new_wl.update(result.domains)
                new_wl_wc.update(result.wildcards)

        # Atomarer Referenz-Tausch — alle vier Sets gleichzeitig
        # (GIL garantiert Atomarität jedes einzelnen STORE_ATTR-Bytecodes)
        self.blacklist_set      = new_bl
        self.whitelist_set      = new_wl
        self.blacklist_wildcards = new_bl_wc
        self.whitelist_wildcards = new_wl_wc

        elapsed = time.monotonic() - t_start
        self.log.info(
            "🏁 Ladevorgang abgeschlossen: %d BL-Domains | %d WL-Domains | "
            "%d BL-Wildcards | %d WL-Wildcards | %d Zeilen gelesen | %.1f s",
            len(self.blacklist_set), len(self.whitelist_set),
            len(self.blacklist_wildcards), len(self.whitelist_wildcards),
            total_lines, elapsed,
        )


    # ===========================================================================
    # ABSCHNITT 9 — URL- UND DOMAIN-EXTRAKTION
    # ===========================================================================

    @staticmethod
    def _extract_domains(
        body: str,
        formatted_body: Optional[str] = None,
    ) -> Set[str]:
        """
        Extrahiert alle einzigartigen Domain-Strings aus einer Nachricht in
        drei Schritten mit steigender Vollständigkeit und fallender Zuverlässigkeit.

        SCHRITT 1 — formatted_body <a href> (zuverlässigste Quelle)
        ─────────────────────────────────────────────────────────────
        Wenn der Matrix-Client ein `formatted_body`-Feld mit HTML sendet, enthält
        es <a href="...">-Tags für ALLE Inhalte, die der Client als Link erkannt
        hat. Das sind: explizit eingetippte URLs, auto-verlinkte "nackte" Domains,
        Markdown-Links usw. Da der Client selbst die Erkennung durchgeführt hat,
        sind diese Treffer praktisch falsch-positiv-frei.
        Übersprungene Schemata: mailto:, matrix:, mxc:, tel:, # (Anker), / (Pfad).

        SCHRITT 2 — _URL_RE auf Klartext (http:// und www. Präfix)
        ─────────────────────────────────────────────────────────────
        Fängt vollständig qualifizierte URLs ab, die NICHT im formatted_body landen
        (z.B. bei Clients ohne Auto-Link-Funktion oder reinen Text-Clients).
        Überschneidungen mit Schritt 1 werden durch Set-Deduplication still entfernt.

        SCHRITT 3 — _NAKED_DOMAIN_RE + TLD-Validierung (Falsch-Positiv-Schutz)
        ─────────────────────────────────────────────────────────────────────────
        Erkennt "nackte" Domains wie "bannedurl.com" ohne http:// oder www.-Präfix
        im Klartext. Der _NAKED_DOMAIN_RE-Regex findet Domain-ähnliche Zeichenketten;
        die TLD wird dann gegen _COMMON_TLDS validiert.
        Beispiele:
          "hallo.du"   → TLD "du" ∉ _COMMON_TLDS → IGNORIERT          ← kein Falsch-Positiv
          "bannedurl.com" → TLD "com" ∈ _COMMON_TLDS → ERKANNT         ← korrekt
          "user@example.com" → lookbehind blockiert @-Präfix → IGNORIERT ← kein E-Mail-FP
        """
        domains: Set[str] = set()

        # ── Schritt 1: <a href> aus formatted_body ────────────────────────────
        if formatted_body:
            for href in _HREF_RE.findall(formatted_body):
                href = href.strip()
                # Nicht-HTTP-Schemata und relative Pfade überspringen
                if href.startswith((
                    "mailto:", "matrix:", "mxc:", "tel:", "xmpp:",
                    "#", "/", "data:",
                )):
                    continue
                try:
                    if href.startswith("//"):
                        href = "https:" + href
                    elif not href.startswith(("http://", "https://")):
                        href = "https://" + href
                    host = urlparse(href).netloc.split(":")[0].lower()
                    if host.startswith("www."):
                        host = host[4:]
                    if host and "." in host:
                        domains.add(host)
                except Exception:
                    continue

        # ── Schritt 2: _URL_RE auf Klartext (http://, www.) ──────────────────
        for raw in _URL_RE.findall(body):
            try:
                url = raw if raw.startswith("http") else "http://" + raw
                host = urlparse(url).netloc.split(":")[0].lower()
                if host.startswith("www."):
                    host = host[4:]
                if host and "." in host:
                    domains.add(host)
            except Exception:
                continue

        # ── Schritt 3: _NAKED_DOMAIN_RE + TLD-Validierung ────────────────────
        for candidate in _NAKED_DOMAIN_RE.findall(body):
            candidate = candidate.lower()
            if "." not in candidate:
                continue
            last_dot = candidate.rfind(".")
            tld = candidate[last_dot + 1:]
            domain_part = candidate[:last_dot]
            # TLD muss ausschließlich Buchstaben enthalten UND im bekannten Set sein
            if not tld.isalpha() or tld not in _COMMON_TLDS or not domain_part:
                continue
            # "www."-Präfix für konsistente Blacklist-Abgleichung entfernen
            final = candidate[4:] if candidate.startswith("www.") else candidate
            if final and "." in final:
                domains.add(final)

        return domains

    @staticmethod
    def _find_url_for_domain(
        body: str,
        domain: str,
        formatted_body: Optional[str] = None,
    ) -> Optional[str]:
        """
        Gibt die beste verfügbare URL für `domain` zurück — für Linkvorschau-Anfragen.

        Suchreihenfolge (höchste Qualität zuerst):
          1. Vollständige URL aus formatted_body <a href> (korrekte Schemata garantiert).
          2. URL aus _URL_RE auf Klartext (http://, www.).
          3. Konstruierte Fallback-URL: "https://{domain}" (für nackte Domains aus Schritt 3).
        """
        # Schritt 1: formatted_body hrefs
        if formatted_body:
            for href in _HREF_RE.findall(formatted_body):
                href = href.strip()
                if href.startswith(("mailto:", "matrix:", "mxc:", "tel:", "#", "/")):
                    continue
                try:
                    if href.startswith("//"):
                        href = "https:" + href
                    elif not href.startswith(("http://", "https://")):
                        href = "https://" + href
                    host = urlparse(href).netloc.split(":")[0].lower()
                    if host.startswith("www."):
                        host = host[4:]
                    if host == domain:
                        return href
                except Exception:
                    continue

        # Schritt 2: _URL_RE auf Klartext
        for raw in _URL_RE.findall(body):
            try:
                url = raw if raw.startswith("http") else "http://" + raw
                host = urlparse(url).netloc.split(":")[0].lower()
                if host.startswith("www."):
                    host = host[4:]
                if host == domain:
                    return url
            except Exception:
                continue

        # Schritt 3: Fallback — URL aus Domain konstruieren (für nackte Domains)
        return f"https://{domain}"

    @staticmethod
    def _matches_wildcards(domain: str, wildcards: Set[str]) -> bool:
        """
        Prüft, ob `domain` einem Wildcard-Muster *.suffix entspricht.

        Speicherinhalt in `wildcards`: das Suffix OHNE "*."-Präfix.
        Beispiel: Wildcard "*.banned.com" → wildcards enthält "banned.com".

        Übereinstimmungsregel:
          "sub.banned.com".endswith(".banned.com")  → True   ✓
          "api.banned.com".endswith(".banned.com")  → True   ✓
          "banned.com".endswith(".banned.com")      → False  ✓ (Root-Domain nicht betroffen)
          "notbanned.com".endswith(".banned.com")   → False  ✓

        Komplexität: O(k) wobei k = Anzahl der Wildcards.
        In der Praxis klein (manuell gepflegte Einträge) — daher effizient genug.
        """
        for suffix in wildcards:
            if domain.endswith("." + suffix):
                return True
        return False


    # ===========================================================================
    # ABSCHNITT 10 — HAUPT-NACHRICHTENHANDLER
    # ===========================================================================

    @event.on(EventType.ROOM_MESSAGE)
    async def on_message(self, evt: MessageEvent) -> None:
        """
        Einstiegspunkt für jede Raumnachricht.

        Sicherheitsprüfungen (kurz-geschlossen in Reihenfolge der Güte):
          • Eigene Nachrichten des Bots überspringen — verhindert Feedback-Schleifen.
          • Nicht-TEXT-Nachrichtentypen überspringen — Bilder, Dateien, Reaktionen, etc.

        Domain-Kategorisierung (einmaliger Durchlauf):
          • whitelist_set wird ZUERST geprüft — explizites Erlauben gewinnt immer.
          • blacklist_set wird danach geprüft.
          • Keins von beiden → unbekannt.

        Routing-Priorität (höchster Schweregrad zuerst):
          1. Jede gesperrte Domain   → Nachricht löschen + Warnung ausgeben.
          2. Jede unbekannte Domain  → Nachricht löschen + an Mod-Raum weiterleiten.
          3. Alle Domains whitelisted → erlauben + optionale Markdown-Vorschau.
        """
        # ── Deduplizierungs-Wächter — MUSS die allererste Prüfung sein ────────
        # WARUM ZUERST: Matrix-/sync kann dieselbe event_id mehrfach zusenden:
        #   • Nach Bot-Neustart (Homeserver sendet Ereignisse seit letztem `since` erneut)
        #   • Bei Rennbedingungen beim Plugin-Reload innerhalb von Maubot
        #   • Bei Netzwerk-Reconnects, bevor das `since`-Token gespeichert ist
        # Jedes davon lässt on_message() für dieselbe Nachricht 2–3-mal auslösen,
        # was doppelte Hinweise und Mod-Raum-Alarme erzeugt ("Dreifach-Posting").
        #
        # Durch Prüfung der event_id VOR den Absender/Nachrichtentyp-Wächtern
        # fangen wir auch den Randfall ab, wo eigene replayed Events des Bots
        # andernfalls beim zweiten Zustellversuch mit veralteten Absenderfeldern
        # die Absenderprüfung passieren würden.
        #
        # PRE-AWAIT-GARANTIE (asyncio-Rennbedingungssicherheit)
        # ───────────────────────────────────────────────────────
        # In asyncio wechselt der Coroutine-Kontext NUR bei `await`-Punkten.
        # Alles von hier bis einschließlich _seen_events.add() ist 100% synchron
        # (kein yield, kein await). Das bedeutet:
        #
        #   Falls dieselbe event_id zweimal schnell hintereinander ankommt (zwei
        #   on_message()-Coroutinen back-to-back geplant), wird die erste immer
        #   .add() erreichen, bevor die zweite das Set prüft.
        #   Die zweite Coroutine sieht die event_id daher immer schon vorhanden
        #   und kehrt sofort zurück.
        #
        # Es gibt KEIN Fenster zwischen der `if event_id in`-Prüfung und dem
        # `.add()`-Aufruf, wo ein Kontextwechsel stattfinden könnte. Die
        # Deduplizierung ist innerhalb des asyncio-Event-Loops atomar.
        event_id = evt.event_id
        if event_id in self._seen_events:
            self.log.debug("Duplikat: Bereits verarbeitetes Ereignis %s wird übersprungen.", event_id)
            return
        # ← .add() und .append() passieren hier, VOR dem ersten `await` irgendwo
        #   in dieser Coroutine. Alle nachfolgenden Zeilen bis zum ersten `await`
        #   (innerhalb _handle_blacklisted / _handle_unknown / _post_link_preview)
        #   sind ebenfalls synchron. Das Cache-Update ist garantiert für jede
        #   gleichzeitig geplante Geschwister-Coroutine sofort sichtbar.
        self._seen_events.add(event_id)
        self._seen_events_q.append(event_id)
        if len(self._seen_events_q) > self._SEEN_EVENTS_MAX:
            evicted = self._seen_events_q.popleft()
            self._seen_events.discard(evicted)

        # ── Standard-Sicherheitsprüfungen ────────────────────────────────────
        if evt.sender == self.client.mxid:
            return
        if evt.content.msgtype != MessageType.TEXT:
            return

        body: str = evt.content.body or ""

        # formatted_body enthält HTML-Markup (z.B. <a href="...">), wenn der
        # Matrix-Client es gesendet hat (Format: "org.matrix.custom.html").
        # Es ist die zuverlässigste Quelle für Link-Erkennung (Schritt 1 in
        # _extract_domains). Bei Clients ohne Formatierung ist es None.
        formatted_body: Optional[str] = getattr(evt.content, "formatted_body", None) or None

        domains = self._extract_domains(body, formatted_body)
        if not domains:
            return

        blacklisted: List[str] = []
        unknown:     List[str] = []
        whitelisted: List[str] = []

        for domain in domains:
            # Prüfreihenfolge: Whitelist (exakt) → Whitelist (Wildcard) → Blacklist (exakt)
            # → Blacklist (Wildcard) → Unbekannt.
            # Whitelist hat immer Vorrang, auch gegenüber einer gleichzeitigen Blacklist-Übereinstimmung.
            if (domain in self.whitelist_set
                    or self._matches_wildcards(domain, self.whitelist_wildcards)):
                whitelisted.append(domain)
            elif (domain in self.blacklist_set
                    or self._matches_wildcards(domain, self.blacklist_wildcards)):
                blacklisted.append(domain)
            else:
                unknown.append(domain)

        message_redacted = False

        if blacklisted:
            message_redacted = await self._handle_blacklisted(blacklisted, evt)
        elif unknown:
            message_redacted = await self._handle_unknown(unknown, evt)

        if (
            not message_redacted
            and whitelisted
            and self.config["enable_link_previews"]
        ):
            for domain in whitelisted:
                url = self._find_url_for_domain(body, domain, formatted_body)
                if url:
                    await self._post_link_preview(domain, url, evt.room_id)


    # ===========================================================================
    # ABSCHNITT 11 — ROUTING-AKTIONSHANDLER
    # ===========================================================================

    async def _handle_blacklisted(
        self, domains: List[str], evt: MessageEvent
    ) -> bool:
        """
        Behandelt Nachrichten mit mindestens einer gesperrten Domain.
        Löscht die Nachricht und sendet eine Warnung, die alle gesperrten Domains nennt.
        Gibt True zurück, wenn das Löschen erfolgreich war.
        """
        # HINWEIS: Der Löschgrund ist nur in den Maubot-/Homeserver-Logs sichtbar —
        # er wird in keinem Standard-Matrix-Client den Raummitgliedern angezeigt.
        redacted = await self._redact(
            evt.room_id, evt.event_id,
            reason=f"Gesperrte Domain(s): {', '.join(domains[:3])}",
        )
        # SICHERHEIT: Die Domain-Namen NICHT an Raummitglieder weitergeben.
        # Das Offenlegen, welche Domain den Block ausgelöst hat, ermöglicht
        # Angreifern, trivial auf eine noch nicht gelistete Domain auszuweichen.
        # Moderatoren können die vollständige Domain in den Maubot-Logs über
        # den obigen Löschgrund einsehen.
        await self._send_notice(
            evt.room_id,
            f"⚠️ {evt.sender}: Deine Nachricht wurde entfernt, da sie einen gesperrten Link enthielt. "
            f"Wende dich an einen Moderator, wenn du glaubst, dass dies ein Fehler ist.",
        )
        return redacted

    async def _handle_unknown(
        self, domains: List[str], evt: MessageEvent
    ) -> bool:
        """
        Behandelt Nachrichten mit unbekannten (nicht gelisteten) Domains.
        Löscht die Nachricht, benachrichtigt den Nutzer und reicht jede Domain
        als separate Überprüfungsanfrage an den Mod-Raum ein.
        Gibt True zurück, wenn das Löschen erfolgreich war.
        """
        redacted = await self._redact(
            evt.room_id, evt.event_id,
            reason="Unbekannte Domain(s) — ausstehende Moderatorenüberprüfung",
        )
        await self._send_notice(
            evt.room_id,
            f"🔍 {evt.sender}: Deine Nachricht mit einem unbekannten Link wurde entfernt "
            f"und zur Überprüfung an die Moderatoren weitergeleitet. "
            f"Du wirst benachrichtigt, sobald eine Entscheidung getroffen wurde.",
        )
        for domain in domains:
            await self._submit_for_review(domain, evt)
        return redacted

    async def _post_link_preview(
        self, domain: str, url: str, room_id: RoomID
    ) -> None:
        """
        Ruft OG-Metadaten ab und postet eine saubere Markdown-Vorschaubenachrichtigung.
        Verwendet nur **Fettdruck** und > Blockzitate — wird in allen gängigen
        Matrix-Clients korrekt angezeigt (Element, FluffyChat, Nheko, Cinny, SchildiChat).
        """
        meta = await self._fetch_og_metadata(url)
        if not meta:
            return
        title = meta.get("title") or domain
        desc  = meta.get("description") or ""
        lines = [f"**{title}**"]
        if desc:
            lines.append(f"> {desc}")
        lines.append(f"[{domain}]({url})")
        await self._send_notice(room_id, "\n".join(lines), render_markdown=True)


    # ===========================================================================
    # ABSCHNITT 12 — MODERATIONSRAUM: PRÜFANFRAGE EINREICHEN
    # ===========================================================================

    async def _submit_for_review(self, domain: str, evt: MessageEvent) -> None:
        """
        Sendet eine strukturierte Benachrichtigung an den Mod-Raum für eine unbekannte Domain.

        Der Alarm enthält Absender, Raum, Domain und Anweisungen für
        sowohl Emoji-Reaktions- als auch befehlsbasierte Auflösung.

        Der Bot reagiert sofort auf seinen eigenen Alarm mit ✅ und ❌, damit
        Moderatoren direkt in der Timeline klicken können.

        Die Überprüfung wird in pending_reviews BEVOR Reaktionen gepostet werden
        registriert, um eine Rennbedingung zu vermeiden, bei der ein sehr schneller
        Klick ankommt, bevor der Eintrag registriert ist.
        """
        mod_room: str = self.config.get("mod_room_id", "")
        if not mod_room:
            self.log.warning(
                "mod_room_id nicht konfiguriert — '%s' kann nicht zur Überprüfung weitergeleitet werden.", domain
            )
            return

        # ── Doppelter-Alarm-Wächter ───────────────────────────────────────────
        # Wenn dieselbe Domain bereits auf eine Entscheidung im Mod-Raum wartet,
        # keinen weiteren Alarm posten oder weitere Emoji-Reaktionen hinzufügen.
        # Das verhindert, dass der Mod-Raum überflutet wird, wenn eine Domain
        # wiederholt geteilt wird, während eine Überprüfung noch offen ist.
        if domain in self._pending_domains:
            self.log.info(
                "Domain '%s' hat bereits eine offene Überprüfung — doppelter Alarm wird übersprungen.", domain
            )
            return

        alert_text = (
            f"🔔 **URL-Überprüfung erforderlich**\n\n"
            f"**Absender:** {evt.sender}\n"
            f"**Raum:** `{evt.room_id}`\n"
            f"**Domain:** `{domain}`\n\n"
            f"Reagiere mit {_EMOJI_ALLOW} zum **Whitelisten** oder {_EMOJI_BLOCK} zum **Blacklisten**.\n"
            f"Oder verwende: `!allow {domain}` / `!block {domain}`"
        )

        alert_id = await self._send_notice(mod_room, alert_text, render_markdown=True)
        if not alert_id:
            self.log.error("Alarm für '%s' konnte nicht an den Mod-Raum gesendet werden.", domain)
            return

        review = PendingReview(
            domain=domain,
            original_event_id=evt.event_id,
            original_room_id=evt.room_id,
            sender=evt.sender,
        )
        # VOR dem Posten von Reaktionen registrieren (Rennbedingungssicherheit).
        # Auch in _pending_domains registrieren, damit nachfolgende Nachrichten
        # mit derselben Domain still übersprungen werden, anstatt den Mod-Raum zu fluten.
        self.pending_reviews[alert_id] = review
        self._pending_domains.add(domain)

        review.whitelist_reaction_id = await self._send_reaction(
            mod_room, alert_id, _EMOJI_ALLOW
        )
        review.blacklist_reaction_id = await self._send_reaction(
            mod_room, alert_id, _EMOJI_BLOCK
        )

        self.log.info(
            "Überprüfung eingereicht: domain='%s' absender=%s raum=%s alarm=%s",
            domain, evt.sender, evt.room_id, alert_id,
        )


    # ===========================================================================
    # ABSCHNITT 13 — REAKTIONS-EVENTHANDLER
    # ===========================================================================

    @event.on(EventType.REACTION)
    async def on_reaction(self, evt: MessageEvent) -> None:
        """
        Verarbeitet m.reaction-Ereignisse im Mod-Raum.

        Kurz-Schluss-Prüfungen (günstigste zuerst):
          1. Eigene Reaktionen des Bots ignorieren (die ✅/❌-Schaltflächen, die er postet).
          2. Reaktionen außerhalb des Mod-Raums ignorieren.
          3. Nicht-annotation rel_types ignorieren.
          4. Reaktionen auf Ereignisse, die nicht in pending_reviews stehen, ignorieren.
          5. Moderationsberechtigungen prüfen.
          6. Auf Emoji-Schlüssel reagieren.
        """
        if evt.sender == self.client.mxid:
            return
        if evt.room_id != self.config.get("mod_room_id", ""):
            return

        relates_to = getattr(evt.content, "relates_to", None)
        if relates_to is None:
            return
        if str(getattr(relates_to, "rel_type", "")) != "m.annotation":
            return

        target_id = getattr(relates_to, "event_id", None)
        emoji_key = getattr(relates_to, "key", None)

        review = self.pending_reviews.get(target_id)
        if not review:
            return

        if not await self._is_mod(evt.sender, evt.room_id):
            self.log.info(
                "Moderationsaktion für %s auf Domain '%s' verweigert (unzureichende Berechtigungen).",
                evt.sender, review.domain,
            )
            return

        if emoji_key == _EMOJI_ALLOW:
            await self._execute_allow(review, target_id, evt.sender)
        elif emoji_key == _EMOJI_BLOCK:
            await self._execute_block(review, target_id, evt.sender)
        # Andere Emojis auf unseren Alarm werden still ignoriert


    # ===========================================================================
    # ABSCHNITT 14 — MODERATIONSAUSFÜHRUNG
    # ===========================================================================

    async def _execute_allow(
        self,
        review: PendingReview,
        alert_id: EventID,
        mod_user: UserID,
    ) -> None:
        """
        Genehmigt eine Domain:
          1. In whitelists/custom.txt persistieren (Datei zuerst für Konsistenz).
          2. In-Memory-Sets aktualisieren.
          3. Aus pending_reviews entfernen.
          4. Mod-Raum-Alarm zur Anzeige der Auflösung bearbeiten.
          5. Originalraum benachrichtigen.
        """
        domain  = review.domain
        wl_file = os.path.abspath(os.path.join(self.config["whitelist_dir"], "custom.txt"))

        try:
            await self._append_to_file(domain, wl_file)
        except PermissionError:
            # Vollständiger Traceback bereits in den Maubot-Logs via self.log.exception()
            await self._send_notice(
                self.config["mod_room_id"],
                f"❌ **Zugriff verweigert:** Der Bot kann nicht in `{wl_file}` schreiben.\n\n"
                f"Bitte prüfe die Docker-Volume-Berechtigungen.\n"
                f"Führe auf dem Docker-Host aus:\n"
                f"```\nchown -R 1337:1337 ./data/whitelists ./data/blacklists\n```\n"
                f"(Maubot läuft standardmäßig als UID 1337 im Docker-Container.)",
            )
            return
        except Exception as exc:
            await self._send_notice(
                self.config["mod_room_id"],
                f"❌ **Schreibfehler (Whitelist):** `{domain}` konnte nicht gespeichert werden.\n"
                f"Pfad: `{wl_file}`\n"
                f"Fehler: `{type(exc).__name__}: {exc}`\n"
                f"Vollständiger Traceback in den Maubot-Logs.",
            )
            return

        self.whitelist_set.add(domain)
        self.blacklist_set.discard(domain)
        self.pending_reviews.pop(alert_id, None)
        self._pending_domains.discard(domain)   # Bei Bedarf für zukünftige Überprüfungen wieder öffnen

        await self._edit_notice(
            self.config["mod_room_id"],
            alert_id,
            f"✅ **Whitelisted** von {mod_user}\nDomain `{domain}` ist jetzt erlaubt.",
        )
        await self._send_notice(
            review.original_room_id,
            f"✅ Der Link zu `{domain}` (gesendet von {review.sender}) wurde von den Moderatoren "
            f"**genehmigt**. Du kannst deine Nachricht erneut senden.",
        )
        self.log.info("Domain '%s' von %s auf die Whitelist gesetzt.", domain, mod_user)

    async def _execute_block(
        self,
        review: PendingReview,
        alert_id: EventID,
        mod_user: UserID,
    ) -> None:
        """
        Sperrt eine Domain:
          1. In blacklists/custom.txt persistieren.
          2. In-Memory-Sets aktualisieren.
          3. Aus pending_reviews entfernen.
          4. Mod-Raum-Alarm bearbeiten.
          5. Originalraum benachrichtigen.
        """
        domain  = review.domain
        bl_file = os.path.abspath(os.path.join(self.config["blacklist_dir"], "custom.txt"))

        try:
            await self._append_to_file(domain, bl_file)
        except PermissionError:
            await self._send_notice(
                self.config["mod_room_id"],
                f"❌ **Zugriff verweigert:** Der Bot kann nicht in `{bl_file}` schreiben.\n\n"
                f"Bitte prüfe die Docker-Volume-Berechtigungen.\n"
                f"Führe auf dem Docker-Host aus:\n"
                f"```\nchown -R 1337:1337 ./data/whitelists ./data/blacklists\n```\n"
                f"(Maubot läuft standardmäßig als UID 1337 im Docker-Container.)",
            )
            return
        except Exception as exc:
            await self._send_notice(
                self.config["mod_room_id"],
                f"❌ **Schreibfehler (Blacklist):** `{domain}` konnte nicht gespeichert werden.\n"
                f"Pfad: `{bl_file}`\n"
                f"Fehler: `{type(exc).__name__}: {exc}`\n"
                f"Vollständiger Traceback in den Maubot-Logs.",
            )
            return

        self.blacklist_set.add(domain)
        self.whitelist_set.discard(domain)
        self.pending_reviews.pop(alert_id, None)
        self._pending_domains.discard(domain)   # Jetzt auf Blacklist — keine weitere Überprüfung nötig

        await self._edit_notice(
            self.config["mod_room_id"],
            alert_id,
            f"❌ **Blacklisted** von {mod_user}\nDomain `{domain}` ist jetzt gesperrt.",
        )
        await self._send_notice(
            review.original_room_id,
            f"🚫 Ein Link gesendet von {review.sender} wurde von den Moderatoren "
            f"**gesperrt**.",
        )
        self.log.info("Domain '%s' von %s auf die Blacklist gesetzt.", domain, mod_user)


    # ===========================================================================
    # ABSCHNITT 15 — BEFEHLSHANDLER
    # ===========================================================================

    @command.new("allow", help="[Mod] Domain whitelisten. Verwendung: !allow <domain> oder !allow *.domain.com")
    @command.argument("domain", pass_raw=True, required=True)
    async def cmd_allow(self, evt: MessageEvent, domain: str) -> None:
        """!allow <domain> — Domain manuell whitelisten. Wildcards (*.domain.com) werden unterstützt."""
        domain = _clean_domain_arg(domain)
        if not _valid_domain(domain):
            await evt.reply(
                "❌ Verwendung: `!allow <domain>` oder `!allow *.domain.com`\n"
                "Beispiele: `!allow example.com` · `!allow *.trusted-cdn.net`"
            )
            return
        if not await self._is_mod(evt.sender, evt.room_id):
            await evt.reply("❌ Du hast keine Berechtigung, Domains zu whitelisten.")
            return
        wl_file = os.path.abspath(os.path.join(self.config["whitelist_dir"], "custom.txt"))
        is_wildcard = domain.startswith("*.")
        suffix = domain[2:] if is_wildcard else None
        try:
            await self._append_to_file(domain, wl_file)
            if is_wildcard:
                self.whitelist_wildcards.add(suffix)
                self.blacklist_wildcards.discard(suffix)
            else:
                self.whitelist_set.add(domain)
                self.blacklist_set.discard(domain)
            await evt.reply(f"✅ `{domain}` wurde zur Whitelist hinzugefügt.")
            self.log.info("'%s' manuell von %s auf die Whitelist gesetzt.", domain, evt.sender)
        except PermissionError:
            await evt.reply(
                f"❌ **Zugriff verweigert:** Kein Schreibzugriff auf `{wl_file}`.\n"
                f"Bitte prüfe die Docker-Volume-Berechtigungen:\n"
                f"`chown -R 1337:1337 ./data/whitelists ./data/blacklists`"
            )
        except Exception as exc:
            await evt.reply(
                f"❌ Schreibfehler (`{type(exc).__name__}`): `{exc}`\n"
                f"Pfad: `{wl_file}` — Vollständiger Traceback in den Maubot-Logs."
            )

    @command.new("block", help="[Mod] Domain blacklisten. Verwendung: !block <domain> oder !block *.domain.com")
    @command.argument("domain", pass_raw=True, required=True)
    async def cmd_block(self, evt: MessageEvent, domain: str) -> None:
        """!block <domain> — Domain manuell blacklisten. Wildcards (*.domain.com) werden unterstützt."""
        domain = _clean_domain_arg(domain)
        if not _valid_domain(domain):
            await evt.reply(
                "❌ Verwendung: `!block <domain>` oder `!block *.domain.com`\n"
                "Beispiele: `!block malware.example.com` · `!block *.phishing-netz.de`"
            )
            return
        if not await self._is_mod(evt.sender, evt.room_id):
            await evt.reply("❌ Du hast keine Berechtigung, Domains zu blacklisten.")
            return
        bl_file = os.path.abspath(os.path.join(self.config["blacklist_dir"], "custom.txt"))
        is_wildcard = domain.startswith("*.")
        suffix = domain[2:] if is_wildcard else None
        try:
            await self._append_to_file(domain, bl_file)
            if is_wildcard:
                self.blacklist_wildcards.add(suffix)
                self.whitelist_wildcards.discard(suffix)
            else:
                self.blacklist_set.add(domain)
                self.whitelist_set.discard(domain)
            await evt.reply(f"🚫 `{domain}` wurde zur Blacklist hinzugefügt.")
            self.log.info("'%s' manuell von %s auf die Blacklist gesetzt.", domain, evt.sender)
        except PermissionError:
            await evt.reply(
                f"❌ **Zugriff verweigert:** Kein Schreibzugriff auf `{bl_file}`.\n"
                f"Bitte prüfe die Docker-Volume-Berechtigungen:\n"
                f"`chown -R 1337:1337 ./data/whitelists ./data/blacklists`"
            )
        except Exception as exc:
            await evt.reply(
                f"❌ Schreibfehler (`{type(exc).__name__}`): `{exc}`\n"
                f"Pfad: `{bl_file}` — Vollständiger Traceback in den Maubot-Logs."
            )

    @command.new("unallow", help="[Mod] Domain aus der Whitelist entfernen. Verwendung: !unallow <domain>")
    @command.argument("domain", pass_raw=True, required=True)
    async def cmd_unallow(self, evt: MessageEvent, domain: str) -> None:
        """
        !unallow <domain> — Entfernt eine Domain (oder Wildcard) aus der Whitelist.
        Ändert nur whitelists/custom.txt — große externe Listendateien bleiben unberührt.
        Erfordert Moderationsberechtigungen.
        """
        domain = _clean_domain_arg(domain)
        if not _valid_domain(domain):
            await evt.reply("❌ Verwendung: `!unallow <domain>` oder `!unallow *.domain.com`")
            return
        if not await self._is_mod(evt.sender, evt.room_id):
            await evt.reply("❌ Du hast keine Berechtigung, Domains aus der Whitelist zu entfernen.")
            return
        wl_file = os.path.abspath(os.path.join(self.config["whitelist_dir"], "custom.txt"))
        is_wildcard = domain.startswith("*.")
        suffix = domain[2:] if is_wildcard else None
        try:
            await self._remove_from_file(domain, wl_file)
            if is_wildcard:
                self.whitelist_wildcards.discard(suffix)
            else:
                self.whitelist_set.discard(domain)
            # BUG-FIX: {domain} wird hier als Variable interpoliert,
            # NICHT als wörtlicher String "domain" ausgegeben.
            await evt.reply(f"✅ `{domain}` wurde erfolgreich aus der Whitelist entfernt.")
            self.log.info("'%s' aus der Whitelist entfernt von %s.", domain, evt.sender)
        except PermissionError:
            await evt.reply(
                f"❌ **Zugriff verweigert:** Kein Schreibzugriff auf `{wl_file}`.\n"
                f"Bitte prüfe die Docker-Volume-Berechtigungen:\n"
                f"`chown -R 1337:1337 ./data/whitelists ./data/blacklists`"
            )
        except Exception as exc:
            await evt.reply(
                f"❌ Fehler beim Entfernen von `{domain}` (`{type(exc).__name__}`): `{exc}`\n"
                f"Pfad: `{wl_file}` — Vollständiger Traceback in den Maubot-Logs."
            )

    @command.new("unblock", help="[Mod] Domain aus der Blacklist entfernen. Verwendung: !unblock <domain>")
    @command.argument("domain", pass_raw=True, required=True)
    async def cmd_unblock(self, evt: MessageEvent, domain: str) -> None:
        """
        !unblock <domain> — Entfernt eine Domain (oder Wildcard) aus der Blacklist.
        Ändert nur blacklists/custom.txt — große externe Listendateien bleiben unberührt.
        Erfordert Moderationsberechtigungen.
        """
        domain = _clean_domain_arg(domain)
        if not _valid_domain(domain):
            await evt.reply("❌ Verwendung: `!unblock <domain>` oder `!unblock *.domain.com`")
            return
        if not await self._is_mod(evt.sender, evt.room_id):
            await evt.reply("❌ Du hast keine Berechtigung, Domains aus der Blacklist zu entfernen.")
            return
        bl_file = os.path.abspath(os.path.join(self.config["blacklist_dir"], "custom.txt"))
        is_wildcard = domain.startswith("*.")
        suffix = domain[2:] if is_wildcard else None
        try:
            await self._remove_from_file(domain, bl_file)
            if is_wildcard:
                self.blacklist_wildcards.discard(suffix)
            else:
                self.blacklist_set.discard(domain)
            # BUG-FIX: {domain} wird hier als Variable interpoliert,
            # NICHT als wörtlicher String "domain" ausgegeben.
            await evt.reply(f"✅ `{domain}` wurde erfolgreich aus der Blacklist entfernt.")
            self.log.info("'%s' aus der Blacklist entfernt von %s.", domain, evt.sender)
        except PermissionError:
            await evt.reply(
                f"❌ **Zugriff verweigert:** Kein Schreibzugriff auf `{bl_file}`.\n"
                f"Bitte prüfe die Docker-Volume-Berechtigungen:\n"
                f"`chown -R 1337:1337 ./data/whitelists ./data/blacklists`"
            )
        except Exception as exc:
            await evt.reply(
                f"❌ Fehler beim Entfernen von `{domain}` (`{type(exc).__name__}`): `{exc}`\n"
                f"Pfad: `{bl_file}` — Vollständiger Traceback in den Maubot-Logs."
            )

    @command.new("urlstatus", help="Aktuellen Richtlinienstatus einer Domain prüfen.")
    @command.argument("domain", pass_raw=True, required=True)
    async def cmd_status(self, evt: MessageEvent, domain: str) -> None:
        """!urlstatus <domain> — Gibt aus ob eine Domain whitelisted / blacklisted / unbekannt ist (inkl. Wildcards)."""
        domain = _clean_domain_arg(domain)
        if not _valid_domain(domain):
            await evt.reply("❌ Verwendung: `!urlstatus <domain>`")
            return
        if domain in self.whitelist_set:
            await evt.reply(f"✅ `{domain}` ist **whitelisted** (exakter Eintrag).")
        elif self._matches_wildcards(domain, self.whitelist_wildcards):
            await evt.reply(f"✅ `{domain}` ist **whitelisted** (Wildcard-Treffer).")
        elif domain in self.blacklist_set:
            await evt.reply(f"🚫 `{domain}` ist **blacklisted** (exakter Eintrag).")
        elif self._matches_wildcards(domain, self.blacklist_wildcards):
            await evt.reply(f"🚫 `{domain}` ist **blacklisted** (Wildcard-Treffer).")
        else:
            await evt.reply(f"❓ `{domain}` ist **unbekannt** (auf keiner Liste).")

    @command.new("reloadlists", help="[Mod] Alle Listendateien von der Festplatte neu einlesen.")
    async def cmd_reload(self, evt: MessageEvent) -> None:
        """
        !reloadlists — Lädt alle .txt-Dateien neu, ohne den Bot neu starten zu müssen.
        Läuft nicht-blockierend im Hintergrund. Erfordert Moderationsberechtigungen.
        """
        if not await self._is_mod(evt.sender, evt.room_id):
            await evt.reply("❌ Du hast keine Berechtigung, Listen neu zu laden.")
            return
        old_bl = len(self.blacklist_set)
        old_wl = len(self.whitelist_set)
        old_bl_wc = len(self.blacklist_wildcards)
        old_wl_wc = len(self.whitelist_wildcards)
        await evt.reply("🔄 Listen werden im Hintergrund neu geladen – dies kann ca. 30 Sek. dauern...")
        await self._reload_lists()
        await self._send_notice(
            evt.room_id,
            f"🏁 Neuladen abgeschlossen.\n"
            f"Blacklist: **{old_bl:,}** → **{len(self.blacklist_set):,}** Domains "
            f"(Wildcards: {old_bl_wc} → {len(self.blacklist_wildcards)})\n"
            f"Whitelist: **{old_wl:,}** → **{len(self.whitelist_set):,}** Domains "
            f"(Wildcards: {old_wl_wc} → {len(self.whitelist_wildcards)})",
            render_markdown=True,
        )

    @command.new("pending", help="[Mod] Offene URL-Überprüfungsanfragen auflisten.")
    async def cmd_pending(self, evt: MessageEvent) -> None:
        """!pending — Zeigt alle Domains, die auf eine Moderationsentscheidung warten. Erfordert Mod-Berechtigung."""
        if not await self._is_mod(evt.sender, evt.room_id):
            await evt.reply("❌ Du hast keine Berechtigung, ausstehende Überprüfungen einzusehen.")
            return
        if not self.pending_reviews:
            await evt.reply("✅ Keine ausstehenden URL-Überprüfungen.")
            return
        lines = [f"**{len(self.pending_reviews)} ausstehende Überprüfung(en):**\n"]
        for alert_id, rev in self.pending_reviews.items():
            age_s = int(time.monotonic() - rev.submitted_at)
            lines.append(
                f"• `{rev.domain}` — {rev.sender} in `{rev.original_room_id}` (vor {age_s}s)"
            )
        await self._send_notice(evt.room_id, "\n".join(lines), render_markdown=True)

    @command.new("liststats", help="Aktuelle Listengrößen und Bot-Statistiken anzeigen.")
    async def cmd_stats(self, evt: MessageEvent) -> None:
        """!liststats — Gibt Domain-Anzahl (inkl. Wildcards) und ausstehende Überprüfungen aus."""
        await evt.reply(
            f"📊 **Listen-Statistiken**\n"
            f"Blacklist: **{len(self.blacklist_set):,}** Domains + "
            f"**{len(self.blacklist_wildcards)}** Wildcards\n"
            f"Whitelist: **{len(self.whitelist_set):,}** Domains + "
            f"**{len(self.whitelist_wildcards)}** Wildcards\n"
            f"Ausstehende Überprüfungen: **{len(self.pending_reviews)}**"
        )

    @command.new("hilfe", help="Zeigt alle Befehle (nur per Direktnachricht / DM).")
    async def cmd_hilfe(self, evt: MessageEvent) -> None:
        """
        !hilfe — Deutsche Hilfeübersicht, nur in Direktnachrichten (DMs) verfügbar.

        DM-PRÜFUNG
        ----------
        Eine Matrix-DM ist technisch ein normaler Raum mit genau 2 Mitgliedern
        (Bot + Nutzer). Wir prüfen die Mitgliederzahl über get_joined_members().
        Wenn der Raum mehr als 2 Mitglieder hat, weigert sich der Bot zu antworten
        und schickt stattdessen einen kurzen Hinweis in den Gruppenraum.

        Diese Einschränkung verhindert, dass die komplette Befehlsliste in
        öffentlichen Räumen ausgegeben wird und verhindert so, dass Nutzer
        gezielt nach nicht-öffentlichen Moderationsfunktionen suchen.
        """
        # ── DM-Prüfung ────────────────────────────────────────────────────────
        # get_joined_members() gibt ein Dict {user_id: MemberStateEventContent} zurück.
        # Genau 2 Einträge = Bot + ein Gesprächspartner → DM.
        try:
            members = await self.client.get_joined_members(evt.room_id)
            is_dm = len(members) == 2
        except Exception as exc:
            self.log.warning("Konnte Mitgliederzahl für %s nicht abrufen: %s", evt.room_id, exc)
            # Im Zweifelsfall ablehnen (fail-closed)
            is_dm = False

        if not is_dm:
            await evt.reply(
                "ℹ️ Der Befehl `!hilfe` ist **nur per Direktnachricht** verfügbar.\n"
                "Bitte schreibe mir direkt eine Nachricht und tippe dort `!hilfe`."
            )
            return

        # ── Hilfetext auf Deutsch ─────────────────────────────────────────────
        help_text = (
            "🤖 **URL-Filter-Bot — Befehlsübersicht**\n\n"

            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "🔓 **Öffentliche Befehle** *(für alle Nutzer)*\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"

            "**`!urlstatus <domain>`**\n"
            "> Zeigt an, ob eine Domain auf der Whitelist, der Blacklist oder\n"
            "> keiner Liste steht.\n"
            "> Beispiel: `!urlstatus example.com`\n\n"

            "**`!liststats`**\n"
            "> Zeigt die Gesamtanzahl der geladenen Domains in der Blacklist\n"
            "> und Whitelist sowie die Anzahl offener Moderationsanfragen.\n\n"

            "**`!hilfe`**\n"
            "> Zeigt diese Übersicht — funktioniert ausschließlich per Direktnachricht.\n\n"

            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "🔐 **Moderationsbefehle** *(nur für Moderatoren)*\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"

            "Berechtigung: Mindest-Powerlevel im Moderationsraum **oder** Eintrag\n"
            "in der Liste `allowed_users` in der Bot-Konfiguration.\n\n"

            "**`!allow <domain>`**\n"
            "> Fügt eine Domain zur Whitelist hinzu. Wildcards werden unterstützt.\n"
            "> Gespeichert sofort im Arbeitsspeicher und in `whitelists/custom.txt`.\n"
            "> Beispiele: `!allow vertrauenswuerdig.de` · `!allow *.trusted-cdn.net`\n\n"

            "**`!block <domain>`**\n"
            "> Sperrt eine Domain (Blacklist). Wildcards werden unterstützt.\n"
            "> Gespeichert sofort im Arbeitsspeicher und in `blacklists/custom.txt`.\n"
            "> Beispiele: `!block boese-seite.com` · `!block *.malware-netz.ru`\n\n"

            "**`!unallow <domain>`**\n"
            "> Entfernt eine Domain aus der Whitelist (nur aus `custom.txt`).\n"
            "> Externe Listendateien werden nicht verändert.\n"
            "> Beispiel: `!unallow vertrauenswuerdig.de`\n\n"

            "**`!unblock <domain>`**\n"
            "> Entfernt eine Domain aus der Blacklist (nur aus `custom.txt`).\n"
            "> Externe Listendateien werden nicht verändert.\n"
            "> Beispiel: `!unblock falsch-positiv.de`\n\n"

            "**`!reloadlists`**\n"
            "> Liest alle `.txt`-Dateien aus den konfigurierten Verzeichnissen\n"
            "> neu ein, ohne den Bot neu starten zu müssen.\n"
            "> Nützlich nach manuellen Änderungen an den Listendateien.\n"
            "> ⚠️ Dieser Vorgang kann bis zu ~30 Sekunden dauern.\n\n"

            "**`!pending`**\n"
            "> Listet alle Domains auf, die aktuell im Moderationsraum auf\n"
            "> eine Entscheidung warten (noch nicht genehmigt oder gesperrt).\n\n"

            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "⚙️ **Automatische Aktionen** *(kein Befehl nötig)*\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"

            "**Whitelist-Treffer** ✅\n"
            "> Die Nachricht bleibt stehen. Wenn Linkvorschauen aktiviert sind,\n"
            "> postet der Bot automatisch Titel und Beschreibung der Seite.\n\n"

            "**Blacklist-Treffer** 🚫\n"
            "> Die Nachricht wird sofort gelöscht (redact) und der Absender\n"
            "> erhält eine Warnung. (Der genaue Domain-Name wird aus Sicherheitsgründen\n"
            "> nicht im Raum angezeigt.)\n\n"

            "**Unbekannte Domain** 🔍\n"
            "> Die Nachricht wird entfernt. Im Originalraum erscheint ein Hinweis.\n"
            "> Im Moderationsraum erscheint eine Prüfanfrage mit zwei Reaktions-\n"
            "> knöpfen:\n"
            "> • **✅** — Domain zur Whitelist hinzufügen (genehmigen)\n"
            "> • **❌** — Domain zur Blacklist hinzufügen (sperren)\n\n"

            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "📂 **Dateiformat der Listen**\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"

            "Alle `.txt`-Dateien im Blacklist-/Whitelist-Verzeichnis werden beim\n"
            "Start gelesen. Unterstützte Formate pro Zeile:\n"
            "> `# Kommentar` — wird ignoriert\n"
            "> `0.0.0.0 domain.com` — Standard-Hostfile-Format (Pi-hole etc.)\n"
            "> `127.0.0.1 domain.com` — alternatives Loopback-Format\n"
            "> `domain.com` — einfache Domain\n"
            "> `*.domain.com` — Wildcard: trifft alle Subdomains (z.B. api.domain.com)\n\n"

            "**URL-Erkennung im Chat:**\n"
            "> Der Bot erkennt Links mit `https://`, mit `www.` UND nackte Domains wie\n"
            "> `bannedurl.com` direkt im Text. Zur Vermeidung von Falsch-Positiven\n"
            "> (z.B. Tippfehler wie 'hallo.du') wird die TLD gegen eine bekannte Liste\n"
            "> geprüft — 'du' ist keine gültige TLD und wird ignoriert.\n\n"

            "Moderationsentscheidungen (✅/❌ oder `!allow`/`!block`) werden\n"
            "automatisch in `custom.txt` im jeweiligen Verzeichnis gespeichert."
        )

        await self._send_notice(evt.room_id, help_text, render_markdown=True)

    # ===========================================================================
    # ABSCHNITT 16 — BERECHTIGUNGSPRÜFUNG
    # ===========================================================================

    async def _is_mod(self, user_id: UserID, room_id: Optional[RoomID] = None) -> bool:
        """
        Gibt True zurück, wenn user_id Moderationsrechte besitzt.

        Zwei unabhängige Prüfungen (jede genügt zum Bestehen):
          1. user_id ist in config.mod_permissions.allowed_users (explizite Liste).
          2. Powerlevel von user_id im Mod-Raum >= min_power_level.

        Schlägt geschlossen fehl: gibt bei API-Fehlern False zurück.
        """
        mod_cfg      = self.config.get("mod_permissions", {})
        allowed_list = mod_cfg.get("allowed_users", [])
        min_level    = int(mod_cfg.get("min_power_level", 50))

        if str(user_id) in allowed_list:
            return True

        check_room = room_id or self.config.get("mod_room_id", "")
        if check_room:
            return await self._get_power_level(check_room, user_id) >= min_level

        return False

    async def _get_power_level(self, room_id: RoomID, user_id: UserID) -> int:
        """
        Gibt den Matrix-Powerlevel von user_id in room_id zurück.
        Gibt bei API-Fehlern 0 zurück (Ablehnen) — Fail-Closed-Richtlinie.

        NULL-SICHERE LOOKUP-STRATEGIE
        ------------------------------
        mautrix-python speichert den Powerlevel-Zustand in PowerLevelStateEventContent wo:
          • levels.users ein Dict ist, dessen Schlüssel je nach mautrix-Version und
            Ereignisparser UserID-Objekte oder normale Strings sein können.
          • levels.users_default None sein kann, wenn das Feld im Raumzustand fehlte
            (die Matrix-Spezifikation besagt, dass der Standard-Standardwert 0 ist).

        Wir prüfen beide Schlüsselformen (UserID und str) und fallen durch
        users_default auf 0 zurück, was alle Randfälle behandelt ohne auf
        dict.get()'s Standard int() auf einem None-Wert aufzurufen.
        """
        try:
            levels: PowerLevelStateEventContent = await self.client.get_state_event(
                room_id, EventType.ROOM_POWER_LEVELS
            )
            # Zuerst UserID-Schlüssel versuchen (nativer Typ), dann str-Schlüssel (einige mautrix-Versionen)
            user_level = levels.users.get(user_id, None)
            if user_level is None:
                user_level = levels.users.get(str(user_id), None)
            # Auf users_default zurückfallen; falls auch das None ist, schreibt die Spezifikation 0 vor
            if user_level is None:
                default = levels.users_default
                user_level = int(default) if default is not None else 0
            return int(user_level)
        except Exception as exc:
            self.log.warning(
                "Powerlevel für %s in %s konnte nicht abgerufen werden: %s", user_id, room_id, exc
            )
            return 0


    # ===========================================================================
    # ABSCHNITT 17 — LINKVORSCHAU (OG-METADATEN)
    # ===========================================================================

    async def _fetch_og_metadata(self, url: str) -> Optional[dict]:
        """
        Ruft `url` ab und extrahiert Open-Graph- / HTML-Metadaten.

        Grenzen:
          • HTTP-Timeout: link_preview_timeout Sekunden (Standard 5).
          • Body-Begrenzung: 65.536 Byte — genug für jeden <head>-Abschnitt.
          • Verarbeitet nur text/html-Antworten.
          • ssl=False: Vorschau-URLs können selbst signierte Zertifikate haben;
            wir benötigen kein verifiziertes TLS für rein lesende Metadaten.

        Alle Fehler werden auf DEBUG-Ebene protokolliert, um Log-Rauschen in
        stark frequentierten Räumen zu vermeiden.
        """
        timeout = float(self.config.get("link_preview_timeout", 5))
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; MatrixURLFilterBot/2.0)",
            "Accept": "text/html,application/xhtml+xml",
        }
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    headers=headers,
                    allow_redirects=True,
                    ssl=False,
                    max_redirects=5,
                ) as resp:
                    if resp.status != 200:
                        return None
                    if "text/html" not in resp.headers.get("Content-Type", ""):
                        return None
                    raw  = await resp.content.read(65_536)
                    html = raw.decode("utf-8", errors="replace")

        except asyncio.TimeoutError:
            self.log.debug("Linkvorschau-Timeout für %s", url)
            return None
        except aiohttp.ClientError as exc:
            self.log.debug("Linkvorschau-Netzwerkfehler für %s: %s", url, exc)
            return None
        except Exception as exc:
            self.log.debug("Linkvorschau-Fehler für %s: %s", url, exc)
            return None

        title = _og_tag(html, "og:title") or _html_title(html)
        desc  = _og_tag(html, "og:description") or _meta_name(html, "description")

        if not title and not desc:
            return None
        return {"title": (title or "").strip(), "description": (desc or "").strip()}


    # ===========================================================================
    # ABSCHNITT 18 — MATRIX-NACHRICHTENDIENSTPROGRAMME
    # ===========================================================================

    async def _redact(
        self, room_id: RoomID, event_id: EventID, reason: str
    ) -> bool:
        """
        Löscht eine Nachricht (redact). Gibt True bei Erfolg zurück, False bei Fehler.

        FEHLERBEHANDLUNG — unzureichendes Powerlevel
        ----------------------------------------------
        Wenn der Powerlevel des Bots unter dem `redact_events`-Schwellwert des Raums
        liegt (typischerweise 50), wirft mautrix eine Ausnahme (HTTP 403 MForbidden).

        Wir fangen ALLE Ausnahmen ab, schreiben eine strukturierte Warnmeldung ins Log
        und geben False zurück. Das bedeutet:
          • Die ursprüngliche Nachricht wird NICHT entfernt (für Nutzer sichtbar).
          • Der Warnhinweis und der Mod-Raum-Alarm werden trotzdem gesendet.
          • Der Moderationsablauf wird fortgesetzt — nur das Löschen wird übersprungen.
          • Der Betreiber sieht "REDACT FAILED ... Gib dem Bot Powerlevel 50+"
            in Maubots Log und kann die Raumkonfiguration anpassen.

        Das ist gewollt: im Log laut fehlzuschlagen während der Moderationsablauf
        fortgesetzt wird, ist weit besser als den Fehler still zu verschlucken und
        unbekannte URLs ohne Aufsicht zu lassen.
        """
        try:
            await self.client.redact(room_id, event_id, reason=reason)
            return True
        except Exception as exc:
            self.log.warning(
                "LÖSCHEN FEHLGESCHLAGEN: ereignis=%s raum=%s — wahrscheinlich unzureichendes Powerlevel. "
                "Dem Bot PL 50+ geben (redact_events-Einstellung des Raums beachten). Fehler: %s",
                event_id, room_id, exc,
            )
            return False

    async def _send_notice(
        self,
        room_id: RoomID,
        text: str,
        render_markdown: bool = False,
    ) -> Optional[EventID]:
        """
        Sendet eine m.notice-Nachricht. Gibt EventID bei Erfolg zurück, None bei Fehler.
        m.notice ist die Matrix-Konvention für Bot-Nachrichten — Clients zeigen sie
        mit reduzierter Deckkraft an; andere Bots ignorieren sie, um Schleifen zu verhindern.
        """
        try:
            content = TextMessageEventContent(
                msgtype=MessageType.NOTICE,
                body=text,
            )
            if render_markdown:
                content.format = Format.HTML
                content.formatted_body = _md_to_html(text)
            return await self.client.send_message(room_id, content)
        except Exception as exc:
            # ── 403 / Mitgliedschaftsprüfung ──────────────────────────────────
            # Ein 403 MForbidden bedeutet fast immer, dass der Bot kein Mitglied
            # des Zielraums ist (meistens die mod_room_id). Eine klare, umsetzbare
            # Meldung protokollieren, damit Betreiber schnell diagnostizieren können.
            exc_str = str(exc)
            if (
                "403" in exc_str
                or "M_FORBIDDEN" in exc_str.upper()
                or "MForbidden" in exc_str
            ):
                self.log.error(
                    "FEHLER: Bot kann nicht in Raum %s senden (403 Verboten). "
                    "Stelle sicher, dass der Bot in den in mod_room_id konfigurierten Raum eingeladen wurde "
                    "und die Berechtigung 'Nachrichten senden' hat. "
                    "Raum-ID in der Konfiguration: %s",
                    room_id,
                    self.config.get("mod_room_id", "<nicht gesetzt>"),
                )
            else:
                self.log.error("Hinweis an %s konnte nicht gesendet werden: %s", room_id, exc)
            return None

    async def _edit_notice(
        self, room_id: RoomID, event_id: EventID, new_text: str
    ) -> None:
        """
        Bearbeitet einen zuvor gesendeten Hinweis mithilfe der Matrix-m.replace-Relation.
        Clients mit Bearbeitungsunterstützung (Element, FluffyChat, Nheko) zeigen den
        aktualisierten Text an der Stelle an, wo der ursprüngliche Alarm war.
        """
        try:
            html = _md_to_html(new_text)
            content = TextMessageEventContent(
                msgtype=MessageType.NOTICE,
                body=f"* {new_text}",
                format=Format.HTML,
                formatted_body=html,
            )
            content["m.new_content"] = {
                "msgtype": "m.notice",
                "body": new_text,
                "format": "org.matrix.custom.html",
                "formatted_body": html,
            }
            content["m.relates_to"] = {
                "rel_type": "m.replace",
                "event_id": str(event_id),
            }
            await self.client.send_message(room_id, content)
        except Exception as exc:
            self.log.error("Hinweis %s in %s konnte nicht bearbeitet werden: %s", event_id, room_id, exc)

    async def _send_reaction(
        self, room_id: RoomID, target_id: EventID, key: str
    ) -> Optional[EventID]:
        """
        Postet eine m.reaction (Emoji-Annotation) auf `target_id`.
        Rohdaten-Dict-Payload wird verwendet, um mautrix-python-Versionskopplung zu vermeiden.
        """
        try:
            return await self.client.send_message_event(
                room_id,
                EventType.REACTION,
                {
                    "m.relates_to": {
                        "rel_type": "m.annotation",
                        "event_id": str(target_id),
                        "key": key,
                    }
                },
            )
        except Exception as exc:
            self.log.error(
                "Reaktion '%s' auf %s in %s konnte nicht gepostet werden: %s",
                key, target_id, room_id, exc,
            )
            return None


    # ===========================================================================
    # ABSCHNITT 19 — DATEI-E/A-DIENSTPROGRAMM
    # ===========================================================================

    async def _append_to_file(self, domain: str, filepath: str) -> None:
        """
        Hängt `domain` auf einer eigenen Zeile an `filepath` an, unter asyncio.Lock.

        THREADSICHERHEITSANALYSE
        ------------------------
        `self._file_lock` ist ein asyncio.Lock. Alle Aufrufer (_execute_allow,
        _execute_block, cmd_allow, cmd_block) sind Coroutinen, die auf dem
        einzelnen asyncio-Event-Loop laufen, also bedeutet "gleichzeitig" verschränkt,
        nicht wirklich parallel.

        Szenario: Zwei Mods klicken ✅ auf zwei verschiedene Überprüfungen innerhalb
        desselben Event-Loop-Ticks. Zwei Coroutinen werden erstellt und geplant. Die erste,
        die `await self._file_lock` erreicht, erwirbt es und fährt fort. Die zweite
        pausiert an diesem await-Punkt — übergibt die Kontrolle zurück an den Event-Loop
        (der andere Ereignisse, Pings usw. verarbeitet). Wenn die erste Coroutine fertig
        ist und `self._file_lock.release()` aufruft, setzt die zweite fort.

        Ergebnis: Schreibvorgänge sind IMMER sequentiell, nie verschränkt. Die Datei
        kann nicht von zwei Coroutinen gleichzeitig geschrieben werden.

        Das synchrone open()+write() innerhalb des Locks dauert < 1 ms für einen
        einzeiligen Anhang, daher wäre run_in_executor-Overhead hier verschwendet.

        Wirft eine Ausnahme bei Fehler (Aufrufer fängt ab und meldet an den Mod-Raum).

        PFADAUFLÖSUNG
        -------------
        `filepath` wird über `os.path.abspath()` zu einem ABSOLUTEN Pfad aufgelöst
        bevor irgendwelche E/A durchgeführt wird. Das ist in Docker/systemd-Deployments
        entscheidend, wo Maubots Prozess-Arbeitsverzeichnis (CWD) ein interner Pfad
        wie `/opt/maubot/` ist, auf den der Prozess möglicherweise keine Schreibberechtigung hat.

        Auflösungsreihenfolge:
          1. Wenn `filepath` bereits absolut ist → unverändert verwenden.
          2. Wenn relativ → gegen das Prozess-CWD auflösen.

        EMPFOHLENE KONFIGURATION:
        `blacklist_dir` und `whitelist_dir` auf ABSOLUTE Pfade in der Maubot-
        Instanzkonfiguration setzen, z.B.:
            blacklist_dir: /data/blacklists/
            whitelist_dir: /data/whitelists/
        Das eliminiert CWD-Mehrdeutigkeiten vollständig.
        """
        # Zu absolut auflösen, damit Fehlermeldungen immer den echten Pfad zeigen.
        # Wenn die Konfiguration /data/blacklists/ oder /data/whitelists/ verwendet
        # (Docker-Volume vom Host gemountet), ist der Pfad bereits absolut — abspath() ist ein No-Op.
        abs_filepath = os.path.abspath(filepath)
        async with self._file_lock:
            try:
                # Elternverzeichnis immer (neu) erstellen — harmlos wenn es existiert.
                # Behandelt den Fall, wo das Docker-Volume existiert, aber die
                # Unterverzeichnisse (blacklists/ / whitelists/) noch nie erstellt wurden.
                parent = os.path.dirname(abs_filepath)
                if parent:
                    os.makedirs(parent, exist_ok=True)
                with open(abs_filepath, "a", encoding="utf-8") as fh:
                    fh.write(f"\n{domain}\n")

            except PermissionError:
                # ── Docker-spezifischer Zweig ──────────────────────────────────
                # PermissionError bedeutet, das Verzeichnis existiert, aber der Maubot-
                # Prozessnutzer hat keinen Schreibzugriff — klassisches Docker-Volume-Problem.
                # Vollständigen Traceback protokollieren UND erneut auslösen, damit Aufrufer
                # die umsetzbare Docker-Fix-Nachricht an den Mod-Raum senden können.
                self.log.exception(
                    "ZUGRIFF VERWEIGERT: '%s' kann nicht in '%s' geschrieben werden. "
                    "Korrektur auf dem Docker-Host: "
                    "chown -R 1337:1337 ./data/blacklists ./data/whitelists "
                    "(Maubot läuft standardmäßig als UID 1337)",
                    domain, abs_filepath,
                )
                raise  # Aufrufer fangen PermissionError ab und senden den Docker-Hinweis

            except Exception:
                # ── Generischer Zweig ──────────────────────────────────────────
                # FileNotFoundError, OSError, etc. — vollständiger Traceback in den Logs.
                self.log.exception(
                    "SCHREIBEN FEHLGESCHLAGEN: '%s' konnte nicht an '%s' angehängt werden. "
                    "Prüfen ob der Pfad korrekt und das Dateisystem beschreibbar ist.",
                    domain, abs_filepath,
                )
                raise  # Erneut auslösen, damit Aufrufer eine Fehlerbenachrichtigung an den Mod-Raum senden können

        self.log.debug("'%s' an '%s' angehängt.", domain, abs_filepath)

    async def _remove_from_file(self, domain: str, filepath: str) -> None:
        """
        Entfernt alle Zeilen, die `domain` aus `filepath` matchen, unter asyncio.Lock.

        HOSTFILE-FORMAT-ERKENNUNG
        -------------------------
        Folgende Zeilenformate werden alle korrekt erkannt und entfernt:
          domain.com
          0.0.0.0 domain.com
          127.0.0.1 domain.com
          *.domain.com
          0.0.0.0 *.domain.com
          domain.com  # Inline-Kommentar

        Kommentarzeilen (startend mit #) und Leerzeilen bleiben erhalten.

        THREADSICHERHEIT
        ----------------
        Dieselbe `self._file_lock`-Garantie wie `_append_to_file`:
        alle Aufrufer sind Coroutinen auf dem einzelnen asyncio-Event-Loop,
        sodass Lesen→Filtern→Schreiben niemals verschränkt werden kann.

        FEHLERBEHANDLUNG
        ----------------
        Wirft PermissionError oder OSError bei Fehler — Aufrufer fängt ab
        und sendet umsetzbare Fehlerbenachrichtigung an den Mod-Raum.
        """
        abs_filepath = os.path.abspath(filepath)
        async with self._file_lock:
            try:
                if not os.path.exists(abs_filepath):
                    # Datei existiert nicht → nichts zu entfernen, still zurückgeben
                    return

                with open(abs_filepath, "r", encoding="utf-8") as fh:
                    lines = fh.readlines()

                domain_lower = domain.lower()
                new_lines: list = []

                for line in lines:
                    stripped = line.strip()

                    # Leerzeilen und Kommentarzeilen immer beibehalten
                    if not stripped or stripped.startswith("#"):
                        new_lines.append(line)
                        continue

                    # Inline-Kommentar abschneiden: "domain.com  # Notiz" → "domain.com"
                    ci = stripped.find(" #")
                    check = stripped[:ci].rstrip() if ci != -1 else stripped

                    # Hostfile-Präfix normalisieren: "0.0.0.0 domain.com" → "domain.com"
                    parts = check.split(None, 2)
                    if not parts:
                        new_lines.append(line)
                        continue

                    if len(parts) >= 2 and parts[0] in _LOOPBACK:
                        entry = parts[1].lower()
                    else:
                        entry = parts[0].lower()

                    # Zeile verwerfen, wenn sie der zu entfernenden Domain entspricht
                    if entry == domain_lower:
                        continue

                    new_lines.append(line)

                with open(abs_filepath, "w", encoding="utf-8") as fh:
                    fh.writelines(new_lines)

            except PermissionError:
                self.log.exception(
                    "ZUGRIFF VERWEIGERT: '%s' kann nicht aus '%s' gelesen/geschrieben werden. "
                    "Korrektur auf dem Docker-Host: "
                    "chown -R 1337:1337 ./data/blacklists ./data/whitelists "
                    "(Maubot läuft standardmäßig als UID 1337)",
                    domain, abs_filepath,
                )
                raise

            except Exception:
                self.log.exception(
                    "ENTFERNEN FEHLGESCHLAGEN: '%s' konnte nicht aus '%s' entfernt werden. "
                    "Prüfen ob der Pfad korrekt und das Dateisystem beschreibbar ist.",
                    domain, abs_filepath,
                )
                raise

        self.log.debug("'%s' aus '%s' entfernt.", domain, abs_filepath)


# ===========================================================================
# ABSCHNITT 20 — MODULGLOBALE HILFSFUNKTIONEN
# ===========================================================================

def _list_txt_files(directory: str) -> List[str]:
    """Gibt sortierte absolute Pfade aller .txt-Dateien in `directory` zurück."""
    if not os.path.isdir(directory):
        try:
            os.makedirs(directory, exist_ok=True)
        except OSError:
            pass
        return []
    return sorted(
        os.path.join(directory, fn)
        for fn in os.listdir(directory)
        if fn.endswith(".txt")
    )


def _clean_domain_arg(raw: str) -> str:
    """Entfernt Leerzeichen; gibt das erste leerraumgetrennte Token in Kleinbuchstaben zurück."""
    tokens = raw.strip().lower().split()
    return tokens[0] if tokens else ""


def _valid_domain(domain: str) -> bool:
    """
    Minimale Plausibilitätsprüfung: nicht leer, enthält Punkt, kein Skip-Eintrag.

    Akzeptiert sowohl reguläre Domains ("example.com") als auch
    Wildcard-Einträge ("*.example.com"). Bei Wildcards wird das
    "*."-Präfix vor der Validierung abgeschnitten, sodass der Suffix
    "example.com" dieselben Regeln erfüllen muss.
    """
    if not domain:
        return False
    # Wildcard-Präfix normalisieren: "*.example.com" → "example.com"
    check = domain[2:] if domain.startswith("*.") else domain
    return bool(check) and "." in check and check not in _SKIP_DOMAINS


def _og_tag(html: str, prop: str) -> Optional[str]:
    """
    Extrahiert content="..." aus einem OG-<meta property="...">-Tag.
    Behandelt beide Attributreihenfolgen. Content-Länge auf 512 Zeichen begrenzt
    mit einem possessiven Äquivalent [^"']+ — kein katastrophales Backtracking.
    """
    p = re.escape(prop)
    m = re.search(
        r'<meta[^>]+property=["\']' + p + r'["\'][^>]+content=["\']([^"\']{1,512})["\']'
        r'|<meta[^>]+content=["\']([^"\']{1,512})["\'][^>]+property=["\']' + p + r'["\']',
        html, re.IGNORECASE,
    )
    if m:
        return (m.group(1) or m.group(2) or "").strip() or None
    return None


def _meta_name(html: str, name: str) -> Optional[str]:
    """Extrahiert content="..." aus einem <meta name="...">-Tag."""
    n = re.escape(name)
    m = re.search(
        r'<meta[^>]+name=["\']' + n + r'["\'][^>]+content=["\']([^"\']{1,512})["\']'
        r'|<meta[^>]+content=["\']([^"\']{1,512})["\'][^>]+name=["\']' + n + r'["\']',
        html, re.IGNORECASE,
    )
    if m:
        return (m.group(1) or m.group(2) or "").strip() or None
    return None


def _html_title(html: str) -> Optional[str]:
    """Extrahiert Text aus <title>...</title>."""
    m = re.search(r"<title[^>]*>([^<]{1,256})</title>", html, re.IGNORECASE)
    return m.group(1).strip() if m else None


def _md_to_html(text: str) -> str:
    """
    Konvertiert die kleine Markdown-Untermenge, die dieser Bot verwendet, in HTML
    für das Matrix-formatted_body-Feld.

    Behandelte Konstrukte (in Verarbeitungsreihenfolge):
      &, <, >         — zuerst HTML-kodiert, um Injection zu verhindern
      > Blockzitate   — <blockquote> (nach Kodierung als &gt; erkannt)
      **Fett**        — <strong>
      `Inline-Code`   — <code>
      [Label](URL)    — <a href="...">

    Alle Regex-Längen sind begrenzt, um Regex-Verlangsamung bei präparierten Eingaben zu verhindern.
    """
    # 1. HTML-Sonderzeichen kodieren (verhindert Injection)
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    # 2. Zeilenweise für Blockzitate verarbeiten (> wurde zu &gt; kodiert)
    lines = text.split("\n")
    out: List[str] = []
    for line in lines:
        if line.startswith("&gt; "):
            out.append(f"<blockquote>{line[5:]}</blockquote>")
        else:
            out.append(line)
    text = "<br>\n".join(out)

    # 3. **fett** → <strong>
    text = re.sub(r"\*\*(.{1,500}?)\*\*", r"<strong>\1</strong>", text)

    # 4. `code` → <code>
    text = re.sub(r"`([^`]{1,200})`", r"<code>\1</code>", text)

    # 5. [Label](URL) → <a href="URL">Label</a>
    text = re.sub(
        r"\[([^\]]{1,200})\]\((https?://[^)]{1,2000})\)",
        r'<a href="\2">\1</a>',
        text,
    )

    return text


# ===========================================================================
# ABSCHNITT 21 — SELBSTAUDIT
# ===========================================================================
#
# ╔═════════════════════════════════════════════════════════════════════════╗
# ║  SELBSTAUDIT: Speicher · Threadsicherheit · Fehlerbehandlung · ReDoS   ║
# ╚═════════════════════════════════════════════════════════════════════════╝
#
# ── §1  SPEICHERBEDARF ─────────────────────────────────────────────────────
#
#  Eingabekorpus: 6.500.000 eindeutige Domain-Strings (13 Dateien × ca. 500 K).
#  Speicherstruktur: Python set (offene Adressierung, 2/3 Auslastungsfaktor).
#
#  Kosten pro Eintrag (CPython 3.11, 64-Bit Linux):
#    str-Objekt-Header:      49 Byte  (jeder Python-str, längenunabhängig)
#    String-Inhalt (ASCII): ~20 Byte (typische Domain z.B. "sub.example.com")
#    Hash-Tabellen-Slot:      8 Byte  (Zeiger) × 1,5 (Auslastungsfaktor-Overhead)
#    ─────────────────────────────────────────────────────────────────────────
#    Pro Domain (ca.):  ~89 Byte
#
#  Gesamt:
#    6.500.000 × 89 Byte  ≈ 579 MB  (theoretisches Minimum)
#    + Python-Allokator-Overhead (~15-20%)
#    ─────────────────────────────────────────────────────────────────────────
#    Realistischer Steady-State-RAM: 680 MB – 1,05 GB
#
#  Während des parallelen Ladens (13 Pro-Datei-Sets gleichzeitig vor Zusammenführung):
#    Peak ≈ finales Set-RAM + 12 × (kleinste verbleibende nicht zusammengeführte Sets)
#    Schlimmster Fall: ~1,05 GB + ~90 MB = ~1,15 GB  (kurz, GC gibt schnell frei)
#
#  ABHILFEMASSNAHMEN bei RAM-Knappheit:
#    a) BloomFilter (pybloom-live): 7,4 MB für 6,5 Mio. Einträge bei 0,1% Falschpositivrate.
#       Kompromiss: ~1/1000 unbekannte URLs erscheinen möglicherweise fälschlich als "bekannt".
#    b) Nur die Hochrisiko-Listen laden (Malware, Phishing, Ransomware).
#    c) Auf einem Server mit ≥ 2 GB RAM ausführen (dringend empfohlen).
#
# ── §2  THREADSICHERHEIT ───────────────────────────────────────────────────
#
#  Gemeinsamer veränderbarer Zustand und ihre Schutzmechanismen:
#
#  A) self.blacklist_set / self.whitelist_set
#     Schreiber: _execute_allow, _execute_block, cmd_allow, cmd_block,
#                _reload_lists (alle auf dem asyncio-Event-Loop)
#     Leser:     on_message (asyncio-Event-Loop)
#     SICHER: Alle Mutationen auf dem Single-Thread-Event-Loop.
#     set.add() / set.discard() sind GIL-geschützt. Der Referenz-Tausch
#     `self.blacklist_set = new_bl` ist auf CPython-Ebene atomar (ein
#     einziger STORE_ATTR-Bytecode-Befehl). Kein Lock nötig.
#
#  B) self.pending_reviews (dict)
#     Schreiber + Leser: on_message, on_reaction, Befehle — alle Event-Loop.
#     SICHER: Single-Thread; kein Lock nötig.
#
#  C) whitelists/custom.txt und blacklists/custom.txt
#     Schreiber: _append_to_file (Coroutinen auf dem Event-Loop)
#     Risiko: Zwei Mods reagieren gleichzeitig → zwei Coroutinen schreiben gleichzeitig.
#     Schutz: self._file_lock (asyncio.Lock) serialisiert alle Schreibvorgänge.
#     Garantie: Datei wird nie von zwei Coroutinen gleichzeitig geöffnet.
#               Siehe _append_to_file-Docstring für den detaillierten Ablauf.
#
#  D) Datei-Parsen (ThreadPoolExecutor-Worker)
#     Jeder Worker erhält seinen eigenen privaten `filepath` und schreibt in sein
#     eigenes privates `LoadResult.domains`-Set — kein gemeinsamer veränderbarer
#     Zustand zwischen Threads. Worker rufen nur self.log (threadsicher) auf und
#     lesen self.config (unveränderlich während des Ladens).
#     SICHER: Null gemeinsamer Zustand zwischen Threads.
#
# ── §3  FEHLERBEHANDLUNG ──────────────────────────────────────────────────
#
#  Szenario: Bot hat kein "Redact"-Powerlevel in einem Raum.
#    → client.redact() wirft eine Ausnahme (typischerweise HTTP 403 MForbidden).
#    → _redact() fängt ab und protokolliert:
#        "LÖSCHEN FEHLGESCHLAGEN: ereignis=... raum=... — wahrscheinlich unzureichendes Powerlevel.
#         Dem Bot PL 50+ geben (redact_events-Einstellung des Raums beachten). Fehler: ..."
#    → Gibt False zurück. Der Aufrufer (on_message) beachtet message_redacted=False,
#      SETZT ABER FORT: Warnhinweis und Mod-Raum-Alarm werden trotzdem gesendet.
#    → Moderationsaufsicht bleibt auch ohne Löschfähigkeit gewahrt.
#
#  Weitere Fehlerszenarien und ihre Behandlung:
#    • mod_room_id nicht gesetzt:       _submit_for_review protokolliert Warnung, kehrt früh zurück.
#    • Datei-Schreiben schlägt fehl:    _execute_allow/block fängt OSError ab, sendet Fehlerhinweis
#                                       an Mod-Raum, aktualisiert NICHT das In-Memory-Set
#                                       (Festplatte und RAM bleiben synchron).
#    • Linkvorschau-Timeout:            _fetch_og_metadata gibt None zurück, DEBUG-protokolliert.
#    • Missgeformte URL:                _extract_domains fängt pro-URL ab, fährt fort.
#    • Datei nicht gefunden:            _domain_generator fängt OSError pro Datei ab.
#    • Einzelner Loader-Fehler:         asyncio.gather(return_exceptions=True) protokolliert
#                                       und lädt verbleibende Dateien weiter.
#    • Powerlevel-API-Fehler:           _get_power_level gibt 0 (ablehnen) zurück und warnt.
#    • Fehlgeschlagener Hinweisversand: _send_notice fängt ab und protokolliert, gibt None zurück.
#
# ── §4  ReDoS-SICHERHEIT ──────────────────────────────────────────────────
#
#  Verwendeter Regex (aus Abschnitt 4):
#    (?:https?://|www\.)  [flache_zeichenklasse]+  (?<![abschließende_satzzeichen])
#
#  Warum katastrophales Backtracking hier unmöglich ist:
#
#  1. EINZELNE ZEICHENKLASSE mit EINEM Quantifizierer
#     Der wiederholte Teil ist [a-zA-Z0-9\-._~:@!$&'()*+,;=/?#%\[\]]+
#     Eine Zeichenklasse ist als Bitset-Lookup in Pythons `re` implementiert:
#     jedes Zeichen ist entweder im Set (vorwärts) oder nicht (stopp).
#     Die Engine trifft eine O(1)-Entscheidung pro Zeichen. Es gibt keine
#     Alternativen zu versuchen, keine Untergruppen zu expandieren. Dies ist
#     inhärent linear: O(n) wobei n = Anzahl der übereinstimmenden Zeichen.
#
#  2. KEINE GESCHACHTELTEN QUANTIFIZIERER
#     Das gefährliche Muster (X+)+ hat KEIN Äquivalent hier.
#     Das äußere + gilt für eine einzelne Zeichenentscheidung, nicht für ein
#     Teilmuster mit eigenem Quantifizierer. (X+)+ kann O(2^n) Pfade erstellen;
#     ein flaches [klasse]+ erstellt genau 1 Pfad.
#
#  3. KEINE ALTERNATION INNERHALB DER WIEDERHOLTEN GRUPPE
#     (a|b)+ verursacht Backtracking, weil die Engine an jeder Position beide
#     Alternativen versucht. Unsere Zeichenklasse ist eine logische Vereinigung,
#     in O(1) durch das Bitset ausgewertet, ohne alternative Zweige.
#
#  4. FESTES LOOKBEHIND
#     (?<![.,;:!?)\]]) prüft genau 1 Zeichen hinter dem Match-Ende.
#     Pythons `re`-Modul wertet feste Lookbehinds in O(1) aus.
#
#  5. re.ASCII-FLAG
#     Beschränkt die Engine auf 7-Bit-ASCII, vermeidet Unicode-Kategorie-
#     Scanning (\w im Unicode-Modus berührt Unicode-Tabellen). Bei Nachrichten
#     mit vielen Emojis oder CJK-Zeichen könnte der Nicht-ASCII-Modus langsamer sein.
#
#  Adversarieller Test: 50.000 Leerzeichen gefolgt von einem URL-Zeichen.
#    Der Regex scannt linear, überspringt alle Leerzeichen (nicht in der Klasse),
#    findet kein gültiges URL-Präfix und terminiert. O(50001). Kein Explodieren.
#
# ── ENDE DES SELBSTAUDITS ──────────────────────────────────────────────────
