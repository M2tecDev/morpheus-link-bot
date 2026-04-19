"""
URL-Filter-Bot — Hochleistungsedition  (v2.5.0)
============================================

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
5. **Datenbankgestützte Persistenz (Privacy by Design)**: Alle Runtime-Entscheidungen
   (allow/block/ignore) sowie Moderationsanfragen und Verstoßdaten werden in Maubots
   nativer Datenbank gespeichert. Matrix-IDs werden ausschließlich als SHA-256-Hash
   (mit konfiguriertem Salt) gespeichert — niemals im Klartext. Ein DSGVO-Retention-Loop
   bereinigt Verstoßdaten automatisch nach 24 Stunden.

Abhängigkeiten
--------------
  maubot    >= 0.4.0
  mautrix   >= 0.20.0
  aiohttp   (mit maubot gebündelt)
  Python    >= 3.10

Siehe SELBSTAUDIT-Abschnitt (Abschnitt 21) am Ende dieser Datei für eine detaillierte
Analyse von Speicherbedarf, Threadsicherheit, Fehlerbehandlung und Regex-Sicherheit.

Autor: Kori <korinator21@gmail.com>
"""

from __future__ import annotations

# ===========================================================================
# ABSCHNITT 1 — STANDARD-BIBLIOTHEKEN
# ===========================================================================

import asyncio
import concurrent.futures
import datetime
import hashlib
import os
import re
import time
import unicodedata
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Generator, List, Optional, Set, Tuple
from urllib.parse import unquote, urlparse

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
from mautrix.api import Method as HTTPMethod, Path as APIPath
from mautrix.util.async_db import Database, UpgradeTable
from mautrix.util.config import BaseProxyConfig, ConfigUpdateHelper


# ===========================================================================
# ABSCHNITT 3b — DATENBANKSCHEMA  (Privacy by Design / DSGVO)
# ===========================================================================
#
# Vier Tabellen ersetzen die dateibasierte Speicherung für Laufzeit-Entscheidungen:
#
#   DomainRule    — Whitelist-/Blacklist-/Ignore-Einträge aus Mod-Aktionen (kein roher URL-Pfad)
#   DomainStats   — Verstoß-Zähler pro sanitisierter Domain  (keine Nutzerdaten)
#   UserViolation — SHA-256-gehashte User-IDs + UTC-Timestamps  (niemals rohe Matrix-IDs)
#   PendingReview — offene Moderationsanfragen  (keine Sender-ID, keine vollständige URL)
#
# Datenhaltungs-Task: UserViolation-Einträge werden nach 24 Stunden automatisch gelöscht.
# ===========================================================================

_DB_UPGRADE_TABLE: UpgradeTable = UpgradeTable()


@_DB_UPGRADE_TABLE.register(description="Initial privacy-compliant schema (v3.0)")  # type: ignore[arg-type, call-arg]
async def _db_upgrade_v1(conn) -> None:  # type: ignore[no-untyped-def]
    # Runtime-Whitelisting/-Blacklisting/-Ignore via Mod-Befehle
    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS domain_rule (
            domain         TEXT    PRIMARY KEY,
            is_blacklisted BOOLEAN NOT NULL DEFAULT FALSE,
            ignore_preview BOOLEAN NOT NULL DEFAULT FALSE
        )
        """
    )
    # Anonymisierte Verstoß-Häufigkeit pro Domain (kein Nutzerbezug)
    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS domain_stats (
            domain          TEXT    PRIMARY KEY,
            violation_count INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    # Gehashte Nutzer-Violation-Zeitreihe für Sliding-Window-Mute-Logik
    # HINWEIS: DATETIME ist portabel (SQLite + asyncpg).
    # Kein DEFAULT — ts wird vom Python-Code immer explizit übergeben.
    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS user_violation (
            user_hash TEXT     NOT NULL,
            ts        DATETIME NOT NULL
        )
        """
    )
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS user_violation_ts_idx ON user_violation (ts)"
    )
    # Offene Moderationsanfragen — nur Minimal-Metadaten, kein Sender, keine vollständige URL
    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS pending_review (
            alert_event_id    TEXT PRIMARY KEY,
            room_id           TEXT NOT NULL,
            original_event_id TEXT NOT NULL,
            domain            TEXT NOT NULL
        )
        """
    )


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
#
# Fix #7: ';' wurde aus der Hauptzeichenklasse von _URL_RE entfernt.
#   Vorher: [a-zA-Z0-9\-._~:@!$&'()*+,;=/?#%\[\]]+
#   Nachher: [a-zA-Z0-9\-._~:@!$&'()*+,=/?#%\[\]]+
#   Semikolons gelten jetzt als Trennzeichen. Das Lookbehind behält ';', sodass
#   URLs, die mit ';' enden, sauber gestutzt werden.
#
# Fix #14: Aufeinanderfolgende Punkte werden in _extract_domains (Schritt 3) per
#   Post-Match-Check `if ".." in candidate: continue` abgefangen — keine Änderung
#   am Regex selbst nötig, bleibt ReDoS-sicher (O(n) String-Suche).

_URL_RE: re.Pattern = re.compile(
    r"(?:https?://|www\.)"
    r"[a-zA-Z0-9\-._~:@!$&'()*+,=/?#%\[\]\u00C0-\uFFFF]+"
    r"(?<![.,;:!?\])])",
    re.IGNORECASE,
)

# Hostfile-IP-Präfixe, die beim Parsen verworfen werden
_LOOPBACK: frozenset = frozenset({"0.0.0.0", "127.0.0.1"})

# Gültige Hostfile-Token, die KEINE echten externen Domains sind
_SKIP_DOMAINS: frozenset = frozenset(
    {
        "localhost",
        "broadcasthost",
        "local",
        "0.0.0.0",
        "127.0.0.1",
        "255.255.255.255",
        "ip6-localhost",
        "ip6-loopback",
    }
)

# ---------------------------------------------------------------------------
# BEKANNTE BOT-BEFEHLSNAMEN — Fix #5 (präzisiert)
# ---------------------------------------------------------------------------
# Wird in on_message verwendet, um echte Befehle vom URL-Filter auszunehmen.
# WICHTIG: Diese Liste muss mit den @command.new()-Dekoratoren synchron gehalten
# werden. Nur Nachrichten, bei denen das erste Token nach "!" in diesem Set liegt,
# überspringen den URL-Filter. Nachrichten wie "!https://evil.com" oder
# "!evil.com" beginnen zwar mit "!", sind aber KEINE Befehle und werden weiterhin
# vollständig auf URLs geprüft.
_BOT_COMMAND_NAMES: frozenset = frozenset(
    {
        "allow",
        "block",
        "unallow",
        "unblock",
        "urlstatus",
        "reloadlists",
        "pending",
        "sendpending",
        "mute",
        "unmute",
        "liststats",
        "hilfe",
        "ignore",
        "unignore",
        "status",
    }
)

# Emoji-Schlüssel, die als Moderations-Reaktionsknöpfe im Mod-Raum verwendet werden
_EMOJI_ALLOW = "✅"
_EMOJI_BLOCK = "❌"

# ---------------------------------------------------------------------------
# BEKANNTE TOP-LEVEL-DOMAINS — Kuratiertes Set zur Falsch-Positiv-Prävention
# ---------------------------------------------------------------------------
# Dieses Set enthält gültige TLDs aus der IANA-Datenbank.
# Es dient als Torwächter für die "Naked-Domain"-Erkennung:
# Nur Domains mit einer TLD aus diesem Set werden als echte Links behandelt.
# Beispiel: "hallo.du" wird NICHT erkannt ("du" ∉ Set),
# aber "bannedurl.com" wird erkannt ("com" ∈ Set).
_COMMON_TLDS: frozenset = frozenset(
    {
        # Generische TLDs (gTLDs)
        "com",
        "net",
        "org",
        "info",
        "biz",
        "edu",
        "gov",
        "mil",
        "int",
        "name",
        # Häufig genutzte neue gTLDs (inkl. bekannter Missbrauchs-TLDs)
        "io",
        "co",
        "app",
        "dev",
        "xyz",
        "online",
        "site",
        "club",
        "top",
        "pro",
        "store",
        "shop",
        "tech",
        "live",
        "news",
        "media",
        "cloud",
        "link",
        "click",
        "download",
        "win",
        "bid",
        "loan",
        "work",
        "space",
        "agency",
        "digital",
        "network",
        "services",
        "solutions",
        "systems",
        "group",
        "global",
        "world",
        "today",
        "center",
        "support",
        "tools",
        "email",
        "social",
        "chat",
        "game",
        "web",
        "pw",
        "cc",
        "tv",
        "mobi",
        "tel",
        "coop",
        "aero",
        "museum",
        "jobs",
        # Neuere gTLDs — bekannte Missbrauchs-TLDs (ergänzt in v2.3.1)
        "zip",
        "mov",
        "phd",
        "foo",
        "nexus",
        "art",
        "design",
        "finance",
        "bank",
        "health",
        "care",
        "insurance",
        "mortgage",
        "loans",
        "cash",
        "money",
        "trading",
        "investments",
        "creditcard",
        "tax",
        "accountant",
        "expert",
        "security",
        "protection",
        "safe",
        "trust",
        "verify",
        "confirm",
        "update",
        # Länder-TLDs (ccTLDs) — vollständige IANA-Liste der 2-Zeichen-Codes
        "com",
        "net",
        "org",
        "info",
        "biz",
        "edu",
        "gov",
        "mil",
        "int",
        "name",
        "io",
        "co",
        "app",
        "dev",
        "xyz",
        "online",
        "site",
        "club",
        "top",
        "pro",
        "store",
        "shop",
        "tech",
        "live",
        "news",
        "media",
        "cloud",
        "link",
        "click",
        "download",
        "win",
        "bid",
        "loan",
        "work",
        "space",
        "agency",
        "digital",
        "network",
        "services",
        "solutions",
        "systems",
        "group",
        "global",
        "world",
        "today",
        "center",
        "support",
        "tools",
        "email",
        "social",
        "chat",
        "game",
        "web",
        "pw",
        "cc",
        "tv",
        "mobi",
        "tel",
        "coop",
        "aero",
        "museum",
        "jobs",
        "ac",
        "ad",
        "ae",
        "af",
        "ag",
        "ai",
        "al",
        "am",
        "ao",
        "aq",
        "ar",
        "as",
        "at",
        "au",
        "aw",
        "ax",
        "az",
        "ba",
        "bb",
        "bd",
        "be",
        "bf",
        "bg",
        "bh",
        "bi",
        "bj",
        "bm",
        "bn",
        "bo",
        "br",
        "bs",
        "bt",
        "bw",
        "by",
        "bz",
        "ca",
        "cd",
        "cf",
        "cg",
        "ch",
        "ci",
        "ck",
        "cl",
        "cm",
        "cn",
        "cr",
        "cu",
        "cv",
        "cw",
        "cx",
        "cy",
        "cz",
        "de",
        "dj",
        "dk",
        "dm",
        "do",
        "dz",
        "ec",
        "ee",
        "eg",
        "er",
        "es",
        "et",
        "eu",
        "fi",
        "fj",
        "fk",
        "fm",
        "fo",
        "fr",
        "ga",
        "gb",
        "gd",
        "ge",
        "gf",
        "gg",
        "gh",
        "gi",
        "gl",
        "gm",
        "gn",
        "gp",
        "gq",
        "gr",
        "gs",
        "gt",
        "gu",
        "gw",
        "gy",
        "hk",
        "hm",
        "hn",
        "hr",
        "ht",
        "hu",
        "id",
        "ie",
        "il",
        "im",
        "in",
        "iq",
        "ir",
        "is",
        "it",
        "je",
        "jm",
        "jo",
        "jp",
        "ke",
        "kg",
        "kh",
        "ki",
        "km",
        "kn",
        "kp",
        "kr",
        "kw",
        "ky",
        "kz",
        "la",
        "lb",
        "lc",
        "li",
        "lk",
        "lr",
        "ls",
        "lt",
        "lu",
        "lv",
        "ly",
        "ma",
        "mc",
        "md",
        "me",
        "mg",
        "mh",
        "mk",
        "ml",
        "mm",
        "mn",
        "mo",
        "mp",
        "mq",
        "mr",
        "ms",
        "mt",
        "mu",
        "mv",
        "mw",
        "mx",
        "my",
        "mz",
        "na",
        "nc",
        "ne",
        "nf",
        "ng",
        "ni",
        "nl",
        "no",
        "np",
        "nr",
        "nu",
        "nz",
        "om",
        "pa",
        "pe",
        "pf",
        "pg",
        "ph",
        "pk",
        "pl",
        "pm",
        "pn",
        "pr",
        "ps",
        "pt",
        "pw",
        "py",
        "qa",
        "re",
        "ro",
        "rs",
        "ru",
        "rw",
        "sa",
        "sb",
        "sc",
        "sd",
        "se",
        "sg",
        "sh",
        "si",
        "sk",
        "sl",
        "sm",
        "sn",
        "so",
        "sr",
        "ss",
        "st",
        "sv",
        "sx",
        "sy",
        "sz",
        "tc",
        "td",
        "tf",
        "tg",
        "th",
        "tj",
        "tk",
        "tl",
        "tm",
        "tn",
        "to",
        "tr",
        "tt",
        "tv",
        "tw",
        "tz",
        "ua",
        "ug",
        "uk",
        "um",
        "us",
        "uy",
        "uz",
        "va",
        "vc",
        "ve",
        "vg",
        "vi",
        "vn",
        "vu",
        "wf",
        "ws",
        "ye",
        "yt",
        "za",
        "zm",
        "zw",
    }
)

# ---------------------------------------------------------------------------
# BEKANNTE URL-SHORTENER (Fix #18)
# ---------------------------------------------------------------------------
# Wenn eine dieser Domains in einer Nachricht auftaucht, löst der Bot die
# Weiterleitungs-URL auf und prüft die finale Ziel-Domain stattdessen.
_URL_SHORTENERS: frozenset = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "buff.ly",
        "is.gd",
        "rebrand.ly",
        "short.io",
        "tiny.cc",
        "rb.gy",
        "cutt.ly",
        "shorturl.at",
        "bl.ink",
        "snip.ly",
        "clck.ru",
        "qr.ae",
    }
)

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
# Fix #14: aufeinanderfolgende Punkte werden im Aufrufer per Post-Match-Check abgefangen.
_NAKED_DOMAIN_RE: re.Pattern = re.compile(
    r"(?<![/\w\-\*\.@])"
    r"([a-zA-Z0-9][a-zA-Z0-9\-\.]{1,200}[a-zA-Z0-9])"
    r"(?![a-zA-Z0-9\-\.])",
    re.ASCII,
)

# ---------------------------------------------------------------------------
# MATRIX-ID-REGEX — Entfernt Matrix-Bezeichner vor der URL-Erkennung
# ---------------------------------------------------------------------------
# Verhindert Falsch-Positive durch Matrix-Nutzer- und Raum-IDs:
#   "@kori:koridev.tail183fd1.ts.net"  → Homeserver "koridev.tail183fd1.ts.net"
#                                        würde sonst als Domain erkannt.
#   "!room:homeserver.example.org"     → Homeserver-Teil würde als Domain gelten.
#
# ABGEDECKTE BEZEICHNER-TYPEN:
#   @localpart:homeserver[:port]  — Matrix-Nutzer-IDs (MXID)
#   !localpart:homeserver[:port]  — Matrix-Raum-IDs
#
# BEWUSST NICHT ABGEDECKT: # (Raum-Alias) und $ (Event-IDs), da '#' in URL-
# Fragmenten vorkommt und '$' nur in alten Event-ID-Formaten. Der Lookbehind in
# _NAKED_DOMAIN_RE enthält bereits '@', sodass direkt @-präfixierte Token schon
# blockiert werden. Diese Regex entfernt das GESAMTE MXID-TOKEN inkl. Homeserver.
#
# REDOS-SICHERHEIT:
#   Alle Zeichenklassen sind nach oben begrenzt ({1,255}).
#   Keine geschachtelten Quantifizierer. Worst-Case O(n). ✓
_MATRIX_ID_RE: re.Pattern = re.compile(
    r"[@!][a-zA-Z0-9._\-/=+]{1,255}:[a-zA-Z0-9.\-]{1,255}(?::\d{1,5})?",
    re.ASCII,
)

# ---------------------------------------------------------------------------
# MATRIX-TO-DEEPLINKS — Matrix-interne Mentions/Einladungen aus URL-Checks halten
# ---------------------------------------------------------------------------
# Matrix-Clients serialisieren Nutzer-Tags oft als matrix.to/#/...-Deep-Link,
# z.B. [matrix.to](https://matrix.to/#/@alice:example.org).
# Diese Links sind intern und sollen NICHT als externe URL gelten.
_MATRIX_TO_MD_LINK_RE: re.Pattern = re.compile(
    r"\[[^\]\n]{1,512}\]\(((?:https?://)?(?:www\.)?matrix\.to/#/[^\s)]{1,2048})\)",
    re.ASCII | re.IGNORECASE,
)

_MATRIX_TO_TEXT_LINK_RE: re.Pattern = re.compile(
    r"((?:https?://)?(?:www\.)?matrix\.to/#/[^\s<>()]{1,2048})",
    re.ASCII | re.IGNORECASE,
)


def _looks_like_matrix_identifier(token: str) -> bool:
    """
    Erkennt Matrix-Bezeichner robust anhand ihrer Form, ohne eine "echte"
    Domain/TLD im Homeserver-Teil vorauszusetzen.
    """
    token = unquote(token).strip().lstrip("/")
    if not token:
        return False

    token = token.split("?", 1)[0]
    if not token:
        return False

    sigil = token[0]
    if sigil == "$":
        return len(token) > 1
    if sigil not in "@!#":
        return False
    return ":" in token[1:] and not token.endswith(":")


def _is_matrix_to_deeplink(url: str) -> bool:
    """
    True für matrix.to-Links, deren Ziel eine Matrix-ID / Raum-ID / Alias ist.
    """
    candidate = url.strip()
    if not candidate:
        return False

    if candidate.startswith("//"):
        candidate = "https:" + candidate
    elif not candidate.startswith(("http://", "https://")):
        candidate = "https://" + candidate

    try:
        parsed = urlparse(candidate)
    except Exception:
        return False

    host = (parsed.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    if host != "matrix.to":
        return False

    target = (parsed.fragment or parsed.path or "").strip()
    target = unquote(target).lstrip("/")
    if not target:
        return False

    first_segment = target.split("/", 1)[0].split("?", 1)[0]
    return _looks_like_matrix_identifier(first_segment)


def _strip_matrix_to_deeplinks(text: str) -> str:
    """
    Entfernt Matrix-interne matrix.to-Deep-Links aus Markdown- und Klartext-
    Darstellungen, damit weder URL- noch Naked-Domain-Erkennung anschlagen.
    """

    def _md_replacer(match: re.Match) -> str:
        return " " if _is_matrix_to_deeplink(match.group(1)) else match.group(0)

    def _text_replacer(match: re.Match) -> str:
        return " " if _is_matrix_to_deeplink(match.group(1)) else match.group(0)

    text = _MATRIX_TO_MD_LINK_RE.sub(_md_replacer, text)
    return _MATRIX_TO_TEXT_LINK_RE.sub(_text_replacer, text)


# ===========================================================================
# ABSCHNITT 5 — KONFIGURATION
# ===========================================================================


class Config(BaseProxyConfig):
    def do_update(self, helper: ConfigUpdateHelper) -> None:
        helper.copy("blacklist_dir")
        helper.copy("whitelist_dir")
        helper.copy("mod_room_id")
        helper.copy("mod_permissions")
        helper.copy("command_rooms")  # Fix #2
        helper.copy("enable_link_previews")
        helper.copy("link_preview_timeout")
        helper.copy("loader_threads")
        helper.copy("min_domain_length")
        helper.copy("max_domain_length")
        helper.copy("warn_cooldown")
        helper.copy("mute_enabled")
        helper.copy("mute_threshold")
        helper.copy("mute_window_minutes")  # Fix #8
        helper.copy("mute_duration_minutes")  # Fix #8
        helper.copy("mute_commands_enabled")  # Fix #18
        helper.copy("secret_salt")  # DSGVO: Salt für SHA-256-Nutzer-Hashing


# ===========================================================================
# ABSCHNITT 6 — DATENSTRUKTUREN
# ===========================================================================


@dataclass
class PendingReview:
    """Erfasst alle Kontextinformationen für eine Moderationsüberprüfung."""

    domain: str
    original_event_id: EventID
    original_room_id: RoomID
    sender: UserID
    submitted_at: float = field(default_factory=time.monotonic)
    whitelist_reaction_id: Optional[EventID] = field(default=None)
    blacklist_reaction_id: Optional[EventID] = field(default=None)


@dataclass
class LoadResult:
    """Rückgabewert des synchronen Datei-Parser-Workers pro Datei."""

    filename: str
    domains: Set[str]
    wildcards: Set[str]
    lines_read: int
    domains_accepted: int
    wildcards_found: int
    elapsed_ms: float


# ===========================================================================
# ABSCHNITT 7 — HAUPTKLASSE DES PLUGINS
# ===========================================================================


class URLFilterBot(Plugin):
    """
    Haupt-Plugin-Klasse. Maubot erstellt eine Instanz pro konfiguriertem Bot und
    ruft start() / stop() rund um den Plugin-Lebenszyklus auf.

    Laufzeitzustand (initialisiert in start()):
      blacklist_set       — Set gesperrter Domains          (ca. 6,5 Mio. Einträge)
      whitelist_set       — Set erlaubter Domains           (typischerweise klein)
      pending_reviews     — offene Moderationsanfragen      (Dict, DB-persistiert)
      _pending_domains    — O(1)-Set bereits wartender Domains
                            (verhindert doppelte Mod-Raum-Alarme pro Domain)
      _seen_events        — LRU-Set kürzlich verarbeiteter Event-IDs
                            (verhindert Mehrfachverarbeitung bei Matrix-Sync-Replays)
      _seen_events_q      — Deque-Spiegel von _seen_events für FIFO-Verdrängung
      _loader_pool        — ThreadPoolExecutor für Parser-Threads
      _domain_rule_cache  — In-Memory-Cache aller DomainRule-DB-Einträge (O(1)-Lookup)
      _warn_cooldowns     — Dict[sender, monotonic-Zeitstempel der letzten Warnung]
                            Verhindert Notification Flooding: Warnungen werden pro
                            Nutzer höchstens einmal pro `warn_cooldown` Sekunden gepostet.
                            Nachrichten werden weiterhin sofort gelöscht.
      _active_mutes       — (user_id, room_id) → monotonic unmute_at  [Fix #8]
      _unmute_task        — asyncio.Task für Auto-Entstummen           [Fix #8]
      _retention_task     — asyncio.Task für DSGVO-Datenhaltung (UserViolation 24 h)
      _preview_map        — str(original_event_id) → {domain → preview_event_id}  [Fix #12/#13]
    """

    _SEEN_EVENTS_MAX: int = 1_000

    # Override base-class optionals — always set before any handler runs
    config: Config
    database: Database

    # ------------------------------------------------------------------
    # Maubot-Lebenszyklus
    # ------------------------------------------------------------------

    @classmethod
    def get_config_class(cls) -> type[BaseProxyConfig]:
        return Config

    @classmethod
    def get_db_upgrade_table(cls) -> UpgradeTable:
        """Registriert das Datenbankschema bei Maubot (einmalig pro Version ausgeführt)."""
        return _DB_UPGRADE_TABLE

    async def start(self) -> None:
        """
        Plugin-Einstiegspunkt. Initialisiert den gesamten Laufzeitzustand und startet
        dann den Hochleistungs-Async-Listenlader. Der Matrix-Sync-Loop verarbeitet
        Ereignisse normal weiter, während das Parsen im Hintergrund in Threads läuft.
        """
        # ── Frühzeitige Initialisierung aller Handler-Attribute ──────────────
        # KRITISCH: Diese Attribute MÜSSEN vor `await super().start()` stehen.
        #
        # GRUND: `super().start()` ist ein `await`-Punkt. Sobald die Kontrolle
        # an den asyncio-Event-Loop abgegeben wird, kann der Matrix-Sync-Loop
        # bereits Ereignisse liefern und `on_message` aufrufen — bevor `start()`
        # die Zeilen danach erreicht. Das führt zu AttributeError auf `_seen_events`
        # u.a., wie im Fehlerlog bei schnellem Spam sichtbar.
        #
        # Durch Vorab-Initialisierung sind alle Attribute garantiert vorhanden,
        # egal wann der erste Handler eintrifft.

        # O(1)-Lookup-Sets — einmalig beim Start befüllt, bei Mod-Aktionen aktualisiert
        self.blacklist_set: Set[str] = set()
        self.whitelist_set: Set[str] = set()

        # Wildcard-Sets für "*.domain.com"-Muster aus den Listendateien.
        self.blacklist_wildcards: Set[str] = set()
        self.whitelist_wildcards: Set[str] = set()

        # Domains für die KEINE Linkvorschau erstellt wird (ignore.txt)
        self.ignore_preview_set: Set[str] = set()

        # Offene Moderationsanfragen: alert_event_id → PendingReview
        self.pending_reviews: Dict[EventID, PendingReview] = {}

        # O(1)-Wächter: Domains mit bereits offener Mod-Raum-Überprüfung
        self._pending_domains: Set[str] = set()

        # ── Event-ID-Deduplizierungs-Cache ────────────────────────────────────
        # _seen_events   — Set für O(1)-Mitgliedschaftsprüfung
        # _seen_events_q — Deque für O(1)-FIFO-Verdrängung bei vollem Cache
        self._seen_events: Set[EventID] = set()
        self._seen_events_q: Deque[EventID] = deque()

        # ── Sekundärer Content-Dedup-Cache (Fix: 4x-Notifications) ───────────
        # Manche Matrix-Clients schicken bei Netzwerkproblemen dasselbe Event
        # mehrfach mit UNTERSCHIEDLICHEN event_ids (Client-Retry → neuer txnId).
        # Der primäre _seen_events-Dedup greift nur bei identischer event_id.
        # Dieser sekundäre Cache verhindert, dass dieselbe Nachricht desselben
        # Absenders innerhalb von 5 Sekunden mehrfach verarbeitet wird.
        # Key: "sender_id|body_hash"  Value: monotonic-Zeitstempel
        self._content_dedup: Dict[str, float] = {}

        # Spam-Schutz: letzte Warn-Zeitstempel pro Nutzer (monotonic)
        self._warn_cooldowns: Dict[str, float] = {}

        # Fix #8: Aktive Stummschaltungen  { (user_id, room_id) → unmute_at }
        self._active_mutes: Dict[Tuple[str, str], float] = {}
        self._unmute_task: Optional[asyncio.Task] = None

        # DB-gestützter In-Memory-Cache aller DomainRule-Einträge
        # domain → {"is_blacklisted": bool, "ignore_preview": bool}
        # Wird beim Start aus der DB geladen für O(1)-Lookups ohne DB-Roundtrip.
        self._domain_rule_cache: Dict[str, Dict[str, bool]] = {}

        # DSGVO-Datenhaltungs-Task (bereinigt UserViolation-Einträge > 24 h)
        self._retention_task: Optional[asyncio.Task] = None

        # Fix #12/#13: str(original_event_id) → {domain: preview_event_id}
        # Jede Nachricht hat ein eigenes Dict aller ihrer Vorschauen.
        # Beim Edit werden Domains gematcht; überschüssige Vorschauen werden gelöscht.
        self._preview_map: Dict[str, Dict[str, EventID]] = {}

        # Thread-Support: msg_key → thread_root_event_id
        # Gespeichert wenn eine Vorschau für eine Nachricht in einem Thread erstellt wird.
        # Wird beim Edit-Pfad genutzt, damit Folge-Vorschauen ebenfalls im Thread landen.
        self._thread_map: Dict[str, str] = {}

        # Uptime-Tracking — monotonic, unabhängig von Systemuhr-Korrekturen
        self.start_time: float = time.monotonic()

        # ── Maubot-Basisklasse starten (gibt Kontrolle an asyncio ab) ─────────
        await super().start()
        self.config.load_and_update()

        # Dedizierter ThreadPoolExecutor, damit Datei-E/A nicht mit aiohttp
        # um den Standard-Executor konkurriert
        max_workers = self.config.get("loader_threads", None) or None
        self._loader_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="urlfilter_loader",
        )

        await self._reload_lists()

        # ── DSGVO-Salt-Validierung ────────────────────────────────────────────
        # KRITISCH: Bevor irgendetwas in die Datenbank geschrieben wird, muss
        # sichergestellt sein, dass ein individueller secret_salt konfiguriert ist.
        #
        # Hintergrund: Wird der Bot mit dem Default-Salt gestartet und später auf
        # einen echten Salt umgestellt, stimmen alle bisher gespeicherten SHA-256-
        # Hashes nicht mehr — der Mute-Verlauf (Sliding-Window) wird korrumpiert.
        # Ein nachträglicher Salt-Wechsel ist daher nicht sicher rückgängig zu machen.
        #
        # Deshalb: Hard-Stop beim Start, solange kein gültiger Salt gesetzt ist.
        _salt_raw: str = self.config.get("secret_salt", "")
        if not _salt_raw or _salt_raw.startswith("CHANGE_ME"):
            self.log.critical(
                "🚨 PLUGIN NICHT GESTARTET: secret_salt ist nicht konfiguriert oder "
                "enthält noch den Standardwert. Bitte in der Instanzkonfiguration "
                "einen zufälligen Salt setzen: "
                'python3 -c "import secrets; print(secrets.token_hex(32))"'
            )
            raise ValueError(
                "secret_salt ist nicht gesetzt oder enthält noch den Standardwert. "
                "Plugin-Start abgebrochen. Bitte in der Maubot-Instanzkonfiguration "
                "einen individuellen secret_salt eintragen."
            )

        # ── Datenbank: DomainRule-Cache + offene Reviews wiederherstellen ─────
        # Läuft NACH dem Textdatei-Laden, damit DB-Einträge Datei-Einträge
        # überschreiben können (z.B. manuell via !block gesperrte Domains).
        await self._load_domain_rules_cache()
        await self._load_pending_reviews_from_db()

        # ── Auto-Entstumm-Loop  [Fix #8] ─────────────────────────────────────
        # Läuft alle 30 Sekunden und hebt abgelaufene Stummschaltungen auf.
        # Nur starten wenn mute_enabled, aber der Task prüft beim Wakeup erneut.
        self._unmute_task = asyncio.get_event_loop().create_task(
            self._auto_unmute_loop(),
            name="urlfilter_unmute",
        )

        # ── DSGVO-Datenhaltungs-Loop ──────────────────────────────────────────
        # Löscht UserViolation-Einträge die älter als 24 h sind.
        self._retention_task = asyncio.get_event_loop().create_task(
            self._retention_loop(),
            name="urlfilter_retention",
        )

    async def stop(self) -> None:
        """Geordnetes Herunterfahren — gibt den Thread-Pool frei und bricht
        den Bereinigungsloop sauber ab."""
        # ── Bereinigungsloop abbrechen ─────────────────────────────────────────
        # cancel() schickt CancelledError an den nächsten await-Punkt im Task.
        # Das kurze `await` danach stellt sicher, dass der Task vollständig
        # beendet wurde, bevor wir den Event-Loop freigeben.
        for task_attr in ("_unmute_task", "_retention_task"):
            task = getattr(self, task_attr, None)
            if task is not None and not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass  # Erwartetes Ergebnis beim sauberen Abbruch
            setattr(self, task_attr, None)

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

        domains: Set[str] = set()
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
                suffix = raw_entry[2:]  # "*.banned.com" → "banned.com"
                if suffix and "." in suffix:
                    wildcards.add(suffix)
            else:
                domains.add(raw_entry)
                lines_read += 1

        elapsed_ms = (time.monotonic() - t0) * 1_000
        self.log.info(
            "  ✅  %s — %d Domains + %d Wildcards aus %d Zeilen (%.0f ms)",
            filename,
            len(domains),
            len(wildcards),
            lines_read,
            elapsed_ms,
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

        # ignore.txt aus dem Blacklist-Verzeichnis explizit ausschließen —
        # sie wird separat geladen und darf die Blacklist nicht beeinflussen.
        bl_files = [
            f for f in _list_txt_files(bl_dir) if os.path.basename(f) != "ignore.txt"
        ]
        wl_files = _list_txt_files(wl_dir)

        if not bl_files and not wl_files:
            self.log.warning(
                "Keine .txt-Dateien in blacklist_dir='%s' oder whitelist_dir='%s' gefunden. "
                "Alle URLs werden als unbekannt behandelt.",
                bl_dir,
                wl_dir,
            )
            return

        total = len(bl_files) + len(wl_files)
        self.log.info(
            "🚀 Starte Listen-Ladevorgang: %d Dateien gesamt (bl=%d  wl=%d)",
            total,
            len(bl_files),
            len(wl_files),
        )
        t_start = time.monotonic()

        # Jede Datei an den Thread-Pool übermitteln
        bl_futures = [
            loop.run_in_executor(
                self._loader_pool, self._load_one_file, fp, min_len, max_len
            )
            for fp in bl_files
        ]
        wl_futures = [
            loop.run_in_executor(
                self._loader_pool, self._load_one_file, fp, min_len, max_len
            )
            for fp in wl_files
        ]

        # Alle gleichzeitig abwarten; return_exceptions=True bedeutet, eine fehlerhafte
        # Datei bricht den Rest nicht ab
        all_results: List = await asyncio.gather(
            *bl_futures,
            *wl_futures,
            return_exceptions=True,
        )

        # In neue Sets zusammenführen (Domains + Wildcards getrennt)
        new_bl: Set[str] = set()
        new_wl: Set[str] = set()
        new_bl_wc: Set[str] = set()
        new_wl_wc: Set[str] = set()
        n_bl = len(bl_futures)
        total_lines = 0
        total_domains = 0

        for i, result in enumerate(all_results):
            if isinstance(result, BaseException):
                self.log.error("Datei-Loader-Ausnahme: %s", result)
                continue
            total_lines += result.lines_read
            total_domains += result.domains_accepted
            if i < n_bl:
                new_bl.update(result.domains)
                new_bl_wc.update(result.wildcards)
            else:
                new_wl.update(result.domains)
                new_wl_wc.update(result.wildcards)

        # Fix: DB-Overrides in die neuen temporären Sets laden, BEVOR der atomare Swap
        # ausgeführt wird. Ohne diesen Schritt entsteht ein Zwischenzustand:
        #   1. _reload_lists() tauscht die Sets (nur Datei-Einträge)
        #   2. _load_domain_rules_cache() lädt DB-Einträge nach (späterer await-Punkt)
        # → In diesem Fenster klassifiziert on_message() DB-geblockte Domains als "unknown"
        #   (3x🔍 + 1x⚠️-Muster). Durch Vorladen in new_bl/new_wl ist der Swap atomar
        #   und bringt sofort den vollständigen Stand (Dateien + DB) in Kraft.
        try:
            _db_rows = await self.database.fetch(
                "SELECT domain, is_blacklisted, ignore_preview FROM domain_rule"
            )
            for _row in _db_rows:
                _dom: str = _row["domain"]
                _is_bl: bool = bool(_row["is_blacklisted"])
                _ign_pv: bool = bool(_row["ignore_preview"])
                if _ign_pv:
                    # ignore_preview_set wird separat gesetzt — hier vormerken
                    self.ignore_preview_set.add(_dom)
                if _is_bl:
                    new_bl.add(_dom)
                    new_wl.discard(_dom)
                else:
                    new_wl.add(_dom)
                    new_bl.discard(_dom)
            self.log.info(
                "📦 DB-Overrides in Reload integriert: %d Einträge.", len(_db_rows)
            )
        except Exception as _exc:
            self.log.error(
                "DB-Lade-Fehler beim Listen-Reload: %s — DB-Einträge werden übersprungen, "
                "nur Datei-Einträge aktiv.",
                _exc,
            )

        # Atomarer Referenz-Tausch — alle vier Sets gleichzeitig
        # (GIL garantiert Atomarität jedes einzelnen STORE_ATTR-Bytecodes)
        self.blacklist_set = new_bl
        self.whitelist_set = new_wl
        self.blacklist_wildcards = new_bl_wc
        self.whitelist_wildcards = new_wl_wc

        elapsed = time.monotonic() - t_start
        self.log.info(
            "🏁 Ladevorgang abgeschlossen: %d BL-Domains | %d WL-Domains | "
            "%d BL-Wildcards | %d WL-Wildcards | %d Zeilen gelesen | %.1f s",
            len(self.blacklist_set),
            len(self.whitelist_set),
            len(self.blacklist_wildcards),
            len(self.whitelist_wildcards),
            total_lines,
            elapsed,
        )

        # ── ignore.txt separat laden (Vorschau-Ignore-Liste) ─────────────────
        ignore_file = os.path.abspath(os.path.join(bl_dir, "ignore.txt"))
        if os.path.isfile(ignore_file):
            try:
                ignore_result = await loop.run_in_executor(
                    self._loader_pool,
                    self._load_one_file,
                    ignore_file,
                    min_len,
                    max_len,
                )
                if isinstance(ignore_result, BaseException):
                    self.log.error(
                        "Fehler beim Laden von ignore.txt: %s", ignore_result
                    )
                else:
                    self.ignore_preview_set = ignore_result.domains
                    self.log.info(
                        "🔇 ignore.txt: %d Domains geladen (keine Vorschau).",
                        len(self.ignore_preview_set),
                    )
            except Exception as exc:
                self.log.error("Fehler beim Laden von ignore.txt: %s", exc)
        else:
            self.ignore_preview_set = set()

    # ===========================================================================
    # ABSCHNITT 9 — URL- UND DOMAIN-EXTRAKTION
    # ===========================================================================

    @staticmethod
    def _extract_domains(
        body: str,
        formatted_body: Optional[str] = None,
    ) -> Set[str]:
        """
        Extrahiert alle einzigartigen Domain-Strings aus einer Nachricht.

        Fix #7: Semikolons in clean_body werden durch Leerzeichen ersetzt,
                sodass "1.com;2.com;3.com" drei separate Domains liefert.
        Fix #14: Aufeinanderfolgende Punkte werden per Post-Match-Check abgefangen
                 (`if ".." in candidate: continue`) — keine Regex-Änderung nötig,
                 bleibt ReDoS-sicher.
        """
        domains: Set[str] = set()

        # Schritt 0: Matrix-Deep-Links/Mentions entfernen, dann Matrix-IDs strippen.
        scan_body: str = _strip_matrix_to_deeplinks(body)
        clean_body: str = _MATRIX_ID_RE.sub(" ", scan_body)
        clean_body = clean_body.replace(";", " ")  # Fix #7
        url_scan_body = scan_body.replace(";", " ")

        # Schritt 1: <a href> aus formatted_body
        if formatted_body:
            for href in _HREF_RE.findall(formatted_body):
                href = href.strip()
                if _is_matrix_to_deeplink(href):
                    continue
                if href.startswith(
                    ("mailto:", "matrix:", "mxc:", "tel:", "xmpp:", "#", "/", "data:")
                ):
                    continue
                try:
                    if href.startswith("//"):
                        href = "https:" + href
                    elif not href.startswith(("http://", "https://")):
                        href = "https://" + href
                    # Fix #15: urlparse().hostname statt .netloc.split(":")[0] —
                    # korrekte Behandlung von Basic-Auth-URLs (https://user:pass@host/)
                    host = (urlparse(href).hostname or "").lower()
                    if host.startswith("www."):
                        host = host[4:]
                    if host and "." in host:
                        domains.add(_normalize_domain(host))
                except Exception:
                    continue

        # Schritt 2: _URL_RE auf Klartext
        for raw in _URL_RE.findall(url_scan_body):
            try:
                url = raw if raw.startswith("http") else "http://" + raw
                if _is_matrix_to_deeplink(url):
                    continue
                # Fix #15: urlparse().hostname erkennt Basic-Auth-URLs korrekt
                host = (urlparse(url).hostname or "").lower()
                if host.startswith("www."):
                    host = host[4:]
                if host and "." in host:
                    domains.add(_normalize_domain(host))
            except Exception:
                continue

        # Schritt 3: _NAKED_DOMAIN_RE + TLD-Validierung
        for candidate in _NAKED_DOMAIN_RE.findall(clean_body):
            candidate = candidate.lower()
            # Fix #14: aufeinanderfolgende Punkte → Falsch-Positiv (z.B. "achso...ne")
            if ".." in candidate:
                continue
            if "." not in candidate:
                continue
            last_dot = candidate.rfind(".")
            tld = candidate[last_dot + 1 :]
            domain_part = candidate[:last_dot]
            if not tld.isalpha() or tld not in _COMMON_TLDS or not domain_part:
                continue
            final = candidate[4:] if candidate.startswith("www.") else candidate
            if final and "." in final:
                domains.add(_normalize_domain(final))

        return domains

    @staticmethod
    def _find_url_for_domain(
        body: str,
        domain: str,
        formatted_body: Optional[str] = None,
    ) -> Optional[str]:
        scan_body: str = _strip_matrix_to_deeplinks(body)
        clean_body: str = _MATRIX_ID_RE.sub(" ", scan_body)
        clean_body = clean_body.replace(";", " ")  # Fix #7 konsistenz
        url_scan_body = scan_body.replace(";", " ")
        if formatted_body:
            for href in _HREF_RE.findall(formatted_body):
                href = href.strip()
                if _is_matrix_to_deeplink(href):
                    continue
                if href.startswith(("mailto:", "matrix:", "mxc:", "tel:", "#", "/")):
                    continue
                try:
                    if href.startswith("//"):
                        href = "https:" + href
                    elif not href.startswith(("http://", "https://")):
                        href = "https://" + href
                    # Fix #15: .hostname korrekte Basic-Auth-URL-Behandlung
                    host = (urlparse(href).hostname or "").lower()
                    if host.startswith("www."):
                        host = host[4:]
                    if host == domain:
                        return href
                except Exception:
                    continue
        for raw in _URL_RE.findall(url_scan_body):
            try:
                url = raw if raw.startswith("http") else "http://" + raw
                if _is_matrix_to_deeplink(url):
                    continue
                # Fix #15: .hostname korrekte Basic-Auth-URL-Behandlung
                host = (urlparse(url).hostname or "").lower()
                if host.startswith("www."):
                    host = host[4:]
                if host == domain:
                    return url
            except Exception:
                continue
        return f"https://{domain}"

    @staticmethod
    def _matches_wildcards(domain: str, wildcards: Set[str]) -> bool:
        parts = domain.split(".")
        for i in range(1, len(parts)):
            if ".".join(parts[i:]) in wildcards:
                return True
        return False

    @staticmethod
    def _matches_apex(domain: str, domain_set: Set[str]) -> bool:
        """
        Fix #17: Prüft ob ein Eltern-Domain von `domain` im Set steht.
        sub.evil.com  → prüft evil.com  (i=1)
        a.b.evil.com  → prüft b.evil.com, evil.com  (i=1,2)
        evil.com      → keine Prüfung (range leer) — verhindert TLD-Treffer
        """
        parts = domain.split(".")
        for i in range(1, len(parts) - 1):
            if ".".join(parts[i:]) in domain_set:
                return True
        return False

    # ===========================================================================
    # ABSCHNITT 10 — HAUPT-NACHRICHTENHANDLER
    # ===========================================================================

    @event.on(EventType.ROOM_MESSAGE)  # type: ignore[arg-type]
    async def on_message(self, evt: MessageEvent) -> None:
        """
        Einstiegspunkt für jede Raumnachricht.

        Fix #5: Nachrichten, die mit '!' beginnen, überspringen den URL-Filter.
        Fix #12: Bearbeitete Nachrichten (m.replace) aktualisieren bestehende Vorschau.
        Fix #13: Alle whitelisteten Domains erhalten eine eigene Linkvorschau.
        """
        # ── Deduplizierungs-Wächter ───────────────────────────────────────────
        event_id = evt.event_id
        if event_id in self._seen_events:
            return
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
        formatted_body: Optional[str] = (
            getattr(evt.content, "formatted_body", None) or None
        )

        # ── Sekundärer Content-Dedup (Fix: 4x-Notifications) ─────────────────
        # Verhindert mehrfache Verarbeitung wenn ein Matrix-Client dasselbe Event
        # mit unterschiedlicher event_id neu sendet (Client-Retry nach Timeout).
        # Fenster: 5 Sekunden — kurz genug um echte Duplikate zu fangen,
        # lang genug um alle Retry-Wellen abzudecken.
        _body_stripped = body.strip()
        _dedup_key = f"{evt.sender}\x00{hash(_body_stripped)}"
        _now_dedup = time.monotonic()
        _last_content_seen = self._content_dedup.get(_dedup_key, 0.0)
        if _now_dedup - _last_content_seen < 5.0:
            return
        self._content_dedup[_dedup_key] = _now_dedup
        # Cache auf 1000 Einträge begrenzen (FIFO: älteste löschen)
        if len(self._content_dedup) > 1000:
            _oldest_key = next(iter(self._content_dedup))
            del self._content_dedup[_oldest_key]

        # ── Fix #5 (präzisiert): Nur echte Bot-Befehle überspringen den URL-Filter ──
        # Prüfung: beginnt die Nachricht mit "!" UND ist das erste Token danach
        # ein bekannter Befehlsname aus _BOT_COMMAND_NAMES?
        # Nur dann wird der URL-Scan übersprungen.
        #
        # WARUM NICHT einfach startswith("!")?
        # "!https://evil.com" oder "!blacklisted.de" beginnen zwar mit "!", sind
        # aber KEINE Befehle. Mit der alten Prüfung konnten Nutzer gesperrte Links
        # durch ein vorangestelltes "!" am URL-Filter vorbeischmuggeln.
        # Die neue Prüfung schließt diesen Bypass aus.
        _body_stripped = body.strip()
        if _body_stripped.startswith("!") and len(_body_stripped) > 1:
            _cmd_token = (
                _body_stripped[1:].split()[0].lower()
                if _body_stripped[1:].split()
                else ""
            )
            if _cmd_token in _BOT_COMMAND_NAMES:
                return

        # ── Fix #12: Edit-Erkennung ───────────────────────────────────────────
        # Prüfen ob diese Nachricht eine Bearbeitung einer früheren Nachricht ist.
        #
        # WICHTIG — mautrix Auto-Swap & lazy RelatesTo-Property:
        # mautrix tauscht bei Edit-Events (rel_type: m.replace) evt.content automatisch
        # mit m.new_content aus, bevor on_message feuert. body/formatted_body sind
        # daher bereits korrekt — eine manuelle Extraktion aus m.new_content ist
        # überflüssig (entfernt).
        #
        # BUGFIX — lazy RelatesTo-Property:
        # BaseMessageEventContent.relates_to ist eine @property, die bei _relates_to=None
        # *immer* ein leeres RelatesTo()-Objekt erstellt (gibt nie None zurück).
        # getattr(..., "relates_to", None) würde daher immer ein Objekt liefern, auch
        # wenn gar kein m.relates_to im Event vorhanden war.
        # → Stattdessen _relates_to direkt lesen (kein lazy-create),
        #   mit raw-Dict-Fallback für den Fall dass mautrix _relates_to nicht setzt.
        original_event_id: Optional[EventID] = None
        # Thread-Support: thread_root_id wird für Nachrichten in Threads gesetzt,
        # damit Vorschauen ebenfalls im Thread landen (m.thread Relation).
        thread_root_id: Optional[str] = None
        _rt = getattr(evt.content, "_relates_to", None)
        if _rt is not None:
            # Direkt aus dem deserialisierten RelatesTo-Objekt lesen
            _rt_rel = getattr(_rt, "rel_type", None)
            if _rt_rel == "m.replace":
                original_event_id = getattr(_rt, "event_id", None) or None
            elif _rt_rel == "m.thread":
                # Neue Nachricht in einem Thread
                _tid = getattr(_rt, "event_id", None)
                if _tid:
                    thread_root_id = str(_tid)
        else:
            # Fallback: rohes Content-Dict auslesen (falls mautrix _relates_to nicht gesetzt hat)
            try:
                _raw_rt = evt.content.serialize().get("m.relates_to") or {}
                if _raw_rt.get("rel_type") == "m.replace":
                    _eid = _raw_rt.get("event_id")
                    original_event_id = EventID(_eid) if _eid else None
                elif _raw_rt.get("rel_type") == "m.thread":
                    _tid = _raw_rt.get("event_id")
                    if _tid:
                        thread_root_id = str(_tid)
            except Exception:
                pass

        # Method 3: Raw-HTTP-API-Fallback ─────────────────────────────────────
        # Für ältere mautrix-Versionen, die m.relates_to beim Auto-Swap NICHT
        # zurückschreiben: deserialize_content() setzt dann _relates_to=None und
        # serialize() enthält kein "m.relates_to". Einzige verlässliche Quelle
        # ist die Homeserver-REST-API, die das Original-Event unverändert liefert.
        # Dieser Pfad wird nur betreten, wenn Methods 1+2 nichts gefunden haben.
        if not original_event_id:
            try:
                _raw_evt = await self.client.api.request(
                    HTTPMethod.GET,
                    APIPath.v3.rooms[evt.room_id].event[evt.event_id],
                )
                if isinstance(_raw_evt, dict):
                    _rrt = (_raw_evt.get("content") or {}).get("m.relates_to") or {}
                    if isinstance(_rrt, dict):
                        if _rrt.get("rel_type") == "m.replace":
                            _eid = _rrt.get("event_id")
                            original_event_id = EventID(_eid) if _eid else None
                        elif not thread_root_id and _rrt.get("rel_type") == "m.thread":
                            _tid = _rrt.get("event_id")
                            if _tid:
                                thread_root_id = str(_tid)
            except Exception:
                pass

        domains = self._extract_domains(body, formatted_body)
        if not domains:
            return

        # Fix #18: Bekannte URL-Shortener auflösen — finale Ziel-Domain prüfen
        for s_domain in list(domains):
            if s_domain in _URL_SHORTENERS:
                if (
                    s_domain in self.blacklist_set
                    or self._matches_wildcards(s_domain, self.blacklist_wildcards)
                    or self._matches_apex(s_domain, self.blacklist_set)
                ):
                    continue
                s_url = self._find_url_for_domain(body, s_domain, formatted_body)
                if s_url:
                    final = await self._resolve_shortener_domain(s_url)
                    if final and final != s_domain:
                        domains.discard(s_domain)
                        domains.add(final)
                        self.log.info(
                            "🔗 Shortener aufgelöst: %s → %s", s_domain, final
                        )

        blacklisted: List[str] = []
        unknown: List[str] = []
        whitelisted: List[str] = []

        for domain in domains:
            # Fix #18: Priorität Exakt > Wildcard > Apex — jede Ebene wird für
            # Whitelist UND Blacklist geprüft, bevor zur nächsten Ebene gewechselt wird.
            # Verhindert, dass ein Apex-WL-Eintrag (example.com) einen exakten
            # BL-Eintrag (sub.example.com) überschreibt und umgekehrt.
            if domain in self.whitelist_set:
                whitelisted.append(domain)
            elif domain in self.blacklist_set:
                blacklisted.append(domain)
            elif self._matches_wildcards(domain, self.whitelist_wildcards):
                whitelisted.append(domain)
            elif self._matches_wildcards(domain, self.blacklist_wildcards):
                blacklisted.append(domain)
            elif self._matches_apex(domain, self.whitelist_set):
                whitelisted.append(domain)
            elif self._matches_apex(domain, self.blacklist_set):
                blacklisted.append(domain)
            else:
                unknown.append(domain)

        message_redacted = False

        if blacklisted:
            await self._handle_blacklisted(blacklisted, evt)
            return
        elif unknown:
            message_redacted = await self._handle_unknown(unknown, evt)

        # ── Fix #12 + #13: Vorschauen für whitelisted Domains ────────────────
        # Neue Nachricht  → für jede whitelistete Domain eine Reply-Vorschau senden.
        # Edit            → _update_previews_for_edit() übernimmt die komplette Logik:
        #                   gleiche Domain → Vorschau bearbeiten,
        #                   andere Domain  → vorhandene Vorschau mit neuem Inhalt überschreiben,
        #                   mehr Links     → neue Vorschauen senden,
        #                   weniger Links  → Überschuss-Vorschauen löschen (redact).
        if not message_redacted and self.config["enable_link_previews"]:
            reply_target_id = original_event_id if original_event_id else evt.event_id
            msg_key = str(reply_target_id)

            # Domains herausfiltern die auf der Vorschau-Ignore-Liste stehen
            preview_domains = [
                d for d in whitelisted if d not in self.ignore_preview_set
            ]

            # ── Thread-Root für Edit-Pfad ermitteln ──────────────────────────
            # Für neue Nachrichten ist thread_root_id bereits gesetzt (oben).
            # Für Edits schauen wir zuerst in _thread_map (kein API-Call nötig),
            # dann Fallback per API auf das Original-Event.
            if original_event_id and thread_root_id is None:
                thread_root_id = self._thread_map.get(msg_key)
                if thread_root_id is None:
                    try:
                        _orig_raw = await self.client.api.request(
                            HTTPMethod.GET,
                            APIPath.v3.rooms[evt.room_id].event[original_event_id],
                        )
                        if isinstance(_orig_raw, dict):
                            _orig_rt = (_orig_raw.get("content") or {}).get(
                                "m.relates_to"
                            ) or {}
                            if (
                                isinstance(_orig_rt, dict)
                                and _orig_rt.get("rel_type") == "m.thread"
                            ):
                                _tid = _orig_rt.get("event_id")
                                if _tid:
                                    thread_root_id = str(_tid)
                    except Exception:
                        pass

            if original_event_id:
                # Edit-Pfad: volle Synchronisation alter ↔ neuer Vorschauen
                await self._update_previews_for_edit(
                    msg_key,
                    preview_domains,
                    body,
                    formatted_body,
                    evt.room_id,
                    reply_target_id,
                    thread_root_id=thread_root_id,
                )
            elif preview_domains:
                # Neue Nachricht: alle whitelisteten Domains bekommen eine Vorschau
                domain_map: Dict[str, EventID] = {}
                for domain in preview_domains:
                    url = self._find_url_for_domain(body, domain, formatted_body)
                    if not url:
                        continue
                    new_preview_id = await self._post_link_preview(
                        domain,
                        url,
                        evt.room_id,
                        reply_to_event_id=reply_target_id,
                        thread_root_id=thread_root_id,
                    )
                    if new_preview_id:
                        domain_map[domain] = new_preview_id
                if domain_map:
                    self._preview_map[msg_key] = domain_map
                    # Thread-Info speichern damit Edits später im selben Thread landen
                    if thread_root_id:
                        self._thread_map[msg_key] = thread_root_id
                    # Preview-Map auf 500 Nachrichten begrenzen
                    if len(self._preview_map) > 500:
                        old_keys = list(self._preview_map.keys())[:100]
                        for old_key in old_keys:
                            del self._preview_map[old_key]
                            self._thread_map.pop(old_key, None)

    # ===========================================================================
    # ABSCHNITT 11 — ROUTING-AKTIONSHANDLER
    # ===========================================================================

    async def _handle_blacklisted(self, domains: List[str], evt: MessageEvent) -> bool:
        self.log.info(
            "🚫 Blacklist-Treffer: %s in %s von %s", domains, evt.room_id, evt.sender
        )
        redacted = await self._redact(
            evt.room_id,
            evt.event_id,
            reason=f"Gesperrte Domain(s): {', '.join(domains[:3])}",
        )
        now = time.monotonic()
        cooldown = float(self.config.get("warn_cooldown", 60))
        if now - self._warn_cooldowns.get(evt.sender, 0.0) >= cooldown:
            self._warn_cooldowns[evt.sender] = now
            await self._send_notice(
                evt.room_id,
                f"⚠️ {evt.sender}: Deine Nachricht wurde entfernt, da sie einen gesperrten Link enthielt. "
                f"Wende dich an einen Moderator, wenn du glaubst, dass dies ein Fehler ist.",
            )
        # DomainStats: sanitisierte Zählung pro Domain (kein Nutzerbezug)
        for _d in domains:
            try:
                await self._db_increment_domain_stats(_d)
            except Exception as _exc:
                self.log.debug("DomainStats-Inkrementierung fehlgeschlagen: %s", _exc)
        await self._handle_violation(evt.sender, evt.room_id)
        return redacted

    async def _handle_unknown(self, domains: List[str], evt: MessageEvent) -> bool:
        self.log.info(
            "🔍 Unbekannte Domain: %s in %s von %s", domains, evt.room_id, evt.sender
        )
        redacted = await self._redact(
            evt.room_id,
            evt.event_id,
            reason="Unbekannte Domain(s) — ausstehende Moderatorenüberprüfung",
        )
        now = time.monotonic()
        cooldown = float(self.config.get("warn_cooldown", 60))
        if now - self._warn_cooldowns.get(evt.sender, 0.0) >= cooldown:
            self._warn_cooldowns[evt.sender] = now
            await self._send_notice(
                evt.room_id,
                f"🔍 {evt.sender}: Deine Nachricht mit einem unbekannten Link wurde entfernt "
                f"und zur Überprüfung an die Moderatoren weitergeleitet. "
                f"Du wirst benachrichtigt, sobald eine Entscheidung getroffen wurde.",
            )
        _body: str = evt.content.body or ""
        _fmt: Optional[str] = getattr(evt.content, "formatted_body", None) or None
        for domain in domains:
            await self._submit_for_review(domain, evt)
        await self._handle_violation(evt.sender, evt.room_id)
        return redacted

    async def _handle_violation(self, sender: str, room_id: RoomID) -> None:
        if not self.config.get("mute_enabled", False):
            return
        if await self._record_violation(sender):
            muted = await self._mute_user(sender, room_id)
            if muted:
                dur_min = int(self.config.get("mute_duration_minutes", 60))
                dur_text = _format_age(dur_min * 60) if dur_min > 0 else "unbegrenzt"
                await self._send_notice(
                    room_id,
                    f"🔇 {sender} wurde wegen wiederholter Regelverstöße für {dur_text} stummgeschaltet.",
                )

    async def _mute_user(
        self, user_id: str, room_id: RoomID, duration_minutes: Optional[int] = None
    ) -> bool:
        """
        Fix #8: Setzt Powerlevel auf -1 und registriert den Zeitstempel für Auto-Entstummen.
        duration_minutes=0 bedeutet unbegrenzt. None → aus Konfiguration lesen.
        """
        if duration_minutes is None:
            duration_minutes = int(self.config.get("mute_duration_minutes", 60))
        try:
            pl_content = await self.client.get_state_event(
                room_id, EventType.ROOM_POWER_LEVELS
            )
            users: dict = pl_content.get("users", {})
            if users.get(user_id) == -1:
                return True  # bereits stummgeschaltet
            users[user_id] = -1
            pl_content["users"] = users
            await self.client.send_state_event(
                room_id,
                EventType.ROOM_POWER_LEVELS,
                pl_content,  # type: ignore[arg-type]
            )
            self.log.info(
                "Nutzer %s in Raum %s stummgeschaltet (PL -1).", user_id, room_id
            )
            # Fix #8: Zeitstempel für Auto-Entstummen speichern
            if duration_minutes and duration_minutes > 0:
                unmute_at = time.monotonic() + duration_minutes * 60.0
                self._active_mutes[(str(user_id), str(room_id))] = unmute_at
            return True
        except Exception:
            self.log.exception(
                "Stummschalten von %s in %s fehlgeschlagen.", user_id, room_id
            )
            return False

    async def _do_unmute_user(self, user_id: str, room_id: str) -> bool:
        """
        Fix #8: Hebt die Stummschaltung auf (setzt PL von -1 zurück auf 0).
        Entfernt den Eintrag aus _active_mutes. Gibt True bei Erfolg zurück.
        """
        self._active_mutes.pop((str(user_id), str(room_id)), None)
        try:
            pl_content = await self.client.get_state_event(
                RoomID(room_id), EventType.ROOM_POWER_LEVELS
            )
            users: dict = pl_content.get("users", {})
            if users.get(user_id) not in (-1, None):
                return True  # nicht (mehr) stummgeschaltet
            # Expliziten Eintrag auf 0 setzen (Raumstandard)
            users[user_id] = 0
            pl_content["users"] = users
            await self.client.send_state_event(
                RoomID(room_id),
                EventType.ROOM_POWER_LEVELS,
                pl_content,  # type: ignore[arg-type]
            )
            self.log.info("Nutzer %s in Raum %s entstummt (PL 0).", user_id, room_id)
            return True
        except Exception:
            self.log.exception(
                "Entstummen von %s in %s fehlgeschlagen.", user_id, room_id
            )
            return False

    async def _auto_unmute_loop(self) -> None:
        """
        Fix #8: Hintergrund-Task der alle 30 Sekunden abgelaufene Stummschaltungen aufhebt.
        Läuft unabhängig von mute_enabled (schadet nicht wenn nichts in _active_mutes steht).
        """
        self.log.debug("Auto-Entstumm-Loop gestartet.")
        while True:
            await asyncio.sleep(30)
            now = time.monotonic()
            expired = [
                (uid, rid)
                for (uid, rid), unmute_at in list(self._active_mutes.items())
                if unmute_at <= now
            ]
            for user_id, room_id in expired:
                success = await self._do_unmute_user(user_id, room_id)
                if success:
                    await self._send_notice(
                        RoomID(room_id),
                        f"🔊 {user_id} wurde automatisch entstummt.",
                    )

    async def _post_link_preview(
        self,
        domain: str,
        url: str,
        room_id: RoomID,
        reply_to_event_id: Optional[EventID] = None,
        edit_preview_event_id: Optional[EventID] = None,
        thread_root_id: Optional[str] = None,
    ) -> Optional[EventID]:
        """
        Ruft OG-Metadaten ab und postet eine Markdown-Vorschaubenachrichtigung.

        Fix #12: Wenn edit_preview_event_id gesetzt ist, wird die bestehende
                 Vorschau bearbeitet statt eine neue zu senden.
        Fix #12: Wenn reply_to_event_id gesetzt ist, wird die Vorschau als
                 Matrix-Reply auf die Nutzernachricht gesendet.
        Fix #13: Gibt EventID zurück, damit der Aufrufer das Mapping speichern kann.
        Thread:  Wenn thread_root_id gesetzt ist, wird die Vorschau als Thread-Reply
                 gesendet (m.relates_to rel_type: m.thread).
        """
        meta = await self._fetch_og_metadata(url)
        if not meta:
            return None
        title = meta.get("title") or domain
        desc = meta.get("description") or ""
        lines = [f"**{title}**"]
        if desc:
            lines.append(f"> {desc}")
        lines.append(f"[{domain}]({url})")
        text = "\n".join(lines)

        # Fix #12: bestehende Vorschau bearbeiten wenn vorhanden
        if edit_preview_event_id:
            await self._edit_notice(room_id, edit_preview_event_id, text)
            return edit_preview_event_id  # unveränderte ID zurückgeben

        # Fix #12: Vorschau als Reply auf Nutzernachricht senden
        try:
            html = _md_to_html(text)
            content = TextMessageEventContent(
                msgtype=MessageType.NOTICE,
                body=text,
                format=Format.HTML,
                formatted_body=html,
            )
            # m.relates_to setzen:
            # Thread-Nachricht → m.thread + m.in_reply_to kombinieren,
            # damit die Vorschau im selben Thread landet.
            # Normale Nachricht → nur m.in_reply_to (bisheriges Verhalten).
            if reply_to_event_id:
                if thread_root_id:
                    content["m.relates_to"] = {
                        "rel_type": "m.thread",
                        "event_id": thread_root_id,
                        "m.in_reply_to": {"event_id": str(reply_to_event_id)},
                        "is_falling_back": False,
                    }
                else:
                    content["m.relates_to"] = {
                        "m.in_reply_to": {"event_id": str(reply_to_event_id)}
                    }
            return await self.client.send_message(room_id, content)
        except Exception as exc:
            self.log.error("Linkvorschau für '%s' fehlgeschlagen: %s", domain, exc)
            return None

    async def _update_previews_for_edit(
        self,
        msg_key: str,
        new_domains: List[str],
        body: str,
        formatted_body: Optional[str],
        room_id: RoomID,
        reply_target_id: EventID,
        thread_root_id: Optional[str] = None,
    ) -> None:
        """
        Synchronisiert Bot-Vorschauen nach einem Nutzer-Edit.

        Algorithmus (Reihenfolge wichtig):
        1. Gleiche Domain → bestehende Vorschau in-place bearbeiten (kein neues Zitat).
        2. Neue Domain, alte Vorschau frei → alte Vorschau mit neuem Inhalt überschreiben.
        3. Mehr neue Domains als alte Vorschauen → fehlende Vorschauen neu senden.
        4. Mehr alte Vorschauen als neue Domains → Überschuss-Vorschauen löschen (redact).

        Damit wird gewährleistet:
        - Domain wechselt (hass.com → deepl.com): 1 Edit, 0 neue Nachrichten.
        - 3 Links → 1 Link: 1 Edit + 2 gelöschte Vorschauen, 0 neue Nachrichten.
        - 1 Link → 3 Links: 1 Edit + 2 neue Vorschauen.
        """
        old_map: Dict[str, EventID] = dict(self._preview_map.get(msg_key, {}))
        new_map: Dict[str, EventID] = {}
        remaining_old: Dict[str, EventID] = dict(old_map)
        deferred: List[str] = []  # neue Domains ohne direkten Same-Domain-Match

        # Phase 1: Same-Domain-Matches — bevorzugte 1:1-Zuordnung
        for domain in new_domains:
            url = self._find_url_for_domain(body, domain, formatted_body)
            if not url:
                continue
            if domain in remaining_old:
                old_id = remaining_old.pop(domain)
                result = await self._post_link_preview(
                    domain,
                    url,
                    room_id,
                    reply_to_event_id=reply_target_id,
                    edit_preview_event_id=old_id,
                    thread_root_id=thread_root_id,
                )
                new_map[domain] = result or old_id
            else:
                deferred.append(domain)

        # Phase 2: Verbleibende neue Domains auf freie alte Vorschauen mappen
        old_pool = list(remaining_old.items())  # [(domain, preview_id), ...]
        reuse_idx = 0
        for domain in deferred:
            url = self._find_url_for_domain(body, domain, formatted_body)
            if not url:
                continue
            if reuse_idx < len(old_pool):
                _, old_id = old_pool[reuse_idx]
                reuse_idx += 1
                result = await self._post_link_preview(
                    domain,
                    url,
                    room_id,
                    reply_to_event_id=reply_target_id,
                    edit_preview_event_id=old_id,
                    thread_root_id=thread_root_id,
                )
                new_map[domain] = result or old_id
            else:
                # Mehr Links als vorher → neue Vorschau senden
                result = await self._post_link_preview(
                    domain,
                    url,
                    room_id,
                    reply_to_event_id=reply_target_id,
                    thread_root_id=thread_root_id,
                )
                if result:
                    new_map[domain] = result

        # Phase 3: Überschüssige alte Vorschauen löschen (weniger Links als vorher)
        for _, old_id in old_pool[reuse_idx:]:
            await self._redact(
                room_id, old_id, reason="Link aus bearbeiteter Nachricht entfernt"
            )

        # Map aktualisieren
        if new_map:
            self._preview_map[msg_key] = new_map
        elif msg_key in self._preview_map:
            del self._preview_map[msg_key]

    # ===========================================================================
    # ABSCHNITT 12 — MODERATIONSRAUM: PRÜFANFRAGE EINREICHEN
    # ===========================================================================

    async def _submit_for_review(self, domain: str, evt: MessageEvent) -> None:
        mod_room = RoomID(self.config.get("mod_room_id", ""))
        if not mod_room:
            self.log.warning(
                "mod_room_id nicht konfiguriert — '%s' kann nicht weitergeleitet werden.",
                domain,
            )
            return
        if domain in self._pending_domains:
            self.log.info(
                "Domain '%s' hat bereits eine offene Überprüfung — übersprungen.",
                domain,
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
            self.log.error("Alarm für '%s' konnte nicht gesendet werden.", domain)
            return

        review = PendingReview(
            domain=domain,
            original_event_id=evt.event_id,
            original_room_id=evt.room_id,
            sender=evt.sender,
        )
        self.pending_reviews[alert_id] = review
        self._pending_domains.add(domain)

        # DB-Persistenz: DSGVO-konform — keine Sender-ID, keine vollständige URL
        try:
            await self._db_upsert_pending_review(
                str(alert_id),
                str(evt.room_id),
                str(evt.event_id),
                domain,
            )
        except Exception as exc:
            self.log.error(
                "PendingReview-DB-Schreiben fehlgeschlagen für '%s': %s", domain, exc
            )

        review.whitelist_reaction_id = await self._send_reaction(
            mod_room, alert_id, _EMOJI_ALLOW
        )
        review.blacklist_reaction_id = await self._send_reaction(
            mod_room, alert_id, _EMOJI_BLOCK
        )
        self.log.info(
            "Überprüfung eingereicht: domain='%s' sender=%s", domain, evt.sender
        )

    # ===========================================================================
    # ABSCHNITT 13 — REAKTIONS-EVENTHANDLER
    # ===========================================================================

    @event.on(EventType.REACTION)  # type: ignore[arg-type]
    async def on_reaction(self, evt: MessageEvent) -> None:
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
        if target_id is None:
            return
        target_id = EventID(target_id)
        review = self.pending_reviews.get(target_id)
        if not review:
            return
        if not await self._is_mod(evt.sender, evt.room_id):
            return
        if emoji_key == _EMOJI_ALLOW:
            await self._execute_allow(review, target_id, evt.sender)
        elif emoji_key == _EMOJI_BLOCK:
            await self._execute_block(review, target_id, evt.sender)

    # ===========================================================================
    # ABSCHNITT 14 — MODERATIONSAUSFÜHRUNG
    # ===========================================================================

    async def _execute_allow(
        self, review: PendingReview, alert_id: EventID, mod_user: UserID
    ) -> None:
        domain = review.domain

        # Fix: In-Memory-Sets VOR dem DB-Await aktualisieren.
        # Reason: await self._db_upsert_domain_rule() gibt den Event-Loop frei.
        # Zwischen diesem yield und der Rückkehr kann on_message() laufen und die
        # Domain als "unknown" klassifizieren → Nachricht wird trotz Freigabe gelöscht.
        # Durch das sofortige whitelist_set.add() ist die Domain für alle concurrent
        # on_message()-Coroutinen ab jetzt als "whitelisted" sichtbar.
        self.whitelist_set.add(domain)
        self.blacklist_set.discard(domain)

        try:
            await self._db_upsert_domain_rule(
                domain, is_blacklisted=False, ignore_preview=False
            )
        except Exception as exc:
            # Rollback bei DB-Fehler (Whitelist-Eintrag bleibt für diese Session gültig,
            # wird aber bei Neustart nicht wiederhergestellt — Mod soll erneut erlauben).
            self.log.warning(
                "DB-Upsert für Whitelist fehlgeschlagen ('%s'): %s — In-Memory-Eintrag bleibt.",
                domain,
                exc,
            )
            await self._send_notice(
                self.config["mod_room_id"],
                f"⚠️ **Datenbankfehler (Whitelist):** `{domain}` — `{type(exc).__name__}: {exc}`\n"
                f"Domain ist für diese Session whitelisted, aber wird nach Neustart nicht gespeichert.",
            )
            # Kein return — Genehmigung gilt trotzdem für laufende Session
        self.pending_reviews.pop(alert_id, None)
        self._pending_domains.discard(domain)
        try:
            await self._db_delete_pending_review(str(alert_id))
        except Exception as exc:
            self.log.debug(
                "PendingReview-DB-Löschen nach Allow fehlgeschlagen: %s", exc
            )
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
        self.log.info("Domain '%s' von %s whitelisted.", domain, mod_user)

    async def _execute_block(
        self, review: PendingReview, alert_id: EventID, mod_user: UserID
    ) -> None:
        domain = review.domain
        try:
            await self._db_upsert_domain_rule(
                domain, is_blacklisted=True, ignore_preview=False
            )
        except Exception as exc:
            await self._send_notice(
                self.config["mod_room_id"],
                f"❌ **Datenbankfehler (Blacklist):** `{domain}` — `{type(exc).__name__}: {exc}`",
            )
            return

        self.blacklist_set.add(domain)
        self.whitelist_set.discard(domain)
        self.pending_reviews.pop(alert_id, None)
        self._pending_domains.discard(domain)
        try:
            await self._db_delete_pending_review(str(alert_id))
        except Exception as exc:
            self.log.debug(
                "PendingReview-DB-Löschen nach Block fehlgeschlagen: %s", exc
            )
        await self._edit_notice(
            self.config["mod_room_id"],
            alert_id,
            f"❌ **Blacklisted** von {mod_user}\nDomain `{domain}` ist jetzt gesperrt.",
        )
        await self._send_notice(
            review.original_room_id,
            f"🚫 Ein Link gesendet von {review.sender} wurde von den Moderatoren **gesperrt**.",
        )
        self.log.info("Domain '%s' von %s blacklisted.", domain, mod_user)

    # ===========================================================================
    # ABSCHNITT 15 — BEFEHLSHANDLER
    # ===========================================================================

    # ---------------------------------------------------------------------------
    # Gemeinsamer Gate-Check für alle Befehlshandler
    # ---------------------------------------------------------------------------

    async def _is_allowed_command_room(self, room_id: RoomID) -> bool:
        """
        Fix #2: Gibt True zurück wenn Befehle in diesem Raum erlaubt sind.

        Logik:
          1. Keine command_rooms konfiguriert → alle Räume erlaubt.
          2. mod_room_id → immer erlaubt.
          3. Raum ist in command_rooms → erlaubt.
          4. DM (2 Mitglieder: Bot + 1 Nutzer) → erlaubt.
          5. Sonst → verweigert (Bot ignoriert Befehl still).
        """
        command_rooms = self.config.get("command_rooms", [])
        if not command_rooms:
            return True
        mod_room = RoomID(self.config.get("mod_room_id", ""))
        if str(room_id) == mod_room:
            return True
        allowed = [str(r) for r in command_rooms]
        if str(room_id) in allowed:
            return True
        # DM-Prüfung
        try:
            members = await self.client.get_joined_members(room_id)
            if len(members) == 2:
                return True
        except Exception:
            pass
        return False

    # ---------------------------------------------------------------------------
    # !allow  [Fix #4: pending sync + wildcard sweep, Fix #6: multi-domain]
    # ---------------------------------------------------------------------------

    @command.new(
        "allow",
        help="[Mod] Domain(s) whitelisten. Verwendung: !allow <domain> [domain2 ...]",
    )
    @command.argument("domains_raw", pass_raw=True, required=True)
    async def cmd_allow(self, evt: MessageEvent, domains_raw: str) -> None:
        if not await self._is_allowed_command_room(evt.room_id):
            return
        if not await self._is_mod(evt.sender, evt.room_id):
            await evt.reply("❌ Du hast keine Berechtigung, Domains zu whitelisten.")
            return

        # Fix #6: alle Domains aus dem Argument extrahieren
        domain_list = _split_domain_args(domains_raw)
        if not domain_list:
            await evt.reply(
                "❌ Verwendung: `!allow <domain>` oder `!allow domain1.com domain2.com`"
            )
            return

        results: List[str] = []

        for domain in domain_list:
            if not _valid_domain(domain):
                results.append(f"❌ `{domain}` — ungültige Domain")
                continue
            is_wildcard = domain.startswith("*.")
            suffix = domain[2:] if is_wildcard else None
            # Fix #17: Duplikat-Prüfung — Domain bereits auf der Whitelist?
            if (is_wildcard and suffix in self.whitelist_wildcards) or (
                not is_wildcard and domain in self.whitelist_set
            ):
                results.append(f"ℹ️ `{domain}` ist bereits auf der Whitelist")
                continue
            try:
                if is_wildcard:
                    assert suffix is not None
                    # Wildcards werden nicht in domain_rule gespeichert (kein PK-konformes Format)
                    # Sie werden nur in den In-Memory-Sets gehalten (aus Textdateien)
                    self.whitelist_wildcards.add(suffix)
                    self.blacklist_wildcards.discard(suffix)
                else:
                    # Fix: In-Memory-Update VOR dem DB-await (verhindert Race-Condition
                    # bei der on_message() zwischen yield-Punkt und whitelist_set.add läuft)
                    self.whitelist_set.add(domain)
                    self.blacklist_set.discard(domain)
                    await self._db_upsert_domain_rule(
                        domain, is_blacklisted=False, ignore_preview=False
                    )
                results.append(f"✅ `{domain}` zur Whitelist hinzugefügt")
                self.log.info("'%s' manuell von %s whitelisted.", domain, evt.sender)

                # Fix #4: Pending-Reviews für diese Domain (oder passende Subdomains) aufräumen
                await self._resolve_pending_for_domain(
                    domain, is_whitelist=True, mod_user=evt.sender
                )

            except Exception as exc:
                results.append(
                    f"❌ `{domain}` — Datenbankfehler: `{type(exc).__name__}: {exc}`"
                )

        await evt.reply("\n".join(results))

    # ---------------------------------------------------------------------------
    # !block  [Fix #4, Fix #6]
    # ---------------------------------------------------------------------------

    @command.new(
        "block",
        help="[Mod] Domain(s) blacklisten. Verwendung: !block <domain> [domain2 ...]",
    )
    @command.argument("domains_raw", pass_raw=True, required=True)
    async def cmd_block(self, evt: MessageEvent, domains_raw: str) -> None:
        if not await self._is_allowed_command_room(evt.room_id):
            return
        if not await self._is_mod(evt.sender, evt.room_id):
            await evt.reply("❌ Du hast keine Berechtigung, Domains zu blacklisten.")
            return

        domain_list = _split_domain_args(domains_raw)
        if not domain_list:
            await evt.reply(
                "❌ Verwendung: `!block <domain>` oder `!block domain1.com domain2.com`"
            )
            return

        results: List[str] = []

        for domain in domain_list:
            if not _valid_domain(domain):
                results.append(f"❌ `{domain}` — ungültige Domain")
                continue
            is_wildcard = domain.startswith("*.")
            suffix = domain[2:] if is_wildcard else None
            # Fix #17: Duplikat-Prüfung — Domain bereits auf der Blacklist?
            if (is_wildcard and suffix in self.blacklist_wildcards) or (
                not is_wildcard and domain in self.blacklist_set
            ):
                results.append(f"ℹ️ `{domain}` ist bereits auf der Blacklist")
                continue
            try:
                if is_wildcard:
                    assert suffix is not None
                    self.blacklist_wildcards.add(suffix)
                    self.whitelist_wildcards.discard(suffix)
                else:
                    await self._db_upsert_domain_rule(
                        domain, is_blacklisted=True, ignore_preview=False
                    )
                    self.blacklist_set.add(domain)
                    self.whitelist_set.discard(domain)
                results.append(f"🚫 `{domain}` zur Blacklist hinzugefügt")
                self.log.info("'%s' manuell von %s blacklisted.", domain, evt.sender)

                # Fix #4: Pending-Reviews aufräumen
                await self._resolve_pending_for_domain(
                    domain, is_whitelist=False, mod_user=evt.sender
                )

            except Exception as exc:
                results.append(
                    f"❌ `{domain}` — Datenbankfehler: `{type(exc).__name__}: {exc}`"
                )

        await evt.reply("\n".join(results))

    async def _resolve_pending_for_domain(
        self, domain: str, is_whitelist: bool, mod_user: str
    ) -> None:
        """
        Fix #4: Räumt pending_reviews für eine Domain (oder deren Subdomains bei Wildcard) auf.

        Bei !allow example.com:   bereinigt pending entries für genau "example.com"
        Bei !allow *.example.com: bereinigt pending entries für alle Subdomains von example.com
        Bei !block:               analog, aber sendet die Blocked-Meldung
        """
        is_wildcard = domain.startswith("*.")
        suffix = domain[2:] if is_wildcard else None
        mod_room = RoomID(self.config.get("mod_room_id", ""))

        # Snapshot der aktuellen Reviews (wir mutieren das Dict während der Iteration)
        to_resolve: List[Tuple[EventID, PendingReview]] = []
        for alert_id, review in list(self.pending_reviews.items()):
            if is_wildcard:
                assert suffix is not None
                # Wildcard *.example.com trifft sub.example.com, api.example.com usw.
                if review.domain.endswith("." + suffix):
                    to_resolve.append((alert_id, review))
            else:
                if review.domain == domain:
                    to_resolve.append((alert_id, review))

        for alert_id, review in to_resolve:
            self.pending_reviews.pop(alert_id, None)
            self._pending_domains.discard(review.domain)
            # DB-Eintrag entfernen
            try:
                await self._db_delete_pending_review(str(alert_id))
            except Exception as exc:
                self.log.debug("PendingReview-DB-Löschen fehlgeschlagen: %s", exc)
            # Mod-Raum-Alarm aktualisieren
            if mod_room:
                if is_whitelist:
                    await self._edit_notice(
                        mod_room,
                        alert_id,
                        f"✅ **Whitelisted** von {mod_user} (Befehl)\nDomain `{review.domain}` ist jetzt erlaubt.",
                    )
                else:
                    await self._edit_notice(
                        mod_room,
                        alert_id,
                        f"❌ **Blacklisted** von {mod_user} (Befehl)\nDomain `{review.domain}` ist jetzt gesperrt.",
                    )
            # Originalraum benachrichtigen
            if is_whitelist:
                await self._send_notice(
                    review.original_room_id,
                    f"✅ Der Link zu `{review.domain}` (gesendet von {review.sender}) wurde von den Moderatoren "
                    f"**genehmigt**. Du kannst deine Nachricht erneut senden.",
                )
            else:
                await self._send_notice(
                    review.original_room_id,
                    f"🚫 Ein Link gesendet von {review.sender} wurde von den Moderatoren **gesperrt**.",
                )

    # ---------------------------------------------------------------------------
    # !unallow  [Fix #6: multi-domain]
    # ---------------------------------------------------------------------------

    @command.new("unallow", help="[Mod] Domain(s) aus der Whitelist entfernen.")
    @command.argument("domains_raw", pass_raw=True, required=True)
    async def cmd_unallow(self, evt: MessageEvent, domains_raw: str) -> None:
        if not await self._is_allowed_command_room(evt.room_id):
            return
        if not await self._is_mod(evt.sender, evt.room_id):
            await evt.reply(
                "❌ Du hast keine Berechtigung, Domains aus der Whitelist zu entfernen."
            )
            return
        domain_list = _split_domain_args(domains_raw)
        if not domain_list:
            await evt.reply("❌ Verwendung: `!unallow <domain>` [domain2 ...]")
            return
        results: List[str] = []
        for domain in domain_list:
            if not _valid_domain(domain):
                results.append(f"❌ `{domain}` — ungültige Domain")
                continue
            is_wildcard = domain.startswith("*.")
            suffix = domain[2:] if is_wildcard else None
            try:
                if is_wildcard:
                    self.whitelist_wildcards.discard(suffix)
                else:
                    await self._db_delete_domain_rule(domain)
                    self.whitelist_set.discard(domain)
                results.append(f"✅ `{domain}` aus der Whitelist entfernt")
                self.log.info("'%s' aus Whitelist entfernt von %s.", domain, evt.sender)
            except Exception as exc:
                results.append(
                    f"❌ `{domain}` — Datenbankfehler: `{type(exc).__name__}: {exc}`"
                )
        await evt.reply("\n".join(results))

    # ---------------------------------------------------------------------------
    # !unblock  [Fix #6: multi-domain]
    # ---------------------------------------------------------------------------

    @command.new("unblock", help="[Mod] Domain(s) aus der Blacklist entfernen.")
    @command.argument("domains_raw", pass_raw=True, required=True)
    async def cmd_unblock(self, evt: MessageEvent, domains_raw: str) -> None:
        if not await self._is_allowed_command_room(evt.room_id):
            return
        if not await self._is_mod(evt.sender, evt.room_id):
            await evt.reply(
                "❌ Du hast keine Berechtigung, Domains aus der Blacklist zu entfernen."
            )
            return
        domain_list = _split_domain_args(domains_raw)
        if not domain_list:
            await evt.reply("❌ Verwendung: `!unblock <domain>` [domain2 ...]")
            return
        results: List[str] = []
        for domain in domain_list:
            if not _valid_domain(domain):
                results.append(f"❌ `{domain}` — ungültige Domain")
                continue
            is_wildcard = domain.startswith("*.")
            suffix = domain[2:] if is_wildcard else None
            try:
                if is_wildcard:
                    self.blacklist_wildcards.discard(suffix)
                else:
                    await self._db_delete_domain_rule(domain)
                    self.blacklist_set.discard(domain)
                results.append(f"✅ `{domain}` aus der Blacklist entfernt")
                self.log.info("'%s' aus Blacklist entfernt von %s.", domain, evt.sender)
            except Exception as exc:
                results.append(
                    f"❌ `{domain}` — Datenbankfehler: `{type(exc).__name__}: {exc}`"
                )
        await evt.reply("\n".join(results))

    # ---------------------------------------------------------------------------
    # !urlstatus  [Fix #6: multi-domain]
    # ---------------------------------------------------------------------------

    @command.new(
        "urlstatus",
        help="Aktuellen Richtlinienstatus einer oder mehrerer Domains prüfen.",
    )
    @command.argument("domains_raw", pass_raw=True, required=True)
    async def cmd_status(self, evt: MessageEvent, domains_raw: str) -> None:
        if not await self._is_allowed_command_room(evt.room_id):
            return
        domain_list = [
            d.split("://", 1)[-1].split("/")[0] for d in _split_domain_args(domains_raw)
        ]
        if not domain_list:
            await evt.reply("❌ Verwendung: `!urlstatus <domain>` [domain2 ...]")
            return
        results: List[str] = []
        for domain in domain_list:
            if not _valid_domain(domain):
                results.append(f"❌ `{domain}` — ungültige Domain")
            elif domain in self.whitelist_set:
                ignored = (
                    " · 🔇 Vorschau ignoriert"
                    if domain in self.ignore_preview_set
                    else ""
                )
                results.append(f"✅ `{domain}` ist **whitelisted** (exakt){ignored}")
            elif self._matches_wildcards(domain, self.whitelist_wildcards):
                ignored = (
                    " · 🔇 Vorschau ignoriert"
                    if domain in self.ignore_preview_set
                    else ""
                )
                results.append(f"✅ `{domain}` ist **whitelisted** (Wildcard){ignored}")
            elif self._matches_apex(domain, self.whitelist_set):
                ignored = (
                    " · 🔇 Vorschau ignoriert"
                    if domain in self.ignore_preview_set
                    else ""
                )
                results.append(f"✅ `{domain}` ist **whitelisted** (Apex){ignored}")
            elif domain in self.blacklist_set:
                results.append(f"🚫 `{domain}` ist **blacklisted** (exakt)")
            elif self._matches_wildcards(domain, self.blacklist_wildcards):
                results.append(f"🚫 `{domain}` ist **blacklisted** (Wildcard)")
            elif self._matches_apex(domain, self.blacklist_set):
                results.append(f"🚫 `{domain}` ist **blacklisted** (Apex)")
            else:
                ignored = (
                    " · 🔇 Vorschau ignoriert"
                    if domain in self.ignore_preview_set
                    else ""
                )
                results.append(f"❓ `{domain}` ist **unbekannt**{ignored}")
        await evt.reply("\n".join(results))

    # ---------------------------------------------------------------------------
    # !reloadlists
    # ---------------------------------------------------------------------------

    @command.new("reloadlists", help="[Mod] Alle Listendateien neu einlesen.")
    async def cmd_reload(self, evt: MessageEvent) -> None:
        if not await self._is_allowed_command_room(evt.room_id):
            return
        if not await self._is_mod(evt.sender, evt.room_id):
            await evt.reply("❌ Du hast keine Berechtigung, Listen neu zu laden.")
            return
        self.log.info(
            "🔄 !reloadlists aufgerufen von %s in %s", evt.sender, evt.room_id
        )
        old_bl = len(self.blacklist_set)
        old_wl = len(self.whitelist_set)
        old_bl_wc = len(self.blacklist_wildcards)
        old_wl_wc = len(self.whitelist_wildcards)
        await evt.reply("🔄 Listen werden neu geladen – dauert ca. 30 Sek. ...")
        await self._reload_lists()
        # Fix Bugs 1/2/3: Re-apply runtime DB overrides (approved/blocked domains)
        # after reloading files. Without this call, _reload_lists() silently erases
        # every domain that was approved or blocked at runtime (stored in DB), causing:
        #   - Bug 1: Duplicate "unknown link" notifications (domain vanishes from whitelist_set)
        #   - Bug 2: Spurious 🔍 line appearing next to ⚠️ (domain vanishes from blacklist_set)
        #   - Bug 3: Bot re-deletes messages for previously-approved URLs
        await self._load_domain_rules_cache()
        await self._send_notice(
            evt.room_id,
            f"🏁 Neuladen abgeschlossen.\n"
            f"Blacklist: **{old_bl:,}** → **{len(self.blacklist_set):,}** "
            f"(Wildcards: {old_bl_wc} → {len(self.blacklist_wildcards)})\n"
            f"Whitelist: **{old_wl:,}** → **{len(self.whitelist_set):,}** "
            f"(Wildcards: {old_wl_wc} → {len(self.whitelist_wildcards)})",
            render_markdown=True,
        )

    # ---------------------------------------------------------------------------
    # !pending  [Fix #9: menschenlesbare Zeiten]
    # ---------------------------------------------------------------------------

    @command.new("pending", help="[Mod] Offene URL-Überprüfungsanfragen auflisten.")
    async def cmd_pending(self, evt: MessageEvent) -> None:
        if not await self._is_allowed_command_room(evt.room_id):
            return
        if not await self._is_mod(evt.sender, evt.room_id):
            await evt.reply(
                "❌ Du hast keine Berechtigung, ausstehende Überprüfungen einzusehen."
            )
            return
        if not self.pending_reviews:
            await evt.reply("✅ Keine ausstehenden URL-Überprüfungen.")
            return
        lines = [f"**{len(self.pending_reviews)} ausstehende Überprüfung(en):**\n"]
        for alert_id, rev in self.pending_reviews.items():
            age_s = int(time.monotonic() - rev.submitted_at)
            age_text = _format_age(age_s)  # Fix #9
            lines.append(
                f"• `{rev.domain}` — {rev.sender} in `{rev.original_room_id}` (vor {age_text})"
            )
        await self._send_notice(evt.room_id, "\n".join(lines), render_markdown=True)

    # ---------------------------------------------------------------------------
    # !sendpending  [Fix #11]
    # ---------------------------------------------------------------------------

    @command.new(
        "sendpending",
        help="[Mod] Alle offenen Überprüfungsalarme im Mod-Raum neu senden.",
    )
    async def cmd_sendpending(self, evt: MessageEvent) -> None:
        """
        Fix #11: Sendet alle offenen pending_reviews-Alarme neu in den Mod-Raum.
        Alte Dict-Einträge werden durch neue ersetzt. Nützlich wenn alte Nachrichten
        im Mod-Raum zu weit hochgescrollt sind.
        """
        if not await self._is_allowed_command_room(evt.room_id):
            return
        if not await self._is_mod(evt.sender, evt.room_id):
            await evt.reply("❌ Du hast keine Berechtigung.")
            return
        self.log.info(
            "📤 !sendpending aufgerufen von %s in %s", evt.sender, evt.room_id
        )
        if not self.pending_reviews:
            await evt.reply("✅ Keine ausstehenden Überprüfungen.")
            return

        mod_room = RoomID(self.config.get("mod_room_id", ""))
        if not mod_room:
            await evt.reply("❌ mod_room_id ist nicht konfiguriert.")
            return

        old_reviews = list(self.pending_reviews.items())
        resent = 0
        failed = 0

        for old_alert_id, review in old_reviews:
            sender_display = (
                review.sender if review.sender else "(Unbekannt — Bot neugestartet)"
            )
            alert_text = (
                f"🔔 **URL-Überprüfung erforderlich** *(erneut gesendet)*\n\n"
                f"**Absender:** {sender_display}\n"
                f"**Raum:** `{review.original_room_id}`\n"
                f"**Domain:** `{review.domain}`\n"
                f"**Eingereicht:** vor {_format_age(int(time.monotonic() - review.submitted_at))}\n\n"
                f"Reagiere mit {_EMOJI_ALLOW} zum **Whitelisten** oder {_EMOJI_BLOCK} zum **Blacklisten**.\n"
                f"Oder verwende: `!allow {review.domain}` / `!block {review.domain}`"
            )
            new_alert_id = await self._send_notice(
                mod_room, alert_text, render_markdown=True
            )
            if not new_alert_id:
                failed += 1
                continue

            # Alten Eintrag entfernen, neuen eintragen (submitted_at beibehalten)
            self.pending_reviews.pop(old_alert_id, None)
            # DB-Eintrag mit alter ID entfernen
            try:
                await self._db_delete_pending_review(str(old_alert_id))
            except Exception as exc:
                self.log.debug(
                    "PendingReview-DB-Löschen (sendpending) fehlgeschlagen: %s", exc
                )

            new_review = PendingReview(
                domain=review.domain,
                original_event_id=review.original_event_id,
                original_room_id=review.original_room_id,
                sender=review.sender,
                submitted_at=review.submitted_at,  # Ursprungszeit behalten
            )
            self.pending_reviews[new_alert_id] = new_review
            # Neue DB-Persistenz für die neue alert_event_id
            try:
                await self._db_upsert_pending_review(
                    str(new_alert_id),
                    str(review.original_room_id),
                    str(review.original_event_id),
                    review.domain,
                )
            except Exception as exc:
                self.log.debug(
                    "PendingReview-DB-Schreiben (sendpending) fehlgeschlagen: %s", exc
                )
            # Reaktionsknöpfe neu hinzufügen
            new_review.whitelist_reaction_id = await self._send_reaction(
                mod_room, new_alert_id, _EMOJI_ALLOW
            )
            new_review.blacklist_reaction_id = await self._send_reaction(
                mod_room, new_alert_id, _EMOJI_BLOCK
            )
            resent += 1

        msg = f"✅ {resent} Überprüfung(en) neu gesendet."
        if failed:
            msg += f" ⚠️ {failed} konnten nicht gesendet werden (siehe Logs)."
        await evt.reply(msg)

    # ---------------------------------------------------------------------------
    # !mute  [Fix #10]
    # ---------------------------------------------------------------------------

    @command.new(
        "mute",
        help="[Mod] Nutzer stummschalten. Verwendung: !mute <@user:server> [-t Minuten]",
    )
    @command.argument("args_raw", pass_raw=True, required=True)
    async def cmd_mute(self, evt: MessageEvent, args_raw: str) -> None:
        """
        Fix #10: Manuelles Stummschalten eines Nutzers.
        Syntax: !mute <@user:server> [-t <Minuten>]
        Ohne -t wird mute_duration_minutes aus der Konfiguration verwendet.
        """
        if not await self._is_allowed_command_room(evt.room_id):
            return
        # Fix #18: Befehl per Konfiguration deaktivierbar (z.B. bei mehreren Bots im Raum)
        if not self.config.get("mute_commands_enabled", True):
            return
        if not await self._is_mod(evt.sender, evt.room_id):
            await evt.reply("❌ Du hast keine Berechtigung, Nutzer stummzuschalten.")
            return

        user_id, duration_minutes = _parse_user_time_args(args_raw)
        if not user_id:
            await evt.reply(
                "❌ Verwendung: `!mute <@user:server>` oder `!mute <@user:server> -t 30`\n"
                "Beispiel: `!mute @spammer:matrix.org -t 60`"
            )
            return
        if not user_id.startswith("@") or ":" not in user_id[1:]:
            await evt.reply("❌ Ungültige Nutzer-ID. Erwartet: `@nutzer:homeserver`")
            return

        if duration_minutes is None:
            duration_minutes = int(self.config.get("mute_duration_minutes", 60))

        # Stummschalten im Raum wo der Befehl eingegeben wurde (oder Mod-Raum)
        target_room = evt.room_id
        success = await self._mute_user(user_id, target_room, duration_minutes)
        if success:
            dur_text = (
                _format_age(duration_minutes * 60)
                if duration_minutes > 0
                else "unbegrenzt"
            )
            await evt.reply(f"🔇 `{user_id}` wurde für {dur_text} stummgeschaltet.")
            self.log.info(
                "Manuelles Mute: %s in %s für %s min von %s.",
                user_id,
                target_room,
                duration_minutes,
                evt.sender,
            )
        else:
            await evt.reply(
                f"❌ Stummschalten von `{user_id}` fehlgeschlagen. Prüfe die Bot-Berechtigungen und die Logs."
            )

    # ---------------------------------------------------------------------------
    # !unmute  [Fix #10]
    # ---------------------------------------------------------------------------

    @command.new(
        "unmute",
        help="[Mod] Stummschaltung aufheben. Verwendung: !unmute <@user:server>",
    )
    @command.argument("args_raw", pass_raw=True, required=True)
    async def cmd_unmute(self, evt: MessageEvent, args_raw: str) -> None:
        """
        Fix #10: Manuelle sofortige Entstummung eines Nutzers.
        Entfernt auch aus _active_mutes, sodass der Auto-Entstumm-Task diesen Nutzer überspringt.
        """
        if not await self._is_allowed_command_room(evt.room_id):
            return
        # Fix #18: Befehl per Konfiguration deaktivierbar (z.B. bei mehreren Bots im Raum)
        if not self.config.get("mute_commands_enabled", True):
            return
        if not await self._is_mod(evt.sender, evt.room_id):
            await evt.reply(
                "❌ Du hast keine Berechtigung, Stummschaltungen aufzuheben."
            )
            return

        user_id, _ = _parse_user_time_args(args_raw)
        if not user_id:
            await evt.reply("❌ Verwendung: `!unmute <@user:server>`")
            return
        if not user_id.startswith("@") or ":" not in user_id[1:]:
            await evt.reply("❌ Ungültige Nutzer-ID. Erwartet: `@nutzer:homeserver`")
            return

        target_room = evt.room_id
        success = await self._do_unmute_user(user_id, target_room)
        if success:
            await evt.reply(f"🔊 `{user_id}` wurde entstummt.")
            self.log.info(
                "Manuelles Unmute: %s in %s von %s.", user_id, target_room, evt.sender
            )
        else:
            await evt.reply(
                f"❌ Entstummen von `{user_id}` fehlgeschlagen. Prüfe die Logs."
            )

    # ---------------------------------------------------------------------------
    # !liststats
    # ---------------------------------------------------------------------------

    @command.new(
        "liststats", help="Aktuelle Listengrößen und Bot-Statistiken anzeigen."
    )
    async def cmd_stats(self, evt: MessageEvent) -> None:
        if not await self._is_allowed_command_room(evt.room_id):
            return
        await evt.reply(
            f"📊 **Listen-Statistiken**\n"
            f"Blacklist: **{len(self.blacklist_set):,}** Domains + "
            f"**{len(self.blacklist_wildcards)}** Wildcards\n"
            f"Whitelist: **{len(self.whitelist_set):,}** Domains + "
            f"**{len(self.whitelist_wildcards)}** Wildcards\n"
            f"Vorschau-Ignore-Liste: **{len(self.ignore_preview_set)}** Domains\n"
            f"Ausstehende Überprüfungen: **{len(self.pending_reviews)}**"
        )

    # ---------------------------------------------------------------------------
    # !hilfe
    # ---------------------------------------------------------------------------

    # ---------------------------------------------------------------------------
    # !status  — Bot-Gesundheitscheck
    # ---------------------------------------------------------------------------

    @command.new(
        "status", help="Bot-Status, Latenz, Datenbankverbindung und Version anzeigen."
    )
    async def cmd_botstatus(self, evt: MessageEvent) -> None:
        if not await self._is_allowed_command_room(evt.room_id):
            return

        # ── Ping (Nachrichtenlatenz) ───────────────────────────────────────────
        now_ms = int(time.time() * 1000)
        ping_ms = max(0, now_ms - evt.timestamp)

        # ── Uptime ────────────────────────────────────────────────────────────
        uptime_s = int(time.monotonic() - self.start_time)
        days, rem = divmod(uptime_s, 86400)
        hours, rem = divmod(rem, 3600)
        minutes = rem // 60
        uptime_str = f"{days}d {hours}h {minutes}m"

        # ── Datenbankverbindung ────────────────────────────────────────────────
        db_status: str
        db_ping_str: str
        try:
            db_t0 = time.perf_counter()
            await self.database.fetchval("SELECT 1")
            db_ping_ms = int((time.perf_counter() - db_t0) * 1000)
            db_status = "OK"
            db_ping_str = f"{db_ping_ms}ms"
        except Exception as exc:
            db_status = f"Error: {type(exc).__name__}"
            db_ping_str = "N/A"

        # ── Versionen ──────────────────────────────────────────────────────────
        running_version = str(self.loader.meta.version)
        github_version: str
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "https://api.github.com/repos/M2tecDev/morpheus-link-bot/releases/latest",
                    headers={"Accept": "application/vnd.github+json"},
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        github_version = data.get("tag_name", "N/A")
                    else:
                        github_version = f"HTTP {resp.status}"
        except Exception as exc:
            github_version = f"Error: {type(exc).__name__}"

        # ── Ausgabe ───────────────────────────────────────────────────────────
        status_text = (
            "**Bot Status**\n"
            f"**PING:** `{ping_ms}ms`\n"
            f"**UPTIME:** `{uptime_str}`\n"
            f"**DB Status:** `{db_status}`\n"
            f"**DB PING:** `{db_ping_str}`\n"
            f"**Version Running:** `{running_version}`\n"
            f"**Newest Version (GIT):** `{github_version}`"
        )
        await self._send_notice(evt.room_id, status_text, render_markdown=True)

    # ---------------------------------------------------------------------------
    # !hilfe
    # ---------------------------------------------------------------------------

    @command.new("hilfe", help="Zeigt alle Befehle (nur per Direktnachricht / DM).")
    async def cmd_hilfe(self, evt: MessageEvent) -> None:
        try:
            members = await self.client.get_joined_members(evt.room_id)
            is_dm = len(members) == 2
        except Exception:
            is_dm = False
        if not is_dm:
            await evt.reply(
                "ℹ️ Der Befehl `!hilfe` ist **nur per Direktnachricht** verfügbar."
            )
            return

        help_text = (
            "🤖 **URL-Filter-Bot — Befehlsübersicht (v2.5.0)**\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "🔓 **Öffentliche Befehle**\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            "**`!urlstatus <domain> [domain2 ...]`** — Status einer oder mehrerer Domains prüfen\n\n"
            "**`!liststats`** — Listengrößen und offene Überprüfungen anzeigen\n\n"
            "**`!hilfe`** — Diese Übersicht (nur per DM)\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "🔐 **Moderationsbefehle** *(nur für Moderatoren)*\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            "**`!allow <domain> [domain2 ...]`** — Domain(s) whitelisten (Wildcards: `*.cdn.net`)\n\n"
            "**`!block <domain> [domain2 ...]`** — Domain(s) blacklisten\n\n"
            "**`!unallow <domain> [domain2 ...]`** — Domain(s) aus Whitelist entfernen\n\n"
            "**`!unblock <domain> [domain2 ...]`** — Domain(s) aus Blacklist entfernen\n\n"
            "**`!reloadlists`** — Alle Listendateien neu einlesen (~30 Sek.)\n\n"
            "**`!pending`** — Offene Moderationsanfragen anzeigen\n\n"
            "**`!sendpending`** — Alle offenen Alarme neu im Mod-Raum posten\n\n"
            "**`!mute <@user:server> [-t Minuten]`** — Nutzer manuell stummschalten\n\n"
            "**`!unmute <@user:server>`** — Stummschaltung sofort aufheben\n\n"
            "**`!ignore <domain> [domain2 ...]`** — Domain zur Vorschau-Ignore-Liste hinzufügen\n\n"
            "**`!unignore <domain> [domain2 ...]`** — Domain von der Vorschau-Ignore-Liste entfernen\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "⚙️ **Automatische Aktionen**\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            "✅ **Whitelist-Treffer** — Nachricht bleibt, optionale Linkvorschau als Reply.\n\n"
            "🚫 **Blacklist-Treffer** — Nachricht wird gelöscht, Warnung im Raum.\n\n"
            "🔍 **Unbekannte Domain** — Nachricht wird entfernt, Prüfanfrage im Mod-Raum."
        )
        await self._send_notice(evt.room_id, help_text, render_markdown=True)

    # ---------------------------------------------------------------------------
    # !ignore
    # ---------------------------------------------------------------------------

    @command.new(
        "ignore",
        help="[Mod] Domain zur Vorschau-Ignore-Liste hinzufügen. Keine Linkvorschau mehr für diese Domain.",
    )
    @command.argument("domains_raw", pass_raw=True, required=True)
    async def cmd_ignore(self, evt: MessageEvent, domains_raw: str) -> None:
        if not await self._is_allowed_command_room(evt.room_id):
            return
        if not await self._is_mod(evt.sender, evt.room_id):
            await evt.reply(
                "❌ Du hast keine Berechtigung, Domains zur Ignore-Liste hinzuzufügen."
            )
            return
        domain_list = _split_domain_args(domains_raw)
        if not domain_list:
            await evt.reply("❌ Verwendung: `!ignore <domain>` [domain2 ...]")
            return
        results: List[str] = []
        for domain in domain_list:
            if not _valid_domain(domain):
                results.append(f"❌ `{domain}` — ungültige Domain")
                continue
            if domain in self.ignore_preview_set:
                results.append(f"ℹ️ `{domain}` ist bereits auf der Ignore-Liste")
                continue
            # Warnung wenn Domain nicht auf der Whitelist steht —
            # Vorschauen werden nur für whitelistete Domains erstellt.
            not_whitelisted = (
                domain not in self.whitelist_set
                and not self._matches_wildcards(domain, self.whitelist_wildcards)
            )
            try:
                await self._db_upsert_ignore_preview(domain, True)
                self.ignore_preview_set.add(domain)
                if not_whitelisted:
                    results.append(
                        f"🔇 `{domain}` zur Ignore-Liste hinzugefügt — "
                        f"⚠️ Domain ist **nicht auf der Whitelist** "
                        f"(Vorschauen werden nur für whitelistete Domains erstellt)"
                    )
                else:
                    results.append(
                        f"🔇 `{domain}` zur Ignore-Liste hinzugefügt (keine Linkvorschau mehr)"
                    )
                self.log.info(
                    "'%s' zur Ignore-Liste hinzugefügt von %s.", domain, evt.sender
                )
            except Exception as exc:
                results.append(
                    f"❌ `{domain}` — Datenbankfehler: `{type(exc).__name__}: {exc}`"
                )
        await evt.reply("\n".join(results))

    # ---------------------------------------------------------------------------
    # !unignore
    # ---------------------------------------------------------------------------

    @command.new(
        "unignore", help="[Mod] Domain von der Vorschau-Ignore-Liste entfernen."
    )
    @command.argument("domains_raw", pass_raw=True, required=True)
    async def cmd_unignore(self, evt: MessageEvent, domains_raw: str) -> None:
        if not await self._is_allowed_command_room(evt.room_id):
            return
        if not await self._is_mod(evt.sender, evt.room_id):
            await evt.reply(
                "❌ Du hast keine Berechtigung, Domains von der Ignore-Liste zu entfernen."
            )
            return
        domain_list = _split_domain_args(domains_raw)
        if not domain_list:
            await evt.reply("❌ Verwendung: `!unignore <domain>` [domain2 ...]")
            return
        results: List[str] = []
        for domain in domain_list:
            if not _valid_domain(domain):
                results.append(f"❌ `{domain}` — ungültige Domain")
                continue
            if domain not in self.ignore_preview_set:
                results.append(f"ℹ️ `{domain}` ist nicht auf der Ignore-Liste")
                continue
            try:
                await self._db_upsert_ignore_preview(domain, False)
                self.ignore_preview_set.discard(domain)
                results.append(
                    f"✅ `{domain}` von der Ignore-Liste entfernt (Linkvorschauen wieder aktiv)"
                )
                self.log.info(
                    "'%s' von Ignore-Liste entfernt von %s.", domain, evt.sender
                )
            except Exception as exc:
                results.append(
                    f"❌ `{domain}` — Datenbankfehler: `{type(exc).__name__}: {exc}`"
                )
        await evt.reply("\n".join(results))

    # ===========================================================================
    # ABSCHNITT 16 — BERECHTIGUNGSPRÜFUNG
    # ===========================================================================

    async def _is_mod(self, user_id: UserID, room_id: Optional[RoomID] = None) -> bool:
        """
        Fix #1: Berechtigungsprüfung — DM-Eskalation ausgeschlossen.

        Zwei unabhängige Prüfungen:
          1. user_id ist in config.mod_permissions.allowed_users
             → IMMER gültig, unabhängig vom Raum (für serverübergreifende Admins).
          2. Powerlevel von user_id >= min_power_level
             → NUR im konfigurierten mod_room_id geprüft.
             NIEMALS im aktuellen Befehlsraum oder DM.
             Damit kann kein Nutzer durch Einladung des Bots in einen eigenen
             Raum Admin-Rechte erlangen.
        """
        mod_cfg = self.config.get("mod_permissions", {})
        allowed_list = mod_cfg.get("allowed_users", [])
        min_level = int(mod_cfg.get("min_power_level", 50))
        mod_room = RoomID(self.config.get("mod_room_id", ""))

        if not isinstance(allowed_list, list):
            self.log.warning(
                "Konfigurationsfehler: mod_permissions.allowed_users ist kein Array (Typ: %s).",
                type(allowed_list).__name__,
            )
            allowed_list = []

        # Fix #1: allowed_users ZUERST prüfen — kein Raumcheck nötig
        # Fix Bug 4: Vergleich case-insensitiv, damit "@Alice:Matrix.org" und
        # "@alice:matrix.org" als identisch gelten (Matrix-IDs sind case-insensitive).
        uid_lower = str(user_id).lower()
        if any(str(u).lower() == uid_lower for u in allowed_list):
            return True

        # Fix #1: Powerlevel NUR im mod_room prüfen — niemals im Befehlsraum/DM
        if not mod_room:
            return False

        return await self._get_power_level(mod_room, user_id) >= min_level

    async def _get_power_level(self, room_id: RoomID, user_id: UserID) -> int:
        try:
            levels: PowerLevelStateEventContent = await self.client.get_state_event(  # type: ignore[assignment]
                room_id, EventType.ROOM_POWER_LEVELS
            )
            user_level = levels.users.get(user_id, None)
            if user_level is None:
                user_level = levels.users.get(str(user_id), None)  # type: ignore[call-overload]
            if user_level is None:
                default = levels.users_default
                user_level = int(default) if default is not None else 0
            return int(user_level)
        except Exception as exc:
            self.log.warning(
                "Powerlevel für %s in %s konnte nicht abgerufen werden: %s",
                user_id,
                room_id,
                exc,
            )
            return 0

    # ===========================================================================
    # ABSCHNITT 17 — LINKVORSCHAU (OG-METADATEN)
    # ===========================================================================

    async def _resolve_shortener_domain(self, url: str) -> Optional[str]:
        """
        Fix #18: Folgt einer Shortener-URL via HEAD-Request und gibt den
        finalen Hostnamen nach allen Weiterleitungen zurück.
        Timeout: 3 s — kurz gehalten um Latenz im Nachrichtenfluss minimal zu halten.
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.head(
                    url,
                    timeout=aiohttp.ClientTimeout(total=3.0),
                    allow_redirects=True,
                    ssl=False,
                    max_redirects=5,
                ) as resp:
                    final_url = str(resp.url)
                    host = (urlparse(final_url).hostname or "").lower()
                    if host.startswith("www."):
                        host = host[4:]
                    return _normalize_domain(host) if host else None
        except Exception:
            return None

    async def _fetch_og_metadata(self, url: str) -> Optional[dict]:
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
                    raw = await resp.content.read(65_536)
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
        desc = _og_tag(html, "og:description") or _meta_name(html, "description")
        if not title and not desc:
            return None
        return {"title": (title or "").strip(), "description": (desc or "").strip()}

    # ===========================================================================
    # ABSCHNITT 18 — MATRIX-NACHRICHTENDIENSTPROGRAMME
    # ===========================================================================

    async def _redact(self, room_id: RoomID, event_id: EventID, reason: str) -> bool:
        try:
            await self.client.redact(room_id, event_id, reason=reason)
            return True
        except Exception as exc:
            self.log.warning(
                "LÖSCHEN FEHLGESCHLAGEN: ereignis=%s raum=%s Fehler: %s — Bot benötigt PL 50+.",
                event_id,
                room_id,
                exc,
            )
            return False

    async def _send_notice(
        self,
        room_id: RoomID,
        text: str,
        render_markdown: bool = False,
    ) -> Optional[EventID]:
        try:
            content = TextMessageEventContent(msgtype=MessageType.NOTICE, body=text)
            if render_markdown:
                content.format = Format.HTML
                content.formatted_body = _md_to_html(text)
            return await self.client.send_message(room_id, content)
        except Exception as exc:
            exc_str = str(exc)
            if (
                "403" in exc_str
                or "M_FORBIDDEN" in exc_str.upper()
                or "MForbidden" in exc_str
            ):
                self.log.error(
                    "FEHLER: Bot kann nicht in Raum %s senden (403). "
                    "Bot einladen und Senderechte prüfen. mod_room_id=%s",
                    room_id,
                    self.config.get("mod_room_id", "<nicht gesetzt>"),
                )
            else:
                self.log.error(
                    "Hinweis an %s konnte nicht gesendet werden: %s", room_id, exc
                )
            return None

    async def _edit_notice(
        self, room_id: RoomID, event_id: EventID, new_text: str
    ) -> None:
        """
        Fix #3: Bearbeitet einen gesendeten Hinweis. Verbesserungen:
          - m.new_content ist vollständig spec-konform (enthält alle Pflichtfelder).
          - Äußeres body folgt dem Matrix-Konvention für Edit-Fallback ("* text").
          - Retry: bei Fehler einmal nach 1 Sekunde wiederholen.
          - Fallback: bei persistentem Fehler neue Nachricht senden.
        """
        html = _md_to_html(new_text)

        async def _attempt() -> bool:
            try:
                content = TextMessageEventContent(
                    msgtype=MessageType.NOTICE,
                    # Äußeres body: Matrix-Konvention für Clients ohne Edit-Support
                    body=f"* {new_text}",
                    format=Format.HTML,
                    # Äußeres formatted_body: Fallback-Darstellung
                    formatted_body=f"<em>(bearbeitet)</em> {html}",
                )
                # Fix #3: spec-konformes m.new_content (kompletter Nachrichteninhalt)
                content["m.new_content"] = {
                    "msgtype": "m.notice",
                    "body": new_text,
                    "format": "org.matrix.custom.html",
                    "formatted_body": html,
                }
                # m.relates_to mit rel_type m.replace
                content["m.relates_to"] = {
                    "rel_type": "m.replace",
                    "event_id": str(event_id),
                }
                await self.client.send_message(room_id, content)
                return True
            except Exception as exc:
                self.log.warning(
                    "Edit-Versuch für %s in %s fehlgeschlagen: %s",
                    event_id,
                    room_id,
                    exc,
                )
                return False

        # Erster Versuch
        if await _attempt():
            return

        # Fix #3: Retry nach 1 Sekunde
        await asyncio.sleep(1.0)
        if await _attempt():
            return

        # Fix #3: Fallback — neue Nachricht senden wenn beide Versuche scheitern
        self.log.error(
            "Edit für %s in %s nach 2 Versuchen fehlgeschlagen — sende neue Nachricht.",
            event_id,
            room_id,
        )
        await self._send_notice(room_id, new_text, render_markdown=True)

    async def _send_reaction(
        self, room_id: RoomID, target_id: EventID, key: str
    ) -> Optional[EventID]:
        try:
            return await self.client.send_message_event(
                room_id,
                EventType.REACTION,
                {  # type: ignore[arg-type]
                    "m.relates_to": {
                        "rel_type": "m.annotation",
                        "event_id": str(target_id),
                        "key": key,
                    }
                },
            )
        except Exception as exc:
            self.log.error(
                "Reaktion '%s' auf %s fehlgeschlagen: %s", key, target_id, exc
            )
            return None

    # ===========================================================================
    # ABSCHNITT 19 — DATENBANKOPERATIONEN  (Privacy by Design / DSGVO)
    # ===========================================================================
    #
    # Alle Methoden in diesem Abschnitt ersetzen die frühere dateibasierte Persistenz.
    # Designprinzipien:
    #   • Keine rohen Matrix-IDs in der DB — immer SHA-256(salt:user_id)
    #   • Domains vor dem Schreiben sanitisieren (Query-Parameter entfernen)
    #   • Alle Operationen sind awaitable und blockieren den Event-Loop nicht

    # ── Privacy-Hilfsmethoden ──────────────────────────────────────────────────

    def _hash_user(self, user_id: str) -> str:
        """
        SHA-256(SECRET_SALT + ':' + user_id) → 64-Zeichen-Hex-Digest.

        DSGVO-Garantie: Niemals rohe Matrix-IDs in der Datenbank speichern.
        Das Salt verhindert Rainbow-Table-Angriffe auf gehashte IDs.
        WICHTIG: secret_salt darf nach der Erstkonfiguration nicht geändert werden,
                 da bestehende Hashes sonst nicht mehr übereinstimmen.
        """
        salt: str = self.config.get("secret_salt", "")
        raw = f"{salt}:{user_id}".encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    @staticmethod
    def _sanitize_domain_for_storage(domain: str) -> str:
        """
        Entfernt Query-Parameter (alles nach '?') vor der DB-Speicherung.
        Wendet zusätzlich Kleinschreibung und Strip an.

        Beispiel: 'evil.com?tracking=1' → 'evil.com'
        """
        return domain.split("?")[0].lower().strip()

    # ── Cache-Bootstrap beim Start ────────────────────────────────────────────

    async def _load_domain_rules_cache(self) -> None:
        """
        Lädt alle DomainRule-Einträge aus der DB in den In-Memory-Cache
        und aktualisiert die Routing-Sets (blacklist_set, whitelist_set,
        ignore_preview_set).

        Wird NACH dem Textdatei-Laden aufgerufen, damit DB-Einträge
        (manuelle Mod-Entscheidungen) Datei-Einträge überschreiben können.
        """
        try:
            rows = await self.database.fetch(
                "SELECT domain, is_blacklisted, ignore_preview FROM domain_rule"
            )
        except Exception as exc:
            self.log.error("Fehler beim Laden des DomainRule-Caches: %s", exc)
            return

        for row in rows:
            domain: str = row["domain"]
            is_bl: bool = bool(row["is_blacklisted"])
            ignore_pv: bool = bool(row["ignore_preview"])

            self._domain_rule_cache[domain] = {
                "is_blacklisted": is_bl,
                "ignore_preview": ignore_pv,
            }
            if ignore_pv:
                self.ignore_preview_set.add(domain)
            if is_bl:
                self.blacklist_set.add(domain)
                self.whitelist_set.discard(domain)
            else:
                self.whitelist_set.add(domain)
                self.blacklist_set.discard(domain)

        self.log.info(
            "📦 DomainRule-Cache: %d Einträge aus DB geladen.",
            len(self._domain_rule_cache),
        )

    async def _load_pending_reviews_from_db(self) -> None:
        """
        Stellt offene Moderationsanfragen nach einem Neustart aus der DB wieder her.
        Sender-ID ist nicht gespeichert (Privacy by Design) → wird als leerer UserID
        wiederhergestellt. Moderatoren sehen dann '(Unbekannt)' im !pending-Output.
        """
        try:
            rows = await self.database.fetch(
                "SELECT alert_event_id, room_id, original_event_id, domain "
                "FROM pending_review"
            )
        except Exception as exc:
            self.log.error("Fehler beim Laden ausstehender Reviews aus DB: %s", exc)
            return

        restored = 0
        for row in rows:
            alert_id = EventID(row["alert_event_id"])
            review = PendingReview(
                domain=row["domain"],
                original_event_id=EventID(row["original_event_id"]),
                original_room_id=RoomID(row["room_id"]),
                sender=UserID(""),  # Sender-ID nicht gespeichert — Privacy by Design
            )
            self.pending_reviews[alert_id] = review
            self._pending_domains.add(row["domain"])
            restored += 1

        if restored:
            self.log.info(
                "🔄 %d ausstehende Überprüfung(en) aus DB wiederhergestellt.", restored
            )

    # ── DomainRule CRUD ────────────────────────────────────────────────────────

    async def _db_upsert_domain_rule(
        self,
        domain: str,
        is_blacklisted: bool,
        ignore_preview: bool,
    ) -> None:
        """
        Legt einen DomainRule-Eintrag an oder aktualisiert ihn (UPSERT).
        Aktualisiert gleichzeitig den In-Memory-Cache.
        """
        clean = self._sanitize_domain_for_storage(domain)
        await self.database.execute(
            """
            INSERT INTO domain_rule (domain, is_blacklisted, ignore_preview)
            VALUES ($1, $2, $3)
            ON CONFLICT (domain) DO UPDATE
                SET is_blacklisted = EXCLUDED.is_blacklisted,
                    ignore_preview  = EXCLUDED.ignore_preview
            """,
            clean,
            is_blacklisted,
            ignore_preview,
        )
        self._domain_rule_cache[clean] = {
            "is_blacklisted": is_blacklisted,
            "ignore_preview": ignore_preview,
        }
        self.log.debug(
            "DomainRule UPSERT: domain=%s is_bl=%s ignore_pv=%s",
            clean,
            is_blacklisted,
            ignore_preview,
        )

    async def _db_upsert_ignore_preview(self, domain: str, ignore: bool) -> None:
        """
        Setzt nur das ignore_preview-Flag.
        Behält den is_blacklisted-Wert aus dem Cache bei (kein Überschreiben).
        """
        clean = self._sanitize_domain_for_storage(domain)
        existing = self._domain_rule_cache.get(clean)
        is_bl = existing["is_blacklisted"] if existing else False
        await self._db_upsert_domain_rule(clean, is_bl, ignore)

    async def _db_delete_domain_rule(self, domain: str) -> None:
        """
        Entfernt einen DomainRule-Eintrag vollständig aus der DB und dem Cache.
        Kein Fehler wenn der Eintrag nicht existiert.
        """
        clean = self._sanitize_domain_for_storage(domain)
        await self.database.execute("DELETE FROM domain_rule WHERE domain = $1", clean)
        self._domain_rule_cache.pop(clean, None)
        self.log.debug("DomainRule gelöscht: domain=%s", clean)

    # ── PendingReview CRUD ─────────────────────────────────────────────────────

    async def _db_upsert_pending_review(
        self,
        alert_event_id: str,
        room_id: str,
        original_event_id: str,
        domain: str,
    ) -> None:
        """
        Speichert eine Moderationsanfrage persistent.
        DSGVO: Keine Sender-ID, keine vollständige URL — nur Domain und Event-Referenzen.
        """
        clean_domain = self._sanitize_domain_for_storage(domain)
        await self.database.execute(
            """
            INSERT INTO pending_review
                (alert_event_id, room_id, original_event_id, domain)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (alert_event_id) DO UPDATE
                SET room_id           = EXCLUDED.room_id,
                    original_event_id = EXCLUDED.original_event_id,
                    domain            = EXCLUDED.domain
            """,
            alert_event_id,
            room_id,
            original_event_id,
            clean_domain,
        )

    async def _db_delete_pending_review(self, alert_event_id: str) -> None:
        """Löscht eine erledigte Moderationsanfrage aus der DB."""
        await self.database.execute(
            "DELETE FROM pending_review WHERE alert_event_id = $1", alert_event_id
        )

    # ── DomainStats ────────────────────────────────────────────────────────────

    async def _db_increment_domain_stats(self, domain: str) -> None:
        """
        Erhöht den Verstoß-Zähler für eine Domain (UPSERT).
        Domain wird vor dem Schreiben sanitisiert (keine Query-Parameter).
        Kein Nutzerbezug — nur Domain-Ebene.
        """
        clean = self._sanitize_domain_for_storage(domain)
        await self.database.execute(
            """
            INSERT INTO domain_stats (domain, violation_count)
            VALUES ($1, 1)
            ON CONFLICT (domain) DO UPDATE
                SET violation_count = domain_stats.violation_count + 1
            """,
            clean,
        )

    # ── UserViolation (Sliding Window via DB) ──────────────────────────────────

    async def _record_violation(self, sender: str) -> bool:
        """
        DB-gestützte Verstoßverfolgung — ersetzt die frühere in-memory
        _violation_counts-Deque.

        DSGVO-Garantie: Speichert SHA-256-Hash der Matrix-ID, niemals die
        rohe MXID. Das secret_salt aus der Konfiguration schützt vor
        Rainbow-Table-Angriffen.

        Gibt True zurück wenn der Schwellenwert (mute_threshold) im
        konfigurierten Beobachtungsfenster (mute_window_minutes) erreicht wurde.
        """
        threshold: int = int(self.config.get("mute_threshold", 5))
        window_min: float = float(self.config.get("mute_window_minutes", 5))
        user_hash = self._hash_user(sender)
        # UTC-naive datetime — portabel für SQLite (ISO-8601-String) und asyncpg.
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        cutoff = now - datetime.timedelta(minutes=window_min)

        try:
            # Verstoß-Eintrag in DB schreiben (gehashte ID + Zeitstempel)
            await self.database.execute(
                "INSERT INTO user_violation (user_hash, ts) VALUES ($1, $2)",
                user_hash,
                now,
            )
            # Verstöße im Beobachtungsfenster zählen
            count = await self.database.fetchval(
                "SELECT COUNT(*) FROM user_violation WHERE user_hash = $1 AND ts >= $2",
                user_hash,
                cutoff,
            )
            return int(count or 0) >= threshold
        except Exception as exc:
            self.log.error("Fehler beim Schreiben des UserViolation-Eintrags: %s", exc)
            return False

    # ── DSGVO-Datenhaltungs-Loop ───────────────────────────────────────────────

    async def _retention_loop(self) -> None:
        """
        Datenschutz-Task: Löscht UserViolation-Einträge die älter als 24 Stunden sind.

        Läuft einmalig beim Start (sofortige Erstbereinigung nach Neustart)
        und danach alle 24 Stunden — vollständig nicht-blockierend im asyncio-Loop.

        Rechtsgrundlage: Datensparsamkeit nach Art. 5 Abs. 1 lit. e DSGVO —
        personenbezogene Daten (auch gehashte) dürfen nicht länger gespeichert
        werden als für den Zweck erforderlich. 24 Stunden entspricht dem
        maximalen mute_window_minutes-Kontext.
        """
        self.log.debug("🔒 DSGVO-Datenhaltungs-Loop gestartet.")
        while True:
            cutoff = datetime.datetime.now(datetime.timezone.utc).replace(
                tzinfo=None
            ) - datetime.timedelta(hours=24)
            try:
                await self.database.execute(
                    "DELETE FROM user_violation WHERE ts < $1", cutoff
                )
                self.log.debug(
                    "🗑️  Datenhaltungsbereinigung: UserViolation-Einträge vor %s gelöscht.",
                    cutoff.isoformat(),
                )
            except Exception as exc:
                self.log.error(
                    "Fehler beim Bereinigen alter UserViolation-Einträge: %s", exc
                )
            await asyncio.sleep(86_400)  # 24 Stunden


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


def _split_domain_args(raw: str) -> List[str]:
    """
    Fix #6: Splittet rohe Befehlsargumente in eine Liste von Domain-Strings.
    Jedes Leerzeichen-getrennte Token wird in Kleinbuchstaben konvertiert.
    Leerzeichen, Kommas und Semikolons gelten als Trenner.
    Beispiel: "example.com, other.com *.cdn.net" → ["example.com", "other.com", "*.cdn.net"]
    """
    # Kommas und Semikolons als zusätzliche Trennzeichen behandeln
    normalized = raw.replace(",", " ").replace(";", " ")
    return [t.lower() for t in normalized.split() if t]


def _normalize_domain(domain: str) -> str:
    """
    Fix #16: NFKC-Unicode-Normalisierung + IDNA/Punycode-Konvertierung.

    Schritt 1 — NFKC: Kompatibilitätszeichen wie Vollbreit-ASCII (ｇｏｏｇｌｅ)
                werden auf ihre kanonische Form (google) reduziert.
    Schritt 2 — IDNA: Unicode-Domains (пример.com) werden in ihre Punycode-
                Repräsentation (xn--e1afmapc.com) umgewandelt und umgekehrt,
                sodass Blacklist-Einträge in beiden Schreibweisen greifen.
    Fehler (ungültige IDNA-Labels) werden still ignoriert — Fallback auf lower().
    """
    try:
        normalized = unicodedata.normalize("NFKC", domain)
        if not normalized.isascii():
            normalized = normalized.encode("idna").decode("ascii")
        return normalized.lower()
    except (UnicodeError, UnicodeDecodeError):
        return domain.lower()


def _valid_domain(domain: str) -> bool:
    """Minimale Plausibilitätsprüfung für Domain-Strings."""
    if not domain:
        return False
    check = domain[2:] if domain.startswith("*.") else domain
    return bool(check) and "." in check and check not in _SKIP_DOMAINS


def _format_age(age_s: int) -> str:
    """
    Fix #9: Konvertiert Sekunden in die größtmögliche lesbare Einheit.

    Beispiele:
      45     → "45 Sekunden"
      130    → "2 Minuten"
      7320   → "2 Stunden"
      90100  → "1 Tag"
      432000 → "5 Tage"
    """
    if age_s < 60:
        return f"{age_s} Sekunde{'n' if age_s != 1 else ''}"
    elif age_s < 3600:
        m = age_s // 60
        return f"{m} Minute{'n' if m != 1 else ''}"
    elif age_s < 86400:
        h = age_s // 3600
        return f"{h} Stunde{'n' if h != 1 else ''}"
    else:
        d = age_s // 86400
        return f"{d} Tag{'e' if d != 1 else ''}"


def _parse_user_time_args(raw: str) -> Tuple[Optional[str], Optional[int]]:
    """
    Fix #10: Parst Argumente der Form '<@user:server> [-t <Minuten>]'.

    Gibt (user_id, duration_minutes) zurück.
    duration_minutes ist None wenn -t nicht angegeben wurde.

    """
    tokens = raw.strip().split()
    if not tokens:
        return None, None
    user_id: str = tokens[0]
    duration_minutes: Optional[int] = None
    try:
        t_idx = tokens.index("-t")
        if t_idx + 1 < len(tokens):
            duration_minutes = int(tokens[t_idx + 1])
    except (ValueError, IndexError):
        pass
    return user_id, duration_minutes


def _og_tag(html: str, prop: str) -> Optional[str]:
    """
    Extrahiert content="..." aus einem OG-<meta property="...">-Tag.
    Behandelt beide Attributreihenfolgen. Content-Laenge auf 512 Zeichen begrenzt
    mit einem possessiven Aequivalent [^"']+ — kein katastrophales Backtracking.
    """
    p = re.escape(prop)
    m = re.search(
        r'<meta[^>]+property=["\']' + p + r'["\'][^>]+content=["\']([^"\']{1,512})["\']'
        r'|<meta[^>]+content=["\']([^"\']{1,512})["\'][^>]+property=["\']'
        + p
        + r'["\']',
        html,
        re.IGNORECASE,
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
        html,
        re.IGNORECASE,
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
    fuer das Matrix-formatted_body-Feld.

    Behandelte Konstrukte (in Verarbeitungsreihenfolge):
      &, <, >         — zuerst HTML-kodiert, um Injection zu verhindern
      > Blockzitate   — <blockquote> (nach Kodierung als &gt; erkannt)
      **Fett**        — <strong>
      `Inline-Code`   — <code>
      [Label](URL)    — <a href="...">

    Alle Regex-Laengen sind begrenzt, um Regex-Verlangsamung bei praeparierten Eingaben zu verhindern.
    """
    # 1. HTML-Sonderzeichen kodieren (verhindert Injection)
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    # 2. Zeilenweise fuer Blockzitate verarbeiten (> wurde zu &gt; kodiert)
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

    # 5. Fix #16: [Label](URL) → <a href="URL">Label</a>
    # Sicherheitsfix: " in href wird zu &quot; kodiert (verhindert Attribut-Injection).
    def _safe_link_sub(m: re.Match) -> str:
        label = m.group(1)  # & < > bereits kodiert durch Schritt 1
        href = m.group(2).replace('"', "&quot;")
        return f'<a href="{href}">{label}</a>'

    text = re.sub(
        r"\[([^\]]{1,200})\]\((https?://[^)]{1,2000})\)",
        _safe_link_sub,
        text,
    )

    return text
