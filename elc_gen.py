#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
import math
import time
import json
import gzip
import struct
import hashlib
import argparse
import itertools
import configparser
import urllib.request
import ssl
import urllib.error
from html.parser import HTMLParser
from typing import List, Set, Tuple, Dict, Optional, Generator

if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass


class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

BANNER = f"""{Colors.GREEN}
  .   ____ _                            __ _ _
 /\\\\ / ___| | ___ ______  __ _  ___ _ __ \\ \\ \\ \\
( ( )|  __| |/ __|______/ _` |/ _ \\ '_ \\ \\ \\ \\ \\
 \\\\/ | |__| | (__      | (_| |  __/ | | | ) ) ) )
  '  |____|_|\\___|      \\__, |\\___|_| |_|/ / / /
 =======================|___/============/_/_/_/{Colors.RESET}
 {Colors.GREEN}{Colors.BOLD}:: elc-gen ::{Colors.RESET}                 {Colors.DIM}(v3.0.0-PRO-CYBER-RELEASE){Colors.RESET}
 {Colors.CYAN}{Colors.BOLD}Target-Focused Password Intelligence, OSINT & Wordlist Attack Suite{Colors.RESET}
"""


def _md4(message: bytes) -> bytes:
    def F(x, y, z): return (x & y) | (~x & z)
    def G(x, y, z): return (x & y) | (x & z) | (y & z)
    def H(x, y, z): return x ^ y ^ z
    def lrot(val, n): return ((val << n) & 0xFFFFFFFF) | (val >> (32 - n))

    msg_len = len(message)
    message += b'\x80'
    message += b'\x00' * ((56 - (msg_len + 1) % 64) % 64)
    message += struct.pack('<Q', msg_len * 8)

    A, B, C, D = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    for i in range(0, len(message), 64):
        X = struct.unpack('<16I', message[i:i+64])
        AA, BB, CC, DD = A, B, C, D
        for j, s in [(0,3), (1,7), (2,11), (3,19), (4,3), (5,7), (6,11), (7,19),
                     (8,3), (9,7), (10,11), (11,19), (12,3), (13,7), (14,11), (15,19)]:
            A = lrot((A + F(B, C, D) + X[j]) & 0xFFFFFFFF, s)
            A, B, C, D = D, A, B, C
        for j, s in [(0,3), (4,5), (8,9), (12,13), (1,3), (5,5), (9,9), (13,13),
                     (2,3), (6,5), (10,9), (14,13), (3,3), (7,5), (11,9), (15,13)]:
            A = lrot((A + G(B, C, D) + X[j] + 0x5A827999) & 0xFFFFFFFF, s)
            A, B, C, D = D, A, B, C
        for j, s in [(0,3), (8,9), (4,11), (12,15), (2,3), (10,9), (6,11), (14,15),
                     (1,3), (9,9), (5,11), (13,15), (3,3), (11,9), (7,11), (15,15)]:
            A = lrot((A + H(B, C, D) + X[j] + 0x6ED9EBA1) & 0xFFFFFFFF, s)
            A, B, C, D = D, A, B, C
        A = (A + AA) & 0xFFFFFFFF
        B = (B + BB) & 0xFFFFFFFF
        C = (C + CC) & 0xFFFFFFFF
        D = (D + DD) & 0xFFFFFFFF
    return struct.pack('<4I', A, B, C, D)


def calculate_hash(password: str, algo: str) -> str:
    algo = algo.lower()
    raw = password.encode('utf-8')
    if algo == 'md5':
        return hashlib.md5(raw).hexdigest()
    elif algo == 'sha1':
        return hashlib.sha1(raw).hexdigest()
    elif algo == 'sha256':
        return hashlib.sha256(raw).hexdigest()
    elif algo == 'sha512':
        return hashlib.sha512(raw).hexdigest()
    elif algo == 'ntlm':
        try:
            return hashlib.new('md4', password.encode('utf-16le')).hexdigest()
        except Exception:
            return _md4(password.encode('utf-16le')).hex()
    return ""


def calculate_shannon_entropy(pwd: str) -> float:
    if not pwd:
        return 0.0
    freq = {}
    for c in pwd:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(pwd)
        entropy -= p * math.log2(p)
    return entropy * len(pwd)


def get_strength_rating(pwd: str) -> Tuple[str, str]:
    entropy = calculate_shannon_entropy(pwd)
    if entropy < 25 or len(pwd) < 6:
        return "Very Weak", Colors.RED
    elif entropy < 40:
        return "Weak", Colors.YELLOW
    elif entropy < 60:
        return "Moderate", Colors.BLUE
    elif entropy < 80:
        return "Strong", Colors.GREEN
    else:
        return "Very Strong", Colors.MAGENTA


def passes_policy(
    pwd: str,
    min_len: int = 0,
    max_len: int = 999,
    min_upper: int = 0,
    min_lower: int = 0,
    min_digits: int = 0,
    min_symbols: int = 0,
    policy_ad: bool = False,
    include_regex: Optional[str] = None,
    exclude_regex: Optional[str] = None
) -> bool:
    length = len(pwd)
    if length < min_len or length > max_len:
        return False

    uppers = sum(1 for c in pwd if c.isupper())
    lowers = sum(1 for c in pwd if c.islower())
    digits = sum(1 for c in pwd if c.isdigit())
    specials = length - (uppers + lowers + digits)

    if uppers < min_upper or lowers < min_lower or digits < min_digits or specials < min_symbols:
        return False

    if policy_ad:
        if length < 8:
            return False
        categories = (uppers > 0) + (lowers > 0) + (digits > 0) + (specials > 0)
        if categories < 3:
            return False

    if include_regex and not re.search(include_regex, pwd):
        return False
    if exclude_regex and re.search(exclude_regex, pwd):
        return False

    return True


_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_CFG_PATH = os.path.join(_SCRIPT_DIR, "elc_gen.cfg")
_LOADED_CONFIG = None


def _csv(value: str) -> list:
    return [v.strip() for v in value.split(",") if v.strip()]


def load_config(cfg_path: str = None) -> configparser.ConfigParser:
    global _LOADED_CONFIG
    config = configparser.ConfigParser(interpolation=None)
    config.optionxform = str

    path = cfg_path or _DEFAULT_CFG_PATH
    if os.path.isfile(path):
        try:
            config.read(path, encoding="utf-8")
            print(f"{Colors.GREEN}[CONFIG] Loaded configuration file: {path}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.YELLOW}[CONFIG] Failed to read configuration ({e}), using defaults.{Colors.RESET}")
    else:
        if cfg_path:
            print(f"{Colors.YELLOW}[CONFIG] '{path}' not found, using defaults.{Colors.RESET}")

    _LOADED_CONFIG = config
    _apply_config(config)
    return config


def _apply_config(config: configparser.ConfigParser):
    global TR_TO_EN, LEET_RULES
    global TOP_TRAILING_NUMBERS, KEYBOARD_WALKS, REPEATING_DIGITS, SEQUENTIAL_NUMBERS
    global TOP_PLATES, ALL_PLATES, IMPORTANT_YEARS
    global TOP_AFFIXES, ALL_AFFIXES
    global PRIMARY_SYMBOLS, SECONDARY_SYMBOLS, ALL_SYMBOLS
    global COMPLEXITY_TAILS, COMMON_TURKISH_PASSWORDS

    if config.has_section("turkish"):
        TR_TO_EN = {}
        for key, val in config.items("turkish"):
            TR_TO_EN[key.strip()] = val.strip()
    else:
        TR_TO_EN = _DEFAULT_TR_TO_EN.copy()

    if config.has_section("leet"):
        LEET_RULES = {}
        for key, val in config.items("leet"):
            LEET_RULES[key.strip()] = _csv(val)
    else:
        LEET_RULES = {k: list(v) for k, v in _DEFAULT_LEET_RULES.items()}

    if config.has_section("symbols"):
        PRIMARY_SYMBOLS = _csv(config.get("symbols", "primary", fallback="!,.,_,-,@,*"))
        SECONDARY_SYMBOLS = _csv(config.get("symbols", "secondary", fallback="#,+,?,$,&,%"))
        extra = _csv(config.get("symbols", "extra", fallback="/,=,~"))
        ALL_SYMBOLS = PRIMARY_SYMBOLS + SECONDARY_SYMBOLS + extra
    else:
        PRIMARY_SYMBOLS = _DEFAULT_PRIMARY_SYMBOLS[:]
        SECONDARY_SYMBOLS = _DEFAULT_SECONDARY_SYMBOLS[:]
        ALL_SYMBOLS = PRIMARY_SYMBOLS + SECONDARY_SYMBOLS + ["/", "=", "~"]

    if config.has_section("numbers"):
        TOP_TRAILING_NUMBERS = _csv(config.get("numbers", "top_trailing", fallback=""))
        SEQUENTIAL_NUMBERS = _csv(config.get("numbers", "sequential", fallback=""))
        REPEATING_DIGITS = _csv(config.get("numbers", "repeating", fallback=""))
        KEYBOARD_WALKS = _csv(config.get("numbers", "keyboard_walks", fallback=""))
        COMPLEXITY_TAILS = _csv(config.get("numbers", "complexity_tails", fallback=""))
    else:
        TOP_TRAILING_NUMBERS = _DEFAULT_TOP_TRAILING_NUMBERS[:]
        SEQUENTIAL_NUMBERS = _DEFAULT_SEQUENTIAL_NUMBERS[:]
        REPEATING_DIGITS = _DEFAULT_REPEATING_DIGITS[:]
        KEYBOARD_WALKS = _DEFAULT_KEYBOARD_WALKS[:]
        COMPLEXITY_TAILS = _DEFAULT_COMPLEXITY_TAILS[:]

    if config.has_section("cultural"):
        IMPORTANT_YEARS = _csv(config.get("cultural", "important_years", fallback=""))
        TOP_PLATES = _csv(config.get("cultural", "top_plates", fallback=""))
        gen_all = config.get("cultural", "generate_all_plates", fallback="true").strip().lower()
        ALL_PLATES = [f"{i:02d}" for i in range(1, 82)] if gen_all == "true" else TOP_PLATES[:]
    else:
        IMPORTANT_YEARS = _DEFAULT_IMPORTANT_YEARS[:]
        TOP_PLATES = _DEFAULT_TOP_PLATES[:]
        ALL_PLATES = [f"{i:02d}" for i in range(1, 82)]

    if config.has_section("affixes"):
        TOP_AFFIXES = _csv(config.get("affixes", "top", fallback=""))
        ALL_AFFIXES = _csv(config.get("affixes", "all", fallback=""))
    else:
        TOP_AFFIXES = _DEFAULT_TOP_AFFIXES[:]
        ALL_AFFIXES = _DEFAULT_ALL_AFFIXES[:]

    if config.has_section("passwords"):
        COMMON_TURKISH_PASSWORDS = _csv(config.get("passwords", "common_turkish", fallback=""))
        custom = _csv(config.get("passwords", "custom_passwords", fallback=""))
        if custom:
            COMMON_TURKISH_PASSWORDS.extend(custom)
    else:
        COMMON_TURKISH_PASSWORDS = _DEFAULT_COMMON_TURKISH_PASSWORDS[:]


def get_config_value(section: str, key: str, fallback=None):
    if _LOADED_CONFIG and _LOADED_CONFIG.has_option(section, key):
        return _LOADED_CONFIG.get(section, key)
    return fallback


def get_config_int(section: str, key: str, fallback: int = 0) -> int:
    if _LOADED_CONFIG and _LOADED_CONFIG.has_option(section, key):
        try:
            return _LOADED_CONFIG.getint(section, key)
        except ValueError:
            return fallback
    return fallback


_DEFAULT_TR_TO_EN = {
    'ç': 'c', 'Ç': 'C',
    'ğ': 'g', 'Ğ': 'G',
    'ı': 'i', 'I': 'I',
    'İ': 'I', 'i': 'i',
    'ö': 'o', 'Ö': 'O',
    'ş': 's', 'Ş': 'S',
    'ü': 'u', 'Ü': 'U'
}

_DEFAULT_TOP_TRAILING_NUMBERS = [
    '1', '2', '3', '7', '11', '12', '13', '21', '22', '23', '07',
    '01', '02', '06', '10', '34', '35', '42', '55', '61', '99',
    '123', '321', '007', '000', '111', '222', '333', '666', '777', '786', '143',
    '1234', '4321', '1111', '2222', '0000', '1903', '1905', '1907', '1923', '1453',
    '12345', '54321', '11111',
    '123456', '654321', '123321',
]

_DEFAULT_KEYBOARD_WALKS = [
    'qwerty', 'qwert', 'qwer', 'qwe', 'asdf', 'asdfgh', 'zxcv', 'zxcvbn',
    'qwertyuiop', 'qazwsx', 'qaz', 'wsx', 'edc', 'rfv',
    '1qaz', '2wsx', '1qaz2wsx', 'qwe123', 'qwerty123',
    'zaq1', 'xsw2', '1q2w3e', '1q2w3e4r', '1q2w', 'q1w2e3',
    '!qaz', '@wsx', 'asd123', 'zxc123',
    '147', '258', '369', '159', '753', '951', '7894', '1478', '14789', '789456123',
]

_DEFAULT_REPEATING_DIGITS = [
    '00', '11', '22', '33', '44', '55', '66', '77', '88', '99',
    '000', '111', '222', '333', '444', '555', '666', '777', '888', '999',
    '0000', '1111', '2222', '3333', '7777', '1212', '1221', '2121',
    '1010', '2020', '2525', '3131', '6969', '1313', '6161',
    '123123', '321321', '112233', '223344', '998877',
]

_DEFAULT_SEQUENTIAL_NUMBERS = [
    '1', '12', '123', '1234', '12345', '123456', '1234567', '12345678', '123456789', '1234567890',
    '321', '4321', '54321', '654321', '987654', '987654321',
    '0123', '01234', '012345',
]

_DEFAULT_TOP_PLATES = ['34', '06', '35', '01', '07', '16', '55', '42', '61', '41']
_DEFAULT_IMPORTANT_YEARS = [
    '1903', '1905', '1907', '1967',
    '1923', '1919', '1881', '1453',
    '2023', '2024', '2025', '2026',
]

_DEFAULT_TOP_AFFIXES = ['tr', 'admin', 'pass', 'pro', 'vip', 'ist', 'dev', 'app', 'online', 'official']
_DEFAULT_ALL_AFFIXES = [
    'admin', 'pass', 'password', 'sifre', 'parola', 'root', 'user', 'master', 'super',
    'login', 'giris', 'hesap', 'account',
    'pro', 'vip', 'king', 'queen', 'boss', 'chief', 'star', 'legend', 'hero', 'alfa',
    'tr', 'turk', 'turkey', 'ist', 'istanbul', 'ankara', 'izmir',
    'dev', 'app', 'test', 'web', 'mail', 'net', 'sys', 'tech', 'corp', 'digital',
    'love', 'ask', 'canim', 'bebek', 'hayat', 'forever', 'only', 'my',
    'online', 'official', 'team', 'club', 'fan', 'real', 'the', 'new',
]

_DEFAULT_PRIMARY_SYMBOLS = ['!', '.', '_', '-', '@', '*']
_DEFAULT_SECONDARY_SYMBOLS = ['#', '+', '?', '$', '&', '%']

_DEFAULT_COMPLEXITY_TAILS = [
    '!', '.', '*', '#', '!!', '!@', '!1', '@1', '#1', '$1',
    '!@#', '!23', '!2#', '123!', '1!', '!a', '!A',
    '1!', '1@', '1#', '12!', '123!', '1234!',
    '.com', '.tr', '.net',
]

_DEFAULT_COMMON_TURKISH_PASSWORDS = [
    'sifre', 'parola', 'turkiye', 'istanbul', 'ankara', 'fenerbahce', 'galatasaray',
    'besiktas', 'trabzonspor', 'iloveyou', 'sevgilim', 'askim', 'canim',
    'melek', 'allah', 'bismillah', 'insallah', 'masallah',
    'herkull', 'kartal', 'aslan', 'bozkurt', 'ataturk', 'mustafakemal',
    'hayat', 'gunes', 'yildiz', 'deniz', 'merhaba', 'selam', 'tamam',
]

_DEFAULT_LEET_RULES = {
    'a': ['@', '4'],
    'e': ['3'],
    'i': ['1', '!'],
    'ı': ['1', '!'],
    'o': ['0'],
    'ö': ['0'],
    's': ['5', '$'],
    'ş': ['5', '$'],
    't': ['7', '+'],
    'g': ['9'],
    'ğ': ['9'],
    'b': ['8'],
    'l': ['1'],
    'z': ['2'],
    'c': ['('],
    'ç': ['('],
}

TR_TO_EN = _DEFAULT_TR_TO_EN.copy()
TOP_TRAILING_NUMBERS = _DEFAULT_TOP_TRAILING_NUMBERS[:]
KEYBOARD_WALKS = _DEFAULT_KEYBOARD_WALKS[:]
REPEATING_DIGITS = _DEFAULT_REPEATING_DIGITS[:]
SEQUENTIAL_NUMBERS = _DEFAULT_SEQUENTIAL_NUMBERS[:]
TOP_PLATES = _DEFAULT_TOP_PLATES[:]
ALL_PLATES = [f"{i:02d}" for i in range(1, 82)]
IMPORTANT_YEARS = _DEFAULT_IMPORTANT_YEARS[:]
TOP_AFFIXES = _DEFAULT_TOP_AFFIXES[:]
ALL_AFFIXES = _DEFAULT_ALL_AFFIXES[:]
PRIMARY_SYMBOLS = _DEFAULT_PRIMARY_SYMBOLS[:]
SECONDARY_SYMBOLS = _DEFAULT_SECONDARY_SYMBOLS[:]
ALL_SYMBOLS = PRIMARY_SYMBOLS + SECONDARY_SYMBOLS + ['/', '=', '~']
COMPLEXITY_TAILS = _DEFAULT_COMPLEXITY_TAILS[:]
COMMON_TURKISH_PASSWORDS = _DEFAULT_COMMON_TURKISH_PASSWORDS[:]
LEET_RULES = {k: list(v) for k, v in _DEFAULT_LEET_RULES.items()}


def normalize_turkish(word: str) -> str:
    return "".join(TR_TO_EN.get(ch, ch) for ch in word)


def get_casing_variations(word: str) -> Dict[str, Set[str]]:
    w = word.strip()
    if not w:
        return {"primary": set(), "secondary": set(), "tertiary": set()}

    primary = {w.lower(), w.capitalize(), w.upper()}
    secondary = set()
    tertiary = set()

    if len(w) > 1:
        secondary.add(w[0].lower() + w[1:].upper())
        secondary.add(w[:-1].lower() + w[-1].upper())
        secondary.add(w[0].upper() + w[1:-1].lower() + w[-1].upper())
        secondary.add("".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(w)))
        secondary.add("".join(c.lower() if i % 2 == 0 else c.upper() for i, c in enumerate(w)))

    if len(w) > 2:
        tertiary.add(w[:2].upper() + w[2:].lower())
        tertiary.add(w[:-2].lower() + w[-2:].upper())

    return {"primary": primary, "secondary": secondary, "tertiary": tertiary}


def generate_leet_variations(word: str, level: int = 2) -> Dict[str, Set[str]]:
    w_lower = word.lower()
    soft_leet = set()
    deep_leet = set()

    if level >= 1:
        for ch, replacements in LEET_RULES.items():
            if ch in w_lower:
                for rep in replacements:
                    single_rep = w_lower.replace(ch, rep, 1)
                    soft_leet.add(single_rep)
                    soft_leet.add(single_rep.capitalize())

    if level >= 2:
        full_1 = w_lower
        full_2 = w_lower
        for ch, reps in LEET_RULES.items():
            if ch in full_1:
                full_1 = full_1.replace(ch, reps[0])
            if len(reps) > 1 and ch in full_2:
                full_2 = full_2.replace(ch, reps[1])
            elif ch in full_2:
                full_2 = full_2.replace(ch, reps[0])

        if full_1 != w_lower:
            deep_leet.add(full_1)
            deep_leet.add(full_1.capitalize())
        if full_2 != w_lower:
            deep_leet.add(full_2)
            deep_leet.add(full_2.capitalize())

    return {"soft": soft_leet, "deep": deep_leet}


def get_word_mutations(word: str) -> Dict[str, Set[str]]:
    w = word.lower()
    mutations = {"core": set(), "extended": set()}

    if len(w) < 2:
        return mutations

    if len(w) >= 4:
        mutations["core"].add(w[:3])
        mutations["core"].add(w[:4])
        mutations["extended"].add(w[:5])
        mutations["extended"].add(w[-3:])
        mutations["extended"].add(w[-4:])

    consonants = "".join(c for c in w if c not in 'aeıioöuü')
    if len(consonants) >= 2 and consonants != w:
        mutations["extended"].add(consonants)

    if len(w) >= 3:
        mutations["core"].add(w * 2)
        mutations["core"].add(w.capitalize() * 2)

    mutations["extended"].add(w[::-1])
    mutations["extended"].add(w[::-1].capitalize())

    if len(w) >= 3:
        mutations["extended"].add(w[0] + w[-1])

    return mutations


def get_initials_from_words(words: List[str]) -> Set[str]:
    initials = set()
    if len(words) < 2:
        return initials

    first_letters = "".join(w[0].lower() for w in words if w)
    if len(first_letters) >= 2:
        initials.add(first_letters)
        initials.add(first_letters.upper())
        initials.add(first_letters.capitalize())

    if len(words) >= 2:
        two_init = (words[0][0] + words[1][0]).lower()
        initials.add(two_init)
        initials.add(two_init.upper())

    return initials


def generate_date_permutations(numbers: List[str]) -> Set[str]:
    perms = set()
    for n in numbers:
        perms.add(n)
        if len(n) == 4 and (n.startswith("19") or n.startswith("20")):
            short = n[2:]
            perms.add(short)
            perms.add(short * 2)
            perms.add(n * 2)
            perms.add(n[::-1])
        elif len(n) == 2:
            perms.add(n * 2)
            perms.add(n * 3)
    return perms


class HTMLTextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.text_parts = []
        self.ignore_tags = {'script', 'style', 'noscript', 'header', 'footer', 'svg'}
        self.current_tag = None

    def handle_starttag(self, tag, attrs):
        self.current_tag = tag.lower()

    def handle_endtag(self, tag):
        self.current_tag = None

    def handle_data(self, data):
        if self.current_tag not in self.ignore_tags:
            clean = data.strip()
            if clean:
                self.text_parts.append(clean)


def crawl_website_keywords(url: str, min_word_len: int = None, max_words: int = None) -> List[str]:
    if min_word_len is None:
        min_word_len = get_config_int("osint", "min_word_length", fallback=3)
    if max_words is None:
        max_words = get_config_int("osint", "max_words", fallback=150)
    timeout = get_config_int("osint", "timeout", fallback=15)
    user_agent = get_config_value("osint", "user_agent",
                                  fallback="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (elc-gen OSINT Suite)")

    print(f"{Colors.BLUE}[OSINT] Crawling target website: {url}{Colors.RESET}")
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    headers = {'User-Agent': user_agent}
    req = urllib.request.Request(url, headers=headers)

    try:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx) as response:
            html = response.read().decode('utf-8', errors='ignore')
            parser = HTMLTextExtractor()
            parser.feed(html)
            raw_text = " ".join(parser.text_parts)

            words = re.findall(r'\b[A-Za-zçÇğĞıİöÖşŞüÜ]{%d,}\b' % min_word_len, raw_text)
            unique_words = list(dict.fromkeys([w.lower() for w in words]))[:max_words]
            print(f"{Colors.GREEN}[OSINT] Harvested {len(unique_words)} unique target keywords.{Colors.RESET}")
            return unique_words
    except Exception as e:
        print(f"{Colors.RED}[OSINT !] Error crawling website: {e}{Colors.RESET}")
        return []


def generate_security_rules(target_words: List[str], numbers: List[str], output_rule_file: str):
    print(f"\n{Colors.BLUE}[RULE] Generating targeted Hashcat / JtR rule file...{Colors.RESET}")
    rules = [
        "# --- elc-gen Targeted Cyber Security Ruleset ---",
        ":",
        "c",
        "u",
        "l",
        "r",
        "d",
        "t",
        "T0",
    ]

    sample_nums = numbers[:15] + ['1', '123', '1234', '1903', '1905', '1907', '2024', '2025', '2026', '34', '06']
    for num in set(sample_nums):
        rule_suffix = "".join(f"${c}" for c in num)
        rule_prefix = "".join(f"^{c}" for c in reversed(num))
        rules.append(f"{rule_suffix}")
        rules.append(f"c {rule_suffix}")
        rules.append(f"{rule_prefix}")
        rules.append(f"{rule_suffix} $!")
        rules.append(f"c {rule_suffix} $!")
        rules.append(f"{rule_suffix} $@")

    rules.extend([
        "sa@", "se3", "si1", "so0", "ss5", "st7", "sg9", "sb8",
        "c sa@ se3", "c se3 si1", "c sa@ se3 si1 so0"
    ])

    with open(output_rule_file, 'w', encoding='utf-8') as f:
        for r in rules:
            f.write(r + "\n")

    print(f"{Colors.GREEN}[✓] Saved {len(rules)} rules to '{output_rule_file}'!{Colors.RESET}")
    print(f"    {Colors.DIM}Usage with Hashcat: hashcat -m 0 -a 0 hashes.txt rockyou.txt -r {output_rule_file}{Colors.RESET}\n")


def expand_mask_pattern(mask: str, max_limit: int = 100000) -> List[str]:
    charsets = {
        '?d': '0123456789',
        '?l': 'abcdefghijklmnopqrstuvwxyz',
        '?u': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        '?s': '!@#$%^&*._-',
        '?a': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*._-'
    }

    tokens = []
    i = 0
    while i < len(mask):
        if mask[i] == '?' and i + 1 < len(mask) and f"?{mask[i+1]}" in charsets:
            tokens.append(list(charsets[f"?{mask[i+1]}"]))
            i += 2
        else:
            tokens.append([mask[i]])
            i += 1

    total_combos = math.prod(len(t) for t in tokens)
    if total_combos > max_limit:
        print(f"{Colors.YELLOW}[!] Warning: Mask contains {total_combos:,} possibilities. Generating first {max_limit:,}.{Colors.RESET}")

    passwords = []
    for combo in itertools.product(*tokens):
        passwords.append("".join(combo))
        if len(passwords) >= max_limit:
            break
    return passwords


def audit_wordlist_file(file_path: str):
    print(f"\n{Colors.CYAN}{Colors.BOLD}🔍 PASSWORD SECURITY AUDIT & STATISTICAL ANALYSIS{Colors.RESET}")
    print(f"{Colors.DIM}Analyzing File: {os.path.abspath(file_path)}{Colors.RESET}\n")

    if not os.path.exists(file_path):
        print(f"{Colors.RED}[!] File not found: {file_path}{Colors.RESET}")
        return

    total_count = 0
    unique_set = set()
    lengths = {}
    entropies = []
    charsets = {'alpha_lower': 0, 'alpha_upper': 0, 'digits_only': 0, 'mixed_alpha_num': 0, 'with_special': 0}
    top_base_words = {}

    start_time = time.time()
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            raw_line = line.strip()
            if not raw_line:
                continue
            total_count += 1

            pwd = raw_line
            if ":" in raw_line:
                parts = raw_line.split(":")
                if len(parts) >= 2 and all(c in '0123456789abcdefABCDEF' for c in parts[1]) and len(parts[1]) in (32, 40, 64, 128):
                    pwd = parts[0]
                elif len(parts) >= 2 and all(c in '0123456789abcdefABCDEF' for c in parts[0]) and len(parts[0]) in (32, 40, 64, 128):
                    pwd = parts[1]

            unique_set.add(pwd)

            length = len(pwd)
            lengths[length] = lengths.get(length, 0) + 1

            ent = calculate_shannon_entropy(pwd)
            entropies.append(ent)

            has_lower = any(c.islower() for c in pwd)
            has_upper = any(c.isupper() for c in pwd)
            has_digit = any(c.isdigit() for c in pwd)
            has_special = any(not c.isalnum() for c in pwd)

            if has_special:
                charsets['with_special'] += 1
            elif has_digit and not (has_lower or has_upper):
                charsets['digits_only'] += 1
            elif (has_lower or has_upper) and not has_digit:
                if has_lower and not has_upper:
                    charsets['alpha_lower'] += 1
                else:
                    charsets['alpha_upper'] += 1
            else:
                charsets['mixed_alpha_num'] += 1

            base = re.sub(r'[^a-zA-ZçÇğĞıİöÖşŞüÜ]', '', pwd).lower()
            if len(base) >= 3:
                top_base_words[base] = top_base_words.get(base, 0) + 1

    elapsed = time.time() - start_time
    unique_count = len(unique_set)
    avg_entropy = sum(entropies) / len(entropies) if entropies else 0.0

    print(f"{Colors.GREEN}{Colors.BOLD}╔═══════════════════════════════════════════════════════════════╗{Colors.RESET}")
    print(f"{Colors.GREEN}{Colors.BOLD}║                 AUDIT REPORT & STATISTICS                     ║{Colors.RESET}")
    print(f"{Colors.GREEN}{Colors.BOLD}╚═══════════════════════════════════════════════════════════════╝{Colors.RESET}")
    print(f"  • Total Lines            : {Colors.BOLD}{total_count:,}{Colors.RESET}")
    print(f"  • Unique Passwords       : {Colors.BOLD}{unique_count:,}{Colors.RESET} ({unique_count/max(1, total_count)*100:.1f}%)")
    print(f"  • Average Shannon Entropy: {Colors.BOLD}{avg_entropy:.2f} bits/password{Colors.RESET}")
    print(f"  • Analysis Duration      : {Colors.DIM}{elapsed:.3f} seconds{Colors.RESET}\n")

    print(f"{Colors.YELLOW}{Colors.BOLD}📊 Character Set Distribution:{Colors.RESET}")
    for k, v in charsets.items():
        pct = (v / max(1, total_count)) * 100
        bar = "█" * int(pct / 4)
        print(f"  {k:<18}: {v:>8,} ({pct:>5.1f}%) {Colors.CYAN}{bar}{Colors.RESET}")

    print(f"\n{Colors.YELLOW}{Colors.BOLD}📏 Password Length Distribution (Top 5):{Colors.RESET}")
    sorted_len = sorted(lengths.items(), key=lambda x: x[1], reverse=True)[:5]
    for l, c in sorted_len:
        pct = (c / max(1, total_count)) * 100
        print(f"  {l} Characters : {c:>8,} passwords ({pct:.1f}%)")

    if top_base_words:
        print(f"\n{Colors.YELLOW}{Colors.BOLD}🔑 Most Frequent Base Words:{Colors.RESET}")
        top_words = sorted(top_base_words.items(), key=lambda x: x[1], reverse=True)[:6]
        for w, c in top_words:
            print(f"  • {w:<12} ({c:,} times)")

    print(f"\n{Colors.MAGENTA}{Colors.BOLD}⚡ Estimated Brute-Force Crack Times (Average Entropy):{Colors.RESET}")
    print(f"  • Online Attack (100 tries/sec)   : {format_crack_time(2**avg_entropy / 100)}")
    print(f"  • Fast GPU Cluster (100 GH/s - NTLM): {format_crack_time(2**avg_entropy / 100_000_000_000)}")
    print()


def format_crack_time(seconds: float) -> str:
    if seconds < 1: return f"{Colors.GREEN}< 1 second (Instant){Colors.RESET}"
    if seconds < 60: return f"{Colors.GREEN}{seconds:.1f} seconds{Colors.RESET}"
    if seconds < 3600: return f"{Colors.YELLOW}{seconds/60:.1f} minutes{Colors.RESET}"
    if seconds < 86400: return f"{Colors.YELLOW}{seconds/3600:.1f} hours{Colors.RESET}"
    if seconds < 31536000: return f"{Colors.RED}{seconds/86400:.1f} days{Colors.RESET}"
    if seconds < 3153600000: return f"{Colors.MAGENTA}{seconds/31536000:.1f} years{Colors.RESET}"
    return f"{Colors.MAGENTA}> 100 years (Very Strong){Colors.RESET}"


def search_in_file(
    file_path: str,
    terms: List[str],
    case_sensitive: bool = False,
    exact_match: bool = False,
    regex_mode: bool = False,
    check_hashes: bool = False
):
    print(f"\n{Colors.CYAN}{Colors.BOLD}🔍 IN-FILE SEARCH & BREACH LOOKUP{Colors.RESET}")
    print(f"{Colors.DIM}Target File : {os.path.abspath(file_path)}{Colors.RESET}")

    if not os.path.exists(file_path):
        print(f"{Colors.RED}[!] Specified file not found: {file_path}{Colors.RESET}")
        return

    search_map = {}
    for t in terms:
        t_clean = t.strip()
        if not t_clean:
            continue
        targets = [t_clean if case_sensitive else t_clean.lower()]

        if check_hashes:
            md5_h = calculate_hash(t_clean, 'md5')
            sha1_h = calculate_hash(t_clean, 'sha1')
            sha256_h = calculate_hash(t_clean, 'sha256')
            ntlm_h = calculate_hash(t_clean, 'ntlm')
            targets.extend([md5_h, sha1_h, sha256_h, ntlm_h])
            targets.extend([md5_h.upper(), sha1_h.upper(), sha256_h.upper(), ntlm_h.upper()])

        search_map[t_clean] = targets

    print(f"{Colors.DIM}Searched Terms Count: {len(search_map)} | Match Mode: {'Exact Match' if exact_match else 'Substring Match'} | Case Sensitive: {'Yes' if case_sensitive else 'No'}{Colors.RESET}")
    if check_hashes:
        print(f"{Colors.YELLOW}[*] Crypto Hash Checking Active (Searching MD5, SHA1, SHA256, NTLM hashes...){Colors.RESET}")
    print("=" * 65)

    is_gzip = file_path.endswith(".gz")
    open_func = gzip.open if is_gzip else open
    mode_flag = 'rt' if is_gzip else 'r'

    total_lines = 0
    match_count = 0
    term_hits = {t: 0 for t in search_map}
    sample_matches = []

    start_time = time.time()
    with open_func(file_path, mode_flag, encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, start=1):
            total_lines += 1
            raw_line = line.rstrip('\r\n')
            compare_line = raw_line if case_sensitive else raw_line.lower()

            line_matched = False
            for orig_term, target_list in search_map.items():
                for tgt in target_list:
                    matched = False
                    if regex_mode:
                        try:
                            flags = 0 if case_sensitive else re.IGNORECASE
                            matched = bool(re.search(tgt, raw_line, flags=flags))
                        except Exception:
                            pass
                    elif exact_match:
                        if ":" in compare_line:
                            parts = compare_line.split(":")
                            matched = (tgt == compare_line) or (tgt in parts)
                        else:
                            matched = (tgt == compare_line)
                    else:
                        matched = tgt in compare_line

                    if matched:
                        line_matched = True
                        term_hits[orig_term] += 1
                        if len(sample_matches) < 20:
                            highlighted = raw_line
                            try:
                                if not regex_mode:
                                    flags = 0 if case_sensitive else re.IGNORECASE
                                    highlighted = re.sub(f"({re.escape(tgt)})", f"{Colors.YELLOW}{Colors.BOLD}\\1{Colors.RESET}", raw_line, flags=flags)
                            except Exception:
                                pass
                            sample_matches.append((line_num, orig_term, highlighted))
                        break

            if line_matched:
                match_count += 1

    elapsed = time.time() - start_time

    print(f"\n{Colors.GREEN}{Colors.BOLD}╔═══════════════════════════════════════════════════════════════╗{Colors.RESET}")
    print(f"{Colors.GREEN}{Colors.BOLD}║                   SEARCH & MATCH REPORT                       ║{Colors.RESET}")
    print(f"{Colors.GREEN}{Colors.BOLD}╚═══════════════════════════════════════════════════════════════╝{Colors.RESET}")
    print(f"  • Scanned Lines          : {Colors.BOLD}{total_lines:,}{Colors.RESET}")
    print(f"  • Total Matched Lines    : {Colors.BOLD}{match_count:,}{Colors.RESET}")
    print(f"  • Scan Duration          : {Colors.DIM}{elapsed:.3f} seconds{Colors.RESET}\n")

    print(f"{Colors.CYAN}{Colors.BOLD}📊 Per-Term Match Status:{Colors.RESET}")
    for term, hits in term_hits.items():
        if hits > 0:
            status = f"{Colors.GREEN}[✓ FOUND]{Colors.RESET} {Colors.BOLD}{hits:,} times{Colors.RESET}"
        else:
            status = f"{Colors.RED}[✗ NOT FOUND]{Colors.RESET}"
        print(f"  • '{term:<20}' -> {status}")

    if sample_matches:
        print(f"\n{Colors.YELLOW}{Colors.BOLD}🔍 Sample Matched Lines (First {len(sample_matches)}):{Colors.RESET}")
        for l_num, term, text in sample_matches:
            print(f"  {Colors.DIM}[Line {l_num:>6}]{Colors.RESET} ({Colors.CYAN}{term}{Colors.RESET}): {text}")
    print()


def parse_dates_and_numbers(item: str) -> Tuple[Set[str], Set[str]]:
    numbers = set()
    dates = set()

    date_matches = re.findall(r'(\d{1,4})[./\-](\d{1,2})[./\-](\d{1,4})', item)
    for p1, p2, p3 in date_matches:
        if len(p1) == 4:
            year, month, day = p1, f"{int(p2):02d}", f"{int(p3):02d}"
        elif len(p3) == 4:
            day, month, year = f"{int(p1):02d}", f"{int(p2):02d}", p3
        else:
            continue

        dates.add(f"{day}{month}{year}")
        dates.add(f"{day}{month}{year[2:]}")
        dates.add(f"{year}{month}{day}")
        dates.add(f"{day}{month}")
        dates.add(f"{month}{day}")
        numbers.add(year)
        numbers.add(year[2:])

    return numbers, dates


def clean_input_lines(file_path: str) -> Tuple[List[str], List[str]]:
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File '{file_path}' not found!")

    raw_words = set()
    raw_numbers = set()

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            item = line.strip()
            if not item or item.startswith("#"):
                continue

            parsed_nums, parsed_dates = parse_dates_and_numbers(item)
            raw_numbers.update(parsed_nums)
            raw_numbers.update(parsed_dates)

            for part in item.replace(',', ' ').replace(';', ' ').replace(':', ' ').split():
                part_clean = part.strip()
                if not part_clean:
                    continue

                if part_clean.isdigit():
                    raw_numbers.add(part_clean)
                    if len(part_clean) == 4 and (part_clean.startswith("19") or part_clean.startswith("20")):
                        raw_numbers.add(part_clean[2:])
                        raw_numbers.add(part_clean[2:] * 2)
                else:
                    raw_words.add(part_clean)
                    norm = normalize_turkish(part_clean)
                    if norm:
                        raw_words.add(norm)

    return list(raw_words), list(raw_numbers)


def generate_passwords(
    words: List[str],
    custom_numbers: List[str],
    min_len: int = 6,
    max_len: int = 24,
    mode: str = "standard",
    leet_level: int = 2,
    min_upper: int = 0,
    min_lower: int = 0,
    min_digits: int = 0,
    min_symbols: int = 0,
    policy_ad: bool = False,
    include_regex: Optional[str] = None,
    exclude_regex: Optional[str] = None
) -> List[str]:
    tier0 = set()
    tier1 = set()
    tier2 = set()
    tier3 = set()
    tier4 = set()

    date_perms = generate_date_permutations(custom_numbers)

    by_start = get_config_int("generation", "birth_year_start", fallback=1960)
    by_end = get_config_int("generation", "birth_year_end", fallback=2026) + 1
    birth_years_full = [str(y) for y in range(by_start, by_end)]
    by_short_start = by_start % 100
    birth_years_short = [f"{y:02d}" for y in range(0, by_end % 100 + 1)] + [str(y) for y in range(by_short_start, 100)]

    num_pool_tier1 = list(set(
        list(date_perms) + TOP_TRAILING_NUMBERS[:20] + SEQUENTIAL_NUMBERS[:7]
        + IMPORTANT_YEARS + TOP_PLATES
    ))

    num_pool_tier2 = list(set(
        num_pool_tier1 + TOP_TRAILING_NUMBERS + SEQUENTIAL_NUMBERS
        + REPEATING_DIGITS[:20] + birth_years_full + birth_years_short
    ))

    num_pool_deep = list(set(
        num_pool_tier2 + KEYBOARD_WALKS[:10] + REPEATING_DIGITS + ALL_PLATES
    ))

    primary_words = set()
    secondary_words = set()
    tertiary_words = set()
    leet_words_soft = set()
    leet_words_deep = set()
    mutated_words = set()
    initials = set()

    for w in words:
        casings = get_casing_variations(w)
        primary_words.update(casings["primary"])
        secondary_words.update(casings["secondary"])
        tertiary_words.update(casings["tertiary"])

        norm = normalize_turkish(w)
        if norm and norm != w:
            n_casings = get_casing_variations(norm)
            primary_words.update(n_casings["primary"])
            secondary_words.update(n_casings["secondary"])

        mutations = get_word_mutations(w)
        primary_words.update(mutations["core"])
        mutated_words.update(mutations["extended"])

        if norm and norm != w:
            n_mutations = get_word_mutations(norm)
            primary_words.update(n_mutations["core"])
            mutated_words.update(n_mutations["extended"])

        if leet_level > 0:
            leets = generate_leet_variations(w, level=leet_level)
            leet_words_soft.update(leets["soft"])
            if mode in ["standard", "deep"]:
                leet_words_deep.update(leets["deep"])
            if norm and norm != w:
                n_leets = generate_leet_variations(norm, level=leet_level)
                leet_words_soft.update(n_leets["soft"])
                if mode in ["standard", "deep"]:
                    leet_words_deep.update(n_leets["deep"])

    initials = get_initials_from_words(words)

    for cp in COMMON_TURKISH_PASSWORDS:
        tier0.add(cp)
        tier0.add(cp.capitalize())

    for kw in KEYBOARD_WALKS:
        tier0.add(kw)
        tier0.add(kw.capitalize())
    for seq in SEQUENTIAL_NUMBERS:
        if len(seq) >= 4:
            tier0.add(seq)

    for pw in primary_words:
        tier1.add(pw)
        for num in num_pool_tier1:
            tier1.add(f"{pw}{num}")
            tier1.add(f"{num}{pw}")

    for pw in primary_words:
        for num in list(date_perms) + TOP_TRAILING_NUMBERS[:15]:
            for sym in ['!', '.', '_', '*', '@', '#']:
                tier1.add(f"{pw}{num}{sym}")
                tier1.add(f"{pw}{sym}{num}")

    if len(words) >= 2:
        word_pairs = list(itertools.permutations(words[:8], 2))
        for w1, w2 in word_pairs:
            for c1 in [w1.capitalize(), w1.lower()]:
                for c2 in [w2.capitalize(), w2.lower()]:
                    combo = f"{c1}{c2}"
                    tier1.add(combo)
                    tier1.add(f"{c1}_{c2}")
                    tier1.add(f"{c1}.{c2}")

                    for num in list(date_perms) + ['1', '12', '123', '1234', '123!']:
                        tier1.add(f"{combo}{num}")
                        tier1.add(f"{c1}_{c2}_{num}")
                        tier1.add(f"{combo}{num}!")

    for init in initials:
        for num in num_pool_tier1:
            tier1.add(f"{init}{num}")
            tier1.add(f"{num}{init}")
        for num in list(date_perms)[:10]:
            for sym in ['!', '.', '_']:
                tier1.add(f"{init}{num}{sym}")

    for pw in primary_words:
        for tail in COMPLEXITY_TAILS[:10]:
            tier1.add(f"{pw}{tail}")

    if mode in ["standard", "deep"]:
        for pw in primary_words:
            for num in num_pool_tier2:
                tier2.add(f"{pw}{num}")
                tier2.add(f"{num}{pw}")

    for pw in primary_words:
        for sym in PRIMARY_SYMBOLS:
            tier2.add(f"{pw}{sym}")
            tier2.add(f"{sym}{pw}")
            tier2.add(f"{sym}{pw}{sym}")
            tier2.add(f"{pw}{sym * 2}")

        for num in list(date_perms)[:8] + ['1', '123', '1234']:
            for sym in ['!', '@', '#', '*']:
                tier2.add(f"{sym}{pw}{num}{sym}")
                tier2.add(f"{sym}{pw}{sym}{num}")
                tier2.add(f"{pw}{sym}{num}{sym}")

    affixes_pool = TOP_AFFIXES if mode == "light" else ALL_AFFIXES
    for pw in primary_words:
        for aff in affixes_pool:
            for ac in [aff.lower(), aff.upper(), aff.capitalize()]:
                tier2.add(f"{pw}{ac}")
                tier2.add(f"{ac}{pw}")
                tier2.add(f"{pw}_{ac}")
                tier2.add(f"{ac}_{pw}")
                tier2.add(f"{pw}.{ac}")
                for num in list(date_perms)[:5] + ['1', '123']:
                    tier2.add(f"{pw}{ac}{num}")
                    tier2.add(f"{pw}_{ac}{num}!")

    if len(words) >= 2 and mode in ["standard", "deep"]:
        word_pairs = list(itertools.permutations(words[:6], 2))
        for w1, w2 in word_pairs:
            for c1 in [w1.capitalize(), w1.lower()]:
                for c2 in [w2.capitalize(), w2.lower()]:
                    combo = f"{c1}{c2}"
                    tier2.add(f"{c1}-{c2}")
                    tier2.add(f"{c1}_{c2}")

                    for num in list(date_perms)[:6] + ['1', '123', '34']:
                        tier2.add(f"{c1}{num}{c2}")
                        tier2.add(f"{c1}_{num}_{c2}")
                        tier2.add(f"{combo}.{num}")
                        tier2.add(f"{c1}_{c2}_{num}")

    for pw in primary_words:
        for tail in COMPLEXITY_TAILS:
            tier2.add(f"{pw}{tail}")

    if len(words) >= 2 and mode in ["standard", "deep"]:
        for w1, w2 in itertools.permutations(words[:4], 2):
            email_prefix = f"{w1.lower()}.{w2.lower()}"
            tier2.add(email_prefix)
            email_prefix2 = f"{w1.lower()}_{w2.lower()}"
            tier2.add(email_prefix2)
            for num in list(date_perms)[:5]:
                tier2.add(f"{email_prefix}{num}")
                tier2.add(f"{email_prefix2}{num}")

    if mode in ["standard", "deep"]:
        for lw in leet_words_soft:
            tier3.add(lw)
            for num in list(date_perms)[:8] + TOP_TRAILING_NUMBERS[:15]:
                tier3.add(f"{lw}{num}")
                tier3.add(f"{lw}{num}!")
                tier3.add(f"{lw}_{num}")

        for lw in leet_words_deep:
            tier3.add(lw)
            for num in list(date_perms)[:5] + ['1', '123', '1234']:
                tier3.add(f"{lw}{num}")
                tier3.add(f"{lw}{num}!")

        for sw in secondary_words:
            tier3.add(sw)
            for num in list(date_perms)[:8] + ['1', '123', '1234', '123456', '!']:
                tier3.add(f"{sw}{num}")
                tier3.add(f"{sw}{num}!")

        for mw in mutated_words:
            tier3.add(mw)
            tier3.add(mw.capitalize())
            for num in list(date_perms)[:5] + ['1', '123', '1234']:
                tier3.add(f"{mw}{num}")
                tier3.add(f"{mw.capitalize()}{num}")

        for num in custom_numbers:
            if len(num) >= 3:
                tier3.add(f"05{num}")
                tier3.add(f"5{num}")

        for pw in list(primary_words)[:6]:
            for kw in KEYBOARD_WALKS[:8]:
                tier3.add(f"{pw}{kw}")
                tier3.add(f"{kw}{pw}")

    if mode in ["standard", "deep"]:
        for tw in tertiary_words:
            tier4.add(tw)
            for num in list(date_perms)[:5] + ['1', '123']:
                tier4.add(f"{tw}{num}")

        for pw in list(primary_words)[:10]:
            for sym in ALL_SYMBOLS:
                for num in list(date_perms)[:5] + ['1', '12', '123', '34']:
                    tier4.add(f"{pw}{sym}{num}")
                    tier4.add(f"{num}{sym}{pw}")

            for num in list(date_perms)[:5] + ['1', '123', '34']:
                tier4.add(f"{num}{pw}{num}")

        if len(words) >= 3:
            for w1, w2, w3 in itertools.permutations(words[:5], 3):
                c3 = f"{w1.capitalize()}{w2.capitalize()}{w3.capitalize()}"
                c3_under = f"{w1.lower()}_{w2.lower()}_{w3.lower()}"
                tier4.add(c3)
                tier4.add(c3_under)
                for num in list(date_perms)[:3] + ['1', '123']:
                    tier4.add(f"{c3}{num}")
                    tier4.add(f"{c3}{num}!")

    if mode == "deep":
        for pw in list(primary_words)[:8]:
            for num in num_pool_deep:
                tier4.add(f"{pw}{num}")
                tier4.add(f"{num}{pw}")

        for lw in list(leet_words_soft)[:20]:
            for aff in TOP_AFFIXES[:5]:
                tier4.add(f"{lw}{aff}")
                tier4.add(f"{aff}{lw}")
            for tail in COMPLEXITY_TAILS[:5]:
                tier4.add(f"{lw}{tail}")

        for mw in list(mutated_words)[:15]:
            for num in num_pool_tier2[:20]:
                tier4.add(f"{mw}{num}")
                tier4.add(f"{mw.capitalize()}{num}")

    def filter_and_validate(s_set: Set[str]) -> List[str]:
        valid = []
        for p in s_set:
            if passes_policy(
                pwd=p,
                min_len=min_len,
                max_len=max_len,
                min_upper=min_upper,
                min_lower=min_lower,
                min_digits=min_digits,
                min_symbols=min_symbols,
                policy_ad=policy_ad,
                include_regex=include_regex,
                exclude_regex=exclude_regex
            ):
                valid.append(p)
        return valid

    final_passwords = []
    seen = set()
    for tier_set in [tier0, tier1, tier2, tier3, tier4]:
        filtered = filter_and_validate(tier_set)
        for p in filtered:
            if p not in seen:
                seen.add(p)
                final_passwords.append(p)

    return final_passwords


def interactive_target_profiler() -> Tuple[List[str], List[str]]:
    print(f"\n{Colors.YELLOW}{Colors.BOLD}🎯 TARGET OSINT PROFILE WIZARD{Colors.RESET}")
    print(f"{Colors.DIM}Enter known target information (Press Enter to skip any field):{Colors.RESET}\n")

    words = set()
    numbers = set()

    name = input(f"{Colors.BOLD}• Target Name / Company Name    : {Colors.RESET}").strip()
    surname = input(f"{Colors.BOLD}• Target Surname / Division     : {Colors.RESET}").strip()
    nick = input(f"{Colors.BOLD}• Nickname / Handle / Username  : {Colors.RESET}").strip()
    bday = input(f"{Colors.BOLD}• Birth Date (DD.MM.YYYY)       : {Colors.RESET}").strip()
    
    partner = input(f"{Colors.BOLD}• Partner / Spouse Name         : {Colors.RESET}").strip()
    partner_bday = input(f"{Colors.BOLD}• Partner Birth Date (DD.MM.YYYY): {Colors.RESET}").strip()

    child = input(f"{Colors.BOLD}• Child / Sibling Name          : {Colors.RESET}").strip()
    child_bday = input(f"{Colors.BOLD}• Child Birth Date              : {Colors.RESET}").strip()

    pet = input(f"{Colors.BOLD}• Pet Name                      : {Colors.RESET}").strip()
    team = input(f"{Colors.BOLD}• Sports Team / Organization    : {Colors.RESET}").strip()
    city = input(f"{Colors.BOLD}• City / Hometown               : {Colors.RESET}").strip()
    plate = input(f"{Colors.BOLD}• Postal / Region Code          : {Colors.RESET}").strip()
    custom_words = input(f"{Colors.BOLD}• Custom Words (comma-separated): {Colors.RESET}").strip()

    for item in [name, surname, nick, partner, child, pet, team, city]:
        if item:
            for part in item.split():
                words.add(part)
                norm = normalize_turkish(part)
                if norm: words.add(norm)

    if custom_words:
        for cw in custom_words.replace(',', ' ').split():
            cw = cw.strip()
            if cw.isdigit():
                numbers.add(cw)
            elif cw:
                words.add(cw)
                norm = normalize_turkish(cw)
                if norm: words.add(norm)

    if plate:
        numbers.add(plate)

    for bd in [bday, partner_bday, child_bday]:
        if bd:
            nums, dts = parse_dates_and_numbers(bd)
            numbers.update(nums)
            numbers.update(dts)

    while not words:
        print(f"\n{Colors.YELLOW}[!] No target words provided yet.{Colors.RESET}")
        fallback = input(f"{Colors.BOLD}• Please enter at least 1 Name / Target Word: {Colors.RESET}").strip()
        if fallback:
            for part in fallback.split():
                words.add(part)
                norm = normalize_turkish(part)
                if norm: words.add(norm)

    print(f"\n{Colors.GREEN}[✓] Target Profile Extracted: {len(words)} keywords, {len(numbers)} numbers/dates.{Colors.RESET}")
    return list(words), list(numbers)


def execute_generation(
    words: List[str],
    numbers: List[str],
    output_file: str,
    min_len: int = 6,
    max_len: int = 24,
    mode: str = "standard",
    leet_level: int = 2,
    hash_algo: str = "none",
    hash_format: str = "plain_hash",
    file_format: str = "txt",
    min_upper: int = 0,
    min_lower: int = 0,
    min_digits: int = 0,
    min_symbols: int = 0,
    policy_ad: bool = False,
    include_regex: Optional[str] = None,
    exclude_regex: Optional[str] = None,
    rule_output: Optional[str] = None
):
    start_time = time.time()

    print(f"\n{Colors.BLUE}[+] Password generation engine started...{Colors.RESET}")
    print(f"    • Target Words : {Colors.DIM}{', '.join(words[:8])}{'...' if len(words) > 8 else ''}{Colors.RESET}")
    print(f"    • Target Numbers : {Colors.DIM}{', '.join(numbers[:8])}{'...' if len(numbers) > 8 else ''}{Colors.RESET}")
    print(f"    • Generation Mode: {Colors.BOLD}{mode.upper()}{Colors.RESET} (Leet Level: {leet_level})")
    if policy_ad:
        print(f"    • Security Policy: {Colors.YELLOW}Active Directory Complexity Filter Active{Colors.RESET}")
    if hash_algo != "none":
        print(f"    • Crypto Hash    : {Colors.CYAN}{hash_algo.upper()} ({hash_format}){Colors.RESET}")

    passwords = generate_passwords(
        words=words,
        custom_numbers=numbers,
        min_len=min_len,
        max_len=max_len,
        mode=mode,
        leet_level=leet_level,
        min_upper=min_upper,
        min_lower=min_lower,
        min_digits=min_digits,
        min_symbols=min_symbols,
        policy_ad=policy_ad,
        include_regex=include_regex,
        exclude_regex=exclude_regex
    )

    if not passwords:
        print(f"{Colors.RED}[!] No passwords generated matching specified criteria and filters!{Colors.RESET}")
        return

    is_gzip = output_file.endswith(".gz") or file_format == "gz"
    open_func = gzip.open if is_gzip else open
    mode_flag = 'wt' if is_gzip else 'w'

    with open_func(output_file, mode_flag, encoding='utf-8') as f:
        if file_format == "json":
            json_data = []
            for p in passwords:
                item = {"password": p, "length": len(p), "entropy": round(calculate_shannon_entropy(p), 2)}
                if hash_algo != "none":
                    item["hash"] = calculate_hash(p, hash_algo)
                json_data.append(item)
            json.dump(json_data, f, ensure_ascii=False, indent=2)

        elif file_format == "csv":
            header = "password,length,entropy" + (f",{hash_algo}_hash" if hash_algo != "none" else "")
            f.write(header + "\n")
            for p in passwords:
                h_val = f",{calculate_hash(p, hash_algo)}" if hash_algo != "none" else ""
                f.write(f'"{p}",{len(p)},{calculate_shannon_entropy(p):.2f}{h_val}\n')

        else:
            for p in passwords:
                if hash_algo != "none":
                    h = calculate_hash(p, hash_algo)
                    if hash_format == "hash_only":
                        line = h
                    elif hash_format == "hash_plain":
                        line = f"{h}:{p}"
                    else:
                        line = f"{p}:{h}"
                else:
                    line = p
                f.write(line + "\n")

    elapsed = time.time() - start_time
    file_size_kb = os.path.getsize(output_file) / 1024
    file_size_str = f"{file_size_kb:.2f} KB" if file_size_kb < 1024 else f"{file_size_kb/1024:.2f} MB"

    print(f"\n{Colors.GREEN}{Colors.BOLD}╔═══════════════════════════════════════════════════════════════╗{Colors.RESET}")
    print(f"{Colors.GREEN}{Colors.BOLD}║               OPERATION COMPLETED SUCCESSFULLY                ║{Colors.RESET}")
    print(f"{Colors.GREEN}{Colors.BOLD}╚═══════════════════════════════════════════════════════════════╝{Colors.RESET}")
    print(f"  {Colors.CYAN}[✓] Total Passwords Generated : {Colors.BOLD}{len(passwords):,}{Colors.RESET}")
    print(f"  {Colors.CYAN}[✓] Output File Size         : {Colors.BOLD}{file_size_str}{Colors.RESET}")
    print(f"  {Colors.CYAN}[✓] Time Elapsed             : {Colors.BOLD}{elapsed:.3f} seconds{Colors.RESET} ({int(len(passwords)/max(0.001, elapsed)):,} passwords/sec)")
    print(f"  {Colors.CYAN}[✓] Saved Output File        : {Colors.BOLD}{os.path.abspath(output_file)}{Colors.RESET}\n")

    if rule_output:
        generate_security_rules(words, numbers, rule_output)

    sample_categories = [
        ("High Priority (Name+Year / PIN)", [p for p in passwords[:200] if any(c.isdigit() for c in p) and not any(s in p for s in PRIMARY_SYMBOLS)]),
        ("Special Chars & Delimiters", [p for p in passwords[:300] if any(s in p for s in ['!', '.', '_', '@'])]),
        ("Natural Two-Word Combos", [p for p in passwords if any(w.lower() in p.lower() for w in words) and len(p) > 9]),
        ("Leet Speak & Variations", [p for p in passwords if any(c in p for c in ['@', '3', '1', '0', '5', '$', '7'])])
    ]

    print(f"{Colors.YELLOW}{Colors.BOLD}🔍 Realistic Password Samples Generated:{Colors.RESET}")
    for cat_name, cat_list in sample_categories:
        if cat_list:
            samples = cat_list[:4]
            print(f"  {Colors.BOLD}{cat_name:<32}:{Colors.RESET} {Colors.DIM}{' | '.join(samples)}{Colors.RESET}")
    print()


def main():
    parser = argparse.ArgumentParser(
        prog="elc-gen",
        description="Advanced Cyber Security, OSINT & Password Intelligence Wordlist Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example Usage Scenarios:
  1. Standard wordlist generation from input file:
     python elc_gen.py -i target.txt -o wordlist.txt

  2. Harvest keywords from website for targeted OSINT attack list:
     python elc_gen.py --crawl https://target.corp -o corp_wordlist.txt --mode standard

  3. NTLM Hash list with Active Directory compliance:
     python elc_gen.py -i target.txt -o hashes.txt --hash ntlm --policy-ad

  4. Search keywords, passwords, or hashes inside breach file:
     python elc_gen.py -i wordlist.txt --search "john,123456,admin" --hash-check

  5. Generate Hashcat / John the Ripper rule file (.rule):
     python elc_gen.py -i target.txt -o wordlist.txt --generate-rules target.rule

  6. Security audit of an existing wordlist / breach file:
     python elc_gen.py --audit rockyou_sample.txt

  7. Generation with custom configuration file:
     python elc_gen.py -i target.txt -o wordlist.txt --config my_config.cfg
"""
    )

    parser.add_argument("-i", "--input", help="Input .txt target file or file to scan")
    parser.add_argument("-o", "--output", default="wordlist.txt", help="Output wordlist file (Default: wordlist.txt)")
    parser.add_argument("-w", "--wizard", action="store_true", help="Launches interactive target profiler wizard")
    parser.add_argument("-c", "--crawl", "--url", dest="url", help="Harvests OSINT keywords from target website")

    parser.add_argument("--mode", choices=["light", "standard", "deep"], default="standard", help="Generation depth mode (light, standard, deep)")
    parser.add_argument("--min", type=int, default=6, help="Minimum password length (Default: 6)")
    parser.add_argument("--max", type=int, default=24, help="Maximum password length (Default: 24)")
    parser.add_argument("--no-leet", action="store_true", help="Disables leet speak conversions")
    parser.add_argument("--leet-level", type=int, choices=[0, 1, 2, 3], default=2, help="Leet speak complexity level (0: Off, 1: Soft, 2: Full)")

    parser.add_argument("--hash", choices=["none", "md5", "sha1", "sha256", "sha512", "ntlm"], default="none", help="Generates cryptographic hashes for passwords")
    parser.add_argument("--hash-format", choices=["plain_hash", "hash_plain", "hash_only"], default="plain_hash", help="Hash output format")
    parser.add_argument("--format", choices=["txt", "json", "csv", "gz"], default="txt", help="Output file format")

    parser.add_argument("--search", "--find", "--check", dest="search_query", help="Keyword(s) to search in file (comma-separated)")
    parser.add_argument("--search-file", help="Path to file containing search terms")
    parser.add_argument("--exact", action="store_true", help="Require exact line match in search")
    parser.add_argument("--case-sensitive", action="store_true", help="Make search case-sensitive")
    parser.add_argument("--hash-check", action="store_true", help="Also check MD5/SHA256/NTLM hashes of search terms")

    parser.add_argument("--policy-ad", action="store_true", help="Enforce Active Directory complexity policy")
    parser.add_argument("--min-upper", type=int, default=0, help="Minimum uppercase characters")
    parser.add_argument("--min-lower", type=int, default=0, help="Minimum lowercase characters")
    parser.add_argument("--min-digits", type=int, default=0, help="Minimum digit characters")
    parser.add_argument("--min-symbols", type=int, default=0, help="Minimum special characters")
    parser.add_argument("--regex", dest="include_regex", help="Include only passwords matching this Regex pattern")

    parser.add_argument("--generate-rules", dest="rule_output", help="Generates targeted Hashcat / JtR rule file (.rule)")
    parser.add_argument("--mask", help="Expands custom mask pattern in Hashcat format (e.g. 'Admin?d?d?s')")
    parser.add_argument("--audit", help="Analyzes specified wordlist file and generates security audit report")
    parser.add_argument("--config", dest="config_path", help="Custom configuration file path (Default: elc_gen.cfg)")

    args = parser.parse_args()

    load_config(args.config_path)

    if args.audit:
        print(BANNER)
        audit_wordlist_file(args.audit)
        return

    if args.search_query or args.search_file:
        print(BANNER)
        target_file = args.input
        if not target_file:
            target_file = input(f"{Colors.BOLD}Path to file for search: {Colors.RESET}").strip()
        
        terms = []
        if args.search_query:
            terms.extend([t.strip() for t in args.search_query.split(',') if t.strip()])
        if args.search_file and os.path.exists(args.search_file):
            with open(args.search_file, 'r', encoding='utf-8', errors='ignore') as f:
                terms.extend([line.strip() for line in f if line.strip()])

        search_in_file(
            file_path=target_file,
            terms=terms,
            case_sensitive=args.case_sensitive,
            exact_match=args.exact,
            check_hashes=args.hash_check
        )
        return

    if args.mask:
        print(BANNER)
        print(f"{Colors.BLUE}[MASK] Expanding mask pattern '{args.mask}'...{Colors.RESET}")
        passwords = expand_mask_pattern(args.mask)
        with open(args.output, 'w', encoding='utf-8') as f:
            for p in passwords:
                f.write(p + "\n")
        print(f"{Colors.GREEN}[✓] Saved {len(passwords):,} passwords to '{args.output}'.{Colors.RESET}")
        return

    if not args.input and not args.wizard and not args.url:
        while True:
            print(BANNER)
            print(f"{Colors.YELLOW}{Colors.BOLD}[*] CYBER SECURITY INTERACTIVE PASSWORD SUITE{Colors.RESET}\n")
            print(f"  {Colors.GREEN}[1] Interactive Target OSINT Profile Wizard{Colors.RESET}")
            print(f"  {Colors.CYAN}[2] Generate Wordlist from .txt File{Colors.RESET}")
            print(f"  {Colors.MAGENTA}[3] Harvest OSINT Keywords from Website (CeWL Mode){Colors.RESET}")
            print(f"  {Colors.YELLOW}[4] Audit a Wordlist / Breach File{Colors.RESET}")
            print(f"  {Colors.BLUE}[5] In-File Search & Breach Lookup{Colors.RESET}")
            print(f"  {Colors.RED}[0] Exit{Colors.RESET}")
            
            choice = input(f"\n{Colors.BOLD}Select Option [0/1/2/3/4/5] (Default: 1): {Colors.RESET}").strip()
            
            if choice == '0':
                print(f"\n{Colors.GREEN}[*] elc-gen terminated. Happy hunting!{Colors.RESET}\n")
                break

            if choice == '4':
                audit_path = input(f"\n{Colors.BOLD}Path to file to audit: {Colors.RESET}").strip()
                while not os.path.exists(audit_path):
                    print(f"{Colors.RED}[!] File not found!{Colors.RESET}")
                    audit_path = input(f"{Colors.BOLD}Enter valid path (or type 'cancel'): {Colors.RESET}").strip()
                    if audit_path.lower() == 'cancel':
                        break
                if os.path.exists(audit_path):
                    audit_wordlist_file(audit_path)
                input(f"\n{Colors.DIM}Press Enter to return to main menu...{Colors.RESET}")
                continue

            if choice == '5':
                file_to_search = input(f"\n{Colors.BOLD}Path to file for search: {Colors.RESET}").strip()
                while not os.path.exists(file_to_search):
                    print(f"{Colors.RED}[!] File not found!{Colors.RESET}")
                    file_to_search = input(f"{Colors.BOLD}Enter valid path (or type 'cancel'): {Colors.RESET}").strip()
                    if file_to_search.lower() == 'cancel':
                        break

                if os.path.exists(file_to_search):
                    query_in = input(f"{Colors.BOLD}Keywords/passwords to search (comma-separated): {Colors.RESET}").strip()
                    terms = [t.strip() for t in query_in.split(',') if t.strip()]

                    exact_in = input(f"{Colors.BOLD}Require exact match? [y/N]: {Colors.RESET}").strip().lower()
                    exact_match = (exact_in == 'y')

                    hash_in = input(f"{Colors.BOLD}Check MD5/SHA256/NTLM hashes of terms? [Y/n]: {Colors.RESET}").strip().lower()
                    check_hashes = (hash_in != 'n')

                    search_in_file(
                        file_path=file_to_search,
                        terms=terms,
                        case_sensitive=False,
                        exact_match=exact_match,
                        check_hashes=check_hashes
                    )
                input(f"\n{Colors.DIM}Press Enter to return to main menu...{Colors.RESET}")
                continue

            words = []
            numbers = []

            if choice == '2':
                input_file = input(f"\n{Colors.BOLD}Path to input .txt file: {Colors.RESET}").strip()
                while not os.path.exists(input_file):
                    print(f"{Colors.RED}[!] File not found!{Colors.RESET}")
                    input_file = input(f"{Colors.BOLD}Enter valid path (or type 'cancel'): {Colors.RESET}").strip()
                    if input_file.lower() == 'cancel':
                        break
                if not os.path.exists(input_file):
                    continue
                words, numbers = clean_input_lines(input_file)

            elif choice == '3':
                url = input(f"\n{Colors.BOLD}Target Website URL: {Colors.RESET}").strip()
                words = crawl_website_keywords(url)
                numbers = IMPORTANT_YEARS + SEQUENTIAL_NUMBERS

            else:
                words, numbers = interactive_target_profiler()

            if not words:
                print(f"{Colors.RED}[!] No word data collected.{Colors.RESET}")
                input(f"\n{Colors.DIM}Press Enter to return to main menu...{Colors.RESET}")
                continue

            output_file = input(f"\n{Colors.BOLD}Output file name (Default: wordlist.txt): {Colors.RESET}").strip()
            if not output_file:
                output_file = "wordlist.txt"

            print(f"\n{Colors.CYAN}{Colors.BOLD}Select Generation Mode:{Colors.RESET}")
            print(f"   {Colors.GREEN}[1] Light / Fast Mode (Light){Colors.RESET} -> ~2,000 - 8,000 passwords")
            print(f"   {Colors.YELLOW}[2] Standard / Balanced Mode (Standard) [Recommended]{Colors.RESET} -> ~15,000 - 60,000 passwords")
            print(f"   {Colors.MAGENTA}[3] Deep / Brute-Force Mode (Deep){Colors.RESET} -> ~100,000+ passwords")
            mode_choice = input(f"{Colors.BOLD}Select [1/2/3] (Default: 2): {Colors.RESET}").strip()
            mode_map = {'1': 'light', '2': 'standard', '3': 'deep'}
            mode = mode_map.get(mode_choice, 'standard')

            hash_choice = input(f"\n{Colors.BOLD}Save in hash format? (none/md5/sha256/ntlm) [none]: {Colors.RESET}").strip().lower()
            hash_algo = hash_choice if hash_choice in ["md5", "sha1", "sha256", "sha512", "ntlm"] else "none"

            rule_choice = input(f"{Colors.BOLD}Generate .rule file for Hashcat / JtR? [y/N]: {Colors.RESET}").strip().lower()
            rule_output = "target.rule" if rule_choice == 'y' else None

            execute_generation(
                words=words,
                numbers=numbers,
                output_file=output_file,
                mode=mode,
                leet_level=2,
                hash_algo=hash_algo,
                rule_output=rule_output
            )

            input(f"\n{Colors.DIM}Press Enter to return to main menu...{Colors.RESET}")

    else:
        print(BANNER)
        words = []
        numbers = []

        if args.wizard:
            w_list, n_list = interactive_target_profiler()
            words.extend(w_list)
            numbers.extend(n_list)

        if args.url:
            scraped = crawl_website_keywords(args.url)
            words.extend(scraped)

        if args.input:
            f_words, f_numbers = clean_input_lines(args.input)
            words.extend(f_words)
            numbers.extend(f_numbers)

        words = list(dict.fromkeys(words))
        numbers = list(dict.fromkeys(numbers))

        leet_lvl = 0 if args.no_leet else args.leet_level

        execute_generation(
            words=words,
            numbers=numbers,
            output_file=args.output,
            min_len=args.min,
            max_len=args.max,
            mode=args.mode,
            leet_level=leet_lvl,
            hash_algo=args.hash,
            hash_format=args.hash_format,
            file_format=args.format,
            min_upper=args.min_upper,
            min_lower=args.min_lower,
            min_digits=args.min_digits,
            min_symbols=args.min_symbols,
            policy_ad=args.policy_ad,
            include_regex=args.include_regex,
            rule_output=args.rule_output
        )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[!] Operation canceled by user (Ctrl+C).{Colors.RESET}\n")
    except Exception as e:
        print(f"\n\n{Colors.RED}[!] Unexpected error occurred: {e}{Colors.RESET}")
        try:
            input(f"\n{Colors.DIM}Press Enter to exit window...{Colors.RESET}")
        except Exception:
            pass
