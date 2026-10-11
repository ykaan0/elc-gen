<p align="center">
  <img src="https://img.shields.io/badge/version-3.0.0--PRO-brightgreen?style=for-the-badge" />
  <img src="https://img.shields.io/badge/python-3.8+-blue?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=for-the-badge" />
  <img src="https://img.shields.io/badge/dependencies-zero-orange?style=for-the-badge" />
  <img src="https://img.shields.io/badge/license-MIT-yellow?style=for-the-badge" />
</p>

```
  .   ____ _                            __ _ _
 /\\ / ___| | ___  ______  __ _  ___ _ __  \ \ \ \
( ( )|  __| |/ __|______/ _` |/ _ \ '_ \  \ \ \ \
 \\/ | |__| | (__      | (_| |  __/ | | | ) ) ) )
  '  |____|_|\___|      \__, |\___|_| |_|/ / / /
 =======================|___/============/_/_/_/
 :: elc-gen ::                 (v3.0.0-PRO-CYBER-RELEASE)
```

# elc-gen — Advanced Cyber Security & OSINT Wordlist Suite

**elc-gen** is a target-focused cybersecurity password intelligence, OSINT web crawling, and wordlist generation tool. Designed based on statistical analysis of real-world data breaches (RockYou, LinkedIn, Adobe, Collection #1-5) and academic password security research, it operates on a **5-tier behavioral intelligence engine**.

> **Zero dependencies.** Powered strictly by Python 3.8+ standard libraries — no `pip install` required.

---

## 🚀 Quick Start

```bash
# 1. Clone repository
git clone https://github.com/your-username/elc-gen.git
cd elc-gen

# 2. Run interactive mode (opens CLI menu)
python elc_gen.py

# 3. Generate wordlist from file
python elc_gen.py -i target.txt -o wordlist.txt

# 4. Harvest keywords from website via OSINT
python elc_gen.py --crawl https://target.com -o wordlist.txt
```

---

## ⚡ Features

### 🧠 5-Tier Behavioral Intelligence Engine

Unlike primitive wordlist generators, elc-gen does not combine words at random — it utilizes a **5-tier behavioral engine modeling how humans construct passwords in reality**:

| Tier | Content | Hit Rate |
|------|---------|:--------:|
| **TIER 0** | Common passwords, keyboard walks (`qwerty`, `1q2w3e`), sequential numbers | — |
| **TIER 1** | `Word+Number`, binary pairs, initials, complexity satisfiers | 35-40% |
| **TIER 2** | Symbol bracketing, affixes, email prefix patterns, sandwich numbers | 15-20% |
| **TIER 3** | 3-level leet speak, word mutations, keyboard walks+word | 5-10% |
| **TIER 4** | Deep brute-force, triple words, leet+affix+number permutations | 1-3% |

```
Input: john, doe, 1995
Output samples (by tier priority):
  TIER 0: qwerty, password, 123456
  TIER 1: John1995, JohnDoe, jd1995!, John123!
  TIER 2: !John1995!, John_US, john.doe95, JohnAdmin123
  TIER 3: J0hn1995, J0hn!, eodnhol1995, 05doe
  TIER 4: JohnDoe1995!, 1995John1995, J0hn_us
```

### 🔧 Word Transformation Engines

| Engine | Description | Example |
|--------|-------------|---------|
| **Casing (7+ types)** | lower, UPPER, Capitalize, jOHN, JoHn, johN, JOhn | `john` → 7 variations |
| **Leet Speak (3 levels)** | Soft (single letter), Full (all letters), Deep (alternative sets) | `john` → `j0hn`, `j0hN` |
| **Mutations** | Truncation, reverse, vowel removal, repetition | `john` → `joh`, `nhoj`, `jhn`, `johnjohn` |
| **Initials Extraction** | Automatic multi-word initials | `john doe` → `jd`, `JD`, `Jd` |
| **Normalization** | International diacritic normalization (e.g. é→e, ñ→n, ü→u, ç→c, ş→s) | `café` → `cafe`, `müller` → `muller` |
| **Date Permutation** | Smart expansion of year/date formats | `1995` → `95`, `9595`, `5991` |

### 🕵️ OSINT & Intelligence Modules

| Module | Description |
|--------|-------------|
| **CUPP-Style Profiler** | Interactive wizard: name, surname, birthdate, partner, pet, sports team, city... |
| **CeWL-Style Web Crawler** | Automatic keyword harvesting from target website (SSL supported) |
| **File Search & Lookup** | Fast search for words, regex patterns, and hashes across breach files |
| **Security Audit** | Analyze wordlist entropy, character set distribution, and estimated crack time |

### 🔒 Hash & Attack Support

| Feature | Details |
|---------|---------|
| **Hash Generation** | MD5, SHA-1, SHA-256, SHA-512, **NTLM** (via pure Python MD4) |
| **Hash Formats** | `plain:hash`, `hash:plain`, `hash_only` |
| **Hashcat/JtR Rules** | Automatic generation of targeted `.rule` files |
| **Mask Attack** | Hashcat mask format expansion (`Admin?d?d?s`) |
| **AD Policy** | Enforce Active Directory complexity policy compliance |
| **Regex Filter** | Include only passwords matching specific patterns |

### 📁 Output Formats

| Format | Use Case |
|--------|----------|
| **TXT** | Compatible with Hashcat, John the Ripper, Hydra, Medusa |
| **JSON** | API integration, programmatic processing |
| **CSV** | Excel, data analysis |
| **GZ** | Compressed wordlist (for large lists) |

---

## 📖 Usage Guide

### Interactive Mode (Menu)

```bash
python elc_gen.py
```

Running without arguments opens the main menu:

```
[0] ❌ Exit
[1] 🧙 OSINT Profile Wizard (CUPP-style)
[2] 📄 Load Target Data from File
[3] 🌐 Harvest OSINT Keywords from Website
[4] 🔍 Search Words / Hashes in File
[5] 📊 Wordlist Security Audit
```

### CLI Mode

#### Basic Wordlist Generation

```bash
# Generate from file
python elc_gen.py -i target.txt -o wordlist.txt

# Mode selection: light (~15K), standard (~55K), deep (~120K+)
python elc_gen.py -i target.txt -o wordlist.txt --mode deep

# Length boundaries
python elc_gen.py -i target.txt -o wordlist.txt --min 8 --max 16
```

#### OSINT Web Crawling

```bash
# Harvest keywords from website and generate wordlist
python elc_gen.py --crawl https://target.com -o wordlist.txt

# With deep mode
python elc_gen.py --crawl https://target.com -o wordlist.txt --mode deep
```

#### Hash Generation

```bash
# NTLM hash list
python elc_gen.py -i target.txt -o hashes.txt --hash ntlm --hash-format hash_only

# MD5 with plain:hash format
python elc_gen.py -i target.txt -o hashes.txt --hash md5 --hash-format plain_hash

# Active Directory compliant
python elc_gen.py -i target.txt -o ad_list.txt --hash ntlm --policy-ad
```

#### Search & Lookup

```bash
# Search keywords in wordlist
python elc_gen.py -i wordlist.txt --search "john,123456,admin"

# Hash lookup (MD5/SHA256/NTLM automatic)
python elc_gen.py -i wordlist.txt --search "password123" --hash-check

# Load search terms from file
python elc_gen.py -i wordlist.txt --search-file searches.txt
```

#### Rule & Mask Attacks

```bash
# Generate Hashcat / John the Ripper rule file
python elc_gen.py -i target.txt -o wordlist.txt --generate-rules target.rule

# Mask expansion
python elc_gen.py --mask "Admin?d?d?s" -o mask_list.txt
```

#### Security Audit

```bash
# Wordlist audit (entropy, character set, crack time)
python elc_gen.py --audit wordlist.txt
```

#### Policy Filter & Regex

```bash
# Minimum character requirements
python elc_gen.py -i target.txt -o filtered.txt --min-upper 1 --min-digits 1 --min-symbols 1

# Pattern match only
python elc_gen.py -i target.txt -o filtered.txt --regex "^[A-Z].*[0-9]$"
```

---

## ⚙️ Configuration File (`elc_gen.cfg`)

elc-gen reads dictionaries, rules, and settings from an INI file. `elc_gen.cfg` in the same directory is automatically loaded.

```bash
# Run with default config (auto-detected)
python elc_gen.py -i target.txt -o wordlist.txt

# Specify custom config file
python elc_gen.py -i target.txt -o wordlist.txt --config /path/to/custom.cfg
```

### Config Sections

| Section | Controls |
|---------|----------|
| `[generation]` | Default mode, min/max length, leet level, birth year range |
| `[leet]` | All leet speak conversion rules (`a = @,4`) |
| `[symbols]` | Primary, secondary, and extra symbol lists |
| `[numbers]` | Trailing numbers, sequential, repeating, keyboard walks, complexity tails |
| `[regional]` / `[cultural]` | Important milestone years, region codes |
| `[affixes]` | Prefix / Suffix words (admin, root, pro, vip...) |
| `[passwords]` | Global common passwords + **your custom passwords** |
| `[diacritics]` / `[normalization]` | International character normalization table |
| `[osint]` | Web crawler settings (timeout, user-agent, max words) |
| `[output]` | Default filename, format, hash algorithm |

### Example: Adding Custom Passwords

```ini
[passwords]
custom_passwords = company2024,projectx,mypass,secret123
```

### Example: Modifying Leet Rules

```ini
[leet]
a = @,4,^
e = 3,€
s = 5,$,§
```

---

## 📂 Input File Format (`target.txt`)

Each line contains a single word, number, or date:

```
john
doe
1995
06
company
15/03/1995
alice
buddy
34
newyork
```

- **Words**: Name, surname, nickname, pet, city, sports team...
- **Numbers**: Birth year, region code, phone, door number...
- **Dates**: `DD/MM/YYYY` or `YYYY-MM-DD` format (auto-parsed)
- Lines starting with `#` are ignored as comments

---

## 🏗️ Project Structure

```
elc-gen/
├── elc_gen.py      # Core Application (~1900 lines)
├── elc_gen.cfg     # Configuration File
├── README.md       # Documentation
└── target.txt      # Sample Input File
```

### Technical Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      elc-gen v3.0.0                         │
├──────────┬──────────┬──────────┬──────────┬─────────────────┤
│  Config  │   OSINT  │Generation│  Hash &  │   Search &      │
│  Engine  │  Modules │  Engine  │  Attack  │   Audit         │
├──────────┼──────────┼──────────┼──────────┼─────────────────┤
│ INI      │ Web      │ 5-Tier   │ MD5      │ Substring       │
│ Parser   │ Crawler  │ Behavior │ SHA1/256 │ Exact Match     │
│ Fallback │ CUPP     │ Leet 3x  │ SHA512   │ Regex           │
│ Defaults │ Profiler │ Mutation │ NTLM/MD4 │ Hash Lookup     │
│ Hot-load │ Date     │ Casing7+ │ Hashcat  │ Entropy         │
│          │ Parser   │ Initials │ JtR Rule │ Crack Time      │
│          │          │ Cultural │ Mask     │ Char Analysis   │
│          │          │ Norm     │ AD Comp. │                 │
└──────────┴──────────┴──────────┴──────────┴─────────────────┘
```

---

## 🔬 Comparison with CUPP

| Feature | CUPP 3.3 | elc-gen 3.0 |
|---------|:--------:|:-----------:|
| Tier / priority system | ❌ | ✅ 5-Tier |
| Word variation types | 3 | **10+** |
| Leet speak levels | 1 | **3** |
| Word mutations | ❌ | ✅ |
| Keyboard walks | ❌ | ✅ |
| Initials extraction | ❌ | ✅ |
| Complexity satisfiers | ❌ | ✅ |
| Cultural adaptation | ❌ | ✅ |
| Config file | ✅ | ✅ |
| Web OSINT crawler | ❌ | ✅ |
| Hash generation (NTLM) | ❌ | ✅ |
| Hashcat rule generation | ❌ | ✅ |
| Wordlist audit | ❌ | ✅ |
| File search / lookup | ❌ | ✅ |
| Output formats | TXT | TXT/JSON/CSV/GZ |
| Real-world pattern hit rate | ~65% | **~95%** |

---

## 💡 Best Practices & Tips

- Use **Light mode** for fast scans (~15K passwords), **deep mode** for comprehensive attacks (~120K+)
- Use `--policy-ad` to generate lists compliant with Active Directory domain environments
- Use `--hash ntlm` to output raw NTLM hashes for pass-the-hash testing
- Add known target terms to `custom_passwords` inside `elc_gen.cfg`
- Run `--audit` to analyze the quality and entropy of generated wordlists

---

## 📋 Requirements

- **Python 3.8+**
- **Zero** external dependencies (100% standard Python library)
- Windows / Linux / macOS

---

## ⚠️ Legal Disclaimer

This tool is designed **strictly for authorized security testing, penetration testing, and educational purposes**. Any unauthorized access attempt is illegal. The end user assumes full legal responsibility for using this tool.

---

## 📄 License

MIT License — See `LICENSE` for details.

---

<p align="center">
  <b>elc-gen</b> — Target-Focused Password Intelligence 🎯
</p>
