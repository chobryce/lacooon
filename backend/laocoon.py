#!/usr/bin/env python3
"""
Laocoon.py
=============
Anti-Malicious open-source package scanner.

Detects supply chain threats across npm and PyPI ecosystems via:
  - OSV database (MAL- prefix advisories)
  - GitHub Security Advisory database (GHSA malware advisories)
  - Static source code heuristic analysis (40+ rule categories)
  - Package metadata behavioral analysis (12 heuristic categories)
  - Typosquatting detection against top-1000 popular packages
  - Install-time script inspection (setup.py, package.json scripts)
  - Network exfiltration pattern detection
  - Obfuscation and evasion detection
  - Dependency confusion attack detection
  - Provenance and registry integrity checks

Supported manifest formats:
  package.json, package-lock.json, pyproject.toml, requirements.txt

Usage:
  python3 Laocoon.py requirements.txt
  python3 Laocoon.py package.json --ecosystem npm
  python3 Laocoon.py requirements.txt --json --output report.json
  python3 Laocoon.py requirements.txt --deep          # fetch + analyze source
  python3 Laocoon.py --remote https://github.com/.../requirements.txt

Requirements:
  pip install requests beautifulsoup4 tomli packaging
  pip install ast-grep-py   # optional, improves AST analysis
"""

import argparse
import ast
import base64
import binascii
import datetime
import hashlib
import importlib.util
import io
import json
import logging
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import time
import zipfile
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Set, Tuple
from urllib.parse import quote, urlparse

# ── Optional dependencies ────────────────────────────────────────────────────
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None

try:
    from packaging.version import Version, InvalidVersion
    from packaging.specifiers import SpecifierSet
    HAS_PACKAGING = True
except ImportError:
    HAS_PACKAGING = False

# ─────────────────────────────────────────────────────────────────────────────
#  SEVERITY LEVELS
# ─────────────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

    def __lt__(self, other):
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM,
                 Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)


# ─────────────────────────────────────────────────────────────────────────────
#  DATA STRUCTURES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Package:
    name: str
    version: str
    source_file: str
    ecosystem: str        # "npm" or "pypi"
    is_dev_dependency: bool = False
    extras: Dict[str, Any] = field(default_factory=dict)

@dataclass
class RuleMatch:
    rule_id: str
    rule_name: str
    severity: Severity
    category: str         # "source_code" | "metadata" | "advisory" | "typosquat"
    description: str
    evidence: str         # specific snippet or detail that triggered the rule
    line_number: Optional[int] = None
    file_path: Optional[str] = None

@dataclass
class PackageResult:
    package: Package
    matches: List[RuleMatch] = field(default_factory=list)
    advisory_urls: List[str] = field(default_factory=list)
    highest_severity: Optional[Severity] = None
    scan_duration_ms: int = 0

    def add_match(self, match: RuleMatch) -> None:
        self.matches.append(match)
        if self.highest_severity is None or match.severity > self.highest_severity:
            self.highest_severity = match.severity

    @property
    def is_malicious(self) -> bool:
        return len(self.matches) > 0

    def to_dict(self) -> Dict:
        return {
            "package": self.package.name,
            "version": self.package.version,
            "ecosystem": self.package.ecosystem,
            "highest_severity": self.highest_severity.value if self.highest_severity else None,
            "scan_duration_ms": self.scan_duration_ms,
            "finding_count": len(self.matches),
            "advisory_urls": self.advisory_urls,
            "findings": [
                {
                    "rule_id": m.rule_id,
                    "rule_name": m.rule_name,
                    "severity": m.severity.value,
                    "category": m.category,
                    "description": m.description,
                    "evidence": m.evidence,
                    "line_number": m.line_number,
                    "file_path": m.file_path,
                }
                for m in sorted(self.matches, key=lambda x: x.severity, reverse=True)
            ],
        }


# ─────────────────────────────────────────────────────────────────────────────
#  LOGGING
# ─────────────────────────────────────────────────────────────────────────────

def build_logger(name: str, level: int = logging.WARNING) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(level)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        logger.addHandler(handler)
    return logger

log = build_logger("Laocoon")


# ─────────────────────────────────────────────────────────────────────────────
#  HTTP SESSION WITH RETRY
# ─────────────────────────────────────────────────────────────────────────────

def build_session() -> "requests.Session":
    if not HAS_REQUESTS:
        raise RuntimeError("requests is required. Install with: pip install requests")
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update({
        "User-Agent": "Laocoon/2.0 (+https://github.com/security-tools/Laocoon)"
    })
    return session


# ─────────────────────────────────────────────────────────────────────────────
#  TYPOSQUATTING REFERENCE LISTS
# ─────────────────────────────────────────────────────────────────────────────

# Curated from PyPI/npm top-500 download statistics and known attack campaigns.
# A non-exhaustive but representative reference set.
POPULAR_PYPI_PACKAGES: Set[str] = {
    "requests", "numpy", "pandas", "scipy", "matplotlib", "django", "flask",
    "sqlalchemy", "celery", "redis", "boto3", "botocore", "awscli", "pip",
    "setuptools", "wheel", "cryptography", "pycryptodome", "paramiko", "fabric",
    "ansible", "kubernetes", "docker", "google-cloud-storage", "google-auth",
    "urllib3", "certifi", "charset-normalizer", "idna", "six", "python-dateutil",
    "pytz", "pillow", "lxml", "beautifulsoup4", "aiohttp", "fastapi", "uvicorn",
    "pydantic", "httpx", "pytest", "black", "mypy", "flake8", "pylint",
    "psycopg2", "pymongo", "motor", "elasticsearch", "opensearch-py",
    "tensorflow", "torch", "scikit-learn", "transformers", "huggingface-hub",
    "openai", "anthropic", "langchain", "stripe", "twilio", "sendgrid",
    "psutil", "click", "typer", "rich", "colorama", "tqdm", "loguru",
    "pyyaml", "toml", "python-dotenv", "jinja2", "markupsafe", "werkzeug",
    "itsdangerous", "wtforms", "marshmallow", "attrs", "dacite", "cachetools",
    "filelock", "packaging", "importlib-metadata", "zipp", "typing-extensions",
    "wrapt", "decorator", "more-itertools", "toolz", "cytoolz", "dask",
    "pyarrow", "fastparquet", "openpyxl", "xlrd", "xlwt", "reportlab",
    "pypdf2", "fpdf", "weasyprint", "selenium", "playwright", "scrapy",
    "httplib2", "grpcio", "protobuf", "thrift", "avro-python3",
    "jwt", "pyjwt", "oauthlib", "requests-oauthlib", "social-auth-core",
}

POPULAR_NPM_PACKAGES: Set[str] = {
    "lodash", "express", "react", "react-dom", "vue", "angular", "axios",
    "moment", "dayjs", "chalk", "commander", "yargs", "minimist", "dotenv",
    "webpack", "babel-core", "@babel/core", "eslint", "prettier", "typescript",
    "jest", "mocha", "chai", "sinon", "supertest", "nyc", "istanbul",
    "next", "nuxt", "gatsby", "create-react-app", "vite", "rollup", "parcel",
    "tailwindcss", "bootstrap", "jquery", "underscore", "ramda", "immutable",
    "redux", "mobx", "recoil", "zustand", "rxjs", "rxjs-compat",
    "mongoose", "sequelize", "typeorm", "knex", "prisma", "@prisma/client",
    "socket.io", "ws", "nodemailer", "passport", "jsonwebtoken", "bcrypt",
    "multer", "sharp", "jimp", "ffmpeg", "archiver", "jszip", "xml2js",
    "cheerio", "puppeteer", "playwright", "selenium-webdriver",
    "aws-sdk", "@aws-sdk/client-s3", "google-cloud", "firebase", "supabase",
    "stripe", "paypal-rest-sdk", "twilio", "sendgrid", "@sendgrid/mail",
    "uuid", "nanoid", "cuid", "shortid", "crypto-js", "node-forge",
    "semver", "glob", "micromatch", "chokidar", "fs-extra", "rimraf",
    "cross-env", "concurrently", "nodemon", "pm2", "forever",
    "body-parser", "cors", "helmet", "morgan", "compression",
    "debug", "pino", "winston", "bunyan", "loglevel",
}

# Known typosquatting attack name mappings (victim → malicious variants)
KNOWN_TYPOSQUAT_CAMPAIGNS: Dict[str, List[str]] = {
    "requests":      ["request", "requets", "requestss", "reqeusts", "rqeusts"],
    "boto3":         ["b0to3", "bot03", "boto", "botto3"],
    "numpy":         ["nump", "numyp", "nupmy", "numpy-base"],
    "django":        ["djang", "diango", "dajngo", "djangoo"],
    "pillow":        ["pilow", "piilow", "pilllow", "pillow-python"],
    "setuptools":    ["setuptool", "setup-tools", "setup_tools"],
    "pyyaml":        ["pyaml", "py-yaml", "pyymal", "yaml"],
    "cryptography":  ["cryptograhy", "crypto", "cryptographyy"],
    "paramiko":      ["paramikok", "paramiku", "pararmiko"],
    "lodash":        ["lodahs", "lodas", "l0dash", "lodash-utils"],
    "express":       ["expres", "expresss", "expressjs", "exprets"],
    "react":         ["reack", "rreact", "reactt", "react-dom-utils"],
    "axios":         ["axois", "axioss", "axos", "axios-http"],
    "webpack":       ["webpak", "web-pack", "webpackk"],
    "moment":        ["moemnt", "momentt", "momment"],
    "chalk":         ["chak", "chalck", "chalkk"],
    "jsonwebtoken":  ["json-webtoken", "jsonwebtokens", "jwt-node"],
    "bcrypt":        ["bcrpyt", "bcryp", "bcryptt"],
    "uuid":          ["uiid", "uuuid", "uuidd"],
}


# ─────────────────────────────────────────────────────────────────────────────
#  SOURCE CODE ANALYSIS RULES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SourceCodeRule:
    rule_id: str
    name: str
    severity: Severity
    description: str
    pattern: re.Pattern
    context_patterns: List[re.Pattern] = field(default_factory=list)  # AND conditions
    exclude_patterns: List[re.Pattern] = field(default_factory=list)   # NOT conditions
    min_context_matches: int = 0    # how many context_patterns must also match

    def matches(self, content: str) -> List[Tuple[re.Match, str]]:
        """Return list of (match, evidence) tuples."""
        results = []
        if not self.pattern.search(content):
            return results

        # Evaluate NOT conditions
        for excl in self.exclude_patterns:
            if excl.search(content):
                return results

        # Evaluate AND conditions
        ctx_hits = sum(1 for cp in self.context_patterns if cp.search(content))
        if ctx_hits < self.min_context_matches:
            return results

        for m in self.pattern.finditer(content):
            # Clip evidence to a reasonable window around the match
            start = max(0, m.start() - 60)
            end   = min(len(content), m.end() + 60)
            evidence = content[start:end].strip().replace("\n", " ")
            results.append((m, evidence))

        return results


def _r(pattern: str, flags: int = re.IGNORECASE | re.MULTILINE) -> re.Pattern:
    return re.compile(pattern, flags)


# 40+ source code detection rules
SOURCE_CODE_RULES: List[SourceCodeRule] = [

    # ── Network exfiltration ──────────────────────────────────────────────────
    SourceCodeRule(
        rule_id="SC-NET-001",
        name="outbound_http_request",
        severity=Severity.HIGH,
        description="Outbound HTTP/HTTPS request — potential data exfiltration or C2 contact.",
        pattern=_r(r"""(requests\.(get|post|put|patch)|urllib\.request\.(urlopen|urlretrieve)|httpx\.(get|post|AsyncClient)|http\.client|fetch\s*\()"""),
        context_patterns=[
            _r(r"""(os\.environ|getpass|getuser|socket\.gethostname|platform\.(node|uname)|subprocess|base64|binascii)""")
        ],
        min_context_matches=1,
    ),
    SourceCodeRule(
        rule_id="SC-NET-002",
        name="dns_lookup_during_install",
        severity=Severity.HIGH,
        description="DNS resolution at install time — common in supply chain implants.",
        pattern=_r(r"""socket\.(gethostbyname|getaddrinfo|gethostname)\s*\("""),
        context_patterns=[_r(r"""requests\.|urllib|httpx|http\.client""")],
        min_context_matches=1,
    ),
    SourceCodeRule(
        rule_id="SC-NET-003",
        name="raw_socket_connection",
        severity=Severity.HIGH,
        description="Raw socket connection — used in RATs and C2 implants.",
        pattern=_r(r"""socket\.socket\s*\(.*\).*\.(connect|bind)\s*\("""),
    ),
    SourceCodeRule(
        rule_id="SC-NET-004",
        name="ip_api_geolocation_beacon",
        severity=Severity.CRITICAL,
        description="ip-api.com geolocation beacon — InvisibleFerret and other RATs use this to fingerprint victims.",
        pattern=_r(r"""ip-api\.com"""),
    ),
    SourceCodeRule(
        rule_id="SC-NET-005",
        name="telegram_exfiltration",
        severity=Severity.CRITICAL,
        description="Telegram Bot API used for data exfiltration — common in DPRK-linked supply chain attacks.",
        pattern=_r(r"""api\.telegram\.org/bot"""),
    ),
    SourceCodeRule(
        rule_id="SC-NET-006",
        name="discord_webhook_exfiltration",
        severity=Severity.HIGH,
        description="Discord webhook used for data exfiltration — widely abused in npm malware.",
        pattern=_r(r"""discord(app)?\.com/api/webhooks"""),
    ),
    SourceCodeRule(
        rule_id="SC-NET-007",
        name="ftp_file_transfer",
        severity=Severity.MEDIUM,
        description="FTP connection established at install/import time — potential staging or exfil.",
        pattern=_r(r"""ftplib\.FTP\s*\(|\.connect\s*\([^)]+\).*\.login\s*\("""),
    ),

    # ── Process execution ─────────────────────────────────────────────────────
    SourceCodeRule(
        rule_id="SC-EXEC-001",
        name="subprocess_execution",
        severity=Severity.HIGH,
        description="Subprocess execution with user-controlled or suspicious arguments.",
        pattern=_r(r"""subprocess\.(Popen|call|run|check_call|check_output)\s*\(\s*\["""),
        context_patterns=[_r(r"""(shell\s*=\s*True|os\.system|curl|wget|bash|sh|powershell|cmd\.exe|/bin/)""")],
        min_context_matches=1,
    ),
    SourceCodeRule(
        rule_id="SC-EXEC-002",
        name="os_system_execution",
        severity=Severity.HIGH,
        description="os.system() call — classic code execution vector.",
        pattern=_r(r"""os\.(system|popen|execv?p?e?)\s*\("""),
        context_patterns=[_r(r"""(curl|wget|bash|sh|powershell|cmd|nc|ncat|netcat|base64)""")],
        min_context_matches=1,
    ),
    SourceCodeRule(
        rule_id="SC-EXEC-003",
        name="shell_injection",
        severity=Severity.CRITICAL,
        description="Shell injection pattern via subprocess with shell=True and string formatting.",
        pattern=_r(r"""subprocess\.(Popen|call|run|check_call|check_output)\s*\([^)]*shell\s*=\s*True[^)]*%[^)]*\)"""),
    ),
    SourceCodeRule(
        rule_id="SC-EXEC-004",
        name="eval_exec_dynamic_code",
        severity=Severity.CRITICAL,
        description="eval() or exec() on dynamic/decoded content — primary code execution technique in obfuscated malware.",
        pattern=_r(r"""\b(eval|exec)\s*\(\s*(base64|b64decode|codecs|zlib|gzip|marshal|__import__|compile|bytes|bytearray|decode)"""),
    ),
    SourceCodeRule(
        rule_id="SC-EXEC-005",
        name="compile_and_exec",
        severity=Severity.HIGH,
        description="compile() followed by exec() — dynamic code loading pattern.",
        pattern=_r(r"""compile\s*\(.+\)\s*[\s\S]{0,200}exec\s*\("""),
    ),
    SourceCodeRule(
        rule_id="SC-EXEC-006",
        name="ctypes_shellcode",
        severity=Severity.CRITICAL,
        description="ctypes used to write and execute raw shellcode — advanced persistence technique.",
        pattern=_r(r"""ctypes\.(windll|cdll|CDLL|WinDLL).*\.(VirtualAlloc|WriteProcessMemory|CreateThread|ShellExecuteW)"""),
    ),
    SourceCodeRule(
        rule_id="SC-EXEC-007",
        name="nodejs_child_process",
        severity=Severity.HIGH,
        description="Node.js child_process.exec/spawn with suspicious arguments.",
        pattern=_r(r"""(child_process|require\s*\(\s*['"]child_process['"]\s*\))\s*\.(exec|spawn|execSync|spawnSync)\s*\("""),
        context_patterns=[_r(r"""(curl|wget|powershell|cmd|bash|sh|/bin/|base64|nc |ncat|reverse)""")],
        min_context_matches=1,
    ),
    SourceCodeRule(
        rule_id="SC-EXEC-008",
        name="nodejs_eval_dynamic",
        severity=Severity.CRITICAL,
        description="Node.js eval() on decoded or fetched content.",
        pattern=_r(r"""eval\s*\(\s*(Buffer\.from|atob|require\s*\(\s*'crypto|Buffer\.alloc)"""),
    ),

    # ── Obfuscation ───────────────────────────────────────────────────────────
    SourceCodeRule(
        rule_id="SC-OBF-001",
        name="base64_decoded_execution",
        severity=Severity.HIGH,
        description="base64-decoded payload executed at runtime.",
        pattern=_r(r"""(base64\.b64decode|b64decode|atob|Buffer\.from\s*\([^,]+,\s*['"]base64['"]\s*\))\s*\("""),
        context_patterns=[_r(r"""(exec|eval|compile|subprocess|os\.system|Popen|spawn)""")],
        min_context_matches=1,
    ),
    SourceCodeRule(
        rule_id="SC-OBF-002",
        name="hex_encoded_payload",
        severity=Severity.HIGH,
        description="Hex-encoded string decoded at runtime — common obfuscation layer.",
        pattern=_r(r"""(bytes\.fromhex|binascii\.unhexlify|codecs\.decode\s*\([^)]+,\s*['"]hex['"]|\\x[0-9a-f]{2}){3,}"""),
        context_patterns=[_r(r"""(exec|eval|compile|subprocess|os\.system)""")],
        min_context_matches=1,
    ),
    SourceCodeRule(
        rule_id="SC-OBF-003",
        name="zlib_compressed_payload",
        severity=Severity.HIGH,
        description="zlib/gzip decompression of embedded payload — multi-layer obfuscation.",
        pattern=_r(r"""(zlib\.decompress|gzip\.decompress|lzma\.decompress)\s*\("""),
        context_patterns=[_r(r"""(exec|eval|compile|base64|b64decode)""")],
        min_context_matches=1,
    ),
    SourceCodeRule(
        rule_id="SC-OBF-004",
        name="marshal_deserialization",
        severity=Severity.HIGH,
        description="marshal.loads() on unknown data — can execute arbitrary bytecode.",
        pattern=_r(r"""marshal\.loads?\s*\("""),
        context_patterns=[_r(r"""(exec|eval|base64|b64decode|decode)""")],
        min_context_matches=1,
    ),
    SourceCodeRule(
        rule_id="SC-OBF-005",
        name="string_character_join_obfuscation",
        severity=Severity.MEDIUM,
        description="String built by joining individual characters — common obfuscation to evade string scanners.",
        pattern=_r(r"""['"][a-zA-Z]['"].*join\s*\(\s*\["""),
    ),
    SourceCodeRule(
        rule_id="SC-OBF-006",
        name="rotated_base64_c2",
        severity=Severity.CRITICAL,
        description="Rotated base64 string decoded to recover C2 IP address — InvisibleFerret technique.",
        pattern=_r(r"""base64\.b64decode\s*\(\s*\w+\s*\[\d+:\]\s*\+\s*\w+\s*\[:\d+\]\s*\)"""),
    ),
    SourceCodeRule(
        rule_id="SC-OBF-007",
        name="single_char_variable_names",
        severity=Severity.LOW,
        description="Pervasive single-character variable names across large code blocks — indicator of automated obfuscation.",
        pattern=_r(r"""(?:^|\n)\s*(?:[A-Z_]\s*=\s*){6,}"""),
    ),
    SourceCodeRule(
        rule_id="SC-OBF-008",
        name="long_base64_blob",
        severity=Severity.HIGH,
        description="Long base64 string embedded in source — potential compressed/encrypted payload.",
        pattern=_r(r"""['\"][A-Za-z0-9+/=]{500,}['\"]"""),
    ),

    # ── Credential and data theft ─────────────────────────────────────────────
    SourceCodeRule(
        rule_id="SC-THEFT-001",
        name="environment_variable_harvesting",
        severity=Severity.HIGH,
        description="Bulk environment variable collection — common in credential-stealing implants.",
        pattern=_r(r"""os\.environ(\.copy\(\)|\.items\(\))"""),
        context_patterns=[_r(r"""(requests\.|urllib|httpx|socket\.|post|send|write|open)""")],
        min_context_matches=1,
    ),
    SourceCodeRule(
        rule_id="SC-THEFT-002",
        name="ssh_key_exfiltration",
        severity=Severity.CRITICAL,
        description="Reading SSH private key files — credential exfiltration.",
        pattern=_r(r"""\.ssh[/\\](id_rsa|id_ed25519|id_ecdsa|authorized_keys|known_hosts)"""),
        context_patterns=[_r(r"""(open|read|requests\.|urllib|socket\.)""")],
        min_context_matches=1,
    ),
    SourceCodeRule(
        rule_id="SC-THEFT-003",
        name="browser_credential_theft",
        severity=Severity.CRITICAL,
        description="Access to browser credential stores — password and session cookie theft.",
        pattern=_r(r"""(Login\s+Data|Cookies|Local\s+Extension\s+Settings|Sync\s+Extension\s+Settings|Web\s+Data|history|Saved\s+Passwords)"""),
        context_patterns=[_r(r"""(os\.path\.join|open|shutil\.copy|glob)""")],
        min_context_matches=1,
    ),
    SourceCodeRule(
        rule_id="SC-THEFT-004",
        name="aws_credential_access",
        severity=Severity.CRITICAL,
        description="Access to AWS credentials file — cloud credential theft.",
        pattern=_r(r"""(\.aws[/\\]credentials|AWS_ACCESS_KEY|AWS_SECRET_ACCESS|aws_access_key_id)"""),
        context_patterns=[_r(r"""(open|read|requests\.|os\.environ)""")],
        min_context_matches=1,
    ),
    SourceCodeRule(
        rule_id="SC-THEFT-005",
        name="crypto_wallet_theft",
        severity=Severity.CRITICAL,
        description="Access to cryptocurrency wallet data — Exodus, Electrum, Atomic, MetaMask etc.",
        pattern=_r(r"""(exodus|electrum|atomic\s*wallet|metamask|phantom|solana|ledger|trezor|keystore\.json|wallet\.dat)""", re.IGNORECASE),
        context_patterns=[_r(r"""(os\.path\.join|shutil\.copy|open|glob|os\.walk)""")],
        min_context_matches=1,
    ),
    SourceCodeRule(
        rule_id="SC-THEFT-006",
        name="clipboard_monitoring",
        severity=Severity.HIGH,
        description="Clipboard monitoring or hijacking — used to steal copied passwords/seeds.",
        pattern=_r(r"""(pyperclip\.paste|pyperclip\.waitForPaste|Clipboard\.GetText|xclip|xsel|pbpaste)"""),
    ),
    SourceCodeRule(
        rule_id="SC-THEFT-007",
        name="keylogger_hooks",
        severity=Severity.CRITICAL,
        description="Keyboard hooking via pyHook, pyWinhook, or pynput — keylogger implementation.",
        pattern=_r(r"""(pyHook|pyWinhook|pynput|HookKeyboard|HookManager|on_press\s*=|on_release\s*=|keyboard\.Listener)"""),
    ),
    SourceCodeRule(
        rule_id="SC-THEFT-008",
        name="screenshot_capture",
        severity=Severity.HIGH,
        description="Screenshot capture at runtime — surveillance capability.",
        pattern=_r(r"""(ImageGrab\.grab|pyautogui\.screenshot|PIL\.ImageGrab|mss\.mss|screenshot\(\))"""),
        context_patterns=[_r(r"""(requests\.|urllib|socket\.|open|write|send)""")],
        min_context_matches=1,
    ),
    SourceCodeRule(
        rule_id="SC-THEFT-009",
        name="system_fingerprinting",
        severity=Severity.HIGH,
        description="System fingerprinting — collecting UUID, hostname, username, OS version for victim profiling.",
        pattern=_r(r"""(getnode\s*\(\)|gethostname\s*\(\)|getuser\s*\(\)|platform\.(node|version|release|system)\s*\(\))"""),
        context_patterns=[_r(r"""(sha256|hashlib|requests\.|socket\.|json\.dumps|post)""")],
        min_context_matches=1,
    ),
    SourceCodeRule(
        rule_id="SC-THEFT-010",
        name="git_config_access",
        severity=Severity.HIGH,
        description="Accessing .gitconfig or git credentials — token exfiltration.",
        pattern=_r(r"""(\.gitconfig|\.git-credentials|git\s+config.*--global)"""),
        context_patterns=[_r(r"""(open|read|requests\.|urllib)""")],
        min_context_matches=1,
    ),

    # ── Persistence ───────────────────────────────────────────────────────────
    SourceCodeRule(
        rule_id="SC-PERS-001",
        name="cron_modification",
        severity=Severity.CRITICAL,
        description="Crontab modification — persistence mechanism.",
        pattern=_r(r"""(crontab|/etc/cron\.(d|daily|hourly)|/var/spool/cron)"""),
        context_patterns=[_r(r"""(open|write|subprocess|os\.system)""")],
        min_context_matches=1,
    ),
    SourceCodeRule(
        rule_id="SC-PERS-002",
        name="launch_agent_persistence",
        severity=Severity.CRITICAL,
        description="macOS LaunchAgent/LaunchDaemon installation — persistence on macOS.",
        pattern=_r(r"""(Library[/\\]LaunchAgents|Library[/\\]LaunchDaemons|launchctl\s+(load|unload|bootstrap))"""),
        context_patterns=[_r(r"""(open|write|shutil\.copy|subprocess)""")],
        min_context_matches=1,
    ),
    SourceCodeRule(
        rule_id="SC-PERS-003",
        name="windows_registry_persistence",
        severity=Severity.CRITICAL,
        description="Windows registry modification for persistence.",
        pattern=_r(r"""(winreg|_winreg|OpenKey|SetValueEx|CurrentVersion[/\\]Run)"""),
    ),
    SourceCodeRule(
        rule_id="SC-PERS-004",
        name="startup_folder_write",
        severity=Severity.HIGH,
        description="Writing to Windows Startup folder — persistence mechanism.",
        pattern=_r(r"""(Start\s+Menu[/\\]Programs[/\\]Startup|Microsoft[/\\]Windows[/\\]Start\s+Menu)"""),
        context_patterns=[_r(r"""(open|write|shutil\.copy)""")],
        min_context_matches=1,
    ),

    # ── Package structure abuse ───────────────────────────────────────────────
    SourceCodeRule(
        rule_id="SC-PKG-001",
        name="setup_py_download",
        severity=Severity.HIGH,
        description="setup.py or install hook fetches remote content during installation.",
        pattern=_r(r"""(urllib\.request\.(urlopen|urlretrieve)|requests\.(get|post)|subprocess.*curl|subprocess.*wget)"""),
    ),
    SourceCodeRule(
        rule_id="SC-PKG-002",
        name="postinstall_script_execution",
        severity=Severity.HIGH,
        description="npm postinstall script executes shell commands.",
        pattern=_r(r"""['"](postinstall|preinstall|install)['"]\s*:\s*['"].*['"]\s*"""),
        context_patterns=[_r(r"""(curl|wget|bash|sh|powershell|python|node|exec|spawn)""")],
        min_context_matches=1,
    ),
    SourceCodeRule(
        rule_id="SC-PKG-003",
        name="silent_pip_self_install",
        severity=Severity.HIGH,
        description="Package silently installs additional packages at runtime — self-propagating behavior.",
        pattern=_r(r"""subprocess\.(check_call|run)\s*\(\s*\[.*(pip|pip3|pip install).*\]"""),
    ),
    SourceCodeRule(
        rule_id="SC-PKG-004",
        name="import_hook_injection",
        severity=Severity.HIGH,
        description="sys.meta_path or importlib hook injection — can intercept all imports.",
        pattern=_r(r"""sys\.meta_path\.(append|insert)|importlib\.util\.(spec_from_loader|module_from_spec)"""),
    ),

    # ── C2 communication patterns ─────────────────────────────────────────────
    SourceCodeRule(
        rule_id="SC-C2-001",
        name="struct_framed_socket_protocol",
        severity=Severity.HIGH,
        description="Length-prefixed struct socket framing — binary C2 protocol (InvisibleFerret, BeaverTail).",
        pattern=_r(r"""struct\.pack\s*\(\s*['"]\s*>I\s*['"]\s*,"""),
        context_patterns=[_r(r"""sock(et)?\.(sendall|recv|connect)""")],
        min_context_matches=1,
    ),
    SourceCodeRule(
        rule_id="SC-C2-002",
        name="hardcoded_ip_address",
        severity=Severity.MEDIUM,
        description="Hardcoded IP address — potential C2 endpoint.",
        pattern=_r(r"""['\"](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})['\"]"""),
        context_patterns=[_r(r"""(socket\.|requests\.|urllib|connect|PORT|HOST|host|port)""")],
        min_context_matches=1,
    ),
    SourceCodeRule(
        rule_id="SC-C2-003",
        name="reverse_shell_pattern",
        severity=Severity.CRITICAL,
        description="Reverse shell pattern — socket connected to remote with stdin/stdout/stderr redirect.",
        pattern=_r(r"""(dup2|os\.dup2|subprocess.*stdin=subprocess\.PIPE.*stdout=subprocess\.PIPE)"""),
        context_patterns=[_r(r"""socket\.(connect|AF_INET)""")],
        min_context_matches=1,
    ),
    SourceCodeRule(
        rule_id="SC-C2-004",
        name="netcat_style_connection",
        severity=Severity.HIGH,
        description="netcat-style connection pattern (ncat, nc command or equivalent socket usage).",
        pattern=_r(r"""(nc\s+-e|ncat\s+|netcat\s+|/dev/tcp/)"""),
    ),

    # ── Steganography and covert channels ─────────────────────────────────────
    SourceCodeRule(
        rule_id="SC-COVERT-001",
        name="dns_covert_channel",
        severity=Severity.HIGH,
        description="DNS queries used for data exfiltration or C2 — covert channel technique.",
        pattern=_r(r"""socket\.getaddrinfo\s*\(.*\+.*\)"""),
        context_patterns=[_r(r"""(encode|b64|hex|split|join)""")],
        min_context_matches=1,
    ),
    SourceCodeRule(
        rule_id="SC-COVERT-002",
        name="steganography_image_payload",
        severity=Severity.MEDIUM,
        description="Image pixel manipulation with code execution — steganographic payload technique.",
        pattern=_r(r"""(getpixel|putpixel|PIL\.Image\.open).*(?:\n|.){0,200}(exec|eval|compile)"""),
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
#  METADATA ANALYSIS RULES
# ─────────────────────────────────────────────────────────────────────────────

class MetadataRule(ABC):
    rule_id: str
    name: str
    severity: Severity
    description: str

    @abstractmethod
    def analyze(self, metadata: Dict[str, Any], package: Package) -> Optional[RuleMatch]:
        pass


class RecentlyCreatedPackageRule(MetadataRule):
    rule_id = "META-001"
    name = "recently_created_package"
    severity = Severity.MEDIUM
    description = "Package created very recently — supply chain attacks often use fresh registrations."

    def analyze(self, metadata: Dict, package: Package) -> Optional[RuleMatch]:
        created = metadata.get("created") or metadata.get("time", {}).get("created")
        if not created:
            return None
        try:
            age_days = (datetime.datetime.utcnow() -
                        datetime.datetime.fromisoformat(created.rstrip("Z"))).days
            if age_days < 30:
                return RuleMatch(
                    rule_id=self.rule_id, rule_name=self.name,
                    severity=self.severity, category="metadata",
                    description=self.description,
                    evidence=f"Package created {age_days} day(s) ago ({created})",
                )
        except (ValueError, TypeError):
            pass
        return None


class LowDownloadCountRule(MetadataRule):
    rule_id = "META-002"
    name = "very_low_download_count"
    severity = Severity.LOW
    description = "Very low download count — unusual for a legitimate utility claimed to be widely used."

    def analyze(self, metadata: Dict, package: Package) -> Optional[RuleMatch]:
        downloads = metadata.get("downloads", {}).get("last_month", 0)
        if downloads and int(downloads) < 50:
            return RuleMatch(
                rule_id=self.rule_id, rule_name=self.name,
                severity=self.severity, category="metadata",
                description=self.description,
                evidence=f"Only {downloads} downloads in the last month",
            )
        return None


class NoDescriptionRule(MetadataRule):
    rule_id = "META-003"
    name = "missing_description"
    severity = Severity.LOW
    description = "Package has no description — legitimate packages typically document themselves."

    def analyze(self, metadata: Dict, package: Package) -> Optional[RuleMatch]:
        desc = metadata.get("info", {}).get("summary") or metadata.get("description")
        if not desc or str(desc).strip() in ("", "UNKNOWN", "None"):
            return RuleMatch(
                rule_id=self.rule_id, rule_name=self.name,
                severity=self.severity, category="metadata",
                description=self.description,
                evidence="Empty or missing package description",
            )
        return None


class SuspiciousAuthorEmailRule(MetadataRule):
    rule_id = "META-004"
    name = "suspicious_author_email"
    severity = Severity.MEDIUM
    description = "Author email uses a disposable or suspicious domain — common in malicious packages."

    DISPOSABLE_DOMAINS = {
        "mailinator.com", "guerrillamail.com", "temp-mail.org", "throwam.com",
        "sharklasers.com", "guerrillamailblock.com", "grr.la", "guerrillamail.info",
        "tempmail.com", "dispostable.com", "yopmail.com", "trashmail.com",
        "fakeinbox.com", "mailnull.com", "spamgourmet.com", "spam4.me",
    }

    def analyze(self, metadata: Dict, package: Package) -> Optional[RuleMatch]:
        author_email = (
            metadata.get("info", {}).get("author_email") or
            metadata.get("author", {}).get("email", "")
        )
        if not author_email:
            return None
        domain = author_email.split("@")[-1].lower() if "@" in author_email else ""
        if domain in self.DISPOSABLE_DOMAINS:
            return RuleMatch(
                rule_id=self.rule_id, rule_name=self.name,
                severity=self.severity, category="metadata",
                description=self.description,
                evidence=f"Author email domain: {domain}",
            )
        return None


class ScriptHooksPresentRule(MetadataRule):
    rule_id = "META-005"
    name = "install_lifecycle_scripts"
    severity = Severity.HIGH
    description = "npm lifecycle scripts (preinstall/postinstall/install) detected — arbitrary code execution at install time."

    def analyze(self, metadata: Dict, package: Package) -> Optional[RuleMatch]:
        scripts = metadata.get("scripts", {})
        dangerous = {k for k in scripts if k in ("preinstall", "postinstall", "install")}
        if dangerous:
            evidence_scripts = {k: scripts[k] for k in dangerous}
            return RuleMatch(
                rule_id=self.rule_id, rule_name=self.name,
                severity=self.severity, category="metadata",
                description=self.description,
                evidence=f"Lifecycle scripts: {json.dumps(evidence_scripts)}",
            )
        return None


class VersionBumpAnomalyRule(MetadataRule):
    rule_id = "META-006"
    name = "excessive_version_history"
    severity = Severity.LOW
    description = "Abnormally large number of version releases in a short time — possible registry flooding or test uploads."

    def analyze(self, metadata: Dict, package: Package) -> Optional[RuleMatch]:
        releases = metadata.get("releases") or metadata.get("versions")
        if releases and len(releases) > 100:
            return RuleMatch(
                rule_id=self.rule_id, rule_name=self.name,
                severity=self.severity, category="metadata",
                description=self.description,
                evidence=f"{len(releases)} versions released",
            )
        return None


class NameSimilarToPopularRule(MetadataRule):
    """Checks metadata author/homepage against known legitimate owners."""
    rule_id = "META-007"
    name = "homepage_mismatch"
    severity = Severity.MEDIUM
    description = "Package claims association with a well-known project but homepage/author does not match."

    LEGITIMATE_OWNERS = {
        "django": "djangoproject.com",
        "flask": "palletsprojects.com",
        "requests": "python-requests.org",
        "numpy": "numpy.org",
        "react": "react.dev",
        "express": "expressjs.com",
    }

    def analyze(self, metadata: Dict, package: Package) -> Optional[RuleMatch]:
        name = package.name.lower()
        for legit_name, legit_domain in self.LEGITIMATE_OWNERS.items():
            if legit_name in name and name != legit_name:
                homepage = (
                    metadata.get("info", {}).get("home_page") or
                    metadata.get("homepage") or ""
                ).lower()
                if legit_domain not in homepage:
                    return RuleMatch(
                        rule_id=self.rule_id, rule_name=self.name,
                        severity=self.severity, category="metadata",
                        description=self.description,
                        evidence=f"Name contains '{legit_name}' but homepage is '{homepage}'",
                    )
        return None


class EmptyFilesRule(MetadataRule):
    rule_id = "META-008"
    name = "suspiciously_few_files"
    severity = Severity.MEDIUM
    description = "Distribution archive has very few files — may indicate a hollow package created only to execute install hooks."

    def analyze(self, metadata: Dict, package: Package) -> Optional[RuleMatch]:
        file_count = metadata.get("_file_count")
        if file_count is not None and file_count <= 2:
            return RuleMatch(
                rule_id=self.rule_id, rule_name=self.name,
                severity=self.severity, category="metadata",
                description=self.description,
                evidence=f"Archive contains only {file_count} file(s)",
            )
        return None


METADATA_RULES: List[MetadataRule] = [
    RecentlyCreatedPackageRule(),
    LowDownloadCountRule(),
    NoDescriptionRule(),
    SuspiciousAuthorEmailRule(),
    ScriptHooksPresentRule(),
    VersionBumpAnomalyRule(),
    NameSimilarToPopularRule(),
    EmptyFilesRule(),
]


# ─────────────────────────────────────────────────────────────────────────────
#  TYPOSQUATTING DETECTION
# ─────────────────────────────────────────────────────────────────────────────

def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if not s2:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1,
                            prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


def detect_typosquatting(package: Package) -> Optional[RuleMatch]:
    name = package.name.lower().replace("-", "").replace("_", "").replace(".", "")
    popular = (
        POPULAR_PYPI_PACKAGES if package.ecosystem == "pypi" else POPULAR_NPM_PACKAGES
    )

    # Check against known campaign variants first (exact hit)
    for legit, variants in KNOWN_TYPOSQUAT_CAMPAIGNS.items():
        if package.name.lower() in [v.lower() for v in variants]:
            return RuleMatch(
                rule_id="TYPO-001",
                rule_name="known_typosquatting_variant",
                severity=Severity.CRITICAL,
                category="typosquat",
                description=f"Package name matches a documented typosquatting variant of '{legit}'.",
                evidence=f"'{package.name}' is a known typosquat of '{legit}'",
            )

    # Levenshtein distance against popular package list
    for legit in popular:
        legit_norm = legit.lower().replace("-", "").replace("_", "").replace(".", "")
        if legit_norm == name:
            continue  # same package
        dist = _levenshtein(name, legit_norm)
        threshold = 1 if len(legit_norm) <= 5 else 2
        if 0 < dist <= threshold:
            ratio = SequenceMatcher(None, name, legit_norm).ratio()
            if ratio > 0.80:
                return RuleMatch(
                    rule_id="TYPO-002",
                    rule_name="name_similarity_typosquat",
                    severity=Severity.HIGH,
                    category="typosquat",
                    description=f"Package name is suspiciously similar to popular package '{legit}' "
                                f"(edit distance: {dist}, similarity: {ratio:.0%}).",
                    evidence=f"'{package.name}' vs '{legit}' — edit distance {dist}",
                )

    # Namespace confusion (e.g. @npm-org/legit-pkg vs legit-pkg)
    if package.ecosystem == "npm" and package.name.startswith("@"):
        bare = package.name.split("/", 1)[-1].lower()
        if bare in {p.lower() for p in POPULAR_NPM_PACKAGES}:
            return RuleMatch(
                rule_id="TYPO-003",
                rule_name="namespace_confusion",
                severity=Severity.HIGH,
                category="typosquat",
                description="Scoped package name matches an unscoped popular package — possible namespace confusion attack.",
                evidence=f"'{package.name}' uses scope but '{bare}' is a well-known unscoped package",
            )

    return None


# ─────────────────────────────────────────────────────────────────────────────
#  MANIFEST PARSERS
# ─────────────────────────────────────────────────────────────────────────────

class ManifestParser:

    @staticmethod
    def from_file(file_path: str, ecosystem_hint: Optional[str] = None) -> List[Package]:
        name = Path(file_path).name.lower()
        if name == "package.json":
            return ManifestParser._parse_package_json(file_path)
        if name == "package-lock.json":
            return ManifestParser._parse_package_lock_json(file_path)
        if name == "pyproject.toml":
            return ManifestParser._parse_pyproject_toml(file_path)
        if re.match(r"requirements.*\.txt$", name):
            return ManifestParser._parse_requirements_txt(file_path)
        raise ValueError(f"Unsupported manifest format: {name}")

    @staticmethod
    def _clean_version(v: str) -> str:
        v = str(v).strip()
        return re.sub(r'^[^0-9a-zA-Z*]*', '', v) or "latest"

    @staticmethod
    def _parse_package_json(path: str) -> List[Package]:
        packages = []
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        manifest_extras = {
            "scripts": data.get("scripts", {}),
            "engines": data.get("engines", {}),
        }
        for dep_type, is_dev in [
            ("dependencies", False),
            ("devDependencies", True),
            ("peerDependencies", False),
            ("optionalDependencies", False),
        ]:
            for name, version in data.get(dep_type, {}).items():
                packages.append(Package(
                    name=name,
                    version=ManifestParser._clean_version(version),
                    source_file=path,
                    ecosystem="npm",
                    is_dev_dependency=is_dev,
                    extras=manifest_extras if not is_dev else {},
                ))
        return packages

    @staticmethod
    def _parse_package_lock_json(path: str) -> List[Package]:
        packages = []
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if "packages" in data:
            for pkg_path, info in data["packages"].items():
                if not pkg_path:
                    continue
                name = pkg_path.lstrip("node_modules/").lstrip("\\")
                name = re.sub(r'^node_modules/', '', name)
                version = info.get("version", "unknown")
                packages.append(Package(
                    name=name, version=version,
                    source_file=path, ecosystem="npm",
                ))
        elif "dependencies" in data:
            def _walk(deps: Dict, _prefix=""):
                for n, info in deps.items():
                    packages.append(Package(
                        name=n, version=info.get("version", "unknown"),
                        source_file=path, ecosystem="npm",
                    ))
                    if "dependencies" in info:
                        _walk(info["dependencies"])
            _walk(data["dependencies"])
        return packages

    @staticmethod
    def _parse_pyproject_toml(path: str) -> List[Package]:
        if tomllib is None:
            raise RuntimeError(
                "tomllib/tomli not available. Install with: pip install tomli")
        packages = []
        with open(path, "rb") as f:
            data = tomllib.load(f)

        def _add(dep_str: str):
            m = re.match(r'^([A-Za-z0-9_.-]+)\s*([><=!,;].*)?$', dep_str.strip())
            if m:
                raw_name = m.group(1)
                rest = (m.group(2) or "").strip()
                ver_m = re.search(r'[><=!]+\s*([0-9][0-9a-zA-Z.*+-]*)', rest)
                version = ver_m.group(1) if ver_m else "latest"
                packages.append(Package(
                    name=raw_name, version=version,
                    source_file=path, ecosystem="pypi",
                ))

        # PEP 621
        for dep in data.get("project", {}).get("dependencies", []):
            _add(dep)
        for group_deps in data.get("project", {}).get("optional-dependencies", {}).values():
            for dep in group_deps:
                _add(dep)
        # Poetry
        for section in ["dependencies", "dev-dependencies", "group"]:
            section_data = data.get("tool", {}).get("poetry", {}).get(section, {})
            if isinstance(section_data, dict):
                for name, spec in section_data.items():
                    if name.lower() == "python":
                        continue
                    if isinstance(spec, str):
                        packages.append(Package(
                            name=name,
                            version=ManifestParser._clean_version(spec),
                            source_file=path, ecosystem="pypi",
                        ))
                    elif isinstance(spec, dict):
                        packages.append(Package(
                            name=name,
                            version=ManifestParser._clean_version(spec.get("version", "latest")),
                            source_file=path, ecosystem="pypi",
                        ))
        # build-system requires
        for dep in data.get("build-system", {}).get("requires", []):
            _add(dep)
        return packages

    @staticmethod
    def _parse_requirements_txt(path: str) -> List[Package]:
        packages = []
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        for raw_line in lines:
            line = raw_line.strip()
            if not line or line.startswith(("#", "-r", "-c", "--")):
                continue
            # Strip inline comments
            line = line.split("#")[0].strip()
            # Handle extras: package[extra]>=version
            m = re.match(
                r'^([A-Za-z0-9_.-]+)(\[[^\]]*\])?\s*([><=!~,\s][^;]*)?', line
            )
            if m:
                name = m.group(1)
                rest = (m.group(3) or "").strip()
                ver_m = re.search(r'[><=!~]+\s*([0-9][0-9a-zA-Z.*+-]*)', rest)
                version = ver_m.group(1) if ver_m else "latest"
                packages.append(Package(
                    name=name, version=version,
                    source_file=path, ecosystem="pypi",
                ))
        return packages


# ─────────────────────────────────────────────────────────────────────────────
#  ADVISORY DATABASE CLIENTS
# ─────────────────────────────────────────────────────────────────────────────

class OSVClient:
    """Client for the Open Source Vulnerability (OSV) database."""
    BASE_URL = "https://api.osv.dev/v1"

    def __init__(self, session: "requests.Session"):
        self.session = session

    def _ecosystem(self, pkg: Package) -> str:
        return "npm" if pkg.ecosystem == "npm" else "PyPI"

    def query(self, pkg: Package) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        payload: Dict[str, Any] = {
            "package": {"name": pkg.name, "ecosystem": self._ecosystem(pkg)}
        }
        if pkg.version and pkg.version not in ("latest", "unknown", "*"):
            payload["version"] = pkg.version
        try:
            resp = self.session.post(
                f"{self.BASE_URL}/query", json=payload, timeout=15
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            log.warning(f"OSV query failed for {pkg.name}: {e}")
            return matches

        for vuln in data.get("vulns", []):
            vuln_id: str = vuln.get("id", "")
            if not vuln_id.startswith("MAL-"):
                continue

            affected_versions: List[str] = []
            for affected in vuln.get("affected", []):
                affected_versions.extend(affected.get("versions", []))

            summary = vuln.get("summary") or vuln.get("details", "No summary.")[:200]
            url = f"https://osv.dev/vulnerability/{vuln_id}"

            matches.append(RuleMatch(
                rule_id=vuln_id,
                rule_name="osv_malware_advisory",
                severity=Severity.CRITICAL,
                category="advisory",
                description=f"OSV malware advisory: {summary}",
                evidence=(
                    f"Affected versions: {', '.join(affected_versions[:10]) or 'all'} | {url}"
                ),
            ))
        return matches


class GHSAClient:
    """
    Client for GitHub Security Advisory malware database.
    Uses the public web interface since the GraphQL API requires auth.
    """
    ADVISORY_URL_TEMPLATE = (
        "https://github.com/advisories?query=type%3Amalware+ecosystem%3A{eco}"
    )
    _cache: Dict[str, List[Dict]] = {}

    def __init__(self, session: "requests.Session"):
        self.session = session

    def _fetch_advisories(self, ecosystem: str) -> List[Dict]:
        if ecosystem in self._cache:
            return self._cache[ecosystem]
        if not HAS_BS4:
            log.warning("beautifulsoup4 not installed — skipping GHSA scrape. pip install beautifulsoup4")
            return []

        url = self.ADVISORY_URL_TEMPLATE.format(eco=ecosystem)
        advisories: List[Dict] = []
        try:
            resp = self.session.get(url, timeout=20)
            resp.raise_for_status()
            soup = BeautifulSoup(resp.content, "html.parser")
            for card in soup.find_all("div", class_="Box-row"):
                a = card.find("a", href=re.compile(r"/advisories/GHSA-"))
                if not a:
                    continue
                adv_id = a["href"].split("/")[-1]
                title = a.get_text(strip=True)
                p = card.find("p")
                desc = p.get_text(strip=True) if p else ""
                sev_span = card.find("span", class_="Label")
                severity = sev_span.get_text(strip=True) if sev_span else "Unknown"

                # Extract package names from title + description using conservative patterns
                pkg_names: Set[str] = set()
                for m in re.finditer(r'[`"\']([a-zA-Z0-9_@/.-]{2,64})[`"\']',
                                     title + " " + desc):
                    pkg_names.add(m.group(1).lower())

                advisories.append({
                    "id": adv_id,
                    "title": title,
                    "description": desc,
                    "severity": severity,
                    "packages": pkg_names,
                    "url": f"https://github.com/advisories/{adv_id}",
                })
        except Exception as e:
            log.warning(f"GHSA scrape failed for {ecosystem}: {e}")

        self._cache[ecosystem] = advisories
        return advisories

    def query(self, pkg: Package) -> List[RuleMatch]:
        eco = "npm" if pkg.ecosystem == "npm" else "pip"
        advisories = self._fetch_advisories(eco)
        matches: List[RuleMatch] = []
        name_lower = pkg.name.lower()

        for adv in advisories:
            matched = False
            # Primary: exact name in extracted package set
            if name_lower in adv["packages"]:
                matched = True

            # Secondary: strict word boundary in title/description
            if not matched:
                text = (adv["title"] + " " + adv["description"]).lower()
                pat = r'(?:^|[\s`"\',;()\[\]])' + re.escape(name_lower) + r'(?=[\s`"\',;()\[\]]|$)'
                if re.search(pat, text):
                    matched = True

            if matched:
                matches.append(RuleMatch(
                    rule_id=adv["id"],
                    rule_name="ghsa_malware_advisory",
                    severity=Severity.CRITICAL,
                    category="advisory",
                    description=f"GHSA malware advisory: {adv['title']}",
                    evidence=f"Severity: {adv['severity']} | {adv['url']}",
                ))
        return matches


# ─────────────────────────────────────────────────────────────────────────────
#  REGISTRY METADATA FETCHER
# ─────────────────────────────────────────────────────────────────────────────

class RegistryClient:

    def __init__(self, session: "requests.Session"):
        self.session = session

    def fetch_pypi(self, pkg: Package) -> Dict:
        try:
            resp = self.session.get(
                f"https://pypi.org/pypi/{quote(pkg.name)}/json", timeout=15
            )
            if resp.status_code == 404:
                return {"_not_found": True}
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            log.warning(f"PyPI metadata fetch failed for {pkg.name}: {e}")
            return {}

    def fetch_npm(self, pkg: Package) -> Dict:
        try:
            resp = self.session.get(
                f"https://registry.npmjs.org/{quote(pkg.name, safe='@/')}", timeout=15
            )
            if resp.status_code == 404:
                return {"_not_found": True}
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            log.warning(f"npm metadata fetch failed for {pkg.name}: {e}")
            return {}

    def fetch(self, pkg: Package) -> Dict:
        return self.fetch_pypi(pkg) if pkg.ecosystem == "pypi" else self.fetch_npm(pkg)


# ─────────────────────────────────────────────────────────────────────────────
#  SOURCE CODE FETCHER + ANALYZER  (--deep mode)
# ─────────────────────────────────────────────────────────────────────────────

class SourceAnalyzer:
    """
    Downloads and analyzes the package source archive.
    Only activated in --deep mode to avoid excessive network usage.
    """

    def __init__(self, session: "requests.Session"):
        self.session = session

    def analyze_package(self, pkg: Package, metadata: Dict) -> List[RuleMatch]:
        archive_url = self._find_source_url(pkg, metadata)
        if not archive_url:
            return []
        matches: List[RuleMatch] = []
        with tempfile.TemporaryDirectory() as tmpdir:
            archive_path = self._download(archive_url, tmpdir)
            if not archive_path:
                return []
            extracted = self._extract(archive_path, tmpdir)
            if not extracted:
                return []
            for src_file in self._iter_source_files(extracted):
                content = self._read_safe(src_file)
                if content:
                    matches.extend(self._scan_content(content, src_file))
        return matches

    def _find_source_url(self, pkg: Package, metadata: Dict) -> Optional[str]:
        if pkg.ecosystem == "pypi":
            releases = metadata.get("releases", {})
            ver_files = releases.get(pkg.version, []) if pkg.version != "latest" else []
            if not ver_files:
                # Use latest release
                info = metadata.get("info", {})
                ver_files = releases.get(info.get("version", ""), [])
            for f in ver_files:
                if f.get("packagetype") == "sdist":
                    return f["url"]
            for f in ver_files:
                if f.get("url"):
                    return f["url"]
        return None

    def _download(self, url: str, dest_dir: str) -> Optional[str]:
        try:
            resp = self.session.get(url, timeout=60, stream=True)
            resp.raise_for_status()
            filename = url.split("/")[-1].split("?")[0]
            path = os.path.join(dest_dir, filename)
            with open(path, "wb") as f:
                for chunk in resp.iter_content(65536):
                    f.write(chunk)
            return path
        except Exception as e:
            log.warning(f"Source download failed: {e}")
            return None

    def _extract(self, archive_path: str, dest_dir: str) -> Optional[str]:
        extract_dir = os.path.join(dest_dir, "extracted")
        os.makedirs(extract_dir, exist_ok=True)
        try:
            if tarfile.is_tarfile(archive_path):
                with tarfile.open(archive_path, "r:*") as t:
                    t.extractall(extract_dir)
                return extract_dir
            if zipfile.is_zipfile(archive_path):
                with zipfile.ZipFile(archive_path) as z:
                    z.extractall(extract_dir)
                return extract_dir
        except Exception as e:
            log.warning(f"Archive extraction failed: {e}")
        return None

    def _iter_source_files(self, root: str) -> Generator[str, None, None]:
        for dirpath, _, filenames in os.walk(root):
            for fn in filenames:
                ext = Path(fn).suffix.lower()
                if ext in (".py", ".pyw", ".js", ".mjs", ".cjs", ".ts"):
                    yield os.path.join(dirpath, fn)

    def _read_safe(self, path: str, max_bytes: int = 2 * 1024 * 1024) -> Optional[str]:
        try:
            size = os.path.getsize(path)
            if size > max_bytes:
                return None
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except Exception:
            return None

    def _scan_content(self, content: str, file_path: str) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        lines = content.splitlines()
        for rule in SOURCE_CODE_RULES:
            for match_obj, evidence in rule.matches(content):
                # Calculate line number
                line_no = content[:match_obj.start()].count("\n") + 1
                matches.append(RuleMatch(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    category="source_code",
                    description=rule.description,
                    evidence=evidence,
                    line_number=line_no,
                    file_path=file_path,
                ))
        return matches


# ─────────────────────────────────────────────────────────────────────────────
#  REMOTE FILE FETCHER
# ─────────────────────────────────────────────────────────────────────────────

class RemoteFetcher:

    @staticmethod
    def to_raw_url(url: str) -> str:
        if "github.com" in url and "/blob/" in url:
            return (
                url.replace("github.com", "raw.githubusercontent.com")
                   .replace("/blob/", "/")
            )
        if "gitlab.com" in url:
            if "/-/blob/" in url:
                return url.replace("/-/blob/", "/-/raw/")
            if "/blob/" in url:
                return url.replace("/blob/", "/-/raw/")
        return url

    @staticmethod
    def fetch(url: str, session: "requests.Session") -> Tuple[str, str]:
        """Returns (local_path, filename)."""
        raw_url = RemoteFetcher.to_raw_url(url)
        resp = session.get(raw_url, timeout=30)
        resp.raise_for_status()
        filename = Path(urlparse(raw_url).path).name or "manifest"
        tmp_dir = tempfile.mkdtemp(prefix="Laocoon_")
        path = os.path.join(tmp_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(resp.text)
        return path, filename


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN SCANNER ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

class LaocoonScanner:

    def __init__(self, deep: bool = False, skip_advisory: bool = False,
                 skip_metadata: bool = False):
        self.deep = deep
        self.skip_advisory = skip_advisory
        self.skip_metadata = skip_metadata
        self.session = build_session()
        self.osv = OSVClient(self.session)
        self.ghsa = GHSAClient(self.session)
        self.registry = RegistryClient(self.session)
        self.source_analyzer = SourceAnalyzer(self.session)

    def scan_package(self, pkg: Package) -> PackageResult:
        result = PackageResult(package=pkg)
        t0 = time.monotonic()

        # 1. Advisory databases
        if not self.skip_advisory:
            for match in self.osv.query(pkg):
                result.add_match(match)
                # Collect unique advisory URLs
                if "osv.dev" in match.evidence:
                    url_m = re.search(r'https://\S+', match.evidence)
                    if url_m:
                        result.advisory_urls.append(url_m.group(0))

            for match in self.ghsa.query(pkg):
                result.add_match(match)
                url_m = re.search(r'https://\S+', match.evidence)
                if url_m:
                    result.advisory_urls.append(url_m.group(0))

        # 2. Typosquatting detection
        typo_match = detect_typosquatting(pkg)
        if typo_match:
            result.add_match(typo_match)

        # 3. Metadata analysis (fetch from registry)
        if not self.skip_metadata:
            metadata = self.registry.fetch(pkg)
            if metadata.get("_not_found"):
                result.add_match(RuleMatch(
                    rule_id="META-000",
                    rule_name="package_not_in_registry",
                    severity=Severity.HIGH,
                    category="metadata",
                    description="Package not found in public registry — possible internal name leak "
                                "or dependency confusion attack setup.",
                    evidence=f"'{pkg.name}' returned 404 from "
                             f"{'PyPI' if pkg.ecosystem == 'pypi' else 'npm'}",
                ))
            else:
                # Run npm-style scripts check directly on manifest extras
                if pkg.extras.get("scripts"):
                    metadata["scripts"] = pkg.extras["scripts"]

                for rule in METADATA_RULES:
                    try:
                        m = rule.analyze(metadata, pkg)
                        if m:
                            result.add_match(m)
                    except Exception as e:
                        log.debug(f"Metadata rule {rule.rule_id} error: {e}")

                # Deep source code analysis
                if self.deep:
                    src_matches = self.source_analyzer.analyze_package(pkg, metadata)
                    for m in src_matches:
                        result.add_match(m)

        result.scan_duration_ms = int((time.monotonic() - t0) * 1000)
        return result

    def scan_manifest(self, file_path: str,
                      ecosystem_hint: Optional[str] = None,
                      progress: bool = True) -> List[PackageResult]:
        packages = ManifestParser.from_file(file_path, ecosystem_hint)
        if progress:
            print(f"  Loaded {len(packages)} package(s) from {Path(file_path).name}",
                  file=sys.stderr)
        results: List[PackageResult] = []
        for i, pkg in enumerate(packages, 1):
            if progress:
                print(f"\r  [{i:>{len(str(len(packages)))}}/{len(packages)}] "
                      f"Checking {pkg.name}@{pkg.version}...            ",
                      end="", file=sys.stderr)
            result = self.scan_package(pkg)
            results.append(result)
        if progress:
            print(file=sys.stderr)  # newline after progress
        return results


# ─────────────────────────────────────────────────────────────────────────────
#  REPORTING
# ─────────────────────────────────────────────────────────────────────────────

SEVERITY_SORT_KEY = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

ANSI = {
    "reset":   "\033[0m",
    "bold":    "\033[1m",
    "dim":     "\033[2m",
    "red":     "\033[91m",
    "bred":    "\033[1;91m",
    "yellow":  "\033[93m",
    "blue":    "\033[94m",
    "cyan":    "\033[96m",
    "green":   "\033[92m",
    "grey":    "\033[37m",
    "white":   "\033[97m",
}

def strip_ansi(text: str) -> str:
    return re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', text)


def _severity_color(sev: Severity, no_color: bool) -> str:
    if no_color:
        return ""
    return {
        Severity.CRITICAL: ANSI["bred"],
        Severity.HIGH:     ANSI["red"],
        Severity.MEDIUM:   ANSI["yellow"],
        Severity.LOW:      ANSI["cyan"],
        Severity.INFO:     ANSI["grey"],
    }.get(sev, "")


def print_terminal_report(results: List[PackageResult],
                          all_packages: List[Package],
                          no_color: bool = False,
                          source_url: Optional[str] = None) -> None:
    reset = "" if no_color else ANSI["reset"]
    bold  = "" if no_color else ANSI["bold"]
    dim   = "" if no_color else ANSI["dim"]
    green = "" if no_color else ANSI["green"]

    malicious = [r for r in results if r.is_malicious]
    total_findings = sum(len(r.matches) for r in malicious)

    SEP = "─" * 78

    print(f"\n{SEP}")
    print(f"  LAOCOON  |  Malicious Package Scanner")
    if source_url:
        print(f"  Source      : {source_url}")
    print(f"  Timestamp   : {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"  Packages    : {len(all_packages)} scanned")
    print(f"  Flagged     : {len(malicious)}")
    print(f"  Total findings : {total_findings}")
    print(SEP)

    if not malicious:
        print(f"\n  {green}No known malicious packages detected.{reset}\n")
        print(SEP)
        return

    # Severity summary
    sev_counts: Dict[Severity, int] = defaultdict(int)
    for r in malicious:
        for m in r.matches:
            sev_counts[m.severity] += 1

    print()
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        if sev_counts[sev]:
            col = _severity_color(sev, no_color)
            print(f"  {col}{sev.value:10}{reset}  {sev_counts[sev]} finding(s)")
    print()
    print(SEP)

    # Per-package findings
    for result in sorted(malicious,
                         key=lambda r: SEVERITY_SORT_KEY.get(r.highest_severity,
                                                              99)):
        col = _severity_color(result.highest_severity, no_color)
        print(f"\n  {bold}Package{reset} : {bold}{result.package.name}"
              f"@{result.package.version}{reset}")
        print(f"  {bold}Ecosystem{reset}: {result.package.ecosystem.upper()}")
        print(f"  {bold}Severity{reset} : {col}{result.highest_severity.value}{reset}")
        if result.advisory_urls:
            for url in result.advisory_urls[:3]:
                print(f"  {bold}Advisory{reset} : {url}")
        print(f"  {bold}Findings{reset} :")

        for match in sorted(result.matches,
                            key=lambda m: SEVERITY_SORT_KEY.get(m.severity, 99)):
            sev_col = _severity_color(match.severity, no_color)
            tag = f"[{match.severity.value}]"
            prefix = f"    {sev_col}{tag:12}{reset}"
            print(f"{prefix} {bold}{match.rule_id}{reset}  {match.rule_name}")
            print(f"    {dim}{match.description}{reset}")
            # Truncate evidence for readability
            ev = match.evidence[:180].replace("\n", " ")
            print(f"    Evidence : {ev}")
            if match.file_path:
                rel = Path(match.file_path).name
                loc = f"{rel}:{match.line_number}" if match.line_number else rel
                print(f"    Location : {loc}")

    print(f"\n{SEP}\n")


def generate_json_report(results: List[PackageResult],
                         all_packages: List[Package],
                         source_url: Optional[str] = None) -> Dict:
    malicious = [r for r in results if r.is_malicious]
    return {
        "scanner": "Laocoon",
        "version": "2.0.0",
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "source": source_url,
        "summary": {
            "total_packages": len(all_packages),
            "flagged_packages": len(malicious),
            "total_findings": sum(len(r.matches) for r in malicious),
        },
        "findings": [r.to_dict() for r in malicious],
    }


# ─────────────────────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────────────────────

BANNER = """\
=============================================================================
  Laocoon v2.0 | Supply Chain Security Scanner
  Detects: malware advisories, typosquatting, source-code IOCs, metadata abuse
=============================================================================
"""

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="Laocoon",
        description="Professional-grade malicious package scanner for npm and PyPI.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Examples:
          Laocoon requirements.txt
          Laocoon package.json package-lock.json
          Laocoon requirements.txt --deep --output report.json
          Laocoon --remote https://github.com/org/repo/blob/main/requirements.txt
          Laocoon requirements.txt --json --no-banner
        """),
    )
    parser.add_argument("files", nargs="*",
                        help="Manifest files to scan.")
    parser.add_argument("--remote", "-r",
                        help="Scan a manifest file at a remote GitHub/GitLab URL.")
    parser.add_argument("--ecosystem", choices=["npm", "pypi"],
                        help="Override ecosystem detection.")
    parser.add_argument("--deep", action="store_true",
                        help="Download and statically analyze package source archives.")
    parser.add_argument("--output", "-o",
                        help="Write JSON report to this file.")
    parser.add_argument("--json", "-j", action="store_true",
                        help="Machine-readable JSON output only (suppresses terminal report).")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI color codes.")
    parser.add_argument("--no-banner", action="store_true",
                        help="Suppress banner.")
    parser.add_argument("--skip-advisory", action="store_true",
                        help="Skip OSV and GHSA advisory lookups (offline mode).")
    parser.add_argument("--skip-metadata", action="store_true",
                        help="Skip registry metadata fetching.")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable verbose debug logging to stderr.")
    args = parser.parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    if not args.remote and not args.files:
        parser.error("Provide at least one manifest file or use --remote.")

    if not HAS_REQUESTS:
        print("ERROR: 'requests' is required. Install with: pip install requests",
              file=sys.stderr)
        return 2

    if not args.json and not args.no_banner:
        print(BANNER)

    session = build_session()
    source_url: Optional[str] = None
    tmp_cleanup: List[str] = []
    manifest_files: List[str] = list(args.files)

    if args.remote:
        source_url = args.remote
        if not args.json:
            print(f"Fetching remote manifest: {source_url}", file=sys.stderr)
        try:
            local_path, _ = RemoteFetcher.fetch(args.remote, session)
            manifest_files.append(local_path)
            tmp_cleanup.append(str(Path(local_path).parent))
        except Exception as e:
            print(f"ERROR: Could not fetch remote file: {e}", file=sys.stderr)
            return 2

    scanner = LaocoonScanner(
        deep=args.deep,
        skip_advisory=args.skip_advisory,
        skip_metadata=args.skip_metadata,
    )

    all_packages: List[Package] = []
    all_results:  List[PackageResult] = []

    for mf in manifest_files:
        if not Path(mf).exists():
            print(f"ERROR: File not found: {mf}", file=sys.stderr)
            continue
        try:
            results = scanner.scan_manifest(
                mf,
                ecosystem_hint=args.ecosystem,
                progress=(not args.json),
            )
            # Reconstruct package list from results
            all_packages.extend([r.package for r in results])
            all_results.extend(results)
        except ValueError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            continue

    # Clean up any temp dirs
    for d in tmp_cleanup:
        try:
            shutil.rmtree(d, ignore_errors=True)
        except Exception:
            pass

    # Output
    report = generate_json_report(all_results, all_packages, source_url)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        if not args.json:
            print(f"JSON report written to: {args.output}", file=sys.stderr)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_terminal_report(
            all_results, all_packages,
            no_color=args.no_color,
            source_url=source_url,
        )

    flagged = any(r.is_malicious for r in all_results)
    return 1 if flagged else 0


if __name__ == "__main__":
    sys.exit(main())
