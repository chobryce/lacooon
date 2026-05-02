import ast
import hashlib
import json
import os
import re
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from laocoon import LaocoonScanner, ManifestParser, SOURCE_CODE_RULES, Severity


app = FastAPI(title="lacooon API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


MAX_FILE_BYTES = 2 * 1024 * 1024

MANIFEST_EXACT_NAMES = {
    "package.json",
    "package-lock.json",
    "pyproject.toml",
    "requirements.txt",
}

SOURCE_EXTENSIONS = {
    ".py", ".pyw",
    ".js", ".mjs", ".cjs",
    ".ts", ".tsx", ".jsx",
    ".txt", ".log", ".conf", ".cfg",
}

TEXT_EXTENSIONS = MANIFEST_EXACT_NAMES | SOURCE_EXTENSIONS


SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def sse(data: Dict[str, Any]) -> str:
    return f"data: {json.dumps(data, ensure_ascii=False)}\n\n"


@app.get("/")
def home():
    return {
        "status": "lacooon backend online",
        "version": "2.0.0",
        "supports": [
            "requirements.txt",
            "package.json",
            "package-lock.json",
            "pyproject.toml",
            ".py",
            ".js",
            ".ts",
            ".txt containing code",
        ],
    }
@app.get("/ping")
def ping():
    return {"ok": True}

def severity_rank(value: Optional[str]) -> int:
    if not value:
        return 0
    return SEVERITY_ORDER.get(str(value).upper(), 0)


def highest_severity(findings: List[Dict[str, Any]]) -> Optional[str]:
    if not findings:
        return None
    return max(
        (str(f.get("severity", "INFO")).upper() for f in findings),
        key=severity_rank,
    )


def safe_filename(filename: Optional[str]) -> str:
    raw = Path(filename or "uploaded_file").name
    raw = raw.replace("\x00", "")
    return raw or "uploaded_file"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def decode_text(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def clip_evidence(content: str, start: int, end: int, window: int = 120) -> str:
    a = max(0, start - window)
    b = min(len(content), end + window)
    return content[a:b].replace("\n", " ").replace("\r", " ").strip()


def line_number_at(content: str, index: int) -> int:
    return content[:index].count("\n") + 1


def is_probably_binary(data: bytes) -> bool:
    if not data:
        return False
    sample = data[:4096]
    if b"\x00" in sample:
        return True
    control = sum(1 for b in sample if b < 9 or (13 < b < 32))
    return control / max(len(sample), 1) > 0.20


def normalize_manifest_path(filename: str, tmp_dir: str, data: bytes) -> str:
    lower = filename.lower()

    if lower in {"package.json", "package-lock.json", "pyproject.toml"}:
        normalized_name = lower
    elif re.match(r"requirements.*\.txt$", lower):
        normalized_name = "requirements.txt"
    else:
        normalized_name = filename

    path = os.path.join(tmp_dir, normalized_name)
    with open(path, "wb") as f:
        f.write(data)
    return path


def looks_like_requirements_txt(content: str) -> bool:
    requirement_lines = 0
    suspicious_code_lines = 0

    for raw in content.splitlines():
        line = raw.strip()

        if not line or line.startswith("#"):
            continue

        if line.startswith(("-r ", "-c ", "--index-url", "--extra-index-url", "--find-links")):
            requirement_lines += 1
            continue

        if re.match(
            r"^[A-Za-z0-9_.-]+(\[[A-Za-z0-9_,.-]+\])?\s*"
            r"([<>=!~]=?|===)\s*[A-Za-z0-9.*+!_\-]+",
            line,
        ):
            requirement_lines += 1
            continue

        if re.match(r"^[A-Za-z0-9_.-]+$", line):
            requirement_lines += 1
            continue

        if re.search(
            r"\b(import|from|def|class|subprocess|socket|eval|exec|base64|requests\.|os\.system)\b",
            line,
        ):
            suspicious_code_lines += 1

    return requirement_lines > 0 and requirement_lines >= suspicious_code_lines


def looks_like_json_manifest(filename: str, content: str) -> bool:
    lower = filename.lower()
    if lower not in {"package.json", "package-lock.json"}:
        return False

    try:
        data = json.loads(content)
    except Exception:
        return False

    if lower == "package.json":
        return any(
            key in data
            for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies", "scripts")
        )

    if lower == "package-lock.json":
        return "packages" in data or "dependencies" in data

    return False


def looks_like_pyproject(filename: str, content: str) -> bool:
    lower = filename.lower()
    if lower != "pyproject.toml":
        return False

    return (
        "[project]" in content
        or "[tool.poetry" in content
        or "[build-system]" in content
        or "dependencies" in content
    )


def detect_file_kind(filename: str, content: str, data: bytes) -> str:
    lower = filename.lower()
    ext = Path(lower).suffix

    if is_probably_binary(data):
        return "binary"

    if lower in {"package.json", "package-lock.json"} and looks_like_json_manifest(filename, content):
        return "manifest"

    if lower == "pyproject.toml" and looks_like_pyproject(filename, content):
        return "manifest"

    if re.match(r"requirements.*\.txt$", lower) and looks_like_requirements_txt(content):
        return "manifest"

    if lower.endswith(".txt") and looks_like_requirements_txt(content):
        return "manifest"

    if looks_like_source_code(filename, content):
        return "source"

    if ext in SOURCE_EXTENSIONS:
        return "source"

    return "unknown"


def looks_like_source_code(filename: str, content: str) -> bool:
    ext = Path(filename.lower()).suffix

    if ext in {".py", ".pyw", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}:
        return True

    indicators = [
        r"\bimport\s+[A-Za-z0-9_.*{},\s]+",
        r"\bfrom\s+[A-Za-z0-9_.]+\s+import\b",
        r"\bdef\s+[A-Za-z_][A-Za-z0-9_]*\s*\(",
        r"\bclass\s+[A-Za-z_][A-Za-z0-9_]*\s*[:\(]",
        r"\basync\s+def\s+",
        r"\brequire\s*\(",
        r"\bmodule\.exports\b",
        r"\bexports\.",
        r"\bfunction\s+[A-Za-z_$][A-Za-z0-9_$]*\s*\(",
        r"=>\s*[{(]",
        r"\bconst\s+[A-Za-z_$][A-Za-z0-9_$]*\s*=",
        r"\blet\s+[A-Za-z_$][A-Za-z0-9_$]*\s*=",
        r"\bvar\s+[A-Za-z_$][A-Za-z0-9_$]*\s*=",
        r"\bsubprocess\.",
        r"\bos\.system\s*\(",
        r"\bsocket\.",
        r"\bbase64\.",
        r"\beval\s*\(",
        r"\bexec\s*\(",
        r"\brequests\.(get|post|put|patch)\s*\(",
    ]

    hits = sum(1 for pattern in indicators if re.search(pattern, content, re.MULTILINE))
    return hits >= 2


def add_regex_findings(
    findings: List[Dict[str, Any]],
    content: str,
    filename: str,
    rules: List[Dict[str, Any]],
) -> None:
    seen = {(f.get("rule_id"), f.get("line_number"), f.get("evidence")) for f in findings}

    for rule in rules:
        pattern = rule["pattern"]
        flags = rule.get("flags", re.IGNORECASE | re.MULTILINE | re.DOTALL)

        for match in re.finditer(pattern, content, flags):
            evidence = clip_evidence(content, match.start(), match.end())
            line = line_number_at(content, match.start())
            key = (rule["rule_id"], line, evidence)

            if key in seen:
                continue

            findings.append({
                "rule_id": rule["rule_id"],
                "rule_name": rule["rule_name"],
                "severity": rule["severity"],
                "category": rule.get("category", "source_code"),
                "description": rule["description"],
                "evidence": evidence,
                "line_number": line,
                "file_path": filename,
            })
            seen.add(key)


def ast_python_findings(content: str, filename: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    try:
        tree = ast.parse(content)
    except SyntaxError:
        return findings

    dangerous_calls = {
        "eval": ("PY-AST-001", "dynamic_eval", "CRITICAL", "eval() executes dynamic code."),
        "exec": ("PY-AST-002", "dynamic_exec", "CRITICAL", "exec() executes dynamic code."),
        "compile": ("PY-AST-003", "dynamic_compile", "HIGH", "compile() can prepare dynamic code for execution."),
        "open": ("PY-AST-004", "file_access", "LOW", "File access detected."),
    }

    dangerous_attrs = {
        ("os", "system"): ("PY-AST-010", "os_system_execution", "HIGH", "os.system() executes shell commands."),
        ("os", "popen"): ("PY-AST-011", "os_popen_execution", "HIGH", "os.popen() executes shell commands."),
        ("subprocess", "Popen"): ("PY-AST-012", "subprocess_popen", "HIGH", "subprocess.Popen() executes external processes."),
        ("subprocess", "run"): ("PY-AST-013", "subprocess_run", "MEDIUM", "subprocess.run() executes external processes."),
        ("subprocess", "check_output"): ("PY-AST-014", "subprocess_check_output", "HIGH", "subprocess.check_output() executes external processes."),
        ("socket", "socket"): ("PY-AST-015", "raw_socket", "HIGH", "Raw socket usage detected."),
        ("requests", "post"): ("PY-AST-016", "http_post", "HIGH", "HTTP POST request detected."),
        ("requests", "get"): ("PY-AST-017", "http_get", "MEDIUM", "HTTP GET request detected."),
        ("base64", "b64decode"): ("PY-AST-018", "base64_decode", "MEDIUM", "Base64 decoding detected."),
        ("marshal", "loads"): ("PY-AST-019", "marshal_loads", "HIGH", "marshal.loads() can deserialize Python bytecode."),
    }

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                name = node.func.id
                if name in dangerous_calls:
                    rule_id, rule_name, severity, desc = dangerous_calls[name]
                    findings.append({
                        "rule_id": rule_id,
                        "rule_name": rule_name,
                        "severity": severity,
                        "category": "source_code_ast",
                        "description": desc,
                        "evidence": f"{name}(...)",
                        "line_number": getattr(node, "lineno", None),
                        "file_path": filename,
                    })

            if isinstance(node.func, ast.Attribute):
                attr = node.func.attr
                owner = None

                if isinstance(node.func.value, ast.Name):
                    owner = node.func.value.id

                if owner and (owner, attr) in dangerous_attrs:
                    rule_id, rule_name, severity, desc = dangerous_attrs[(owner, attr)]
                    findings.append({
                        "rule_id": rule_id,
                        "rule_name": rule_name,
                        "severity": severity,
                        "category": "source_code_ast",
                        "description": desc,
                        "evidence": f"{owner}.{attr}(...)",
                        "line_number": getattr(node, "lineno", None),
                        "file_path": filename,
                    })

    return findings


def source_scan_rules() -> List[Dict[str, Any]]:
    return [
        {
            "rule_id": "SRC-CRED-001",
            "rule_name": "browser_credential_store_access",
            "severity": "CRITICAL",
            "description": "Access to browser credential, cookie, history, or extension storage artifacts.",
            "pattern": r"(Login\s*Data|Cookies|Local\s*State|Web\s*Data|History|Local\s*Extension\s*Settings|Sync\s*Extension\s*Settings)",
        },
        {
            "rule_id": "SRC-CRED-002",
            "rule_name": "ssh_key_access",
            "severity": "CRITICAL",
            "description": "Access to SSH private keys or SSH credential files.",
            "pattern": r"(\.ssh[/\\](id_rsa|id_ed25519|id_ecdsa|known_hosts|authorized_keys)|BEGIN\s+OPENSSH\s+PRIVATE\s+KEY)",
        },
        {
            "rule_id": "SRC-CRED-003",
            "rule_name": "cloud_credential_access",
            "severity": "CRITICAL",
            "description": "Access to cloud credentials or API secrets.",
            "pattern": r"(\.aws[/\\]credentials|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|GOOGLE_APPLICATION_CREDENTIALS|AZURE_CLIENT_SECRET|api[_-]?key|secret[_-]?key)",
        },
        {
            "rule_id": "SRC-WALLET-001",
            "rule_name": "crypto_wallet_artifact_access",
            "severity": "CRITICAL",
            "description": "Access to cryptocurrency wallet files, seed phrases, or wallet browser extensions.",
            "pattern": r"(Exodus|Electrum|Atomic\s*Wallet|MetaMask|Phantom|wallet\.dat|keystore\.json|mnemonic|seed\s*phrase|Solana|Ledger|Trezor)",
        },
        {
            "rule_id": "SRC-EXFIL-001",
            "rule_name": "network_exfiltration_capability",
            "severity": "HIGH",
            "description": "Network request or socket communication capability detected.",
            "pattern": r"(requests\.(post|get|put|patch)\s*\(|urllib\.request|httpx\.(post|get)\s*\(|socket\.socket\s*\(|fetch\s*\(|XMLHttpRequest|axios\.(post|get)\s*\()",
        },
        {
            "rule_id": "SRC-EXFIL-002",
            "rule_name": "webhook_exfiltration",
            "severity": "CRITICAL",
            "description": "Known webhook or bot API endpoint used frequently for exfiltration.",
            "pattern": r"(discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|hooks\.slack\.com/services)",
        },
        {
            "rule_id": "SRC-EXEC-001",
            "rule_name": "process_execution",
            "severity": "HIGH",
            "description": "External process execution capability detected.",
            "pattern": r"(subprocess\.(Popen|run|call|check_call|check_output)\s*\(|os\.system\s*\(|os\.popen\s*\(|child_process\.(exec|spawn|execSync|spawnSync)\s*\()",
        },
        {
            "rule_id": "SRC-EXEC-002",
            "rule_name": "dynamic_code_execution",
            "severity": "CRITICAL",
            "description": "Dynamic code execution detected.",
            "pattern": r"(\beval\s*\(|\bexec\s*\(|compile\s*\(|Function\s*\(|setTimeout\s*\(\s*['\"]|setInterval\s*\(\s*['\"])",
        },
        {
            "rule_id": "SRC-OBF-001",
            "rule_name": "encoded_or_packed_payload",
            "severity": "HIGH",
            "description": "Encoded, compressed, or serialized payload handling detected.",
            "pattern": r"(base64\.b64decode|Buffer\.from\s*\([^)]*base64|atob\s*\(|binascii\.unhexlify|bytes\.fromhex|zlib\.decompress|gzip\.decompress|marshal\.loads|eval\(atob)",
        },
        {
            "rule_id": "SRC-OBF-002",
            "rule_name": "long_encoded_blob",
            "severity": "HIGH",
            "description": "Long encoded-looking string detected.",
            "pattern": r"['\"][A-Za-z0-9+/=]{300,}['\"]",
        },
        {
            "rule_id": "SRC-FP-001",
            "rule_name": "host_fingerprinting",
            "severity": "HIGH",
            "description": "Host fingerprinting or victim profiling detected.",
            "pattern": r"(getpass\.getuser|getuser\s*\(\)|uuid\.getnode|getnode\s*\(\)|socket\.gethostname|platform\.(node|system|release|version|uname)\s*\(|os\.environ)",
        },
        {
            "rule_id": "SRC-PERSIST-001",
            "rule_name": "persistence_mechanism",
            "severity": "CRITICAL",
            "description": "Persistence mechanism detected.",
            "pattern": r"(crontab|LaunchAgents|LaunchDaemons|launchctl|CurrentVersion[/\\]Run|winreg|Startup[/\\]|systemd|\.bashrc|\.zshrc)",
        },
        {
            "rule_id": "SRC-ANTI-001",
            "rule_name": "anti_analysis_or_evasion",
            "severity": "HIGH",
            "description": "Anti-analysis, sandbox evasion, or debugging detection behavior.",
            "pattern": r"(VirtualBox|VMware|vbox|sandbox|debugger|procmon|wireshark|fiddler|sleep\s*\(\s*[1-9][0-9]{2,}|IsDebuggerPresent)",
        },
        {
            "rule_id": "SRC-INSTALL-001",
            "rule_name": "install_time_execution",
            "severity": "HIGH",
            "description": "Install-time script execution or dependency installation detected.",
            "pattern": r"(postinstall|preinstall|setup\.py|pip\s+install|npm\s+install|curl\s+.*\|\s*(bash|sh)|wget\s+.*\|\s*(bash|sh))",
        },
        {
            "rule_id": "SRC-C2-001",
            "rule_name": "hardcoded_network_indicator",
            "severity": "MEDIUM",
            "description": "Hardcoded IP address, URL, or possible command-and-control endpoint.",
            "pattern": r"((https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+)|(['\"]\d{1,3}(?:\.\d{1,3}){3}['\"]))",
        },
    ]


def run_laocoon_source_rules(content: str, filename: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    for rule in SOURCE_CODE_RULES:
        for match_obj, evidence in rule.matches(content):
            severity = rule.severity.value if isinstance(rule.severity, Severity) else str(rule.severity)
            findings.append({
                "rule_id": rule.rule_id,
                "rule_name": rule.name,
                "severity": severity,
                "category": "source_code",
                "description": rule.description,
                "evidence": evidence,
                "line_number": line_number_at(content, match_obj.start()),
                "file_path": filename,
            })

    return findings


def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    out = []

    for f in findings:
        key = (
            f.get("rule_id"),
            f.get("line_number"),
            str(f.get("evidence", ""))[:160],
        )

        if key in seen:
            continue

        seen.add(key)
        out.append(f)

    out.sort(
        key=lambda x: (
            -severity_rank(x.get("severity")),
            x.get("line_number") or 0,
            x.get("rule_id") or "",
        )
    )

    return out


def scan_source_file(path: str, filename: str, data: bytes) -> Dict[str, Any]:
    start = time.monotonic()
    content = decode_text(data)

    findings: List[Dict[str, Any]] = []
    findings.extend(run_laocoon_source_rules(content, filename))
    add_regex_findings(findings, content, filename, source_scan_rules())

    if Path(filename.lower()).suffix in {".py", ".pyw", ".txt", ".log"} or re.search(
        r"\b(import|def|class|subprocess|socket|base64|requests)\b",
        content,
    ):
        findings.extend(ast_python_findings(content, filename))

    findings = deduplicate_findings(findings)
    highest = highest_severity(findings)

    return {
        "package": filename,
        "version": "",
        "ecosystem": "source-file",
        "highest_severity": highest,
        "scan_duration_ms": int((time.monotonic() - start) * 1000),
        "finding_count": len(findings),
        "advisory_urls": [],
        "findings": findings,
        "file_hash_sha256": sha256_bytes(data),
    }


@app.post("/scan")
async def scan(file: UploadFile = File(...)):
    async def event_stream():
        tmp_dir = tempfile.mkdtemp(prefix="lacooon_")

        try:
            filename = safe_filename(file.filename)
            data = await file.read()

            if not data:
                yield sse({"type": "error", "message": "Uploaded file is empty."})
                return

            if len(data) > MAX_FILE_BYTES:
                yield sse({"type": "error", "message": "File exceeds 2 MB scan limit."})
                return

            tmp_path = os.path.join(tmp_dir, filename)
            with open(tmp_path, "wb") as f:
                f.write(data)

            yield sse({
                "type": "status",
                "phase": "upload",
                "message": f"Received {filename} ({len(data)} bytes)"
            })

            content = decode_text(data)
            kind = detect_file_kind(filename, content, data)

            if kind == "binary":
                yield sse({
                    "type": "error",
                    "message": "Binary files are not supported. Upload a text manifest or source-code file."
                })
                return

            if kind == "source":
                yield sse({
                    "type": "status",
                    "phase": "scan",
                    "message": "Detected source code. Running static malware-oriented source analysis..."
                })

                result = scan_source_file(tmp_path, filename, data)

                if result["finding_count"] > 0:
                    yield sse({"type": "finding", "package": result})

                yield sse({
                    "type": "summary",
                    "total": 1,
                    "flagged": 1 if result["finding_count"] else 0,
                    "total_findings": result["finding_count"],
                    "clean": result["finding_count"] == 0,
                })

                yield sse({"type": "done"})
                return

            if kind == "manifest":
                yield sse({
                    "type": "status",
                    "phase": "parse",
                    "message": "Detected dependency manifest. Parsing packages..."
                })

                manifest_path = normalize_manifest_path(filename, tmp_dir, data)
                packages = ManifestParser.from_file(manifest_path)

                yield sse({
                    "type": "status",
                    "phase": "scan",
                    "message": f"Loaded {len(packages)} package(s). Running supply-chain scan..."
                })

                scanner = LaocoonScanner(deep=False)

                flagged = 0
                total_findings = 0

                for pkg in packages:
                    yield sse({
                        "type": "status",
                        "phase": "scan",
                        "message": f"Checking {pkg.name}@{pkg.version}..."
                    })

                    result = scanner.scan_package(pkg)

                    if result.is_malicious:
                        flagged += 1
                        total_findings += len(result.matches)
                        yield sse({"type": "finding", "package": result.to_dict()})

                yield sse({
                    "type": "summary",
                    "total": len(packages),
                    "flagged": flagged,
                    "total_findings": total_findings,
                    "clean": flagged == 0,
                })

                yield sse({"type": "done"})
                return

            yield sse({
                "type": "error",
                "message": "Unsupported file. Upload package.json, package-lock.json, pyproject.toml, requirements.txt, .py, .js, .ts, or .txt containing code."
            })

        except Exception as e:
            yield sse({
                "type": "error",
                "message": str(e)
            })

        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    return StreamingResponse(event_stream(), media_type="text/event-stream")
