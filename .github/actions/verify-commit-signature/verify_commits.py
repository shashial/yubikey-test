#!/usr/bin/env python3
"""Inspect git commit signatures (SSH/GPG) and emit JSON reports."""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
from typing import Dict, List, Optional, Tuple

DEBUG = os.environ.get("SIGNATURE_DEBUG", "").strip().lower() in {"1", "true", "yes", "on"}


def debug(message: str) -> None:
    if DEBUG:
        print(f"[verify-commit-signature] {message}", file=sys.stderr)


def _run_git(args: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], check=False, capture_output=True, text=True)


def _normalize_algorithms(raw: Optional[str]) -> List[str]:
    if not raw:
        return []
    return [alg.strip() for alg in raw.split(",") if alg.strip()]


def _sanitize_fingerprint(value: str) -> str:
    return "".join(c.upper() for c in value if c in "0123456789abcdefABCDEF")


def _normalize_fingerprints(raw: Optional[str]) -> List[str]:
    if not raw:
        return []
    fingerprints: List[str] = []
    for chunk in raw.replace("\n", ",").split(","):
        cleaned = _sanitize_fingerprint(chunk.strip())
        if cleaned:
            fingerprints.append(cleaned)
    return fingerprints


@dataclasses.dataclass
class Config:
    commit_sha: str
    allowed_algorithms: List[str]
    allowed_gpg_fingerprints: List[str]
    gpg_allowed_fingerprints_file: str
    base_sha: str
    head_sha: str

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            commit_sha=os.environ.get("INPUT_COMMIT_SHA", "HEAD").strip() or "HEAD",
            allowed_algorithms=_normalize_algorithms(
                os.environ.get("INPUT_ALLOWED_ALGORITHMS", "ED25519-SK,ECDSA-SK")
            ),
            allowed_gpg_fingerprints=_normalize_fingerprints(
                os.environ.get("INPUT_GPG_ALLOWED_FINGERPRINTS", "")
            ),
            gpg_allowed_fingerprints_file=os.environ.get(
                "INPUT_GPG_ALLOWED_FINGERPRINTS_FILE", ""
            ),
            base_sha=os.environ.get("INPUT_BASE_SHA", ""),
            head_sha=os.environ.get("INPUT_HEAD_SHA", ""),
        )


def resolve_allowed_gpg_fingerprints(cfg: Config) -> None:
    fingerprints = list(cfg.allowed_gpg_fingerprints)
    file_path = cfg.gpg_allowed_fingerprints_file.strip()
    if file_path:
        path = pathlib.Path(file_path).expanduser()
        if not path.is_file():
            raise SystemExit(
                f"Provided gpg-allowed-fingerprints-file '{file_path}' does not exist"
            )
        file_contents = path.read_text(encoding="utf-8")
        fingerprints.extend(_normalize_fingerprints(file_contents))

    deduped: List[str] = []
    seen = set()
    for fp in fingerprints:
        upper = fp.upper()
        if upper and upper not in seen:
            deduped.append(upper)
            seen.add(upper)
    cfg.allowed_gpg_fingerprints = deduped


def extract_signature_block(commit: str) -> str:
    raw = _run_git(["cat-file", "-p", commit])
    if raw.returncode != 0:
        raise SystemExit(raw.stderr.strip() or f"Unable to read commit {commit}")

    lines = raw.stdout.splitlines()
    block: List[str] = []
    capturing = False
    for line in lines:
        if line.startswith("gpgsig "):
            capturing = True
            block.append(line[len("gpgsig "):])
            continue
        if capturing:
            if line.startswith(" "):
                block.append(line[1:])
                continue
            break
    return "\n".join(block).strip()


def detect_signature_type(block: str) -> Optional[str]:
    if "BEGIN SSH SIGNATURE" in block:
        return "SSH"
    if "BEGIN PGP SIGNATURE" in block:
        return "GPG"
    return None


class SSHSignatureParseError(RuntimeError):
    pass


def _read_ssh_string(buffer: memoryview, offset: int) -> Tuple[bytes, int]:
    if len(buffer) - offset < 4:
        raise SSHSignatureParseError("invalid SSH signature structure")
    length = int.from_bytes(buffer[offset : offset + 4], "big")
    start = offset + 4
    end = start + length
    if end > len(buffer):
        raise SSHSignatureParseError("invalid SSH signature length")
    return bytes(buffer[start:end]), end


def parse_ssh_signature(block: str) -> Dict[str, str]:
    payload = "".join(
        line.strip()
        for line in block.splitlines()
        if "BEGIN" not in line and "END" not in line and line.strip()
    )
    if not payload:
        raise SSHSignatureParseError("missing SSH signature payload")

    decoded = base64.b64decode(payload)
    if not decoded.startswith(b"SSHSIG"):
        raise SSHSignatureParseError("unexpected SSH signature marker")

    idx = len("SSHSIG")
    if len(decoded) - idx < 4:
        raise SSHSignatureParseError("truncated SSH signature")
    version = int.from_bytes(decoded[idx : idx + 4], "big")
    idx += 4
    if version != 1:
        raise SSHSignatureParseError(f"unsupported SSH signature version {version}")

    buf = memoryview(decoded)
    public_key, idx = _read_ssh_string(buf, idx)
    namespace, idx = _read_ssh_string(buf, idx)
    reserved, idx = _read_ssh_string(buf, idx)
    hash_alg, idx = _read_ssh_string(buf, idx)
    debug(
        "Namespace=%s ReservedLen=%d HashAlg=%s"
        % (namespace.decode(errors="ignore"), len(reserved), hash_alg.decode(errors="ignore"))
    )
    signature_field, idx = _read_ssh_string(buf, idx)
    debug(
        f"Public key blob length: {len(public_key)} bytes; signature blob length: {len(signature_field)} bytes"
    )

    key_buf = memoryview(public_key)
    key_type_raw, _ = _read_ssh_string(key_buf, 0)
    key_type = key_type_raw.decode("utf-8")

    algorithm_map = {
        "sk-ssh-ed25519@openssh.com": "ED25519-SK",
        "sk-ecdsa-sha2-nistp256@openssh.com": "ECDSA-SK",
        "ssh-ed25519": "ED25519",
        "ecdsa-sha2-nistp256": "ECDSA",
    }
    algorithm = algorithm_map.get(key_type, key_type.upper())

    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(public_key).digest()).decode("ascii").rstrip("=")

    return {
        "key_type": key_type,
        "algorithm": algorithm,
        "fingerprint": fingerprint,
    }


def parse_gpg_fingerprint(block: str) -> Optional[str]:
    try:
        proc = subprocess.run(
            ["gpg", "--batch", "--list-packets"],
            input=block + "\n",
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return None

    for line in proc.stdout.splitlines():
        line = line.strip()
        if "issuer fpr" in line:
            return line.split()[-1].upper()
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line.startswith("keyid "):
            return line.split()[-1].upper()
    return None


def _fingerprint_from_text(text: str) -> Optional[str]:
    for line in text.splitlines():
        if "fingerprint" in line.lower():
            parts = line.split(":", 1)
            if len(parts) == 2:
                return parts[1].strip()
    return None


def infer_ssh_from_text(signature_block: str, log_text: str) -> Optional[Dict[str, str]]:
    combined = f"{signature_block}\n{log_text}".lower()
    algorithm = ""
    if "sk-ssh-ed25519" in combined:
        algorithm = "ED25519-SK"
    elif "sk-ecdsa" in combined:
        algorithm = "ECDSA-SK"
    elif "ssh-ed25519" in combined:
        algorithm = "ED25519"
    elif "ecdsa-sha2" in combined or "ecdsa" in combined:
        algorithm = "ECDSA"

    if not algorithm:
        debug("Heuristic SSH detection failed; algorithm not found in signature/log text")
        return None

    fingerprint = _fingerprint_from_text(log_text) or ""
    debug("Heuristic SSH detection succeeded (algorithm=%s)" % algorithm)
    return {"algorithm": algorithm, "fingerprint": fingerprint}


def check_commit(commit: str, cfg: Config) -> Dict[str, object]:
    signature_block = extract_signature_block(commit)
    log_proc = _run_git(["log", "--show-signature", "-1", commit])
    log_text = f"{log_proc.stdout}\n{log_proc.stderr}"

    result = {
        "commit": commit,
        "is_signed": False,
        "signature_type": "NONE",
        "algorithm": "",
        "fingerprint": "",
        "ssh_algorithm_allowed": False,
        "gpg_fingerprint_allowed": False,
        "notes": [],
    }

    if not signature_block:
        result["notes"].append("Commit has no signature data")
        return result

    signature_type = detect_signature_type(signature_block)

    if signature_type == "SSH":
        try:
            ssh_info = parse_ssh_signature(signature_block)
        except SSHSignatureParseError as exc:
            debug(f"SSH signature parse failed: {exc}")
            ssh_info = infer_ssh_from_text(signature_block, log_text)
            if not ssh_info:
                result.update(
                    {
                        "signature_type": "SSH",
                        "notes": [str(exc)],
                    }
                )
                return result

        algorithm = ssh_info.get("algorithm", "")
        fingerprint = ssh_info.get("fingerprint", "")
        is_allowed = algorithm in cfg.allowed_algorithms if cfg.allowed_algorithms else True
        notes: List[str] = []
        if not algorithm:
            notes.append("Unable to determine SSH algorithm")
        if not fingerprint:
            notes.append("SSH fingerprint unavailable")

        result.update(
            {
                "is_signed": True,
                "signature_type": "SSH",
                "algorithm": algorithm,
                "fingerprint": fingerprint,
                "ssh_algorithm_allowed": is_allowed,
                "notes": notes,
            }
        )
        return result

    if signature_type == "GPG":
        fingerprint_raw = parse_gpg_fingerprint(signature_block) or _fingerprint_from_text(log_text) or ""
        fingerprint = _sanitize_fingerprint(fingerprint_raw)
        is_allowed = True
        note = "GPG fingerprint extracted"
        if cfg.allowed_gpg_fingerprints:
            if fingerprint:
                is_allowed = fingerprint in cfg.allowed_gpg_fingerprints
                note = (
                    "GPG fingerprint matches allow list"
                    if is_allowed
                    else "GPG fingerprint not in allow list"
                )
            else:
                is_allowed = False
                note = "GPG fingerprint missing; cannot compare against allow list"
        notes = [note]
        if not fingerprint:
            notes.append("GPG fingerprint unavailable")

        result.update(
            {
                "is_signed": True,
                "signature_type": "GPG",
                "algorithm": "GPG",
                "fingerprint": fingerprint,
                "gpg_fingerprint_allowed": is_allowed,
                "notes": notes,
            }
        )
        return result

    result.update(
        {
            "signature_type": signature_type or "UNKNOWN",
            "notes": ["Unsupported or unrecognized signature type"],
        }
    )
    return result


def commits_in_range(cfg: Config) -> List[str]:
    head = cfg.head_sha.strip() or cfg.commit_sha or "HEAD"
    base = cfg.base_sha.strip()
    zero = "0" * 40
    rev_range = head
    if base and base != zero:
        rev_range = f"{base}..{head}"

    rev_list = _run_git(["rev-list", "--reverse", rev_range])
    if rev_list.returncode != 0:
        raise SystemExit(rev_list.stderr.strip() or "Failed to enumerate commits")

    commits = [line.strip() for line in rev_list.stdout.splitlines() if line.strip()]
    if not commits:
        commits = [head]
    return commits


def write_outputs(result: Dict[str, object]) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return
    if result.get("signature_type") == "SSH":
        allowed = result.get("ssh_algorithm_allowed", False)
    elif result.get("signature_type") == "GPG":
        allowed = result.get("gpg_fingerprint_allowed", False)
    else:
        allowed = False
    lines = [
        f"is-signed={'true' if result.get('is_signed') else 'false'}",
        f"algorithm={result.get('algorithm', '')}",
        f"is-allowed={'true' if allowed else 'false'}",
        f"fingerprint={result.get('fingerprint', '')}",
    ]
    with open(output_path, "a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def handle_single(cfg: Config) -> int:
    commit_ref = cfg.commit_sha or "HEAD"
    resolved = _run_git(["rev-parse", commit_ref])
    commit = resolved.stdout.strip() if resolved.returncode == 0 else commit_ref
    result = check_commit(commit_ref, cfg)
    write_outputs(result)
    _print_commit_result(result, commit)
    _emit_report([result])
    return 0


def handle_range(cfg: Config) -> int:
    commits = commits_in_range(cfg)
    report: List[Dict[str, object]] = []
    for commit in commits:
        result = check_commit(commit, cfg)
        _print_commit_result(result, commit)
        report.append(result)
    _emit_report(report)
    return 0


def _status_symbol(result: Dict[str, object]) -> str:
    if not result.get("is_signed"):
        return "⚠️"
    if result.get("signature_type") == "SSH":
        return "✅" if result.get("ssh_algorithm_allowed") else "⚠️"
    if result.get("signature_type") == "GPG":
        return "✅" if result.get("gpg_fingerprint_allowed") else "⚠️"
    return "ℹ️"


def _print_commit_result(result: Dict[str, object], commit_display: str) -> None:
    symbol = _status_symbol(result)
    signature_type = result.get("signature_type") or "UNKNOWN"
    algo = result.get("algorithm") or ""
    fingerprint = result.get("fingerprint") or ""
    message = f"{symbol} {commit_display} - type={signature_type}"
    if algo:
        message += f" algo={algo}"
    if fingerprint:
        message += f" fingerprint={fingerprint}"
    notes = result.get("notes") or []
    if notes:
        message += " [" + ", ".join(notes) + "]"
    if signature_type == "SSH" and not result.get("ssh_algorithm_allowed"):
        message += " [SSH algorithm not in allowed list]"
    if signature_type == "GPG" and not result.get("gpg_fingerprint_allowed"):
        message += " [GPG fingerprint not in allow list]"
    if not result.get("is_signed"):
        message += " [commit not signed]"
    print(message)


def _emit_report(report: List[Dict[str, object]]) -> None:
    if not report:
        return
    workspace = pathlib.Path(os.environ.get("GITHUB_WORKSPACE", "."))
    report_path = workspace / "commit-signature-report.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"📝 Commit signature report written to {report_path}")


def main() -> int:
    if len(sys.argv) < 2:
        raise SystemExit("Mode argument (single|range) is required")
    mode = sys.argv[1]
    cfg = Config.from_env()
    resolve_allowed_gpg_fingerprints(cfg)

    if mode == "single":
        return handle_single(cfg)
    if mode == "range":
        return handle_range(cfg)
    raise SystemExit(f"Unknown mode '{mode}'")


if __name__ == "__main__":
    sys.exit(main())
