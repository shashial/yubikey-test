#!/usr/bin/env python3
"""Verify git commit signatures for SSH (SK) and GPG commits."""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import os
import pathlib
import subprocess
import sys
import tempfile
from typing import Dict, List, Optional, Tuple


DEBUG = os.environ.get("SIGNATURE_DEBUG", "").strip().lower() in {"1", "true", "yes", "on"}


def debug(msg: str) -> None:
    if DEBUG:
        print(f"[verify-commit-signature] {msg}", file=sys.stderr)


def _read_git_output(args: List[str]) -> subprocess.CompletedProcess:
    result = subprocess.run(
        ["git", *args],
        check=False,
        capture_output=True,
        text=True,
    )
    return result


def _to_bool(value: Optional[str], default: bool = True) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _normalize_algorithms(raw: Optional[str]) -> List[str]:
    if not raw:
        return []
    return [alg.strip() for alg in raw.split(",") if alg.strip()]


@dataclasses.dataclass
class Config:
    commit_sha: str
    allowed_algorithms: List[str]
    fail_on_unsigned: bool
    ssh_allowed_signers: str
    ssh_allowed_signers_file: str
    base_sha: str
    head_sha: str
    ssh_verification_ready: bool = False

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            commit_sha=os.environ.get("INPUT_COMMIT_SHA", "HEAD").strip() or "HEAD",
            allowed_algorithms=_normalize_algorithms(
                os.environ.get("INPUT_ALLOWED_ALGORITHMS", "ED25519-SK,ECDSA-SK")
            ),
            fail_on_unsigned=_to_bool(os.environ.get("INPUT_FAIL_ON_UNSIGNED"), True),
            ssh_allowed_signers=os.environ.get("INPUT_SSH_ALLOWED_SIGNERS", ""),
            ssh_allowed_signers_file=os.environ.get("INPUT_SSH_ALLOWED_SIGNERS_FILE", ""),
            base_sha=os.environ.get("INPUT_BASE_SHA", ""),
            head_sha=os.environ.get("INPUT_HEAD_SHA", ""),
        )


def configure_allowed_signers(cfg: Config) -> bool:
    """Configure git to use an allowed_signers file if one is available."""

    def set_allowed_signers(path: pathlib.Path) -> None:
        subprocess.run(
            ["git", "config", "--global", "gpg.ssh.allowedSignersFile", str(path)],
            check=True,
        )

    if cfg.ssh_allowed_signers_file:
        path = pathlib.Path(cfg.ssh_allowed_signers_file).expanduser()
        if not path.is_file():
            raise SystemExit(
                f"Provided ssh-allowed-signers-file '{cfg.ssh_allowed_signers_file}' does not exist"
            )
        set_allowed_signers(path.resolve())
        return True

    content = cfg.ssh_allowed_signers.strip()
    if content:
        temp_dir = pathlib.Path(os.environ.get("RUNNER_TEMP", tempfile.mkdtemp()))
        temp_dir.mkdir(parents=True, exist_ok=True)
        file_path = temp_dir / "allowed_signers"
        file_path.write_text(content, encoding="utf-8")
        set_allowed_signers(file_path)
        return True

    existing = subprocess.run(
        ["git", "config", "--global", "--get", "gpg.ssh.allowedSignersFile"],
        capture_output=True,
        text=True,
        check=False,
    )
    if existing.returncode == 0:
        candidate = existing.stdout.strip()
        if candidate and pathlib.Path(candidate).expanduser().is_file():
            return True

    print(
        "⚠️  No ssh allowed_signers file configured; SSH signatures will be detected but not fully verified.",
        flush=True,
    )
    return False


def extract_signature_block(commit: str) -> str:
    raw = _read_git_output(["cat-file", "-p", commit])
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
    base64_payload = "".join(
        line.strip()
        for line in block.splitlines()
        if "BEGIN" not in line and "END" not in line and line.strip()
    )
    if not base64_payload:
        raise SSHSignatureParseError("missing SSH signature payload")

    decoded = base64.b64decode(base64_payload)
    debug(f"Decoded SSH signature length: {len(decoded)} bytes")
    if not decoded.startswith(b"SSHSIG"):
        raise SSHSignatureParseError("unexpected SSH signature marker")

    buf = memoryview(decoded)
    idx = len("SSHSIG")
    if len(buf) - idx < 4:
        raise SSHSignatureParseError("truncated SSH signature")
    version = int.from_bytes(buf[idx : idx + 4], "big")
    idx += 4
    if version != 1:
        raise SSHSignatureParseError(f"unsupported SSH signature version {version}")

    # Read public key, namespace, reserved and hash algorithm
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
    combined = text.splitlines()
    for line in combined:
        if "fingerprint" in line.lower():
            parts = line.split(":", 1)
            if len(parts) == 2:
                return parts[1].strip()
    return None


def _allowed_signers_error(output: str) -> bool:
    lowered = output.lower()
    return "allowedsignersfile" in lowered or "allowed signers" in lowered


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
    if not signature_block:
        return {
            "commit": commit,
            "is_signed": False,
            "reason": "Commit has no signature data",
        }

    log_proc = _read_git_output(["log", "--show-signature", "-1", commit])
    log_text = f"{log_proc.stdout}\n{log_proc.stderr}"

    signature_type = detect_signature_type(signature_block)
    verify_proc = _read_git_output(["verify-commit", commit])
    verification_ok = verify_proc.returncode == 0
    verify_output = (verify_proc.stdout + verify_proc.stderr).strip()

    if signature_type == "SSH":
        try:
            ssh_info = parse_ssh_signature(signature_block)
        except SSHSignatureParseError as exc:
            debug(f"SSH signature parse failed: {exc}")
            fallback = infer_ssh_from_text(signature_block, log_text)
            if not fallback:
                return {
                    "commit": commit,
                    "is_signed": False,
                    "reason": str(exc),
                    "signature_type": "SSH",
                }
            ssh_info = fallback

        algorithm = ssh_info["algorithm"]
        is_allowed = algorithm in cfg.allowed_algorithms if cfg.allowed_algorithms else True
        verified = verification_ok
        note = ""

        if not verification_ok:
            if not cfg.ssh_verification_ready or _allowed_signers_error(verify_output):
                verified = False
                note = "SSH signature detected but allowed_signers file missing on runner"
                debug(
                    "SSH verification skipped (allowed_signers missing). git output: %s"
                    % verify_output
                )
            else:
                reason = verify_output or "git verify-commit failed for SSH signature"
                return {
                    "commit": commit,
                    "is_signed": False,
                    "reason": reason,
                    "signature_type": "SSH",
                }

        return {
            "commit": commit,
            "is_signed": True,
            "signature_type": "SSH",
            "algorithm": algorithm,
            "fingerprint": ssh_info.get("fingerprint", ""),
            "is_allowed": is_allowed,
            "verified": verified,
            "note": note,
        }

    if signature_type == "GPG":
        fingerprint = parse_gpg_fingerprint(signature_block) or _fingerprint_from_text(log_text) or ""
        return {
            "commit": commit,
            "is_signed": True,
            "signature_type": "GPG",
            "algorithm": "GPG",
            "fingerprint": fingerprint,
            "is_allowed": True,
            "verified": verification_ok,
            "note": "GPG fingerprint extracted without enforcing algorithm",
        }

    return {
        "commit": commit,
        "is_signed": False,
        "reason": "Unsupported signature type",
    }


def commits_in_range(cfg: Config) -> List[str]:
    head = cfg.head_sha.strip() or cfg.commit_sha or "HEAD"
    if not head:
        head = "HEAD"
    base = cfg.base_sha.strip()
    rev_range = head
    zero = "0" * 40
    if base and base != zero:
        rev_range = f"{base}..{head}"

    rev_list = _read_git_output(["rev-list", "--reverse", rev_range])
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
    lines = [
        f"is-signed={'true' if result.get('is_signed') else 'false'}",
        f"algorithm={result.get('algorithm', '') or ''}",
        f"is-allowed={'true' if result.get('is_allowed') else 'false'}",
        f"fingerprint={result.get('fingerprint', '') or ''}",
    ]
    with open(output_path, "a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def handle_single(cfg: Config) -> int:
    commit = cfg.commit_sha or "HEAD"
    result = check_commit(commit, cfg)
    write_outputs(result)

    if not result.get("is_signed"):
        message = result.get("reason", "Commit is not signed")
        print(f"❌ {commit} - {message}")
        return 1 if cfg.fail_on_unsigned else 0

    if result.get("signature_type") == "SSH" and not result.get("is_allowed", False):
        print(
            f"❌ {commit} - Signed with disallowed algorithm '{result.get('algorithm')}'"
        )
        return 1

    algo = result.get("algorithm", "")
    fingerprint = result.get("fingerprint", "")
    status = "✅"
    if result.get("signature_type") == "SSH" and not result.get("verified"):
        status = "⚠️"
    elif result.get("signature_type") == "GPG" and not result.get("verified"):
        status = "ℹ️"

    if algo:
        line = f"{status} {commit} - Algorithm: {algo}"
    else:
        line = f"{status} {commit} - Signed"
    if fingerprint:
        line += f" (fingerprint: {fingerprint})"
    if result.get("note"):
        line += f" [{result['note']}]"
    print(line)
    return 0


def handle_range(cfg: Config) -> int:
    commits = commits_in_range(cfg)
    failed = False
    for commit in commits:
        result = check_commit(commit, cfg)
        if not result.get("is_signed"):
            reason = result.get("reason", "Commit is not signed")
            label = "❌" if cfg.fail_on_unsigned else "⚠️"
            print(f"{label} {commit} - {reason}")
            if cfg.fail_on_unsigned:
                failed = True
            continue

        if result.get("signature_type") == "SSH" and not result.get("is_allowed", False):
            print(
                f"❌ {commit} - Signed with disallowed algorithm '{result.get('algorithm')}'"
            )
            failed = True
            continue

        algo = result.get("algorithm", "")
        fingerprint = result.get("fingerprint", "")
        if result.get("signature_type") == "SSH":
            prefix = "✅" if result.get("verified") else "⚠️"
        else:
            prefix = "ℹ️"
        message = f"{prefix} {commit} - {algo or 'Signed'}"
        if fingerprint:
            message += f" (fingerprint: {fingerprint})"
        if result.get("signature_type") == "GPG" and not result.get("verified"):
            message += " [not verified - missing public key?]"
        if result.get("note"):
            message += f" [{result['note']}]"
        print(message)

    return 1 if failed else 0


def main() -> int:
    if len(sys.argv) < 2:
        raise SystemExit("Mode argument (single|range) is required")
    mode = sys.argv[1]
    cfg = Config.from_env()
    cfg.ssh_verification_ready = configure_allowed_signers(cfg)

    if mode == "single":
        return handle_single(cfg)
    if mode == "range":
        return handle_range(cfg)
    raise SystemExit(f"Unknown mode '{mode}'")


if __name__ == "__main__":
    sys.exit(main())
