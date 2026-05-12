#!/usr/bin/env python3
"""Cross-implementation parity harness for the Traffic Cypher PM.

Boots each PM in turn against an isolated vault file, replays the same
HTTP request sequence, normalises the responses, and asserts that the C
and Rust outputs match. Cases live in parity/cases.json — see the
"_comment" block there for the schema.

Pure-stdlib only: subprocess, urllib.request, json, tempfile, pathlib,
time, socket. Runnable as:

    python3 parity/parity_test.py
    python3 parity/parity_test.py --max-cases 4
    python3 parity/parity_test.py --case create_with_tags
    python3 parity/parity_test.py --verbose

Exits 0 if every case either matched exactly or is flagged
`expected_diff: true`. Exits 1 on any unflagged divergence or any
infrastructure failure (binary missing, port stuck, etc.).
"""

import argparse
import difflib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
CASES_PATH = Path(__file__).resolve().parent / "cases.json"

C_PM_PATH = REPO_ROOT / "traffic_cypher_in_C" / "traffic-cypher-pm"
RUST_PM_PATH = REPO_ROOT / "traffic_cypher_in_Rust" / "target" / "release" / "pm"

PM_PORT = 9876
PM_BASE = f"http://127.0.0.1:{PM_PORT}"
BOOT_TIMEOUT_S = 5.0
SHUTDOWN_WAIT_S = 3.0
# Wait up to this long for the LISTEN socket to free after we kill the PM.
# The C PM's graceful-shutdown handshake (worker pool join + rotation
# daemon join) can take a second or two even after SIGTERM. SO_LINGER
# / TIME_WAIT only affects connected sockets — the LISTEN socket
# disappears when the process exits.
PORT_DRAIN_TIMEOUT_S = 6.0
REQUEST_TIMEOUT_S = 5.0


# ---------------------------------------------------------------------------
# Pretty output helpers
# ---------------------------------------------------------------------------

def _isatty() -> bool:
    return sys.stdout.isatty()


GREEN = "\033[0;32m" if _isatty() else ""
RED = "\033[0;31m" if _isatty() else ""
YELLOW = "\033[1;33m" if _isatty() else ""
CYAN = "\033[0;36m" if _isatty() else ""
BOLD = "\033[1m" if _isatty() else ""
NC = "\033[0m" if _isatty() else ""


def info(msg: str) -> None:
    print(f"  {msg}")


def header(msg: str) -> None:
    print(f"\n{BOLD}{CYAN}==> {msg}{NC}")


def ok(msg: str) -> None:
    print(f"  {GREEN}PASS{NC}: {msg}")


def warn(msg: str) -> None:
    print(f"  {YELLOW}WARN{NC}: {msg}")


def err(msg: str) -> None:
    print(f"  {RED}FAIL{NC}: {msg}")


# ---------------------------------------------------------------------------
# Subprocess + HTTP helpers
# ---------------------------------------------------------------------------

def port_is_free(port: int) -> bool:
    """True iff nothing is listening on 127.0.0.1:port."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.2)
    try:
        rc = s.connect_ex(("127.0.0.1", port))
    finally:
        s.close()
    return rc != 0


def wait_port_free(port: int, timeout_s: float) -> bool:
    """Poll until nothing is bound to `port`, or timeout."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if port_is_free(port):
            return True
        time.sleep(0.1)
    return port_is_free(port)


def wait_for_port(port: int, timeout_s: float) -> bool:
    """Poll /api/auth/status until the listener accepts a connection."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/api/auth/status",
                timeout=1.0,
            ) as resp:
                resp.read()
                return True
        except (urllib.error.URLError, ConnectionError, socket.timeout, OSError):
            time.sleep(0.1)
    return False


def http_request(method: str, path: str, body, token: str | None):
    """Send an HTTP request to the running PM and return (status, json|text)."""
    url = PM_BASE + path
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_S) as resp:
            raw = resp.read()
            status = resp.status
    except urllib.error.HTTPError as e:
        raw = e.read()
        status = e.code
    except urllib.error.URLError as e:
        return (0, {"_transport_error": str(e)})

    text = raw.decode("utf-8", errors="replace")
    if not text:
        return (status, None)
    try:
        return (status, json.loads(text))
    except json.JSONDecodeError:
        return (status, text)


# ---------------------------------------------------------------------------
# Variable substitution and normalisation
# ---------------------------------------------------------------------------

def substitute(value, ctx: dict):
    """Recursively expand ${name} tokens in strings using ctx."""
    if isinstance(value, str):
        out = value
        for k, v in ctx.items():
            out = out.replace(f"${{{k}}}", str(v))
        return out
    if isinstance(value, dict):
        return {k: substitute(v, ctx) for k, v in value.items()}
    if isinstance(value, list):
        return [substitute(v, ctx) for v in value]
    return value


def normalize(value, drop_keys: list):
    """Recursively drop keys in `drop_keys`. Sort `tags` arrays.

    Sorting tags is correct here because the JSON contract treats tags as
    a set — the C and Rust list orders are unspecified, so order-sensitive
    comparison would generate spurious diffs.
    """
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if k in drop_keys:
                continue
            if k == "tags" and isinstance(v, list):
                out[k] = sorted(normalize(item, drop_keys) for item in v)
            else:
                out[k] = normalize(v, drop_keys)
        return out
    if isinstance(value, list):
        return [normalize(v, drop_keys) for v in value]
    return value


def pretty(value) -> str:
    return json.dumps(value, indent=2, sort_keys=True, default=str)


# ---------------------------------------------------------------------------
# Single-impl replay
# ---------------------------------------------------------------------------

class ReplayError(Exception):
    """Raised when an impl cannot complete a request sequence."""


def replay_against_impl(impl_name: str, binary: Path, case: dict, verbose: bool):
    """Boot `binary` against a fresh vault and walk the request list."""
    if not binary.exists() or not os.access(binary, os.X_OK):
        raise ReplayError(f"{impl_name}: binary not executable: {binary}")

    if not port_is_free(PM_PORT):
        raise ReplayError(
            f"port {PM_PORT} already in use; stop the running PM and retry"
        )

    # Per-impl-run isolated vault file.
    vault_fd, vault_path = tempfile.mkstemp(
        prefix=f"parity_{impl_name}_", suffix=".json"
    )
    os.close(vault_fd)
    os.unlink(vault_path)  # PM creates it on first save

    env = os.environ.copy()
    env["TRAFFIC_CYPHER_VAULT_PATH"] = vault_path
    # Some tests source ~/.bashrc which can leak settings; HOME→tmp is
    # safer (mirrors tests/32_rust_build_info.sh).
    tmp_home = tempfile.mkdtemp(prefix=f"parity_{impl_name}_home_")
    env["HOME"] = tmp_home

    log_fd, log_path = tempfile.mkstemp(
        prefix=f"parity_{impl_name}_log_", suffix=".txt"
    )
    log_file = os.fdopen(log_fd, "w+b")

    proc = subprocess.Popen(
        [str(binary)],
        env=env,
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )

    try:
        if not wait_for_port(PM_PORT, BOOT_TIMEOUT_S):
            log_file.flush()
            log_file.seek(0)
            log_tail = log_file.read().decode("utf-8", errors="replace")[-2000:]
            raise ReplayError(
                f"{impl_name} did not bind {PM_PORT} within {BOOT_TIMEOUT_S}s. "
                f"Log tail:\n{log_tail}"
            )

        ctx: dict[str, str] = {}
        token: str | None = None
        responses = []

        for i, raw_req in enumerate(case["requests"]):
            req = substitute(raw_req, ctx)
            method = req["method"]
            path = req["path"]
            body = req.get("body")
            expect_status = req.get("expect_status")

            status, payload = http_request(method, path, body, token)

            if verbose:
                info(f"  [{impl_name}] #{i} {method} {path} -> {status}")

            if expect_status is not None:
                if status != expect_status:
                    raise ReplayError(
                        f"{impl_name} req#{i} {method} {path}: "
                        f"expected status {expect_status}, got {status}; "
                        f"body={payload!r}"
                    )
            elif not (200 <= status < 300):
                raise ReplayError(
                    f"{impl_name} req#{i} {method} {path}: "
                    f"non-2xx status {status}; body={payload!r}"
                )

            # Save substitution variables from the response.
            if isinstance(payload, dict):
                if "save_token_from" in req:
                    key = req["save_token_from"]
                    if key not in payload:
                        raise ReplayError(
                            f"{impl_name} req#{i}: response missing key "
                            f"{key!r} for save_token_from; got {payload!r}"
                        )
                    token = payload[key]
                    ctx["token"] = token
                if "save_id_from" in req:
                    key = req["save_id_from"]
                    if key not in payload:
                        raise ReplayError(
                            f"{impl_name} req#{i}: response missing key "
                            f"{key!r} for save_id_from; got {payload!r}"
                        )
                    ctx["id"] = payload[key]

            responses.append({"status": status, "body": payload})

        return responses

    finally:
        try:
            proc.terminate()
            try:
                proc.wait(timeout=SHUTDOWN_WAIT_S)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=SHUTDOWN_WAIT_S)
        except Exception:
            pass
        log_file.close()
        try:
            os.unlink(log_path)
        except FileNotFoundError:
            pass
        try:
            os.unlink(vault_path)
        except FileNotFoundError:
            pass
        # Side-files written next to vault (e.g. .stream_config).
        for sibling in Path(vault_path).parent.glob(
            Path(vault_path).name + "*"
        ):
            try:
                sibling.unlink()
            except FileNotFoundError:
                pass
        try:
            for p in Path(tmp_home).rglob("*"):
                if p.is_file():
                    p.unlink()
            for p in sorted(
                Path(tmp_home).rglob("*"), key=lambda x: -len(str(x))
            ):
                if p.is_dir():
                    p.rmdir()
            Path(tmp_home).rmdir()
        except FileNotFoundError:
            pass
        # Block until the LISTEN socket is gone. terminate() returns
        # before the C PM has joined its worker pool; without this poll
        # the *next* impl run hits "port already in use".
        if not wait_port_free(PM_PORT, PORT_DRAIN_TIMEOUT_S):
            # Don't raise — let the next replay's own port-free check
            # report the failure with full context.
            pass


# ---------------------------------------------------------------------------
# Case runner
# ---------------------------------------------------------------------------

def run_case(case: dict, verbose: bool) -> str:
    """Run a single case against both impls. Returns one of:
        "pass"             — normalised responses match exactly
        "expected_diff"    — responses differ, but case is flagged as KNOWN
        "fail"             — unflagged divergence or infrastructure error
    """
    name = case["name"]
    header(f"case: {name}")
    if case.get("expected_diff"):
        info(f"flagged expected_diff: {case.get('reason', '(no reason given)')}")

    drop_keys = case.get("normalize_drop", [])

    try:
        c_resp = replay_against_impl("c", C_PM_PATH, case, verbose)
    except ReplayError as e:
        err(f"C impl replay failed: {e}")
        return "fail"

    try:
        rust_resp = replay_against_impl("rust", RUST_PM_PATH, case, verbose)
    except ReplayError as e:
        err(f"Rust impl replay failed: {e}")
        return "fail"

    if len(c_resp) != len(rust_resp):
        err(
            f"response count mismatch: c={len(c_resp)} rust={len(rust_resp)}"
        )
        return "fail"

    any_diff = False
    for i, (c, r) in enumerate(zip(c_resp, rust_resp)):
        nc = {"status": c["status"], "body": normalize(c["body"], drop_keys)}
        nr = {"status": r["status"], "body": normalize(r["body"], drop_keys)}
        if nc != nr:
            any_diff = True
            req = case["requests"][i]
            label = f"req#{i} {req['method']} {req['path']}"
            if case.get("expected_diff"):
                warn(f"KNOWN-DIVERGENT at {label}")
            else:
                err(f"mismatch at {label}")
            c_lines = pretty(nc).splitlines(keepends=True)
            r_lines = pretty(nr).splitlines(keepends=True)
            diff = difflib.unified_diff(
                c_lines, r_lines, fromfile="c", tofile="rust", lineterm=""
            )
            for line in diff:
                print(f"    {line.rstrip()}")

    if any_diff:
        if case.get("expected_diff"):
            warn(f"{name}: KNOWN-DIVERGENT (expected_diff=true)")
            return "expected_diff"
        return "fail"

    ok(f"{name}: parity OK")
    return "pass"


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Cross-impl parity harness")
    ap.add_argument(
        "--cases-file", default=str(CASES_PATH),
        help="path to cases.json",
    )
    ap.add_argument(
        "--max-cases", type=int, default=None,
        help="cap number of cases to run (smoke mode)",
    )
    ap.add_argument(
        "--case", action="append", default=None,
        help="run only this case name (may be passed multiple times)",
    )
    ap.add_argument(
        "--verbose", "-v", action="store_true",
        help="print every request/response status",
    )
    args = ap.parse_args()

    with open(args.cases_file, "r", encoding="utf-8") as f:
        cases_doc = json.load(f)
    cases = cases_doc.get("cases", [])

    if args.case:
        wanted = set(args.case)
        cases = [c for c in cases if c["name"] in wanted]
        if not cases:
            err(f"no cases matched names: {sorted(wanted)}")
            return 1

    if args.max_cases is not None:
        cases = cases[: args.max_cases]

    if not cases:
        err("no cases to run")
        return 1

    for b in (C_PM_PATH, RUST_PM_PATH):
        if not b.exists():
            err(f"binary not built: {b}")
            return 1

    if not port_is_free(PM_PORT):
        err(f"port {PM_PORT} is already in use; stop the running PM first")
        return 1

    start = time.monotonic()
    pass_n = fail_n = known_n = 0
    failed_names = []
    for case in cases:
        rc = run_case(case, args.verbose)
        if rc == "pass":
            pass_n += 1
        elif rc == "expected_diff":
            known_n += 1
        else:
            fail_n += 1
            failed_names.append(case["name"])

    elapsed = time.monotonic() - start
    print(f"\n{BOLD}========================================{NC}")
    print(
        f"  {GREEN}PASS{NC}: {pass_n}   "
        f"{YELLOW}KNOWN-DIVERGENT{NC}: {known_n}   "
        f"{RED}FAIL{NC}: {fail_n}   ({elapsed:.1f}s)"
    )
    if failed_names:
        print(f"  {RED}Failed:{NC}")
        for n in failed_names:
            print(f"    - {n}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
