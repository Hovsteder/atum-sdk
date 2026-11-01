#!/usr/bin/env python3
"""Opt-in public-only integration check. No ATUM private source is imported.

Requires Python Playwright/Chromium, Node/npm dependencies installed with npm ci,
PostgreSQL 16 binaries, openssl and an already synchronized local chrony observer.
Creates a real test passport and service on the configured public ATUM hosts.
The passkey is virtual. The resource, database, keys and Agent state are temporary.
Revokes the test grant on success; the public test passport/service audit remains.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import re
import selectors
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import urlencode

REPO = Path(__file__).resolve().parents[1]
EXAMPLE = REPO / "sdk/examples/calendar-resource"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def command(args, **kwargs):
    result = subprocess.run(args, capture_output=True, text=True, timeout=30, **kwargs)
    require(result.returncode == 0, "local setup command failed: " + Path(str(args[0])).name)
    return result.stdout


def port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class PrivatePostgres:
    """Only a newly initialized Unix-socket cluster; never accepts a database URL."""
    def __init__(self):
        self.root = Path(tempfile.mkdtemp(prefix="atum-sdk-pg-"))
        self.socket = self.root / "socket"
        self.socket.mkdir(mode=0o700)
        self.data = self.root / "data"
        self.number = port()
        self.bin = Path(os.environ.get("ATUM_TEST_PG_BIN", "/usr/lib/postgresql/16/bin"))
        self.prefix = []
        if os.geteuid() == 0:
            account = pwd.getpwnam("postgres")
            for path in (self.root, self.socket):
                os.chown(path, account.pw_uid, account.pw_gid)
            self.prefix = ["runuser", "-u", "postgres", "--"]
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("PG") and k != "DATABASE_URL"}
        self.initialized = False

    def execute(self, binary, *args):
        return command([*self.prefix, str(self.bin / binary), *args], env=self.env, cwd="/tmp")

    def initialize(self):
        self.execute("initdb", "-D", str(self.data), "-U", "postgres", "--auth-local=trust",
                     "--auth-host=reject", "--no-locale", "--encoding=UTF8")
        self.initialized = True
        self.start()

    def start(self):
        self.execute("pg_ctl", "-D", str(self.data), "-l", str(self.root / "postgres.log"),
                     "-o", f"-k {self.socket} -p {self.number} -c listen_addresses='' -c max_connections=32", "-w", "start")

    def stop(self):
        if not self.initialized:
            return
        status = subprocess.run([*self.prefix, str(self.bin / "pg_ctl"), "-D", str(self.data), "status"],
                                env=self.env, cwd="/tmp", capture_output=True)
        if status.returncode == 0:
            self.execute("pg_ctl", "-D", str(self.data), "-m", "fast", "-w", "stop")

    def count(self):
        return int(self.execute("psql", "-h", str(self.socket), "-p", str(self.number), "-U", "postgres",
                                "-d", "postgres", "-At", "-c", "SELECT count(*) FROM atum_example_calendar_usage"))

    @property
    def url(self):
        return "postgresql://postgres@/postgres?" + urlencode({"host": str(self.socket), "port": self.number})

    def close(self):
        self.stop()
        shutil.rmtree(self.root)


class TcpForwarder:
    """Transparent L4 forwarding. Never decrypts TLS or changes HTTP headers."""
    def __init__(self, destination):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.number = self.listener.getsockname()[1]
        self.listener.listen()
        self.listener.settimeout(.2)
        self.destination = destination
        self.stopped = threading.Event()
        self.lock = threading.Lock()
        self.connections = set()
        self.threads = []
        self.count = 0
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def accept(self):
        while not self.stopped.is_set():
            try:
                incoming, _ = self.listener.accept()
            except (TimeoutError, OSError):
                continue
            try:
                outgoing = socket.create_connection(("127.0.0.1", self.destination), timeout=3)
                outgoing.settimeout(None)
            except OSError:
                incoming.close()
                continue
            with self.lock:
                self.count += 1
                self.connections.update((incoming, outgoing))
            thread = threading.Thread(target=self.forward, args=(incoming, outgoing), daemon=True)
            self.threads.append(thread)
            thread.start()

    def forward(self, incoming, outgoing):
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(incoming, selectors.EVENT_READ, outgoing)
                selector.register(outgoing, selectors.EVENT_READ, incoming)
                while not self.stopped.is_set():
                    for key, _ in selector.select(.2):
                        data = key.fileobj.recv(65536)
                        if not data:
                            return
                        key.data.sendall(data)
        except OSError:
            pass
        finally:
            for connection in (incoming, outgoing):
                connection.close()
            with self.lock:
                self.connections.difference_update((incoming, outgoing))

    def close(self):
        self.stopped.set()
        self.listener.close()
        with self.lock:
            for connection in self.connections:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        self.thread.join(3)
        for thread in self.threads:
            thread.join(3)
        require(not self.thread.is_alive() and not any(t.is_alive() for t in self.threads), "TCP forwarding cleanup failed")


def certificates(root):
    ca, ca_key, cert, key = (root / n for n in ("ca.pem", "ca.key", "localhost.pem", "localhost.key"))
    command(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-subj", "/CN=ATUM SDK disposable CA", "-keyout", str(ca_key), "-out", str(ca)])
    csr = root / "localhost.csr"
    command(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
             "-keyout", str(key), "-out", str(csr)])
    extensions = root / "extensions"
    extensions.write_text("subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n")
    command(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key),
             "-CAcreateserial", "-days", "1", "-extfile", str(extensions), "-out", str(cert)])
    for path in root.iterdir():
        path.chmod(0o600)
    return ca, cert, key


def authenticator(context, page):
    cdp = context.new_cdp_session(page)
    cdp.send("WebAuthn.enable", {"enableUI": False})
    result = cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
        "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
        "hasUserVerification": True, "isUserVerified": True, "automaticPresenceSimulation": True}})
    return cdp, result["authenticatorId"]


def first_line(child):
    with selectors.DefaultSelector() as selector:
        selector.register(child.stdout, selectors.EVENT_READ)
        require(selector.select(20), "child did not report readiness")
    return child.stdout.readline()


def stop(child):
    if child is None:
        return
    if child.poll() is None:
        child.terminate()
    try:
        child.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        child.kill()
        child.communicate(timeout=5)
        raise RuntimeError("child required forced termination")


def run(args):
    from playwright.sync_api import expect, sync_playwright
    require(Path(os.environ.get("ATUM_CHRONYC_PATH", "/usr/bin/chronyc")).is_file(), "configure ATUM_CHRONYC_PATH")
    root = Path(tempfile.mkdtemp(prefix="atum-sdk-hosted-"))
    root.chmod(0o700)
    pg = forwarder = clock = resource = agent = browser = context = playwright = None
    report = {"ok": False, "cleanup": False, "stage": "setup", "fixtures": [
        "Chromium virtual CTAP2 passkey", "temporary localhost CA", "private Unix PostgreSQL trust auth",
        "empty calendar", "transparent local TCP forwarding"], "public_hosts": [args.passport, args.issuer, args.verify],
        "private_source_imports": False, "public_audit_retained": True}
    env = {k: v for k, v in os.environ.items() if not k.startswith("ATUM_") and not k.startswith("PG") and k != "DATABASE_URL"}
    env.update({k: v for k, v in os.environ.items() if k in ("ATUM_CHRONYC_PATH", "ATUM_CHRONYC_PORT")})
    env["ATUM_CLOCK_OBSERVATION_FILE"] = str(root / "clock.json")
    children = []
    try:
        pg = PrivatePostgres()
        pg.initialize()
        ca, cert, key = certificates(root)
        backend_port = port()
        forwarder = TcpForwarder(backend_port)
        endpoint = f"https://localhost:{forwarder.number}/v1/atum/operations"
        clock = subprocess.Popen(["node", str(REPO / "sdk/packages/verification/bin/atum-clock.mjs")], env=env,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        children.append(clock)
        deadline = time.monotonic() + 10
        while not (root / "clock.json").exists() and time.monotonic() < deadline:
            time.sleep(.1)
        require((root / "clock.json").exists(), "real chrony observation unavailable")
        playwright = sync_playwright().start()
        launch = {"headless": True, "args": ["--no-sandbox"] if os.geteuid() == 0 else []}
        if os.environ.get("ATUM_TEST_CHROMIUM"):
            launch["executable_path"] = os.environ["ATUM_TEST_CHROMIUM"]
        browser = playwright.chromium.launch(**launch)
        context = browser.new_context()
        page = context.new_page()
        report["stage"] = "passport registration/login"
        page.goto(args.passport, wait_until="networkidle")
        cdp, auth_id = authenticator(context, page)
        page.get_by_role("button", name="Create passport").click()
        page.get_by_role("status").get_by_text("Passport created", exact=False).wait_for(timeout=20_000)
        page.locator("#sign-in").click()
        expect(page.locator("#session-panel")).to_be_visible(timeout=20_000)
        credentials = cdp.send("WebAuthn.getCredentials", {"authenticatorId": auth_id})["credentials"]
        report["stage"] = "open service registration"
        page.goto(args.passport + "/developer", wait_until="networkidle")
        page.locator("#service-name").fill("ATUM public SDK acceptance")
        page.locator("#service-origin").fill(f"https://localhost:{forwarder.number}")
        page.locator("#permissions").fill("calendar.event.read")
        page.get_by_role("button", name="Connect service").click()
        expect(page.locator("#developer-status")).to_contain_text("Service connected", timeout=20_000)
        credential = page.locator("#credential").inner_text()
        require(credential.startswith("atum_svc_"), "service credential not issued")
        env.update({"ATUM_SERVICE_ACCESS_URL": args.verify, "ATUM_SERVICE_CREDENTIAL": credential,
                    "ATUM_CALENDAR_ENDPOINT": endpoint, "ATUM_CALENDAR_LISTEN_HOST": "127.0.0.1",
                    "ATUM_CALENDAR_LISTEN_PORT": str(backend_port), "ATUM_CALENDAR_DATABASE_URL": pg.url,
                    "ATUM_CALENDAR_TLS_KEY_FILE": str(key), "ATUM_CALENDAR_TLS_CERT_FILE": str(cert)})
        report["stage"] = "public example configuration"
        command(["node", "server.mjs", "--migrate"], cwd=EXAMPLE, env=env)
        config = root / "agent.json"
        command(["node", "server.mjs", "--export-agent-config", str(config)], cwd=EXAMPLE, env=env)
        require(credential not in config.read_text(), "public config disclosed service credential")

        def start_resource():
            child = subprocess.Popen(["node", "server.mjs"], cwd=EXAMPLE, env=env,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            children.append(child)
            require("calendar resource listening" in first_line(child), "resource startup failed")
            return child

        resource = start_resource()
        agent_env = {k: v for k, v in env.items() if k not in ("ATUM_SERVICE_ACCESS_URL", "ATUM_SERVICE_CREDENTIAL", "ATUM_CALENDAR_DATABASE_URL")}
        agent_env.update({"ATUM_AGENT_CONFIG_FILE": str(config), "ATUM_AGENT_STATE_DIR": str(root / "agent-state"),
                          "ATUM_CALENDAR_CA_FILE": str(ca)})

        def agent_command(*parts):
            return subprocess.run(["node", "device-agent.mjs", *parts], cwd=EXAMPLE, env=agent_env,
                                  capture_output=True, text=True, timeout=30)

        report["stage"] = "actual Device consent"
        agent = subprocess.Popen(["node", "device-agent.mjs", "authorize"], cwd=EXAMPLE, env=agent_env,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        children.append(agent)
        instruction = first_line(agent)
        match = re.fullmatch(re.escape("Open " + args.issuer + "/device and enter ") + r"([A-Z0-9-]+)\.\n", instruction)
        require(match is not None, "Device code not issued")
        device = context.new_page()
        device.goto(args.issuer + "/device", wait_until="networkidle")
        device.locator('input[name="user_code"]').fill(match.group(1))
        device.get_by_role("button", name="Continue", exact=True).click()
        expect(device.get_by_role("heading", name="Confirm your code")).to_be_visible(timeout=20_000)
        device.get_by_role("button", name="Continue", exact=True).click()
        with context.expect_page() as popup:
            device.get_by_role("link", name=re.compile("Open Atum Passport", re.I)).click()
        consent = popup.value
        consent.wait_for_load_state("networkidle")
        consent_cdp, consent_id = authenticator(context, consent)
        for item in credentials:
            consent_cdp.send("WebAuthn.addCredential", {"authenticatorId": consent_id, "credential": item})
        consent.locator("#grant-issue").click()
        expect(consent.locator("#grant-state")).to_have_text("active", timeout=20_000)
        device.locator("#complete").click()
        output, _ = agent.communicate(timeout=40)
        require(agent.returncode == 0 and "confirmed" in output, "Agent authorization failed")
        state_path = root / "agent-state/agent-state.json"
        saved_key = json.loads(state_path.read_text())["private_jwk"]
        report["stage"] = "public Verify and durable invocation"
        first = agent_command("invoke", "first")
        require(first.returncode == 0 and '"permission_checked":true' in first.stdout, "first invocation failed")
        require(pg.count() == 1, "first invocation missing resource acceptance")
        connections = forwarder.count
        repeat = agent_command("invoke", "first")
        require(repeat.returncode == 0 and forwarder.count == connections and pg.count() == 1,
                "fresh Agent process retransmitted saved operation")
        report["stage"] = "resource/database restart and token refresh"
        stop(resource)
        pg.stop()
        pg.start()
        resource = start_resource()
        require(pg.count() == 1, "database restart lost acceptance")
        refreshed = agent_command("refresh")
        require(refreshed.returncode == 0, "explicit refresh failed")
        require(json.loads(state_path.read_text())["private_jwk"] == saved_key, "Agent key changed across processes")
        second = agent_command("invoke", "second")
        require(second.returncode == 0 and '"permission_checked":true' in second.stdout and pg.count() == 2,
                "second invocation failed after restart")
        report["stage"] = "real owner revocation and subsequent denial"
        consent.locator("#grant-revoke").click()
        expect(consent.locator("#grant-issue")).to_contain_text("Confirm revocation", timeout=20_000)
        consent.locator("#grant-issue").click()
        expect(consent.locator("#grant-state")).to_have_text("revoked", timeout=20_000)
        denied = agent_command("invoke", "after-revoke")
        require(denied.returncode != 0 and "grant_not_active" in denied.stdout + denied.stderr and pg.count() == 2,
                "revoked grant was not explicitly denied without resource effect")
        report.update({"ok": True, "stage": "complete", "real_owner_consent": True, "grant_revoked": True,
                       "resource_acceptances": 2, "agent_restart_no_duplicate_http": True,
                       "agent_key_preserved": True, "explicit_refresh": True, "private_pg_restart": True,
                       "revoked_new_request_denied": True, "public_tls_validation": True,
                       "resource_tls_validation": True, "measured_chrony": True, "tcp_passthrough": True})
    except Exception as error:
        report["error_type"] = type(error).__name__
        if type(error) is RuntimeError:
            report["reason"] = str(error)
    finally:
        cleanup_errors = []
        for child in reversed(children):
            try:
                stop(child)
            except Exception:
                cleanup_errors.append("child process")
        for thing in (context, browser, forwarder, pg):
            if thing is not None:
                try:
                    thing.close()
                except Exception:
                    cleanup_errors.append(type(thing).__name__)
        if playwright:
            try:
                playwright.stop()
            except Exception:
                cleanup_errors.append("Playwright")
        shutil.rmtree(root)
        report["cleanup"] = not cleanup_errors
        report["cleanup_errors"] = cleanup_errors
        report["source_hashes"] = {str(p.relative_to(REPO)): hashlib.sha256(p.read_bytes()).hexdigest()
                                   for p in (Path(__file__), EXAMPLE / "device-agent.mjs", EXAMPLE / "server.mjs")}
        serialized = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.report:
            Path(args.report).write_text(serialized)
        print(serialized)
    return 0 if report["ok"] and report["cleanup"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="create real public test owner/service/consent")
    parser.add_argument("--report", help="safe JSON result path; no credentials are written here")
    parser.add_argument("--passport", default="https://passport.atum.digital")
    parser.add_argument("--issuer", default="https://auth.atum.digital")
    parser.add_argument("--verify", default="https://verify.atum.digital")
    args = parser.parse_args()
    if not args.run:
        parser.print_help()
    else:
        raise SystemExit(run(args))
