#!/usr/bin/env python3
"""
ghorgscan.py - single-file GitHub organisation / domain recon + hardening scanner.

Maps a domain -> GitHub orgs/users, enumerates every repo the token can see
(public AND private), and reports hardening + secret-exposure findings.

  python ghorgscan.py doctor
  python ghorgscan.py discover -d acme.com
  python ghorgscan.py scan -d acme.com --json --html
  python ghorgscan.py scan -o acme --deep --clone

Auth: set GITHUB_TOKEN. Classic scopes: repo, read:org, security_events
"""

from __future__ import annotations

import argparse
import base64
import csv
import html as htmllib
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

VERSION = "1.0.0"
API = "https://api.github.com"
UA = f"ghorgscan/{VERSION}"

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

LOG_PATH: str | None = None
_LOG_LOCK = threading.Lock()


def log(msg: str) -> None:
    line = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
    with _LOG_LOCK:
        print(line, file=sys.stderr)
        if LOG_PATH:
            with open(LOG_PATH, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")


# ---------------------------------------------------------------- patterns ---

SECRET_PATTERNS: dict[str, tuple[re.Pattern, str]] = {
    "github_pat": (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"), "critical"),
    "github_fine_pat": (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}\b"), "critical"),
    "aws_access_key": (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "high"),
    "aws_secret_key": (re.compile(r"(?i)aws_?secret_?access_?key\D{0,10}([A-Za-z0-9/+=]{40})"), "high"),
    "stripe_live": (re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b"), "critical"),
    "openai_key": (re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{24,}\b"), "high"),
    "anthropic_key": (re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"), "high"),
    "slack_token": (re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"), "high"),
    "slack_webhook": (re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"), "medium"),
    "google_api_key": (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "medium"),
    "sendgrid_key": (re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"), "high"),
    "npm_token": (re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), "high"),
    "twilio_key": (re.compile(r"\bSK[0-9a-fA-F]{32}\b"), "medium"),
    "private_key_block": (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), "critical"),
    "db_url_with_creds": (re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/'\"]+:[^\s@/'\"]+@[^\s/'\"]+"), "high"),
    "jwt": (re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), "low"),
    "gcp_service_account": (re.compile(r'"type"\s*:\s*"service_account"'), "medium"),
    "generic_credential": (
        re.compile(r"(?i)\b(?:password|passwd|pwd|secret|api_?key|access_?token|auth_?token)\b\s*[:=]\s*['\"]([^'\"\s]{8,80})['\"]"),
        "low",
    ),
}

PLACEHOLDER_HINTS = (
    "your", "xxx", "example", "changeme", "change_me", "placeholder", "dummy",
    "sample", "${", "***", "redacted", "fake", "todo", "<", "none", "null",
)

SENSITIVE_PATHS = [
    ".env", ".env.local", ".env.production", ".env.development", ".env.example",
    "config.json", "config.js", "config.py", "settings.py", "application.properties",
    "application.yml", "docker-compose.yml", "docker-compose.yaml", ".npmrc",
    ".pypirc", "credentials.json", "id_rsa", "id_ed25519", "firebase.json",
    "terraform.tfvars", ".aws/credentials", "docker-compose.prod.yml",
]

RESERVED_SLUGS = {
    "orgs", "features", "marketplace", "login", "apps", "sponsors", "topics",
    "settings", "pricing", "about", "site", "blog", "security", "enterprise",
    "readme", "collections", "events", "trending", "search", "new", "join",
    "notifications", "dashboard", "explore", "users", "contact", "careers",
    "pulls", "issues", "codespaces", "copilot", "solutions", "resources",
    "customer-stories", "education", "mobile", "github", "account", "logout",
}

CLONE_SKIP_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", ".venv", "venv",
    "__pycache__", "target", ".next", ".nuxt", "site-packages", ".mypy_cache",
    "coverage", ".pytest_cache", "bower_components",
}

CLONE_SKIP_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".bmp", ".tiff",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".mov", ".mp3", ".wav",
    ".zip", ".tar", ".gz", ".7z", ".rar", ".pdf", ".jar", ".war", ".class",
    ".pyc", ".so", ".dll", ".exe", ".bin", ".map",
}

SCAN_MAX_FILE = 1_000_000
SCAN_MAX_FILES = 4000


# ------------------------------------------------------------------ client ---

class TokenBucket:
    def __init__(self, rate_per_min: float, burst: int = 1):
        self.interval = 60.0 / max(rate_per_min, 0.1)
        self.lock = threading.Lock()
        self.next_at = 0.0
        self.burst = burst
        self.tokens = float(burst)

    def acquire(self) -> None:
        with self.lock:
            now = time.monotonic()
            if self.next_at < now:
                self.next_at = now
            delay = self.next_at - now
            self.next_at += self.interval
        if delay > 0:
            time.sleep(delay)


class Client:
    def __init__(self, token: str, workers: int = 6, verbose: bool = False):
        self.token = token
        self.verbose = verbose
        self.sess = requests.Session()
        self.sess.headers.update({
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": UA,
        })
        if token:
            self.sess.headers["Authorization"] = f"Bearer {token}"
        retry = Retry(
            total=4, backoff_factor=0.9,
            status_forcelist=(500, 502, 503, 504),
            allowed_methods=frozenset({"GET"}),
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=workers * 3, pool_maxsize=workers * 3)
        self.sess.mount("https://", adapter)
        self.search_bucket = TokenBucket(20)
        self.core_lock = threading.Lock()
        self.core_reset = 0.0
        self.calls = 0

    def request(self, method: str, path: str, *, params=None, timeout: int = 30,
                max_wait: int = 900) -> requests.Response:
        url = path if path.startswith("http") else API + path
        waits = 0
        while True:
            with self.core_lock:
                if self.core_reset > time.time():
                    sleep_for = min(self.core_reset - time.time(), max_wait)
                    if sleep_for > 0.5:
                        log(f"core rate limit: sleeping {sleep_for:.0f}s")
                        time.sleep(sleep_for)
                self.calls += 1
            try:
                r = self.sess.request(method, url, params=params, timeout=timeout)
            except requests.RequestException as exc:
                if waits < 4:
                    waits += 1
                    time.sleep(2 * waits)
                    continue
                raise
            if r.status_code in (403, 429):
                wait = None
                if r.headers.get("Retry-After"):
                    try:
                        wait = float(r.headers["Retry-After"])
                    except ValueError:
                        wait = None
                elif r.headers.get("X-RateLimit-Remaining") == "0":
                    try:
                        wait = max(1.0, int(r.headers.get("X-RateLimit-Reset", "0")) - time.time()) + random.uniform(0.5, 2)
                    except ValueError:
                        wait = None
                if wait is not None and wait <= max_wait and waits < 6:
                    waits += 1
                    log(f"{r.status_code} rate limited, sleeping {wait:.0f}s")
                    time.sleep(wait)
                    continue
                return r
            remaining = r.headers.get("X-RateLimit-Remaining")
            if remaining == "0" and r.headers.get("X-RateLimit-Reset"):
                try:
                    with self.core_lock:
                        self.core_reset = float(r.headers["X-RateLimit-Reset"])
                except ValueError:
                    pass
            return r

    def get_json(self, path: str, *, params=None) -> tuple[int, Any]:
        r = self.request("GET", path, params=params)
        if r.status_code == 200:
            try:
                return 200, r.json()
            except ValueError:
                return 200, None
        return r.status_code, None

    def paginate(self, path: str, params=None, max_items: int = 1000):
        params = dict(params or {})
        params.setdefault("per_page", 100)
        url: str | None = API + path
        count = 0
        while url and count < max_items:
            r = self.request("GET", url, params=params)
            if r.status_code != 200:
                log(f"paginate {path} -> HTTP {r.status_code}")
                return
            try:
                items = r.json()
            except ValueError:
                return
            if not isinstance(items, list):
                return
            for item in items:
                yield item
                count += 1
                if count >= max_items:
                    return
            url = r.links.get("next", {}).get("url")
            params = {}

    def search(self, path: str, params=None, max_items: int = 100) -> tuple[int, Any]:
        self.search_bucket.acquire()
        r = self.request("GET", path, params=params)
        if r.status_code != 200:
            return r.status_code, None
        try:
            return 200, r.json()
        except ValueError:
            return 200, None


def safe_get(client: Client, path: str, params=None) -> tuple[int, Any]:
    try:
        return client.get_json(path, params=params)
    except requests.RequestException as exc:
        log(f"network error {path}: {exc}")
        return 0, None


# --------------------------------------------------------------- discovery ---

def normalise_domain(raw: str) -> str:
    d = raw.strip().lower()
    d = re.sub(r"^[a-z][a-z0-9+.-]*://", "", d)
    d = d.split("/")[0].split("?")[0].split("#")[0]
    d = d.split(":")[0]
    if d.startswith("www."):
        d = d[4:]
    return d.strip(".")


def valid_domain(d: str) -> bool:
    return bool(re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+", d))


def slug_variants(domain: str) -> list[str]:
    labels = [p for p in domain.split(".") if p]
    if not labels:
        return []
    out = []
    stem = labels[0]
    if stem not in ("www", "mail", "api", "app"):
        out.append(stem)
    if len(labels) > 2:
        out.append("-".join(labels[:-1]))
        out.append("".join(labels[:-1]))
    out.append("-".join(labels[:-1]))
    seen, uniq = set(), []
    for s in out:
        s = re.sub(r"[^a-z0-9-]", "-", s).strip("-")
        if s and s not in seen and s not in RESERVED_SLUGS:
            seen.add(s)
            uniq.append(s)
    return uniq


def fetch_homepage(domain: str, timeout: int = 15) -> str:
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ghorgscan"}
    for scheme in ("https", "http"):
        for path in ("/", "/about", "/contact", "/careers", "/company"):
            url = f"{scheme}://{domain}{path}"
            try:
                r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
                if r.status_code == 200 and r.text:
                    return r.text[:400_000]
            except requests.RequestException:
                continue
    return ""


def extract_github_slugs(text: str) -> set[str]:
    slugs = set()
    for m in re.finditer(r"github\.com/([A-Za-z0-9][A-Za-z0-9._-]{0,38})", text):
        slug = m.group(1).lower().rstrip(".")
        slug = re.sub(r"\.git$", "", slug)
        if slug in RESERVED_SLUGS or len(slug) < 2:
            continue
        if slug.endswith((".png", ".jpg", ".svg", ".md")):
            continue
        slugs.add(slug)
    return slugs


class Candidates:
    def __init__(self):
        self.data: dict[str, dict] = {}
        self.lock = threading.Lock()

    def add(self, slug: str, evidence: str, confidence: int) -> None:
        slug = slug.lower()
        if not slug or slug in RESERVED_SLUGS:
            return
        with self.lock:
            rec = self.data.setdefault(slug, {"slug": slug, "evidence": set(), "confidence": 0, "kind": None})
            rec["evidence"].add(evidence)
            rec["confidence"] = max(rec["confidence"], confidence)

    def all(self) -> list[dict]:
        with self.lock:
            return sorted(self.data.values(), key=lambda r: -r["confidence"])


def verify_candidate(client: Client, cand: dict, domain: str) -> dict | None:
    slug = cand["slug"]
    status, data = safe_get(client, f"/orgs/{quote(slug)}")
    kind = "org"
    if status != 200:
        status, data = safe_get(client, f"/users/{quote(slug)}")
        kind = "user"
    if status != 200 or not isinstance(data, dict):
        return None
    cand["kind"] = kind

    blog = (data.get("blog") or "").lower()
    blog_host = normalise_domain(blog) if blog else ""
    haystack = " ".join(filter(None, [
        (data.get("name") or "").lower(),
        (data.get("description") or "").lower(),
        (data.get("bio") or "").lower(),
        (data.get("company") or "").lower(),
        (data.get("email") or "").lower(),
    ]))

    if blog_host and (blog_host == domain or blog_host.endswith("." + domain) or domain.endswith("." + blog_host)):
        cand["confidence"] = max(cand["confidence"], 95)
        cand["evidence"].add("profile-website-match")
    if domain in haystack:
        cand["confidence"] = max(cand["confidence"], 85)
        cand["evidence"].add("profile-text-match")
    if "@" + domain in haystack:
        cand["confidence"] = max(cand["confidence"], 85)
        cand["evidence"].add("profile-email-match")
    if data.get("is_verified") and kind == "org":
        cand["confidence"] = min(100, cand["confidence"] + 5)
        cand["evidence"].add("verified-org")
    if cand["confidence"] < 40:
        return None
    cand["profile"] = {
        "login": data.get("login"),
        "name": data.get("name"),
        "html_url": data.get("html_url"),
        "blog": data.get("blog"),
        "description": data.get("description"),
        "public_repos": data.get("public_repos"),
        "followers": data.get("followers"),
        "created_at": data.get("created_at"),
        "is_verified": data.get("is_verified"),
    }
    return cand


def discover(client: Client, domain: str, args) -> list[dict]:
    cands = Candidates()

    for slug in slug_variants(domain):
        cands.add(slug, "domain-slug-guess", 60)

    page = fetch_homepage(domain)
    if page:
        for slug in extract_github_slugs(page):
            cands.add(slug, "homepage-link", 70)
        log(f"homepage scraped, {len(extract_github_slugs(page))} github links")
    else:
        log("homepage unreachable (blocked, JS-only, or offline)")

    for path in ("/.well-known/security.txt", "/security.txt"):
        try:
            r = requests.get(f"https://{domain}{path}", timeout=15,
                             headers={"User-Agent": UA})
            if r.status_code == 200:
                for slug in extract_github_slugs(r.text):
                    cands.add(slug, "security.txt", 80)
                break
        except requests.RequestException:
            break

    status, data = client.search("/search/users", {"q": f'"{domain}"', "per_page": 50})
    if status == 200 and data:
        for item in data.get("items", [])[:40]:
            cands.add(item["login"], "user-search", 65)

    status, data = client.search("/search/repositories",
                                 {"q": f'"{domain}" in:readme,description', "per_page": 30})
    if status == 200 and data:
        for item in data.get("items", []):
            owner = item.get("owner", {}).get("login")
            if owner:
                cands.add(owner, "repo-search", 55)

    if args.dns:
        try:
            import dns.resolver  # type: ignore
            for rec in dns.resolver.resolve(domain, "TXT"):
                text = b"".join(rec.strings).decode("utf-8", "ignore")
                for slug in re.findall(r"github[^a-z0-9]+([a-z0-9-]+)", text, re.I):
                    cands.add(slug, "dns-txt", 75)
        except Exception as exc:  # noqa: BLE001
            log(f"dns lookup skipped: {exc}")

    raw = [c for c in cands.all() if c["confidence"] >= 40]
    if not raw:
        return []

    verified: list[dict] = []
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(raw)))) as pool:
        futures = {pool.submit(verify_candidate, client, c, domain): c for c in raw}
        for fut in as_completed(futures):
            try:
                res = fut.result()
            except Exception as exc:  # noqa: BLE001
                log(f"verify failed: {exc}")
                continue
            if res:
                res["evidence"] = sorted(res["evidence"])
                verified.append(res)

    verified.sort(key=lambda c: -c["confidence"])
    return [c for c in verified if c["confidence"] >= args.min_confidence]


# ------------------------------------------------------------------- scan ----

def looks_placeholder(value: str) -> bool:
    low = value.lower()
    return any(h in low for h in PLACEHOLDER_HINTS)


def scan_text(rec: dict, path: str, text: str, source: str) -> None:
    for name, (rx, sev) in SECRET_PATTERNS.items():
        hit = False
        for m in rx.finditer(text):
            value = (m.group(1) if rx.groups else m.group(0)) or m.group(0)
            if len(value) < 8 or looks_placeholder(value):
                continue
            redacted = value if len(value) <= 20 else f"{value[:8]}...{value[-4:]}"
            rec["findings"].append({
                "id": name, "severity": sev, "path": path, "source": source,
                "title": f"Possible {name.replace('_', ' ')}",
                "detail": redacted,
            })
            hit = True
            break
        if hit:
            continue


def add(rec: dict, sev: str, fid: str, title: str, detail: str = "") -> None:
    rec["findings"].append({"id": fid, "severity": sev, "title": title, "detail": detail, "path": "", "source": "api"})


def probe_contents(client: Client, rec: dict, full_name: str) -> None:
    for path in SENSITIVE_PATHS:
        status, data = safe_get(client, f"/repos/{full_name}/contents/{quote(path)}")
        if status == 200 and isinstance(data, dict) and data.get("content"):
            try:
                text = base64.b64decode(data["content"]).decode("utf-8", "ignore")
            except Exception:  # noqa: BLE001
                continue
            add(rec, "low", "sensitive_file_committed", f"Credential-bearing file committed: {path}")
            scan_text(rec, path, text, "contents-api")


def probe_workflows(client: Client, rec: dict, full_name: str) -> None:
    status, data = safe_get(client, f"/repos/{full_name}/contents/.github/workflows")
    if status != 200 or not isinstance(data, list):
        return
    for entry in data[:25]:
        if entry.get("type") != "file":
            continue
        s2, blob = safe_get(client, f"/repos/{full_name}/contents/{entry['path']}")
        if s2 == 200 and isinstance(blob, dict) and blob.get("content"):
            try:
                text = base64.b64decode(blob["content"]).decode("utf-8", "ignore")
            except Exception:  # noqa: BLE001
                continue
            scan_text(rec, entry["path"], text, "workflow")


def clone_and_scan(client: Client, rec: dict, full_name: str, default_branch: str, token: str) -> None:
    if not shutil.which("git"):
        add(rec, "info", "git_missing", "git not on PATH, clone mode skipped")
        return
    tmp = tempfile.mkdtemp(prefix="ghs_")
    url = f"https://x-access-token:{token}@github.com/{full_name}.git" if token else f"https://github.com/{full_name}.git"
    try:
        proc = subprocess.run(
            ["git", "clone", "--depth", "1", "--no-tags", "--single-branch",
             "--branch", default_branch, url, tmp],
            capture_output=True, text=True, timeout=300,
        )
        if proc.returncode != 0:
            add(rec, "info", "clone_failed", proc.stderr.strip()[:200])
            return
        seen = 0
        for root, dirs, files in os.walk(tmp):
            dirs[:] = [d for d in dirs if d not in CLONE_SKIP_DIRS]
            for fname in files:
                if seen >= SCAN_MAX_FILES:
                    break
                ext = os.path.splitext(fname)[1].lower()
                if ext in CLONE_SKIP_EXT:
                    continue
                full = os.path.join(root, fname)
                try:
                    if os.path.getsize(full) > SCAN_MAX_FILE:
                        continue
                    with open(full, "r", encoding="utf-8", errors="ignore") as fh:
                        text = fh.read()
                except OSError:
                    continue
                rel = os.path.relpath(full, tmp).replace("\\", "/")
                seen += 1
                scan_text(rec, rel, text, "clone")
        rec["files_scanned"] = seen
    except subprocess.TimeoutExpired:
        add(rec, "info", "clone_timeout", "clone exceeded 300s")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def scan_repo(client: Client, org: str, repo: dict, args) -> dict:
    full_name = repo["full_name"]
    rec: dict = {
        "org": org,
        "name": repo.get("name"),
        "full_name": full_name,
        "url": repo.get("html_url"),
        "visibility": repo.get("visibility") or ("private" if repo.get("private") else "public"),
        "private": bool(repo.get("private")),
        "archived": bool(repo.get("archived")),
        "fork": bool(repo.get("fork")),
        "disabled": bool(repo.get("disabled")),
        "default_branch": repo.get("default_branch"),
        "size_kb": repo.get("size"),
        "stars": repo.get("stargazers_count"),
        "language": repo.get("language"),
        "license": (repo.get("license") or {}).get("spdx_id"),
        "pushed_at": repo.get("pushed_at"),
        "created_at": repo.get("created_at"),
        "findings": [],
        "metrics": {},
    }
    if rec["archived"]:
        add(rec, "info", "archived", "Repository is archived")
    if rec["fork"]:
        add(rec, "info", "fork", "Repository is a fork")
    if not rec["license"] and not rec["private"]:
        add(rec, "low", "no_license", "Public repo has no license")

    branch = rec["default_branch"] or "main"
    status, prot = safe_get(client, f"/repos/{full_name}/branches/{quote(branch)}/protection")
    if status == 200 and isinstance(prot, dict):
        rec["metrics"]["branch_protected"] = True
        if not prot.get("required_pull_request_reviews"):
            add(rec, "medium", "no_pr_review_required", "Branch protection lacks required PR reviews")
        if (prot.get("allow_force_pushes") or {}).get("enabled"):
            add(rec, "medium", "force_push_allowed", "Force pushes allowed on default branch")
        if (prot.get("allow_deletions") or {}).get("enabled"):
            add(rec, "low", "branch_deletion_allowed", "Default branch deletable")
    elif status == 404:
        rec["metrics"]["branch_protected"] = False
        add(rec, "high" if not rec["private"] else "medium", "no_branch_protection",
            "No branch protection on default branch")
    elif status == 403:
        rec["metrics"]["branch_protected"] = None

    status, hooks = safe_get(client, f"/repos/{full_name}/hooks")
    if status == 200 and isinstance(hooks, list):
        rec["metrics"]["webhooks"] = len(hooks)
        for hook in hooks:
            cfg = hook.get("config") or {}
            host = cfg.get("url", "")
            if not cfg.get("secret"):
                add(rec, "medium", "webhook_no_secret", f"Webhook without secret: {host[:80]}")
            if host and "github.com" not in host:
                add(rec, "low", "webhook_external", f"Webhook to external host: {host[:80]}")

    status, secrets = safe_get(client, f"/repos/{full_name}/actions/secrets")
    if status == 200 and isinstance(secrets, dict):
        rec["metrics"]["actions_secrets"] = secrets.get("total_count", 0)

    status, keys = safe_get(client, f"/repos/{full_name}/keys")
    if status == 200 and isinstance(keys, list):
        rec["metrics"]["deploy_keys"] = len(keys)
        for key in keys:
            if key.get("read_only") is False:
                add(rec, "low", "deploy_key_write", "Deploy key with write access")

    for label, path in (
        ("dependabot_alerts", "dependabot/alerts"),
        ("code_scanning_alerts", "code-scanning/alerts"),
        ("secret_scanning_alerts", "secret-scanning/alerts"),
    ):
        status, data = safe_get(client, f"/repos/{full_name}/{path}",
                                {"state": "open", "per_page": 1} if "dependabot" in path else {"state": "open", "per_page": 1})
        if status == 200 and isinstance(data, list):
            rec["metrics"][label] = len(data)
        elif status in (403, 404):
            rec["metrics"][label] = None

    if rec["metrics"].get("secret_scanning_alerts"):
        add(rec, "critical", "secret_scanning_hits",
            f"{rec['metrics']['secret_scanning_alerts']} open secret-scanning alert(s)")
    if rec["metrics"].get("code_scanning_alerts"):
        add(rec, "high", "code_scanning_hits",
            f"{rec['metrics']['code_scanning_alerts']} open code-scanning alert(s)")
    if rec["metrics"].get("dependabot_alerts"):
        add(rec, "medium", "dependabot_hits",
            f"{rec['metrics']['dependabot_alerts']} open Dependabot alert(s)")

    if args.deep:
        probe_workflows(client, rec, full_name)
        probe_contents(client, rec, full_name)
    if args.clone and not rec["archived"]:
        clone_and_scan(client, rec, full_name, branch, args.token)

    rec["findings"].sort(key=lambda f: -SEV_ORDER.get(f["severity"], 0))
    return rec


def scan_org(client: Client, cand: dict, args) -> dict:
    slug = cand["slug"]
    kind = cand["kind"]
    out: dict = {
        "slug": slug, "kind": kind, "confidence": cand["confidence"],
        "evidence": cand["evidence"], "profile": cand.get("profile", {}),
        "settings": {}, "findings": [], "repos": [], "errors": [],
    }

    if kind == "org":
        status, data = safe_get(client, f"/orgs/{slug}")
        if status == 200 and isinstance(data, dict):
            out["settings"] = {
                "two_factor_required": data.get("two_factor_requirement_enabled"),
                "default_repo_permission": data.get("default_repository_permission"),
                "members_can_create_public_repos": data.get("members_can_create_public_repositories"),
                "members_can_create_private_repos": data.get("members_can_create_private_repositories"),
                "members_can_create_pages": data.get("members_can_create_pages"),
                "members_can_fork_private_repos": data.get("members_can_fork_private_repositories"),
                "total_private_repos": data.get("total_private_repos"),
                "public_repos": data.get("public_repos"),
                "plan": (data.get("plan") or {}).get("name"),
                "is_verified": data.get("is_verified"),
            }
            s = out["settings"]
            if s.get("two_factor_required") is False:
                add(out, "high", "org_no_2fa", "Organisation does not require 2FA")
            if s.get("default_repo_permission") in ("admin", "write"):
                add(out, "high" if s["default_repo_permission"] == "admin" else "medium",
                    "org_default_permission", f"Default repo permission is {s['default_repo_permission']}")
            if s.get("members_can_create_public_repos"):
                add(out, "low", "org_public_repo_creation", "Members can create public repos")
            if s.get("members_can_fork_private_repos"):
                add(out, "medium", "org_private_forking", "Members can fork private repos")
        elif status == 403:
            out["errors"].append("org settings need admin:org")
    else:
        out["errors"].append("user account: settings and private repos limited to self")

    list_path = f"/orgs/{slug}/repos" if kind == "org" else f"/users/{slug}/repos"
    params = {"type": "all", "sort": "pushed", "direction": "desc"} if kind == "org" else {"type": "owner", "sort": "pushed"}
    repos = []
    for repo in client.paginate(list_path, params, max_items=args.max_repos):
        if repo.get("fork") and not args.include_forks:
            continue
        if repo.get("archived") and not args.include_archived:
            continue
        repos.append(repo)
    log(f"{slug}: {len(repos)} repos to scan")

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(scan_repo, client, slug, r, args): r for r in repos}
        for fut in as_completed(futures):
            repo = futures[fut]
            try:
                out["repos"].append(fut.result())
            except Exception as exc:  # noqa: BLE001
                out["errors"].append(f"{repo.get('full_name')}: {exc}")

    out["repos"].sort(key=lambda r: (r["private"], -(r.get("stars") or 0)))
    out["findings"].sort(key=lambda f: -SEV_ORDER.get(f["severity"], 0))
    return out


# ----------------------------------------------------------------- output ----

def summarise(result: dict) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for org in result["orgs"]:
        for f in org["findings"]:
            counts[f["severity"]] += 1
        for repo in org["repos"]:
            for f in repo["findings"]:
                counts[f["severity"]] += 1
    result["summary"] = counts
    return result


def write_json(result: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, default=str)


def write_csv(result: dict, path: str) -> None:
    cols = ["org", "full_name", "visibility", "archived", "fork", "size_kb", "stars",
            "language", "last_push", "default_branch", "branch_protected", "webhooks",
            "actions_secrets", "dependabot_alerts", "code_scanning_alerts",
            "secret_scanning_alerts", "critical", "high", "medium", "low", "url"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        for org in result["orgs"]:
            for r in org["repos"]:
                sev = {k: 0 for k in ("critical", "high", "medium", "low")}
                for f in r["findings"]:
                    if f["severity"] in sev:
                        sev[f["severity"]] += 1
                m = r["metrics"]
                w.writerow([
                    r["org"], r["full_name"], r["visibility"], r["archived"], r["fork"],
                    r["size_kb"], r["stars"], r["language"], r["pushed_at"],
                    r["default_branch"], m.get("branch_protected"), m.get("webhooks"),
                    m.get("actions_secrets"), m.get("dependabot_alerts"),
                    m.get("code_scanning_alerts"), m.get("secret_scanning_alerts"),
                    sev["critical"], sev["high"], sev["medium"], sev["low"], r["url"],
                ])


CSS = """
:root{--bg:#0e1116;--panel:#161b22;--line:#262d38;--txt:#c9d1d9;--dim:#7d8590;
--crit:#f85149;--high:#ff8c42;--med:#e3b341;--low:#58a6ff;--info:#8b949e}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);
font:14px/1.55 -apple-system,"Segoe UI",Roboto,sans-serif;padding:28px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 10px;
border-bottom:1px solid var(--line);padding-bottom:6px}
.meta{color:var(--dim);font-size:12px;margin-bottom:20px}
.cards{display:flex;gap:10px;flex-wrap:wrap;margin:18px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;
padding:12px 18px;min-width:96px}
.card b{display:block;font-size:22px}
.critical b{color:var(--crit)}.high b{color:var(--high)}.medium b{color:var(--med)}
.low b{color:var(--low)}.info b{color:var(--info)}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th,td{text-align:left;padding:6px 9px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--dim);font-weight:600;font-size:11px;text-transform:uppercase}
tr:hover td{background:#12171e}
code{font-family:Consolas,monospace;font-size:11.5px;color:#79c0ff}
.pill{display:inline-block;padding:1px 7px;border-radius:20px;font-size:10.5px;
font-weight:700;text-transform:uppercase}
.p-critical{background:rgba(248,81,73,.16);color:var(--crit)}
.p-high{background:rgba(255,140,66,.16);color:var(--high)}
.p-medium{background:rgba(227,179,65,.16);color:var(--med)}
.p-low{background:rgba(88,166,255,.16);color:var(--low)}
.p-info{background:rgba(139,148,158,.16);color:var(--info)}
.priv{color:var(--med);font-weight:600}.pub{color:var(--dim)}
a{color:#58a6ff;text-decoration:none}a:hover{text-decoration:underline}
.note{background:var(--panel);border-left:3px solid var(--med);padding:10px 14px;
border-radius:0 6px 6px 0;margin:14px 0;font-size:13px}
"""


def esc(value: Any) -> str:
    return htmllib.escape(str(value if value is not None else ""))


def write_html(result: dict, path: str) -> None:
    parts = [
        "<!doctype html><html><head><meta charset='utf-8'>",
        f"<title>ghorgscan - {esc(result['domain'])}</title><style>{CSS}</style></head><body>",
        f"<h1>GitHub exposure report: {esc(result['domain'])}</h1>",
        f"<div class='meta'>Generated {esc(result['generated_at'])} &middot; "
        f"{result['api_calls']} API calls &middot; token {esc(result['token_label'])}</div>",
    ]
    if result["summary"]["critical"] or result["summary"]["high"]:
        parts.append("<div class='note'>Critical or high severity findings present - review those first.</div>")
    parts.append("<div class='cards'>")
    for sev in ("critical", "high", "medium", "low", "info"):
        parts.append(f"<div class='card {sev}'><b>{result['summary'][sev]}</b>{sev}</div>")
    parts.append("</div>")

    for org in result["orgs"]:
        parts.append(f"<h2>{esc(org['slug'])} <span class='pill p-info'>{esc(org['kind'])}</span></h2>")
        p = org["profile"]
        parts.append(
            f"<div class='meta'>confidence {org['confidence']} &middot; "
            f"evidence: {esc(', '.join(org['evidence']))} &middot; "
            f"<a href='{esc(p.get('html_url'))}'>profile</a></div>"
        )
        if org["settings"]:
            s = org["settings"]
            parts.append(
                f"<div class='meta'>2FA required: {esc(s.get('two_factor_required'))} &middot; "
                f"default permission: {esc(s.get('default_repo_permission'))} &middot; "
                f"public repos: {esc(s.get('public_repos'))} &middot; "
                f"private repos: {esc(s.get('total_private_repos'))} &middot; plan: {esc(s.get('plan'))}</div>"
            )
        for err in org["errors"]:
            parts.append(f"<div class='note'>{esc(err)}</div>")

        if org["findings"]:
            parts.append("<table><tr><th>Sev</th><th>Finding</th><th>Detail</th></tr>")
            for f in org["findings"]:
                parts.append(
                    f"<tr><td><span class='pill p-{f['severity']}'>{f['severity']}</span></td>"
                    f"<td>{esc(f['title'])}</td><td><code>{esc(f['detail'])}</code></td></tr>"
                )
            parts.append("</table>")

        if not org["repos"]:
            parts.append("<div class='note'>No repositories visible. Private repos require token membership.</div>")
            continue

        parts.append("<table><tr><th>Repository</th><th>Vis</th><th>Lang</th><th>Pushed</th>"
                     "<th>Prot</th><th>Findings</th></tr>")
        for r in org["repos"]:
            vis = "<span class='priv'>private</span>" if r["private"] else "<span class='pub'>public</span>"
            flags = "".join(
                f"<span class='pill p-{f['severity']}'>{esc(f['id'])}</span> "
                for f in r["findings"] if f["severity"] in ("critical", "high")
            )
            parts.append(
                f"<tr><td><a href='{esc(r['url'])}'>{esc(r['full_name'])}</a></td>"
                f"<td>{vis}</td><td>{esc(r['language'])}</td><td>{esc((r['pushed_at'] or '')[:10])}</td>"
                f"<td>{esc(r['metrics'].get('branch_protected'))}</td>"
                f"<td>{flags or '<span class=\"pub\">-</span>'}</td></tr>"
            )
            for f in r["findings"]:
                if f["severity"] in ("critical", "high", "medium"):
                    parts.append(
                        f"<tr><td colspan='6' style='padding-left:26px;font-size:12px'>"
                        f"<span class='pill p-{f['severity']}'>{f['severity']}</span> "
                        f"{esc(f['title'])} <code>{esc(f['detail'])}</code> "
                        f"<span class='pub'>{esc(f['path'])}</span></td></tr>"
                    )
        parts.append("</table>")

    parts.append("</body></html>")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(parts))


# -------------------------------------------------------------------- cli ----

def load_token(args) -> str:
    token = args.token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
    token = token.strip()
    if token:
        os.environ["GITHUB_TOKEN"] = token
    args.token = token
    return token


def whoami(client: Client) -> dict:
    status, data = client.get_json("/user")
    if status != 200 or not isinstance(data, dict):
        return {}
    return data


def cmd_doctor(args) -> int:
    token = load_token(args)
    ok = True
    print(f"ghorgscan {VERSION}")
    print(f"python      : {sys.version.split()[0]}")
    print(f"platform    : {sys.platform}")
    print(f"git         : {shutil.which('git') or 'NOT FOUND'}")
    if not token:
        print("token       : NOT SET")
        print("\nSet it first:  $env:GITHUB_TOKEN = \"ghp_...\"")
        return 2
    print(f"token       : set ({len(token)} chars, {token[:4]}...)")
    client = Client(token)
    try:
        me = whoami(client)
    except requests.RequestException as exc:
        print(f"network     : FAILED ({exc})")
        return 2
    if not me:
        print("token       : REJECTED by GitHub")
        return 2
    print(f"identity    : {me.get('login')} (type={me.get('type')})")
    status, data = client.get_json("/rate_limit")
    if status == 200 and data:
        core = data["resources"]["core"]
        search = data["resources"]["search"]
        print(f"rate core   : {core['remaining']}/{core['limit']} per hour")
        print(f"rate search : {search['remaining']}/{search['limit']} per minute")
        if core["limit"] < 5000:
            print("warn        : core limit below 5000 - token may lack scopes")
            ok = False
    status, _ = client.get_json("/user/repos?per_page=1&affiliation=organization_member")
    print(f"org repos   : {'visible' if status == 200 else f'HTTP {status}'}")
    print("\nOK" if ok else "\nDEGRADED")
    return 0 if ok else 1


def cmd_discover(args) -> int:
    token = load_token(args)
    domain = normalise_domain(args.domain)
    if not valid_domain(domain):
        print(f"invalid domain: {domain}", file=sys.stderr)
        return 2
    client = Client(token, verbose=args.verbose)
    if not token:
        log("no token set - search is heavily throttled")
    found = discover(client, domain, args)
    if not found:
        print(f"no GitHub org/user linked to {domain} above confidence {args.min_confidence}")
        return 1
    print(f"{len(found)} candidate(s) for {domain}:")
    for c in found:
        print(f"  {c['confidence']:>3}  {c['slug']:<40} {c['kind']:<5} {','.join(c['evidence'])}")
    return 0


def cmd_scan(args) -> int:
    global LOG_PATH
    token = load_token(args)
    if not token:
        print("GITHUB_TOKEN not set. Run 'doctor' for setup help.", file=sys.stderr)
        return 2
    if args.domain:
        domain = normalise_domain(args.domain)
        if not valid_domain(domain):
            print(f"invalid domain: {domain}", file=sys.stderr)
            return 2
    elif args.org:
        domain = args.org.lower()
    else:
        print("need -d/--domain or -o/--org", file=sys.stderr)
        return 2

    os.makedirs(args.out_dir, exist_ok=True)
    LOG_PATH = os.path.join(args.out_dir, "scan.log")
    open(LOG_PATH, "w").close()

    client = Client(token, workers=args.workers, verbose=args.verbose)
    me = whoami(client)
    if not me:
        print("token rejected", file=sys.stderr)
        return 2

    started = time.time()
    result: dict = {
        "tool": f"ghorgscan {VERSION}",
        "domain": domain,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "token_label": me.get("login"),
        "mode": "domain" if args.domain else "org",
        "orgs": [],
    }

    if args.org:
        cands = [{"slug": args.org.lower(), "kind": "org", "confidence": 100,
                  "evidence": ["explicit"], "profile": {}}]
    else:
        cands = discover(client, domain, args)
        if not cands:
            print(f"no org found for {domain}", file=sys.stderr)
            return 1
        log(f"{len(cands)} candidate org(s)")

    for cand in cands:
        log(f"scanning {cand['slug']} (confidence {cand['confidence']})")
        result["orgs"].append(scan_org(client, cand, args))

    result["api_calls"] = client.calls
    result["elapsed_s"] = round(time.time() - started, 1)
    summarise(result)

    json_path = os.path.join(args.out_dir, "report.json")
    csv_path = os.path.join(args.out_dir, "report.csv")
    html_path = os.path.join(args.out_dir, "report.html")
    write_json(result, json_path)
    write_csv(result, csv_path)
    if not args.no_html:
        write_html(result, html_path)

    s = result["summary"]
    total_repos = sum(len(o["repos"]) for o in result["orgs"])
    private_repos = sum(1 for o in result["orgs"] for r in o["repos"] if r["private"])
    print(f"\norgs      : {len(result['orgs'])}")
    print(f"repos     : {total_repos} ({private_repos} private)")
    print(f"findings  : {s['critical']} critical, {s['high']} high, {s['medium']} medium, {s['low']} low")
    print(f"elapsed   : {result['elapsed_s']}s, {result['api_calls']} calls")
    print(f"json      : {json_path}")
    print(f"csv       : {csv_path}")
    if not args.no_html:
        print(f"html      : {html_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ghorgscan", description="GitHub org/domain recon scanner")
    p.add_argument("--version", action="version", version=f"ghorgscan {VERSION}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("-t", "--token", help="GitHub PAT (default: $env:GITHUB_TOKEN)")
        sp.add_argument("-w", "--workers", type=int, default=6)
        sp.add_argument("--min-confidence", type=int, default=55)
        sp.add_argument("--dns", action="store_true", help="DNS TXT lookup (needs dnspython)")
        sp.add_argument("-v", "--verbose", action="store_true")

    d = sub.add_parser("doctor", help="validate token, scopes, connectivity")
    d.add_argument("-t", "--token")
    d.set_defaults(func=cmd_doctor)

    dc = sub.add_parser("discover", help="resolve domain -> GitHub orgs/users")
    dc.add_argument("-d", "--domain", required=True)
    common(dc)
    dc.set_defaults(func=cmd_discover)

    sc = sub.add_parser("scan", help="enumerate and assess repos")
    sc.add_argument("-d", "--domain")
    sc.add_argument("-o", "--org")
    sc.add_argument("--out-dir", default="ghorgscan-out")
    sc.add_argument("--max-repos", type=int, default=500)
    sc.add_argument("--include-forks", action="store_true")
    sc.add_argument("--include-archived", action="store_true")
    sc.add_argument("--deep", action="store_true", help="probe sensitive files and workflows")
    sc.add_argument("--clone", action="store_true", help="shallow-clone and regex every text file")
    sc.add_argument("--no-html", action="store_true")
    common(sc)
    sc.set_defaults(func=cmd_scan)
    return p


def main() -> int:
    args = build_parser().parse_args()
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except requests.RequestException as exc:
        print(f"network failure: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())