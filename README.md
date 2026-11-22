

<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/516e756d-4b3c-4f7e-9468-95c9d1fb5ab0" />



# GHORGSCAN
Map a domain to its GitHub organisations, enumerate every repository the token can see (public and private), and report hardening gaps plus committed secrets.

# ghorgscan

Map a domain to its GitHub organisations, enumerate every repository the token can see
(public and private), and report hardening gaps plus committed secrets.

Single file. Three subcommands. JSON, CSV and a dark HTML report out the back.

Point it at a company domain and it finds the org, then tells you which repos have no
branch protection, which webhooks have no secret, which deploy keys can write, and which
`.env` files got committed with real values in them.

---

## Disclaimer

Read-only. It uses the GitHub REST API with your token and optionally shallow-clones
repos locally. Nothing is written back to GitHub.

Private repository visibility depends entirely on what your token can reach — if the
token isn't a member of the org, private repos simply don't appear. That is a limit of
the token, not a bug.

Use a token scoped to what you need. See [Auth](#auth).

---

## Features

**Discovery**
- Domain slug guessing (`acme.com` → `acme`, `acme-com`)
- Homepage scraping for `github.com/` links across five paths
- `security.txt` parsing
- GitHub user search and repository search
- Optional DNS TXT record lookup
- Confidence scoring with profile verification: blog match, profile text match,
  profile email match, verified-org bonus
- Reserved-slug filtering so `github.com/features` doesn't become a candidate

**Organisation posture**
- 2FA requirement
- Default repository permission
- Member ability to create public repos
- Member ability to fork private repos
- Plan and verification status

**Repository posture**
- Branch protection on the default branch
- Required PR reviews
- Force-push and branch-deletion allowances
- Webhooks without a secret
- Webhooks pointing at external hosts
- Deploy keys with write access
- Actions secret count
- Open Dependabot, code-scanning and secret-scanning alerts

**Secret exposure**
- 19 pattern families: GitHub PAT and fine-grained PAT, AWS access and secret keys,
  Stripe live, OpenAI, Anthropic, Slack tokens and webhooks, Google API, SendGrid, npm,
  Twilio, private key blocks, DB URLs with inline credentials, JWTs, GCP service
  account markers, generic `password = "..."` assignments
- Placeholder filtering (`your`, `xxx`, `changeme`, `${`, `<`, …)
- Two collection modes: targeted sensitive-file probing, or full shallow clone with a
  regex pass over every text file
- Binary, vendor and build directories skipped

**Reporting**
- Severity-sorted JSON
- Per-repo CSV with a findings roll-up
- Self-contained HTML report with severity cards and inline evidence
- Full request log

**Operational**
- Token bucket on the search API
- Core rate-limit awareness with automatic backoff
- Retry with exponential backoff on 5xx
- Pagination with caps
- `doctor` subcommand for token, scope and connectivity validation

---

## Install

Python 3.10+. `git` on `PATH` only if you want `--clone`.

```bash
git clone https://github.com//ghorgscan.git
cd ghorgscan
python3 -m venv .venv
source .venv/bin/activate
pip install requests
```

Windows:

```bat
py -m venv .venv
.venv\Scripts\activate
pip install requests
```

Optional, for `--dns`:

```bash
pip install dnspython
```

---

## Auth

Set a token. Fine-grained tokens are preferred.

```
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
```

PowerShell:

```powershell
$env:GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxx"
```

Classic scopes needed:

| Scope | Why |
|---|---|
| `repo` | Private repo metadata, contents, hooks, keys |
| `read:org` | Org settings and member visibility |
| `security_events` | Code-scanning and secret-scanning alerts |

Without `repo` you only see public repositories. Without `read:org` the org settings
block returns 403. Without `security_events` the alert counters come back `null`.

A read-only fine-grained token with Contents, Administration, Webhooks, Deploy keys and
Secret scanning set to read is the least-privilege configuration that still works.

Validate before scanning:

```bash
python ghorgscan.py doctor
```

---

## Quick start

```bash
python ghorgscan.py doctor
python ghorgscan.py discover -d acme.com
python ghorgscan.py scan -d acme.com --json --html
```

`discover` alone is cheap and worth running first — it prints candidates with confidence
and evidence so you can confirm you've got the right org before spending API budget.

Scan a known org directly, with deep probing:

```bash
python ghorgscan.py scan -o acme --deep
```

Full treatment including clone-based secret scanning:

```bash
python ghorgscan.py scan -d acme.com --deep --clone
```

---

## Subcommands

### `doctor`

Validates token presence, identity, core and search rate limits, and org-repo
visibility. Prints `OK` or `DEGRADED`.

```bash
python ghorgscan.py doctor
```

### `discover`

Resolves a domain to candidate GitHub orgs and users. Prints confidence, slug, kind and
evidence. No repo enumeration.

```bash
python ghorgscan.py discover -d acme.com --min-confidence 70
```

### `scan`

Discovers (or takes `-o` directly), enumerates repos, assesses each, writes reports.

```bash
python ghorgscan.py scan -d acme.com --deep --clone --out-dir acme-audit
```

---

## Flags

### Common

| Flag | Default | Description |
|---|---|---|
| `-t, --token` | `$GITHUB_TOKEN` | Token; falls back to `GH_TOKEN` |
| `-w, --workers` | 6 | Concurrent workers |
| `--min-confidence` | 55 | Minimum discovery confidence |
| `--dns` | off | DNS TXT lookup (needs dnspython) |
| `-v, --verbose` | off | Verbose logging |

### `scan` only

| Flag | Default | Description |
|---|---|---|
| `-d, --domain` | — | Domain to discover and scan |
| `-o, --org` | — | Scan this org directly, skip discovery |
| `--out-dir` | `ghorgscan-out` | Output directory |
| `--max-repos` | 500 | Repo cap per org |
| `--include-forks` | off | Scan forks |
| `--include-archived` | off | Scan archived repos |
| `--deep` | off | Probe sensitive files and workflows |
| `--clone` | off | Shallow clone and scan all text files |
| `--no-html` | off | Skip the HTML report |

---

## Findings

### Organisation

| ID | Severity | Meaning |
|---|---|---|
| `org_no_2fa` | high | Org does not require 2FA |
| `org_default_permission` | high / medium | Default repo permission is admin or write |
| `org_private_forking` | medium | Members can fork private repos |
| `org_public_repo_creation` | low | Members can create public repos |

### Repository

| ID | Severity | Meaning |
|---|---|---|
| `secret_scanning_hits` | critical | Open secret-scanning alerts |
| `code_scanning_hits` | high | Open code-scanning alerts |
| `no_branch_protection` | high / medium | No protection on default branch |
| `no_pr_review_required` | medium | Protection lacks required reviews |
| `force_push_allowed` | medium | Force pushes allowed on default branch |
| `dependabot_hits` | medium | Open Dependabot alerts |
| `webhook_no_secret` | medium | Webhook configured without a secret |
| `branch_deletion_allowed` | low | Default branch deletable |
| `deploy_key_write` | low | Deploy key with write access |
| `webhook_external` | low | Webhook points at a non-GitHub host |
| `sensitive_file_committed` | low | Credential-bearing file present |
| `no_license` | low | Public repo has no license |
| `archived` / `fork` | info | Repo state |

### Secrets

`github_pat`, `github_fine_pat`, `aws_access_key`, `aws_secret_key`, `stripe_live`,
`openai_key`, `anthropic_key`, `slack_token`, `slack_webhook`, `google_api_key`,
`sendgrid_key`, `npm_token`, `twilio_key`, `private_key_block`, `db_url_with_creds`,
`jwt`, `gcp_service_account`, `generic_credential`.

Values are truncated to first-8/last-4 in output so a report can be shared safely.

---

## Output

```
ghorgscan-out/
  report.json   full structured result
  report.csv    per-repo row with severity roll-up
  report.html   standalone dark report
  scan.log      request log
```

JSON shape:

```
{
  "tool": "ghorgscan 1.0.0",
  "domain": "acme.com",
  "generated_at": "...",
  "token_label": "your-login",
  "mode": "domain",
  "orgs": [
    {
      "slug": "acme", "kind": "org", "confidence": 95,
      "evidence": ["homepage-link", "profile-website-match"],
      "profile": { ... },
      "settings": { "two_factor_required": true, ... },
      "findings": [ { id, severity, title, detail } ],
      "repos": [ { full_name, visibility, metrics, findings } ],
      "errors": []
    }
  ],
  "summary": { "critical": 0, "high": 2, "medium": 7, "low": 19, "info": 4 },
  "api_calls": 431,
  "elapsed_s": 96.4
}
```

---

## How discovery scores

| Evidence | Confidence |
|---|---|
| Domain slug guess | 60 |
| Repo search hit | 55 |
| User search hit | 65 |
| Homepage `github.com/` link | 70 |
| DNS TXT | 75 |
| Profile text or email contains domain | 85 |
| Profile website field matches domain | 95 |
| Verified org | +5 |

Candidates below 40 are discarded before verification. `--min-confidence` filters the
final set. A homepage link plus a website match is effectively conclusive; a bare slug
guess that only survives because the account exists is not.

---

## Rate limits

Unauthenticated: 60 requests/hour. Authenticated: 5,000/hour, search 30/minute.

The client buckets search calls and backs off when `X-RateLimit-Remaining` hits zero,
sleeping until reset up to 900s. A 500-repo org with `--deep` will consume a few
thousand calls — budget an hour.

`--max-repos` and `--include-forks`/`--include-archived` are the levers if you're tight.

---

## Limits

- Private repos require token membership. No token, no private data.
- Org settings need `admin:org`; a plain member token gets 403.
- Secret-scanning and code-scanning need `security_events` plus a plan that enables them.
  The counters return `null` otherwise — that's absence of data, not absence of alerts.
- `--clone` is shallow (`--depth 1`, single branch). Secrets only in history are missed;
  use `--deep` plus a real history scan if that matters.
- Clone skips files over 1 MB and stops at 4,000 files per repo.
- Pattern matching is regex, not entropy analysis. Expect some false positives, which is
  why placeholder filtering exists.
- GitHub's own secret scanning is authoritative; this is a fast first pass.

---

## Roadmap

- [ ] Org member and outside-collaborator enumeration
- [ ] Per-repo commit history scan (optional full clone)
- [ ] Entropy scoring alongside regex
- [ ] SARIF output for CI
- [ ] Baseline diffing between runs
- [ ] GitHub Actions workflow for scheduled audits

---

## Contributing

Issues and PRs welcome. New secret patterns, additional posture checks and
false-positive reduction are the most valuable contributions. Keep it single file.

---

## License

MIT


Example:

<img width="964" height="573" alt="image" src="https://github.com/user-attachments/assets/dfd178d1-487c-441d-8b78-ebc993d81d9c" />

