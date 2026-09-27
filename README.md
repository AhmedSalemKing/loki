# LOKI

Terminal-first browser security workspace for testing authenticated web
applications — built to consolidate a handful of manual, repetitive bug
bounty / pentest steps (dual-account IDOR checks, race condition probes,
secret scanning, hidden endpoint discovery, business-logic flow abuse,
per-endpoint authorization sweeps) into single commands, driven by a real
authenticated browser session instead of a raw HTTP client.

## ⚠️ Legal & Scope — read before using

LOKI sends **real requests to live targets** using your authenticated
session, including mutating ones (enroll, purchase, redeem a coupon, vote).
Only run it against:

- an application you own,
- a target where you have explicit, current authorization to test
  (e.g. an active bug bounty / VDP program whose scope and rules permit
  this kind of testing), or
- a local/lab environment you control.

Testing a target without authorization is illegal in most jurisdictions
and will usually violate its Terms of Service, regardless of intent.
**You are solely responsible for how you use this tool and for staying
within the scope and rate limits of any program you test against.**

Commands that can trigger real, possibly duplicated side effects
(`race`, `flow abuse`) require `--dry-run` to preview or an explicit
`--yes`/confirmation prompt before sending anything for exactly this
reason — don't script around that confirmation on a target you haven't
cleared to test at that intensity.

## What LOKI actually does

| Command | Purpose |
|---|---|
| `session start <host>` | Log in manually once in a real browser; LOKI captures cookies, storage, tokens, and auto-crawls to discover endpoints and auth headers (including a separate API host's `Authorization` header, if the frontend uses one). |
| `req get/post/put/delete <path>` | Authenticated request via the browser's own `fetch()` — inherits real cookies/headers, bypasses WAFs that block plain HTTP clients. |
| `diff <path>` | Same request through two isolated account sessions (owner vs. attacker) — first-pass IDOR signal from status/size comparison. |
| `race <path>` | Fire N identical requests at the same instant to test for race conditions (coupon reuse, double-spend, single-use bypass). |
| `fuzz <template>` | IDOR fuzzing with `§ID§`/`§FUZZ§` markers over a range or wordlist. |
| `sweep` | Test every endpoint discovered during crawl as owner / other account / unauthenticated, in one pass — auto-resolves each endpoint's real host and auth header on multi-host deployments. |
| `secrets scan` | Scan captured JS/storage for exposed tokens, keys, and secrets. |
| `recon hidden` | Diff JS-referenced routes against routes actually called during browsing — surfaces unlinked/admin paths. |
| `recon snapshot` / `diff-snapshot` | Snapshot endpoints + JS hashes now, diff against a later snapshot to catch changes over time. |
| `flow record <name>` / `flow abuse <name>` | Record a real multi-step flow (e.g. add-to-cart → checkout), then replay it broken: skip a step, replay an early step after completion, race the last **mutating** step. |

## What LOKI is *not*

- Not a replacement for Burp Suite / ZAP — no proxying, no request
  tampering UI, no scanner engine.
- Not a source of genuinely novel vulnerability classes — every technique
  here (IDOR diffing, race testing, secret scanning, JS route diffing)
  has free, mature equivalents (Autorize, Turbo Intruder, race-the-web,
  LinkFinder, etc.).
- Its value is **consolidation and speed**: one authenticated browser
  session, one CLI, instead of repeating the same manual setup across
  several separate tools for every target.

## Install

```bash
git clone https://github.com/AhmedSalemKing/loki.git
cd loki
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
playwright install chromium
```

Requires Python ≥ 3.10.

## Quick start

```bash
loki session start example.com --slot victim
# log in manually in the browser that opens, press ENTER when done —
# LOKI auto-crawls and captures endpoints + auth headers

loki sweep --slot victim --show-all
loki req get /api/profile/me --slot victim
loki race /api/coupons/redeem --slot victim --count 10 --dry-run
```

## Known limitations

- Host auto-detection (`resolve_host_for_path`) matches against endpoints
  seen during the crawl for that exact path — a path never crawled won't
  auto-resolve and falls back to the session's own host; pass `--host`
  explicitly when that happens.
- `flow abuse`'s race-final-step targets the last **mutating**
  (POST/PUT/PATCH/DELETE) step recorded — if a flow has no mutating step,
  that part is skipped rather than racing a meaningless GET.
- Tested primarily against Next.js/Vercel-style SPA + separate API-host
  deployments; other architectures may need `--host` more often.

## License

MIT — see LICENSE.

## Rate-limiting / staying in scope

Programs that forbid high-traffic automated scanning need conservative
timing:

- `sweep` already waits `--delay` seconds between each endpoint request
  (default 0.4s) and caps total endpoints tested with `--limit` (default
  150).
- `fuzz` waits `--delay` seconds between each batch of concurrent
  requests (default 0.0s, i.e. off — set `--delay 0.5` to `1.0` for
  rate-limited programs).
- `race` and `flow abuse`'s race-final-step are inherently concurrent by
  design (that's the point of a race condition test) — there is no safe
  way to throttle a race test without breaking what it's testing for.
  Only use them where the program's scope explicitly allows race-condition
  testing, and keep `--count` as low as the test still needs.
