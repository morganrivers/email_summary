# Security hardening plan

Status: proposed. Track B is done; nothing else is started except the item in
"Already done" below.
Written 2026-08-07. Owner: Morgan.

## How to read this

This document is written to be actionable without the conversation that produced
it. Every claim about current behaviour carries a file and, where useful, a line
number. Line numbers were accurate at the commit this was written against
(`a46c03e`); if one is off by a few, the function name is the durable reference.

Each track states: why it exists, what the code does today, the changes, what to
test, what "done" means, and what will bite. Tracks marked parallel share no
files and can be worked in any order or simultaneously.

Read `CLAUDE.md` first for the deployment model and the single-sources-of-truth
list. Read `docs/plan_token_custody.md` for the custody design this builds on.

## Context a cold reader needs

Letterlock drafts email replies. It runs on one Hetzner box
(`hezner.morganrivers.com`, app dir `/opt/letterlock`), deployed by
`deploy/deploy.sh`, managed by systemd. There is a second trust domain on the
same box: the co-signer (`cosigner/`), running as its own unix user, holding the
outer half of every Gmail refresh token's encryption plus the DPoP signing key
Google bound those tokens to.

Split custody works like this. A refresh token is encrypted twice. The inner
layer is the application's (`backend/custody/wrapping.py`, key derived by HKDF
from the dstack KMS `app_secret`). The outer layer is the co-signer's
(`cosigner/keys.py`, key derived from a TPM-sealed master credential). The
application holds the ciphertext and cannot strip the outer layer. The co-signer
holds the outer key and no ciphertext at all. Neither box alone gets a usable
token. `cosigner/__init__.py` states the four invariants; read them before
touching anything in that package.

There are currently **no production users**. `MAX_ACCOUNTS` is 100
(`backend/accounts/account.py:63`). This is why several tracks below skip
migration machinery entirely: wiping `database/` and re-onboarding is an
acceptable cost right now, and will not be later.

## Scope

**In scope.** Hardening the current Hetzner deployment. Tracks A through G.

**Out of scope, decided.**

- *Phala / CVM migration.* We are hardening, not going to production. No compose
  changes, no measured-image work, no `cosigner/allowlist.json` re-pinning
  against a built image. `deploy/phala/` stays as it is and continues to be
  generated from `requirements.txt` so it does not rot.
- *Presidio + spaCy PII analyzer.* 96% recall with it, 74% without, the whole gap
  being PERSON entities. It costs about 1.6 GB resident, which does not fit
  alongside the web server in a 2 GB CVM. Decision: keep it commented out of
  `requirements.txt` and off by default, offer it as an option, and do the
  instance sizing only if a paying customer asks for it. Do not size up
  speculatively. `backend/masking/pseudonymizer.analyzer_available()` already
  detects it by module lookup without importing, so switching it on later is an
  install plus a settings flip and touches no code.
- *Policy engine (OPA / Cedar / OpenFGA) and Postgres row-level security.* See
  "Rejected designs" for the reasoning. Do not re-litigate without new
  requirements.

**Deferred with a trigger.** Tracks H, I. Each states its trigger.

## Already done

The checkout IDOR is fixed as of this commit. `frontend/web_server.py`'s
`/billing/return` handler took a `checkout_id` from the query string and passed
it to `billing.PolarBilling.confirm_checkout`, which flipped the signed-in
account to `active` and bound that checkout's Polar `customer_id` to it, with no
check that the checkout belonged to the buyer. Any signed-in account presenting
any paid checkout id took the subscription and then got `portal_url()` pointed at
someone else's Polar customer.

Fix: `billing.CHECKOUT_ACCOUNT_KEY` is stamped into every checkout
`checkout_url()` mints, `PolarBilling.resolve_account()` reads it first, and
`confirm_checkout()` refuses a checkout that does not resolve back to the
signed-in account before it links a customer or flips a plan. Tests in
`tests/test_billing.py`.

Relevant lesson for the tracks below: that bug was not a missing authorization
check. It was an externally supplied identifier used before being resolved to an
owner. Keep that failure mode in mind rather than looking only for missing
`if` statements.

## Stale docstring claims: fix them where the code changes

Several docstrings in this codebase state properties the code does not provide.
**Do not correct them as a standalone pass.** Every one is superseded by a track
below, so a correction written now gets rewritten within weeks, and a docstring
edited twice is worse than one edited once: the intermediate version lands in a
diff someone later reads as the final word.

The rule: a docstring is corrected in the same commit as the behaviour change
that makes it true or false. Never speculatively, never ahead of the code.

| Claim | Where | Why it is wrong today | Corrected in |
|---|---|---|---|
| ~~"no UPDATE and no DELETE appears anywhere in this package"~~ | `cosigner/audit.py` | ~~B3 adds a prune~~ | **done in B3**: the claim is now "no UPDATE anywhere, and deletion only by `retention.py`, only by age" |
| compromising this box yields a wrapping key with nothing to unwrap and a signing key that signs no secrets | `backend/custody/client.py:6-9` | both halves are true, but it omits that the box also holds the customer list and a per-user activity timeline | **F4**, which makes `uid` opaque |
| the version prefix exists so the master key can be rotated | `cosigner/keys.py:54` | `keys.py:129` and `:157` both assert `version == KEY_VERSION`, so rotation cannot execute | **G4**, which implements rotation |
| per-uid derivation makes a future per-user revocation meaningful | `cosigner/keys.py:12-15` | `KEY_VERSION` is a module constant (`keys.py:56`), not a per-account field, so there is nothing to advance for one user | **G5**, where the per-account DEK makes it true |
| the co-signer holds a key you cannot get | `cosigner/__init__.py`, `keys.py:1` | true today; becomes false if Track H moves key material to an HSM, after which the box's value is policy plus audit | **H**, if it happens |

If a track slips far enough that a false claim would sit in `main` for months,
delete the sentence rather than write a provisional replacement.

This list is how the checkout IDOR and the audit-schema gap were both found:
read a docstring against the code it describes and see which one is lying.

## Dependency graph

```
A  dependency hygiene        ──────────────►  independent
B  co-signer policy + audit  ──────────────►  DONE
C  web-tier audit log        ──────────────►  independent
D  session key rotation      ──────────────►  independent
E  egress allowlist          ──────────────►  independent

F  opaque account handle  ──►  G  envelope + per-account encryption

deferred:  G ──► H (HSM)          trigger: cost confirmed acceptable
           I (image provenance)   trigger: independent, do when there is slack
```

A, B, C, D, E are five parallel tracks with no shared files. Start any of them
now, in any order, including simultaneously.

F is small and must land before G, because both change the co-signer wire
contract and doing them separately means two protocol revisions.

G is the long pole and the only track with meaningful design risk.

---

# Track A. Dependency hygiene

**Parallel.** Touches `requirements.txt`, `deploy/phala/`, `.github/`,
`tests/`. Estimated effort: half a day.

## Why

Nothing currently tells you a shipped dependency has a known vulnerability. Pins
are bumped by hand when someone remembers. The scheduled check is the point:
your code does not change daily, but the advisory database does, so the same
pins can become vulnerable overnight with no commit involved.

## Current state

`requirements.txt` is the single dependency list for both the box and the
enclave image (`CLAUDE.md`, "Single sources of truth"). `deploy/requirements.py`
parses it. `deploy/render_pyproject.py` renders `deploy/phala/pyproject.toml`
from it. `deploy/phala/uv.lock` is the resolved transitive closure that uv2nix
builds the image from. `tests/test_requirements.py` fails if the committed
pyproject has drifted from `requirements.txt`.

Hetzner installs via `venv/bin/pip install -r requirements.txt`, triggered by
`deploy/deploy.sh` when the manifest changes.

The three-artifact chain is what makes this track fiddly. Getting it wrong
produces a bot that files PRs which cannot pass CI.

## Changes

**A1. Bump the pins.**

```bash
# edit requirements.txt
python -m deploy.render_pyproject
(cd deploy/phala && uv lock)
micromamba run -n py311 python -m pytest -q
```

Acceptance: `tests/test_requirements.py` passes and the suite result matches the
pre-bump baseline exactly (currently 202 passed, 5 skipped). Record both numbers
in the commit message so a future bump has a baseline to compare against.

**A2. pip-audit as a gated test.**

Audit `deploy/phala/uv.lock`, not `requirements.txt`. The lock is the full
transitive closure; `requirements.txt` holds direct pins only and will miss a
CVE in anything pulled in indirectly (the `urllib3`-under-`requests` case).

Add `pip-audit` to a dev/test extra, not to `requirements.txt`. It must not ship
to the box or into the image.

The test makes a network call to the advisory service. Gate it so a local run
skips it:

```python
@pytest.mark.skipif(
    not os.environ.get("LETTERLOCK_AUDIT"),
    reason="network-dependent; runs in the scheduled job",
)
def test_no_known_vulnerabilities_in_the_lock():
    ...
```

Without the gate the suite fails offline and on any sandboxed runner, and
someone will delete the test rather than debug it. The repo already has 5
skipped tests, so the pattern is established.

**A3. Dependabot, security updates only.**

`.github/dependabot.yml`, ecosystem `pip`, directory `/`, so it edits
`requirements.txt` and only `requirements.txt`.

Do not point it at the `uv` ecosystem. That would make it edit
`deploy/phala/pyproject.toml` directly, which is a generated file, and the next
`render_pyproject` run silently reverts its work.

Set `open-pull-requests-limit` low. Configure for security updates only:
`openai` alone shipped roughly 90 releases in the last year and a full version
feed on this repo is unreadable.

**A4. Regeneration step on Dependabot branches.**

This is the step that decides whether the feed is useful. Dependabot cannot know
`pyproject.toml` is generated, so every PR it files will fail
`tests/test_requirements.py` on arrival. Add a CI job, conditioned on the branch
prefix, that runs:

```bash
python -m deploy.render_pyproject
(cd deploy/phala && uv lock)
```

and commits the result back to the PR branch. Without it, every Dependabot PR
needs a manual follow-up commit, and a feed that is always red gets muted.

**A5. Two scheduled workflows, not one.**

- **Daily, blocking.** Full suite plus `LETTERLOCK_AUDIT=1`, against the
  committed pins. Deterministic. The input that changes is the advisory
  database.
- **Weekly, non-blocking.** Resolve latest instead of the pins, run the suite,
  report. Answers whether the next Dependabot PR will break you.

Keep them separate. They fail for different reasons and at different rates. A
shared exit code means the compatibility failures train you to ignore the
vulnerability failures.

## Risks

`pip-audit` occasionally reports advisories with no fixed version available. The
daily job will then be red with no action possible. Decide up front whether that
blocks (and you pin an ignore with an expiry date and a comment) or warns. An
ignore list with no expiry becomes permanent.

---

# Track B. Co-signer policy, alerting, retention

**Done.** Landed as written, with the decisions it asked for recorded below.
`backend/custody/client.py:6-9` was deliberately left alone: the table above
assigns that correction to F4, and a docstring edited twice is worse than one
edited once.

Decisions taken, all of them next to the constants in `cosigner/policy.py`:
40 distinct accounts per 15 minutes (a full box at one unwrap per account per
hour produces about 25); alert only, no automatic kill switch, because there is
no bypass and a false positive would stop mail for everyone; an account already
counted inside the window is not refused, since refusing it narrows no breach.
Retention is 30 days for ALLOW rows and a year for DENY rows, pruned by
`cosigner/retention.py` on a thread inside the co-signer rather than a systemd
unit — a second process would take an exclusive VACUUM lock on the file the
service answers every request out of.

**Parallel.** Touches `cosigner/policy.py`, `cosigner/audit.py`,
`cosigner/alerts.py`, docstrings in `cosigner/__init__.py` and
`backend/custody/client.py`. Estimated effort: one to two days.

## Why

The threat this addresses is bulk exfiltration. Someone who gets code execution
inside the enclave can ask the co-signer to unwrap one account at a time. The
crypto cannot prevent that, because the enclave is the party legitimately
allowed to ask. What bounds it is the rate limit, and what makes it visible is
the log. Today the rate limit does not catch the shape of a bulk sweep, and
nothing reads the log.

## Current state

`cosigner/policy.py:172` `authorize(uid, action, verdict, precheck)` is the
single policy decision point. Every request goes through it. Order:

1. kill switch (`disabled_reason()`)
2. attestation verdict (`verdict.ok`)
3. request shape (`precheck`, supplied by the caller)
4. wrap-once, for `ACTION_WRAP` only (`_wrap_once_refusal`, `policy.py:129`)
5. rate limit (`_rate_refusal`, `policy.py:134`)

Then `audit.record(...)` at `policy.py:193`, inside the same `with _LOCK`, so
the number the limiter enforced and the number the log shows cannot disagree.
That property is deliberate and documented at `cosigner/audit.py:20-22`. Preserve
it.

Three actions (`policy.py:33-37`): `wrap`, `unwrap-and-sign`, `sign`. Called
from `cosigner/server.py:112`, `:125`, `:137`.

### The audit table

Schema at `cosigner/audit.py:31`:

```sql
CREATE TABLE requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    uid TEXT NOT NULL,
    action TEXT NOT NULL,
    decision TEXT NOT NULL,
    reason TEXT,
    fingerprint TEXT,
    measurement TEXT,
    attested INTEGER NOT NULL
);
CREATE INDEX requests_uid_action_ts ON requests (uid, action, ts);
CREATE INDEX requests_ts ON requests (ts);
```

What each column holds:

| column | source | contents |
|---|---|---|
| `ts` | `time.time()` | when the decision was made |
| `uid` | `protocol.F_UID` off the wire | the account identifier the enclave sent. Today this is `account.id`, which is the user's **email address**. Optional on `sign`, defaulting to `""` (`server.py:124`) |
| `action` | `policy.ACTIONS` | `wrap`, `unwrap-and-sign`, `sign` |
| `decision` | | `allow` or `deny` |
| `reason` | `Refusal.reason` | NULL when allowed; otherwise the kill-switch reason, attestation reason, precheck string (`empty inner`, `empty outer`, an `allowed_target` refusal), wrap-once refusal, or rate refusal |
| `fingerprint` | `verdict.fingerprint` | `sha256(cert_der).hexdigest()` of the enclave's RA-TLS client certificate (`attest.py:114`). New keypair every enclave boot |
| `measurement` | `verdict.measurement` | the TDX measurement set from the quote that matched the allowlist |
| `attested` | `verdict.attested` | 1 in production, 0 when attestation is disabled for dev |

Example rows:

```
id  ts          uid        action           decision  reason                       attested
1   1754531002  dan@x.com  wrap             allow     NULL                         1
2   1754534610  dan@x.com  unwrap-and-sign  allow     NULL                         1
3   1754537221  dan@x.com  wrap             deny      uid already wrapped          1
4   1754540833  eve@y.com  unwrap-and-sign  deny      per-uid ceiling reached (24) 1
5   1754544441  ''         sign             allow     NULL                         1
```

**What is not in a row:** no `inner`, no `outer`, no proof, no token, no message
content. `record()` (`audit.py:93`) takes no argument that could carry one and
the schema has nowhere to put it. This is invariant 4 and it holds as written.

**What is in a row, which is the problem:** `SELECT DISTINCT uid FROM requests`
is the complete customer list in plaintext email addresses. `ts` paired with
`uid` is a per-user activity timeline: an unwrap happens when that person's mail
is processed, so row density per user per hour reveals working hours, timezone,
weekends, holidays, and the week they stopped using the product. That
contradicts `backend/custody/client.py:6-9`, which says compromising this box
yields a wrapping key with nothing to unwrap and a signing key that signs no
secrets. Both halves of that sentence are true; it is the omission that Track F
fixes.

### Readers of the table

- `granted_since(since, action, uid)` (`audit.py:110`). Counts ALLOW rows with
  `ts >= since`. **Always windowed.** Called three ways from `_rate_refusal`
  (`policy.py:145`, `:150`, `:154`).
- `ever_granted(uid, action)` (`audit.py:126`). **Unbounded lookback**, no time
  bound. Called once, `policy.py:129`, for `ACTION_WRAP` only.
- `recent(limit=50)` (`audit.py:138`). Operator view. No retention need.

## Changes

**B1. Distinct-uid velocity limit.**

The existing limiter is per-uid plus a per-action total. A sweep that touches
all 100 accounts once each passes both: every user is comfortably under their
own ceiling. The exact pattern worth detecting is the one that looks most normal
to the current rule.

Add a global rolling-window count of **distinct uids** granted `unwrap-and-sign`.
Normal operation touches a handful of accounts per minute, driven by mail
arriving. A sweep touches all of them in a burst. The `requests_ts` index already
supports the query; no schema change.

```sql
SELECT COUNT(DISTINCT uid) FROM requests
 WHERE decision = 'allow' AND action = ? AND ts >= ?
```

Add it to `audit.py` next to `granted_since` (call it `distinct_uids_since`) and
consult it in `_rate_refusal`. Pick the window and threshold from expected
traffic: after Track G, with a per-account DEK on an hourly cache TTL, steady
state is roughly one unwrap per active account per hour. A 15-minute window with
a ceiling well above that but well below 100 is the shape.

**B2. Alerting.**

`cosigner/alerts.py` is the only thing `cosigner/` imports from `backend/`, and
it reaches Telegram. `policy._alert` (`policy.py:161`) already throttles per
`(action, kind, reason-prefix)` on `ALERT_INTERVAL`. Reuse that mechanism for
the B1 threshold.

Fire once per incident, not once per request. A hundred identical alerts is how
an operator learns to mute the channel; the same discipline is documented for
`ProviderUnavailable` in `CLAUDE.md`.

Decide and write down: alert only, or alert and trip the kill switch. At 100
accounts, alert only. Automatic refusal bounds the loss without you being awake,
but there is deliberately no bypass in this design, so a false positive stops all
mail processing for everyone. Revisit when the account count makes a manual
response too slow.

**B3. Retention.**

The naive rule "prune rows older than the rate window" is wrong and will break
wrap-once. Precisely:

- **Prunable.** ALLOW rows for `unwrap-and-sign` and `sign` older than the
  longest rate window. Only `granted_since` reads them, and it is always
  windowed. This is essentially all the volume: after Track G, roughly 2400 rows
  a day at 100 accounts, near 900k a year.
- **Never prunable.** ALLOW rows where `action = 'wrap'`. `ever_granted` looks
  back to the beginning of time. Delete one and that uid becomes eligible for a
  second wrap, which is exactly the condition `audit.py:127-129` calls either a
  bug or an attacker asking us to re-wrap. One row per account for life, so 100
  rows. Not a volume problem, just a correctness landmine.
- **Prunable but should not be.** DENY rows. Both readers filter
  `decision = ALLOW`, so nothing enforcement-related touches them. They are the
  highest-value evidence in the table. Keep them longest. If they are ever high
  volume, that is B2 firing, not a retention problem.

**Recommended design: split state from log.** The table currently does two jobs,
and B1 makes it worse by adding a third reader with its own window, so the
retention floor becomes the max across all windows and moves whenever someone
adds a limiter.

Add a small table holding wrap-once state only:

```sql
CREATE TABLE grants (
    uid    TEXT NOT NULL,
    action TEXT NOT NULL,
    first_granted_ts REAL NOT NULL,
    PRIMARY KEY (uid, action)
);
```

Write it in the same transaction, under the same `_LOCK`, as the log row. The
invariant at `audit.py:20-22` survives because it is still one call and still
atomic. `ever_granted` reads `grants`. `granted_since` keeps counting out of
`requests`, since that is the windowed reader and where the volume is.
`requests` then becomes freely prunable and retention is a policy dial rather
than a correctness hazard.

*Simpler alternative if you want less surface:* keep one table and prune only
`decision = 'allow' AND action IN ('unwrap-and-sign','sign') AND ts < cutoff`.
Correct, but the safety of the prune then depends on a `WHERE` clause that a
future limiter can silently invalidate. Prefer the split.

**Two things that will bite:**

`cosigner/audit.py:9-11` states that no UPDATE and no DELETE appears anywhere in
the package. Adding a prune makes that false. Either revise the claim or put the
prune in its own module or script so the statement stays true of the package.
The same class of stale claim is what B4 exists to fix.

SQLite `DELETE` does not reclaim pages. Deleted rows remain readable in the
file's free list until `VACUUM`. For a table whose stated point is not to hand
over a customer list, that matters, and it matters for rows written before Track
F makes `uid` opaque. Set `PRAGMA secure_delete=ON` on the connection, or
`VACUUM` after each prune.

## Acceptance

A synthetic sweep of every account in a short window trips B1, produces exactly
one Telegram alert, and leaves a DENY row per refused request. A prune run
leaves `ever_granted` answers unchanged for every account that has ever been
wrapped. `sqlite3 audit.db 'PRAGMA freelist_count'` after a prune plus vacuum is
zero.

---

# Track C. Web-tier audit log

**Parallel with A, B, D, E.** Mild file overlap with Track G if G changes the
settings writers, so land it before G or accept a rebase. Touches
`frontend/web_server.py`, `backend/accounts/account.py`, plus a new module.
Estimated effort: one day.

## Why

The co-signer logs every custody decision. Nothing else is logged anywhere but
stderr, which goes to the journal, is unstructured, and rotates on the host
default. There is no record of who signed in, what they changed, or that an
account was deleted.

## Current state

Every authenticated route in `frontend/web_server.py` does
`acct = self._require_auth()` (`_get_account` / `_require_auth`, around
`:1434-1440`), which derives the account from the HMAC-signed session cookie via
`frontend/session.get_email` (`session.py:118`). No route reads an account id
from the request. That part is sound and should not change.

The mutating paths, all of which currently record nothing:

- sign-in and sign-out (`session.make_cookie` `:92`, `clear_cookie` `:101`)
- `account.set_settings` (`account.py:475`): timezone, auto_schedule,
  inference provider, PII analyzer preference, `ban_dashes`
- `account.set_telegram` (`account.py:418`): link and unlink
- `account.set_voice` (`account.py:457`) and `voice_dna.save` / `clear`
  (`voice_dna.py:205`, `:224`)
- `personal_context.save` / `clear` (`personal_context.py:74`, `:95`)
- `account.set_plan_status` (`account.py:393`) and
  `account.set_polar_customer_id` (`account.py:440`)
- `account.register_account` (`account.py:309`) and `delete_account` (`:536`)
- OAuth consent and re-consent through
  `backend/onboarding/provisioning.handle_callback`

## Changes

**C1.** One writer module, `backend/audit.py` (application side, deliberately
not the co-signer's, which must not learn who users are). Structured rows: `ts`,
`account_id`, `action`, `outcome`, `detail`, `source_ip`, `user_agent`. Same
discipline as the co-signer's: no parameter that can carry secret material, and
say so in the docstring so nobody adds one for debugging.

**C2.** Call it from the account mutators in `account.py` rather than from the
route handlers. The mutators are already the sole writers of the manifest
(`account.py:31-34` documents this), so putting the audit call there means a
future second caller cannot forget it. This is the same reasoning that makes
`set_polar_customer_id` the sole writer of its field.

**C3.** Sign-in, sign-out and consent are not manifest mutations, so they are
logged from `web_server` and `provisioning` directly.

**C4.** Retention and storage. SQLite under `state/`, 0600. Decide a retention
period and implement the prune with it, applying the same `secure_delete` note
from B3.

## Acceptance

Sign in, change every setting, link and unlink Telegram, edit both documents,
delete the account. Every one produces exactly one row with the correct account
and outcome. Grep the module for anything that could carry a token or a document
body and find nothing.

---

# Track D. Session key rotation

**Parallel.** Touches `frontend/session.py` only. Estimated effort: two hours.

## Why

Rotating `SESSION_SECRET` today signs every user out simultaneously, which means
it will never be rotated.

## Current state

`session.py:51` `_mac(purpose, payload)` computes
`hmac.new(_get_secret(), f"{purpose}:{payload}")`. `_signed` (`:63`) formats the
cookie value, `_open_signed` (`:67`) verifies with `hmac.compare_digest`
(`:83`). The secret comes from `_get_secret` (`:40`), whose variable name is
owned by `backend/secrets.py` (`SESSION_SECRET_ENV`) so nothing in `backend/`
reaches into `frontend/`.

There is no key identifier in the cookie, so verification has exactly one key to
try.

## Changes

**D1.** Add a short key id to the signed value. Format becomes
`kid:value:iat:mac`.

**D2.** Accept a set of keys during verification, current plus previous. New
cookies are always minted under the current key. Source the previous key from a
second environment variable, `SESSION_SECRET_PREVIOUS`, registered in
`backend/secrets.py` alongside the current one so `fingerprint()` covers both
and the startup line shows which pair the process captured.

**D3.** The same treatment applies to the OAuth state cookie
(`new_state` `:143`, `state_cookie` `:148`, `state_is_ours` `:177`), which uses
the same MAC. A rotation mid-consent should not turn a legitimate sign-in into a
CSRF alarm.

## Acceptance

Sign in, rotate the secret with the old value moved to
`SESSION_SECRET_PREVIOUS`, restart, and the existing session still works. Remove
the previous value and the same session is rejected. A cookie with an unknown
`kid` is rejected without a timing difference from a bad MAC.

---

# Track E. Egress allowlist

**Parallel.** Touches `deploy/hetzner/hardening.conf` and possibly per-unit
drop-ins. Estimated effort: half a day, most of it verification.

## Why

Nothing constrains where these processes can connect. An RCE in the web server
or the webhook receiver can post user data anywhere. This is one of the few
controls that still functions after code execution.

## Current state

`deploy/hetzner/hardening.conf` is the single copy of the sandbox settings,
fanned out by `deploy/deploy.sh` as
`/etc/systemd/system/<unit>.d/10-hardening.conf` for every unit it deploys. It
currently sets `User=letterlock`, `ProtectSystem=strict`, `NoNewPrivileges`,
`UMask=0077`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` and the usual
`Protect*` set. There is no `IPAddressAllow` / `IPAddressDeny`.

A unit that must differ says so in `deploy/hetzner/<unit>.d/*.conf`, numbered
above `10-hardening.conf`. `cosigner.service.d/20-cosigner.conf` is the existing
example.

## Changes

**E1.** Add `IPAddressDeny=any` plus an `IPAddressAllow=` list to
`hardening.conf`. Destinations needed across the units: Google (OAuth, Gmail,
Calendar), the inference providers named in `llm_client.PROVIDERS`, Telegram,
Polar, and loopback for the co-signer and Caddy.

**E2.** The complication is that these are hostnames behind CDNs with wide and
changing address ranges, and systemd's `IPAddressAllow` takes addresses and
prefixes, not names. Two workable shapes:

- Allow the published prefixes, accept that they change, and treat a connection
  failure after a provider's range moves as an operational event. Brittle.
- Deny by default and route outbound traffic through a local proxy that
  allowlists by hostname, with `IPAddressAllow=localhost` on the units. More
  moving parts, but the allowlist becomes a readable list of hostnames.

Pick one before writing config. The second is more work now and much less
maintenance later.

**E3.** Per-unit narrowing where it is cheap. `cosigner.service` talks to
loopback and Telegram and nothing else, so its drop-in can be far tighter than
the shared file. That is exactly what the numbered drop-in mechanism is for.

## Risks

Getting this wrong takes the system off the network, and the failure looks like
a provider outage rather than a config error. Deploy with `DRY_RUN=1` first,
then to one unit, and check `deploy/preflight.py` still passes before doing the
rest.

---

# Track F. Opaque account handle

**Blocks Track G.** Must land first. Touches `cosigner/protocol.py`,
`cosigner/audit.py`, `cosigner/policy.py`, `backend/custody/client.py`,
`backend/accounts/account.py`. Estimated effort: one day.

## Why

The co-signer's audit table holds every user's email address (see Track B's
column table). The co-signer needs a stable per-user handle to enforce the
per-uid ceiling and wrap-once. It does not need that handle to be a name.

Do this before Track G because both change the wire contract, and one protocol
revision is better than two.

## Current state

`protocol.F_UID` (`protocol.py:53`) carries `account.id`, which is the user's
email. It is sent by `client.wrap` (`client.py:230`) and
`client.unwrap_and_sign` (`client.py:243`), read by `server.wrap_request`
(`server.py:106`) and `server.unwrap_request` (`server.py:132`), passed to
`policy.authorize`, and stored in the audit `uid` column.

The uid is also the AAD and HKDF salt in both crypto layers:
`wrapping.inner_key(uid, key_version)` (`wrapping.py:109`) and
`keys.outer_key(uid, version)` (`keys.py:127`), with `uid` as AES-GCM AAD in
`keys.wrap` / `keys.unwrap` (`keys.py:135`, `:147`). That is what stops a record
being replayed under another tenant's id.

## Changes

**F1.** Add a per-account opaque handle. Two options:

- Random 128-bit value generated at `register_account` (`account.py:309`) and
  stored in the manifest entry. Simplest, and unlinkable by construction.
- `HMAC(k, account.id)` under a key only the enclave holds. No new manifest
  field, and derivable if the manifest is lost, but it is one more key to manage.

Prefer the random value. The manifest is already the account's system of record
and already holds PII, so a new field there adds no new exposure.

**F2.** Send the handle as `F_UID` instead of the email. Nothing on the
co-signer side needs to know it changed, because nothing there parses the value.

**F3.** The crypto AAD and salt must move to the handle at the same time, since
both sides derive from the same value. **This is a breaking change to every
stored record.** With no production users, wipe `database/` and re-onboard. Do
not write a migration.

**F4.** Docstrings, in this commit and not before. `keys.py` describes the salt
as an account id, which stops being true here. `backend/custody/client.py:6-9`
says compromising the co-signer yields a wrapping key with nothing to unwrap and
a signing key that signs no secrets; both halves are true and the omission is
what this track closes, so the corrected sentence should say what the box does
and does not learn, including that the activity timeline survives and is now
attached to an opaque handle rather than a person.

## Acceptance

`SELECT DISTINCT uid FROM audit.db` yields opaque values only. Rate limiting and
wrap-once behave identically under the new handle (existing co-signer tests
should pass unchanged once fixtures are updated). Onboarding a fresh account end
to end works.

## Consequence to accept

The kill switch and any manual intervention now operate on opaque ids. Acting on
a named user requires a lookup on the enclave side. Add a small operator command
for it or you will regret this the first time you need it in a hurry.

---

# Track G. Envelope encryption and per-account data encryption

**Depends on F.** The long pole and the only track with design risk. Touches
`backend/custody/wrapping.py`, `backend/custody/tokens.py`,
`backend/custody/client.py`, `cosigner/keys.py`, `backend/accounts/account.py`,
`backend/drafting/voice_dna.py`, `backend/drafting/personal_context.py`.
Estimated effort: one to two weeks.

## Why

Two separate goals that share one mechanism.

**True envelope semantics.** There is no data encryption key anywhere in this
codebase today. Both layers derive keys and store none: `wrapping.inner_key`
(`wrapping.py:109`) is `HKDF(app_secret, salt=f"{uid}|{version}",
info=b"gmail-refresh")`, and `keys.outer_key` (`keys.py:127`) is
`HKDF(master, salt=uid, info=b"outer")`. Both are computed per call and never
persisted. `encode_record` (`tokens.py:109`) writes
`LLTK | record_version | key_version | outer` with no key field.

The consequence is that rotation means decrypt-and-re-encrypt every record with
code holding both key versions. The inner layer can at least read old versions
(`open_inner` takes the record's `key_version`, `wrapping.py:129`); the outer
layer cannot, because `outer_key` (`keys.py:129`) and `unwrap` (`keys.py:157`)
both assert `version == KEY_VERSION`. So the rotation that `keys.py:54` promises
is structurally impossible today, and no re-wrap routine exists anywhere
(`grep -rn "rotat"` finds only comments).

With a DEK, rotation re-wraps 100 small headers and touches no user data.

**Per-account data isolation.** All six app units run as `letterlock`
(`hardening.conf`), so filesystem permissions do not isolate tenants from each
other or from a process that gets code execution. The envelope covers the Gmail
refresh token only. Voice profiles, personal context, `database/accounts.json`,
`state/` and the drafts are plaintext on disk, protected by 0700/0600 and the
uid alone (`account.py:130` `secure_dir`, `:139` `_write_manifest`,
`tokens.py:138` `store_record`).

Making the DEK cover the whole account directory means a stolen disk yields
ciphertext, and reading it requires going through the co-signer, which rate
limits (Track B) and logs (Track B) and therefore makes bulk exfiltration
visible.

## Design

Per account: one random 32-byte DEK. The DEK encrypts the account's data. The
DEK itself is wrapped by the existing two-layer custody, inner then outer, so the
co-signer remains required to open it and the layer order is unchanged.

```
DEK (random 32 bytes, per account)
  └─ encrypts: token.bin payload, voice-dna.md, personal-context.md,
               anything else under database/<handle>/
wrapped DEK
  └─ inner layer:  AES-GCM under wrapping.inner_key(handle, key_version)
      └─ outer layer: AES-GCM under cosigner keys.outer_key(handle, version)
```

Record header carries `record_version | key_version | wrapped_dek`, so the
version travels with the wrapped key rather than with the data.

## Changes

**G1. DEK generation and the record header.**

- `wrapping.py`: `new_dek()`, and `seal_dek` / `open_dek` replacing the current
  `seal_inner` / `open_inner` role. The inner key becomes the key that wraps the
  DEK rather than the key that encrypts the token.
- `tokens.py:109` `encode_record` and `:120` `decode_record` grow the wrapped-DEK
  field. Keep the `LLTK` magic and bump `RECORD_VERSION` (`tokens.py:43`).
- `tokens.py:165` `take_custody` generates the DEK at custody time.

**G2. Extend coverage to the account directory.**

- `voice_dna.profile_path` (`voice_dna.py:157`), `load` (`:182`), `save`
  (`:205`), `clear` (`:224`).
- `personal_context.context_path` (`personal_context.py:57`), `load` (`:65`),
  `save` (`:74`), `clear` (`:95`).
- Route both through one encrypted-file helper rather than teaching each module
  about crypto. One `read_encrypted(handle, name)` / `write_encrypted(...)` pair
  is the single seam.
- `account._owned_paths` (`account.py:513`) already owns the whole
  `ACCOUNTS_DIR/<id>/` tree, which is why `delete_account` (`:536`) is complete.
  Keep that property.

Note `voice_dna.OWNER_PROFILE` (`voice_dna.py:59`) resolves to
`paths.config_file("voice-dna-email.md")`, which lives in `config/` and is pushed
by the deploy from `~/.system_files`. That one is operator content, not user
content, and stays plaintext. Do not encrypt files the deploy overwrites.

**G3. DEK cache with a bounded TTL.**

Required, not optional. `voice_dna.resolve` (`voice_dna.py:195`) and
`personal_context.section` (`personal_context.py:104`) are read synchronously in
the drafting path and on every web page render. A co-signer round trip per file
read puts a network dependency inside page rendering, and the co-signer is a hard
dependency with no bypass by design.

Cache the unwrapped DEK per account in memory with a TTL. Model it on the
existing access-token cache in `tokens.py:317` `access_token_for`.

**The TTL is a security parameter, not a performance knob.** It determines how
much a warm cache yields to an attacker who lands inside the enclave, and it
determines the co-signer's visibility: one unwrap per account per TTL is the
granularity at which Track B's velocity limiter can see a sweep. Write down the
chosen value and the reasoning next to the constant.

**G4. Rotation, implemented and tested.**

- Remove the `version == KEY_VERSION` assertions at `keys.py:129` and `:157`;
  accept a set of known versions and derive per version.
- A re-wrap routine that reads each record, opens the wrapped DEK under the old
  version, re-wraps under the new, and writes the header back. User data is never
  touched.
- Test: write a record under version 1, bump, rotate, read it back. Then write
  under version 2 and confirm a version 1 record is still readable until the
  rotation runs.
- Correct `keys.py:54` in this commit. It currently promises a rotation the
  assertions prevent; here it becomes true, so the sentence stops being a claim
  and starts being a description.

**G5. Crypto-shred deletion.**

`delete_account` (`account.py:536`) destroys the wrapped DEK explicitly and the
test asserts the account's data is unreadable afterwards even if the directory
is restored from a copy. This is the property a derived-key scheme cannot offer:
today there is nothing account-specific to destroy.

Correct `keys.py:12-15` in this commit. It claims per-uid derivation makes a
future per-user revocation meaningful; the per-account DEK is what actually makes
that true, and this is where it becomes true.

**G6. No migration.**

There are no production users. Wipe `database/`, re-onboard the owner through
`/auth/callback`, verify end to end. Do not write migration code that will be
run once and then rot. Note in the commit that this is only viable pre-launch.

**G7. Backup.**

Once the data is encrypted, a lost key is a lost dataset, and that is a new
failure mode this track creates. Two parts:

- Encrypted ciphertext synced off box. Protects against disk loss. Restoring
  needs the live keys, so the backup itself is not a new exposure.
- Escrow of the **inner** key only, offline. Not the outer. Escrowing both makes
  you a single party who can read everything, which contradicts the split-custody
  claim the whole architecture exists to make. Escrowing the inner half means
  recovery still requires the co-signer, so it is one half of a two-party
  recovery rather than a bypass.

At `MAX_ACCOUNTS = 100`, re-consent stays the recovery path if the outer key is
ever lost: email everyone, they sign in again through `/auth/callback`. Revisit
that when the account count makes it impractical, somewhere in the low thousands.

## What this does not do

A live compromise of the enclave still reads accounts one at a time, at whatever
rate the limiter permits, with every read logged. That is bounded exfiltration
with evidence, not prevention. State it that way in the docstrings rather than
letting the package's stated invariants imply more, which is the same failure
Track B4 is fixing.

## Acceptance

Fresh onboarding produces an encrypted account directory. `strings` over
`database/<handle>/` yields nothing recognisable. Every draft path, the voice
page and the personal page work with the co-signer up. All of them fail closed
with the co-signer down. Rotation test passes. Deletion test asserts
unrecoverability.

---

# Deferred

## Track H. Move key custody to a managed HSM

**Trigger: cost confirmed acceptable. Depends on Track G.**

The idea is to move `cosigner/keys.py`'s master key and DPoP key out of
systemd `LoadCredentialEncrypted=` (TPM-sealed, `credentials_dir()` at
`keys.py:76`) into an EU-hosted HSM-backed key service, so a disk image of the
Hetzner box yields no key material at all.

Why it is deferred: "EU HSM" spans two products that differ by orders of
magnitude in price. A dedicated managed HSM cluster has a monthly floor in the
low thousands. An HSM-backed key in a managed KMS is single-digit euros a month
plus per-operation cost. Only the first is categorically stronger than
TPM-sealed credentials on a box you control; the second is closer to a lateral
move that buys external audit logging and a revocable credential. Confirm which
one you are buying before committing.

Why after G: an HSM wraps small fixed-size objects well and does bulk data and
per-uid HKDF badly. With a DEK you hand it 32 bytes and get 32 bytes back, which
is the shape those APIs expect. Doing it before G means wrapping under a derived
key and rewriting again.

Notes for when it happens:

- **Move both keys.** The wrapping key becomes cheap to rotate after Track G.
  The DPoP key can never be rotated at all: Google binds the refresh token to it
  at the authorization-code exchange (`tokens.py:253` `exchange_with_dpop`,
  `keys.py:204` `dpop_jkt`) and nowhere else, so changing it forces re-consent for
  every existing user. Put the unrotatable key in the strongest custody you are
  paying for.
- **JWS assembly becomes yours.** `keys.py:162` `dpop_key()` builds a
  `requests_oauth2client.DPoPKey` from an in-memory private key and
  `keys.py:186` `dpop_proof()` calls `.proof()` on it. That library wants key
  material, not a signing callback. HSM-backed DPoP means assembling the proof
  yourself: header, payload, signing input, HSM sign over the digest. ES256 over
  P-256 (`DPOP_ALG`, `keys.py:58`; `SECP256R1` at `keys.py:234`), which every HSM
  supports. Roughly thirty lines you now own. Test the proof against Google's
  acceptance, not against your own encoder.
- **What it does and does not buy.** It defeats cold theft: disk imaging,
  credential exfiltration, a decommissioned drive. It does not defeat a live
  compromise of the co-signer process, which must be able to use the keys, so an
  attacker there has an oracle either way. The co-signer's value becomes policy
  enforcement plus audit in front of the only decryption path, which is still the
  anti-bulk-exfiltration control. Update the docstrings to say that rather than
  leaving the current "holds a key you cannot get" framing.
- **Ask the vendor** whether the product enforces its own rate limits and whether
  its audit log is tamper-evident from your side. Those two answers are most of
  the security difference.

## Track I. Image provenance

**Trigger: independent, do when there is slack.**

`backend/integrations/inference_attestation.py` verifies that the NEAR AI
enclave serving completions is one we authorized, pinned in
`backend/integrations/inference_allowlist.json`. The composes are pinned by file
content, and container images inside them by digest.

The open gap, already noted in `CLAUDE.md`: digest to reviewed source needs the
build's Sigstore/SLSA provenance (`cosign verify-attestation`). Until that is
checked, the pins say which bytes ran, not what was in them, and NEAR is both the
image publisher and the machine operator.

The same gap exists in the other direction for our own image, where the fix is a
reproducible build so `compose_hash` corresponds to reviewed source. That half is
only relevant if the Phala track is ever revived.

Note this is not covered by Track A. Dependabot and pip-audit cover the Python
tree, not container provenance.

## Track J. PII analyzer

**Trigger: a paying customer asks for it.**

Presidio + spaCy + `en_core_web_lg` raise masking recall from 74% to 96% on the
public corpus, the whole gap being PERSON entities, at a cost of about 1.6 GB
resident per masking process. The pins are commented out of `requirements.txt`
and the renderer does not emit commented pins, so the enclave image inherits the
same default.

Nothing in the code needs to change to switch it on:
`pseudonymizer.analyzer_available()` answers by module lookup and never imports,
and `new_state()` reconciles the account's stated preference with what is
actually installed. The account's preference is stored even where it cannot run,
so installing the model later restores the behaviour without touching the
manifest.

Do not size hardware up speculatively. Offer it, and do the sizing when someone
bites.

---

# Rejected designs

Recorded so they are not re-proposed without new information.

## Policy engine (OPA, Cedar, OpenFGA)

The authorization rule in this system is: subject equals resource owner. There
are no roles, no sharing, no delegation, and no admin persona.
`owner_account()` (`account.py:149`) is the only owner special case and is used
solely by `backend/accounts/seed_owner.py` and the test harness.

A policy engine adds a runtime, a policy language and a bundle to express
`acct.id == resource.owner`. It would also not have caught the checkout IDOR,
which was an unresolved external identifier rather than a missing check: there
is no policy to write about a Polar checkout id, because the subject and the
resource live in different systems.

The generalization that does help is the rule that every externally supplied
identifier resolves to the signed-in account before use, which is what
`PolarBilling.resolve_account()` now is. Track G does what a policy engine
cannot: it makes a cross-tenant read fail at the crypto layer whether or not
anyone remembered to write the check.

Revisit if roles, sharing, or delegated access ever appear.

## Postgres for row-level security

There is no database engine. The store is `database/accounts.json` plus
per-account directories (`account.py:55-56`). The only SQLite in the tree is the
co-signer's audit log.

RLS is the right answer if a database engine is ever adopted for other reasons.
Adopting one to obtain RLS, on this box, is not.

## Per-unit unix users for tenant isolation

Splitting the six units across separate accounts would buy separation of
function, not separation of tenants: the daemon, the summary sweep and the web
UI each legitimately touch every tenant's directory. Track G is the change that
actually isolates tenants.

`cosigner.service.d/20-cosigner.conf` remains the right pattern for the one case
where separation of function does matter, because the co-signer must not share
the application's account.
