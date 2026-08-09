# Second batch: multi-step flows, failing open, ops/supply chain, deletion/retention

Scope: code that ships to the measured enclave image, i.e. the files listed in
`deploy/phala/image_files.nix`, plus the two files that define the enclave
partition (`deploy/phala/docker-compose.yml`, `flake.nix`). Findings outside that
set are marked **[off-image]** and included only where an enclave code path
depends on them.

Ordered by severity within each class. Each entry states the defect, the failure
it produces, and the fix.

---

## A. Failing open

### A1. The boot gate demands secrets the measured partition deliberately withholds, so no enclave role can start

`backend/tee/tee_boot.py:124` calls `secrets.missing()`, which evaluates the
whole-box `secrets.REQUIRED` tuple (`backend/secrets.py:288`): inference keys,
Telegram, `SESSION_SECRET`, both Polar checks, Google OAuth. Nothing in
`tee_boot`, `secrets` or `flake.nix` is role-aware — `grep -n "role" backend/tee/tee_boot.py backend/secrets.py` returns nothing.

Against `deploy/phala/docker-compose.yml`:

| check | `mail` | `web` |
|---|---|---|
| `inference_configured` (`DEEPSEEK_API_KEY`, `NEARAI_API_KEY`) | ok | **absent by design** |
| `telegram_configured` | ok | **absent by design** |
| `session_configured` (`SESSION_SECRET`) | **absent by design** | ok |
| `google_oauth_configured` | ok | **absent by design** |
| `polar_api_configured` | ok | ok |
| `polar_webhook_configured` (`POLAR_WEBHOOK_SECRET`) | **absent — no role is a receiver** | **absent** |

`gate()` in `flake.nix:141` exits 1 on any gap and `restart: always` retries, so
both `mail` and `web` crash-loop on first boot. Two ways this is worse than a
startup bug:

* The obvious fix an operator reaches for under time pressure is to add every
  variable to every container's `environment:` block. That is precisely the
  partition RTMR3 measures (`docker-compose.yml` header), undone — a web tier
  holding the inference keys, the Google client secret and the Telegram token,
  which is the pre-`01ba733` shape the whole split exists to remove.
* `polar_webhook_configured` can never be satisfied inside the enclave without
  inventing a secret no enclave role uses, so there is no correct value to add.

**Fix.** Make the required set a function of the role, the same way
`deploy/preflight.py` already derives it per unit (`check_unit`, `deploy/preflight.py:208`).
Concretely: add `secrets.REQUIRED_BY_ROLE = {"mail": (...), "web": (...), "hook": ()}`,
have `run_gate()` read the role from `argv`/`LETTERLOCK_ROLE` and pass it to
`missing(role)`, and have the entrypoint call `python -m backend.tee.tee_boot "$role"`.
Assert in `secrets.py` that the union of the per-role tuples equals `REQUIRED`, so
a new check cannot be added to one and forgotten in the other. Drop
`polar_webhook_configured` from every enclave role and state in
`docker-compose.yml` that entitlement in the enclave is `confirm_checkout()` plus
the 3-hourly reconcile. Add a test alongside `tests/test_enclave_boundary.py`
that parses the compose file and asserts each role's `environment:` block
satisfies exactly its own required set — that is the test that keeps the gate and
the partition from drifting again.

### A2. `EXPECTED_COMPOSE_HASH` defaults to empty, so the measurement check silently does nothing

`backend/tee/tee_boot.py:67` returns without checking when the variable is unset,
and `docker-compose.yml` interpolates it as `${EXPECTED_COMPOSE_HASH:-}`. An
operator who never sets it gets a gate that prints "attested" while comparing
nothing. The failure is invisible: the log line at `tee_boot.py:132` prints the
running `compose_hash` either way, so the output of a checking gate and a
non-checking gate are indistinguishable.

**Fix.** Under `secrets.tee_required()`, an absent `EXPECTED_COMPOSE_HASH` is a
refusal, not a skip. Keep the empty-is-skip behaviour only when `TEE_REQUIRED` is
unset. Have the gate's success line say which hash it compared against.

### A3. The enclave does not authenticate the co-signer; it trusts the public PKI

`backend/custody/client.py:162` `_verify()` returns `True` (system trust store)
whenever `COSIGNER_CA` is unset, which is the enclave case. Attestation is
one-directional: `cosigner/attest.py` verifies the enclave's RA-TLS client
certificate, and the enclave verifies only that someone presented a valid
certificate for the co-signer's DNS name.

Whoever can obtain such a certificate or move the DNS record — which includes the
operator the split-custody design is written against — can stand in for the
co-signer. What that yields is bounded but not nothing: `dpop_jwk()`
(`client.py:197`) is fetched over this channel and its thumbprint becomes the
`dpop_jkt` in the consent URL (`provisioning.py:115`), so a substituted co-signer
gets Google to bind every new refresh token to a key it holds. It also yields
unlimited denial of mail processing, and the enclave cannot tell that case from a
genuine outage.

**Fix.** Pin the co-signer. Put its certificate (or SPKI hash) in the image file
list so the pin is measured into the image, and make `_verify()` return that path
under `TEE_REQUIRED` rather than `True`. If the co-signer eventually runs under
its own attestation, verify its RA-TLS server certificate with
`backend/tee/quote_policy.py` instead — the code to do it already exists and is
already used in the other direction.

### A4. An unparseable push body escalates to a full sweep

`backend/daemons/gmail_hook_server.py:254` catches any parse failure and calls
`signal_daemon()` with no address, which the daemon reads as "process every
account". A verified Google push is never unparseable, so this branch is only
reachable by something already holding a valid Pub/Sub OIDC token — but that
token is a bearer credential with no `jti`, no replay cache and a lifetime of
roughly an hour, so anything that captures one (see D3 on TLS termination) can
drive repeated full sweeps.

A full sweep spends one co-signer unwrap-and-sign per account, which is what
`cosigner.policy._sweep_refusal` is built to refuse — and its refusal stops mail
for everyone until an operator clears it. So the fallback that exists to avoid
losing one mail can stop all mail.

**Fix.** Drop the fallback. A verified push whose body does not parse is a
`400` and a log line; there is nothing to route. If the "never lose a wake"
property is wanted, keep it explicit and bounded: rate-limit the address-less
wake to at most one per `WAKE_POLL_SECONDS` in `wake_queue`, so a flood collapses
to a single sweep.

### A5. `checkout_url` falls back to a checkout with no account binding

`backend/billing/billing.py:84`: when `POLAR_PRODUCT_ID` is absent or
`create_checkout` fails, `_static_checkout_url()` returns a dashboard link
carrying only `customer_email`, which the buyer edits at Polar. That checkout
carries no `CHECKOUT_ACCOUNT_KEY` stamp, so everything downstream — the webhook,
the reconcile, and the ownership test in `confirm_checkout` — falls back to
resolving by an attacker-editable field (`_event_email`, `billing.py:166`).

The comment at `billing.py:39` names the stamp as "the exact binding the rest of
the billing surface lacked". The fallback path is that surface, still lacking it,
selected automatically on any transient Polar API failure.

**Fix.** Under `TEE_REQUIRED`, remove the static fallback: no product id or a
failed `create_checkout` renders "checkout unavailable, try again", which
`/billing/checkout` already handles (`web_server.py:1751`). On the box, keep the
fallback but have `resolve_account` refuse the email branch for objects with no
stamp when the account it resolves to already has a `polar_customer_id` — an
unstamped checkout must never be able to move an existing link.

### A6. Attestation mode and allowlist path are environment-overridable inside the enclave

`inference_attestation.allowlist_path()` (`:110`) reads
`LETTERLOCK_INFERENCE_ALLOWLIST`; `mode()` (`:132`) reads
`LETTERLOCK_INFERENCE_ATTESTATION`. `Policy.mode()` refuses `dev-insecure` when
the allowlist has entries (`quote_policy.py:94`) — but repointing the path at an
empty file satisfies both, and then every confidential provider passes
unverified.

Today neither variable appears in `docker-compose.yml` or `allowed_envs`, so the
measurement is what prevents this. That makes it a one-line compose edit away
from being off, in a file whose other edits are all deliberate.

**Fix.** Under `secrets.tee_required()`, assert `allowlist_path() == DEFAULT_ALLOWLIST`
and ignore the mode override. The escape hatches are for a laptop; the enclave
should not be able to spell them.

### A7. `handoff_server` accepts a non-boolean `state_ok` over the wire

`backend/custody/handoff.py:197` asserts `isinstance(state_ok, bool)` on the
client side; `handoff_server._sign_in` (`:85`) does not, and passes it straight
into a predicate evaluated as `if not state_ok(state)` (`provisioning.py:278`).
Any truthy JSON value — including the string `"false"` — passes the browser
check. The web tier is the only permitted peer, so this is hardening rather than
a live hole, but the assert is on the wrong side of the boundary: the callee must
not trust the caller's type discipline.

**Fix.** Move the assert into `_sign_in`, and add `assert isinstance(query, dict)`
beside it.

### A8. Failure detail from the handoff socket is rendered to the browser

`handoff_server.dispatch` (`:153`) returns `err.msg` for `ProvisionError` and
`RemoteRefusal`, and `web_server.py:1674` renders a generic page — good — but
`web_server.py:1861` and `:1880` render `e.msg` from `chat_begin`/`chat_finish`
directly into the settings page. Those messages are `chat_link.ChangeRefused`
strings, which are written for users and safe today. The rule is not enforced
anywhere, so a future refusal that embeds a Polar id, a chat id or an exception
string reaches the browser.

**Fix.** A short assert in `dispatch` that the `msg` on a 4xx matches
`audit.TOKEN`-style safe text, or an explicit allow-list of user-facing refusal
strings in `chat_link`.

---

## B. Multi-step flows

### B1. `/billing/return` mutates state on a GET, and links a Polar customer before payment is confirmed

`frontend/web_server.py:1730`. Two separate defects in one handler.

**Ordering.** `PolarBilling.confirm_checkout` (`billing.py:271`) writes
`set_polar_customer_id` at `:304` — *before* the `state not in PAID_CHECKOUT_STATUSES`
check at `:306`. So an open, unpaid checkout is enough to move an account's
`polar_customer_id`. The attacker path: mint a checkout through `/billing/checkout`
(stamped with the attacker's own account, so the ownership test at `:298`
passes), then on Polar's page enter a victim's address so Polar attaches its
existing customer to that checkout, then return. The attacker's account now
carries the victim's `polar_customer_id`, and `portal_url()` (`billing.py:310`)
mints a Polar customer-portal session for it — payment methods, invoices, the
ability to cancel.

**Uniqueness.** `account_for_customer_id` (`account.py:480`) returns the first
match and `all_accounts()` asserts uniqueness of ids and handles (`:433`, `:435`)
but not of `polar_customer_id`. `set_polar_customer_id` (`:653`) asserts only
that the value is non-empty. So two accounts can hold one customer id, and the
reconcile (`billing.py:363`) then resolves that customer to whichever appears
first in the manifest — silently deciding a third party's entitlement.

**CSRF.** The route is a GET taking `checkout_id` from the query string.
`SameSite=Lax` sends the session cookie on cross-site top-level navigations, so
an attacker-supplied link fires this handler with the victim's session. The
ownership test blocks the interesting direction, but only because of the
metadata stamp — see A5 for the path where that stamp is absent.

**Fix.**
1. Move the customer link after the paid-status check, and after it, assert no
   other account holds that id: `set_polar_customer_id` should raise when
   `account_for_customer_id(customer_id)` returns a different account.
2. Add the uniqueness assert to `all_accounts()` beside the handle one, so a
   manifest that has already drifted is caught at load rather than at resolve.
3. Bind the checkout to the session. `checkout_url()` already stamps the account
   into Polar metadata; also record the minted checkout id in the session cookie
   (or a short-lived signed cookie of its own) and require the returned
   `checkout_id` to match one this browser started. That converts the ownership
   test from "resolves to this account" to "this browser started this checkout",
   which is the binding the class calls for.

### B2. The OAuth state is not consumed, and a failed callback leaves it pending

`frontend/session.py:257` `state_is_ours()` checks membership and TTL and removes
nothing. On success `web_server.py:1686` clears the whole state cookie; on any
refusal path (`RemoteRefusal`, `HandoffUnavailable`, the generic `except`) the
cookie is untouched, so the state stays valid for the remainder of `STATE_TTL`
(1800s).

Replay of the callback itself is blocked by Google (the code is one-time), so
this is not directly exploitable. It matters because it makes the state a
30-minute reusable token rather than a one-shot: anything that later accepts a
state — a second consent surface, a retry link, a support flow — inherits a
window, and the PKCE verifier is a deterministic function of the state
(`provisioning.pkce_verifier`, `:63`), so state reuse is verifier reuse.

**Fix.** Make `state_is_ours` consuming: have the callback rewrite the state
cookie with that value removed, on every outcome including the refusals. Cheapest
form is a `sess.state_cookie_without(state, headers)` helper set on every
`/auth/callback` response.

### B3. Deleting an account does not cancel that account's in-flight work

`account.delete_account` (`:781`) runs in the **web** process. It calls
`keyring.destroy` (`keyring.py:149`), whose `forget()` clears only the *local*
process cache, then `shutil.rmtree` on the account directory. The mail daemon is
a different process and holds:

* `keyring._dek_cache` for up to `DEK_TTL` = 300s (`keyring.py:68`),
* `tokens._access_cache` until the access token expires — up to an hour
  (`tokens.py:284`),
* `google_client`'s per-thread service cache,
* `voice_dna._JOBS`, which `clear_status` refuses to remove while a job is
  running (`voice_dna.py:386`).

So a deletion racing a running voice generation ends with `_run_job` calling
`generate(acct)`, which calls `keyring.write_encrypted` → `dek_for` → cache hit →
`account_store.secure_dir()` recreates `database/<id>/` and writes
`voice-dna.enc` into it, after the user asked to be deleted. The file is
unreadable (the `dek.bin` record is gone), but the directory, its name and its
timestamps are back, and `_JOBS` still names the deleted address.

**Fix.** Add a `handoff` operation — `OP_ACCOUNT_FORGET` — that the delete route
calls before `delete_account`, and have the daemon-side handler cancel/await the
voice job, then call `tokens.forget(acct)` (which already fans out to
`keyring.forget`) and `google_client.forget_services`. Make `keyring.dek_for` and
`write_encrypted` refuse an account with no manifest entry, so the race closes
even if the notification is lost. `_JOBS` should also drop entries for accounts
`account_for_email` no longer resolves.

### B4. The manifest is read-modify-written by several processes with no lock

`account._write_manifest` (`:272`) does `_read_manifest()` → mutate →
`tmp.replace(MANIFEST)`. There is no `fcntl` anywhere in `account.py`
(`grep -n "lock\|fcntl" backend/accounts/account.py` finds only a docstring),
while `backend/spool.py` takes `LOCK_EX` for a much less valuable file.

Writers running concurrently: the web tier (`set_settings`, `set_voice`,
`set_polar_customer_id`, `delete_account`) on a `ThreadingHTTPServer` — so it
races itself across threads — and the mail daemon (`register_account`,
`set_plan_status` from `process_billing` and the reconcile, `set_telegram` from
`chat_link.finish`).

The atomic rename means no torn file, but the last writer wins over a stale read.
Lost updates include: a plan flip discarded by a settings save, a Telegram unlink
discarded by a billing event, and the bad one — `delete_account` racing any other
writer, where the other writer's stale copy of `data["accounts"]` puts the
deleted entry back. The files are crypto-shredded, so the resurrected row is a
zombie the daemon will then try to process, but the user's address, timezone and
Telegram chat id are back on disk after a deletion.

**Fix.** One exclusive lock around read-modify-write, in `account.py`, reusing
the pattern `spool.py` already has: a `database/accounts.lock` at
`paths.file_mode()`, `LOCK_EX` held across `_read_manifest()` and
`_write_manifest()`. Restructure the mutators to `with _manifest_transaction() as data:`
so the lock cannot be taken by one and skipped by another. Add an assert that
`_write_manifest` is only called with the lock held.

### B5. Every externally visible URL the enclave mints names the Hetzner deployment

`backend/site.py:28` defaults `APP_HOST` to `letterlock.morganrivers.com`,
overridable by `LETTERLOCK_HOST`. `deploy/phala/docker-compose.yml` sets
`WEBHOOK_AUD` for the hook but sets neither `LETTERLOCK_HOST` nor
`LETTERLOCK_API_HOST` for `mail` or `web`.

Consequences for the consent round trip, which is the multi-step flow most
affected: `REDIRECT_URI` in `web_server.py` and `site.checkout_success_url()`
(`:142`) both resolve to the box. A user signing in against the enclave is
redirected by Google to the box's `/auth/callback`, which holds a different
`SESSION_SECRET` and a different state cookie — so either the callback is refused
as "did not start in this browser", or, if both deployments share a session
secret, the authorization code is exchanged by the box and the refresh token
takes custody there. Same for `tokens.notify_reauth_required` (`:127`) and every
link in a Telegram message.

The web role also publishes no `ports:` and binds `site.LOOPBACK`
(`web_server.py:69`), so it is currently unreachable in the enclave — which is
why this has not surfaced.

**Fix.** Add `LETTERLOCK_HOST` and `LETTERLOCK_API_HOST` to the `mail` and `web`
environment blocks (and to `allowed_envs`), and assert at startup under
`TEE_REQUIRED` that neither is the compiled-in default. When the web role is
published, set `WEB_HOST=0.0.0.0` explicitly and revisit `site.TRUSTED_PROXIES`
— see D2.

### B6. `chat_link.finish` re-reads the account but not the chat that authorized the unlink

`backend/accounts/chat_link.py:167`. The entry records `chat_id` at `begin()`
time (`:139`) and `finish()` re-reads the account and compares `action_for(acct)`
against the pending action (`:179`) — good. But the unlink branch checks the code
against `entry["chat_id"]`, the target *as it was when the code was minted*,
while `set_telegram(acct.id, clear=True)` at `:205` clears whatever the target is
*now*. Between the two, `action_for` only distinguishes linked from unlinked, so
a target changed from chat A to chat B in the window (unlink A, link B, both
completed) leaves `action_for` == `CHAT_UNLINK` and the pending entry still
naming A. A code posted from A then unlinks B.

Reaching it requires the account owner to complete a full unlink-then-link cycle
inside one 900s window while an older unlink is pending, so it is narrow. It is
listed because the rule's whole content is "ask the chat being replaced", and
this is the one path where the chat asked is not the chat replaced.

**Fix.** Compare the current target against `entry["chat_id"]` in `finish()` and
refuse with the existing "your Telegram settings changed in the meantime"
message when they differ, rather than comparing only the derived action.

### B7. No CSRF token on state-changing POSTs; `SameSite=Lax` is the only defence

Every POST in `_handle_post` (`web_server.py:1781`) — settings, voice, personal,
telegram start/confirm, account delete — relies on `SameSite=Lax` on the session
cookie (`session.py:173`). Lax does block cross-site form POSTs in current
browsers, so this is not a live hole, but it is a single mechanism with no
in-repo check, and it does not cover the GET mutation in B1.

**Fix.** Cheapest durable form: an `Origin`/`Sec-Fetch-Site` check in
`do_POST`, refusing anything whose `Origin` is not `site.app_url()`, applied once
in the wrapper rather than per route. That is a chokepoint a new handler cannot
forget.

---

## C. Deletion and retention

### C1. Deletion destroys the key but leaves the Google grant standing, and cannot revoke afterwards

`account.delete_account` (`:781`) calls `keyring.destroy` first, then removes the
files. The docstring at `:790` states plainly that this is "not revocation" — the
refresh token stops being ours but stays valid at Google until the user revokes
it in their own account settings.

The problem is ordering, not policy: once the data key is destroyed the refresh
token is unreadable, so revocation becomes impossible even if we later decide we
want it. A user who deletes their account has Letterlock listed in their Google
security page indefinitely, with a live grant, and we hold no way to withdraw it.

**Fix.** Best-effort revoke before shredding: read the refresh token via
`keyring.read_encrypted`, POST `https://oauth2.googleapis.com/revoke`, then
destroy — with any failure logged and the destruction proceeding regardless.
Needs the revoke endpoint added to `backend/egress.py` (it is already the same
host as the token endpoint, so verify rather than assume) and a `handoff`
operation, since deletion runs in the web tier and reading `token.bin` does not.
The same handoff operation should also call `users.stop` on the Gmail watch, so
Google stops pushing for a mailbox nobody owns — see C3.

### C2. Deletion leaves the account's address in three spools and one log

None of these are touched by `delete_account`:

* `state/wake_queue.jsonl` — carries raw email addresses (`wake_queue.py:30`).
  Drained by the daemon, which drops unknown addresses, so entries clear on the
  next pass. Bounded, but a daemon that is down holds a plaintext address list.
* `state/billing_queue.jsonl` — carries whole Polar event bodies, including
  `customer_email` (`billing_queue.py:67`). Same lifetime.
* `backend/audit.py` rows — deliberate and documented (`audit.py:42`,
  `RETENTION_DAYS = 180`).
* **[off-image]** the co-signer's `grants` table — wrap-once state, "never
  deleted" per `cosigner/__init__.py`. The handle is pseudonymous and the enclave
  holds the only mapping back, so this is a defensible retention choice, but it
  is a permanent record of an account that asked to be erased and it is not
  written down anywhere a data-deletion request would find it.

**Fix.** No code change needed for the spools — state the lifetime in
`backend/spool.py`'s docstring so it is a known bound rather than an oversight.
For audit rows and co-signer grants, write the retention answer down where an
erasure request lands: what is kept, keyed by what, and for how long. If the
audit table's 180-day window is too long to defend for a deleted account, add an
operator command that redacts the address to the handle while keeping the row.

### C3. A deleted account's Gmail watch keeps firing

`watch_renew.renew_account` registers a `users.watch` at provisioning
(`provisioning.py:247`); nothing calls `users.stop` on deletion. Google keeps
pushing that address to the hook for up to seven days, each push spooling the
address into `wake_queue` and waking the daemon, which resolves nothing and moves
on. Cost is noise and a plaintext address in a spool for a user who asked to be
forgotten.

**Fix.** Fold `users.stop` into the C1 handoff operation, before the token is
destroyed — same ordering constraint, same one round trip.

### C4. `voice_dna._JOBS` and `web_server._PENDING_CHATS` outlive their accounts

`_JOBS` (`voice_dna.py:370`) is keyed by account id and only removed by
`clear_status`, which refuses while a job is running (`:386`). `_PENDING_CHATS`
(`web_server.py:132`) is pruned only on the read path for that same account
(`_get_pending`, `:142`), so an account that never returns to the settings page
leaves its entry — action, code, bot username — resident for the process
lifetime.

Both are in-memory and small. They are listed because they hold an address and a
live link code for an account that may have been deleted, and neither has a
sweeper.

**Fix.** Give `_get_pending` a whole-dict prune (it already computes `time.time()`),
and have `_JOBS` drop finished entries older than a few minutes on each `status()`
call. Both are three lines and remove the class.

---

## D. Operational and supply chain (enclave)

### D1. Private keys are written world-readable, then chmodded

Three places write a private key and set the mode afterwards:

* `tee_boot._write_attestation_record` (`:49`) writes `ra_tls.key`, then writes
  two more files, then chmods to `0600` at `:64`.
* `custody/client._client_identity` (`:156`) writes `cosigner_client.key` then
  chmods at `:157`.

Both land in `/app/attestation`, a tmpfs the compose file mounts `mode: 0777`
(`docker-compose.yml`, the `tmpfs` block). The window is short and the container
runs one process, so exposure is small — but the mitigation is one line and the
argument for the current shape is only that nothing else is running.

**Fix.** `os.open(path, O_WRONLY|O_CREAT|O_TRUNC, 0o600)` — or `umask(0o077)`
around the writes. Chmod immediately after each key write, never after an
unrelated one.

### D2. In the enclave the audit log will record the docker bridge address for every request

`web_server._source_ip` (`:1571`) trusts `X-Forwarded-For` only from a peer in
`site.TRUSTED_PROXIES`, which is `{127.0.0.1, ::1}` (`site.py:79`). On the box
Caddy proxies from loopback and this is right. In the enclave there is no Caddy;
whatever fronts the web role connects from the docker bridge (172.x), so the
header is discarded and every row in `backend/audit.py` records one address.

`site.upstream()` asserts loopback is in `TRUSTED_PROXIES` (`site.py:89`) — the
assert that would catch this is written for the box's topology and passes
regardless.

This is a detectability finding, not an access one: it makes the audit log unable
to answer "which browser did this", which is the question it exists for.

**Fix.** Decide the enclave's front-end story before publishing the web role,
then make `TRUSTED_PROXIES` configurable from the same place `WEB_HOST` is set,
and assert at startup that it is non-empty and does not contain `0.0.0.0`.

### D3. The hook's TLS terminates outside the guest — confirm before launch

`docker-compose.yml` publishes `hook` on `8787:8787` in plaintext with no TLS
terminator in the compose. Pub/Sub requires an HTTPS endpoint, so something
outside the containers terminates it. If that is the dstack gateway, the OIDC
bearer token and the push body — which carries the user's email address — are
readable by the gateway operator, and the token is replayable for its lifetime
(see A4). That is the host operator TDX is supposed to exclude.

I have not been able to confirm from this repository which of TLS termination or
passthrough dstack does here, so this is a verify item rather than an assertion.

**Fix.** Confirm the termination point. If it terminates outside the guest,
either terminate inside (a TLS listener in the hook container with a cert the
enclave holds) or accept and document that the push address list is visible to
the gateway. Independently, bind the token to the request: keep a small
`jti`/`iat` replay cache in `SigningCerts`-style state so one captured token
cannot be reused.

### D4. `dcap-qvl` availability is untested at boot

`quote_policy.load_dcap()` (`:128`) returns `None` when the wheel is absent, and
`verify()` (`:179`) returns a failing verdict — correctly fail-closed. But
nothing in the boot gate asks, so a build that drops the wheel produces an
enclave that starts cleanly and refuses every confidential draft at the first
email, with the reason buried in a per-draft log line.
`secrets.inference_configured` checks only that keys are present;
`inference_attestation.configured()` does check `load_dcap()` (`:146`) but is
called from `deploy/preflight.py`, which does not run in the enclave.

**Fix.** Add `inference_attestation.configured(llm_client.PROVIDERS.values())` to
the mail role's boot gate checks (see A1 — it belongs in `REQUIRED_BY_ROLE["mail"]`).

### D5. `/contact` is an unauthenticated relay into the operator's Telegram

`web_server.py:1791` → `_deliver_contact` (`:187`). One honeypot field
(`website`), no rate limit, no size limit beyond `MAX_BODY` (128 KB), and each
submission both writes a journal line and sends a Telegram message on the
operator's bot token. Anyone can flood both. The message is HTML-escaped
(`_h`), so this is abuse and log pollution rather than injection.

**Fix.** A per-source-IP token bucket in the handler and a cap on `message`
length before delivery. `telegram.notify_once` already has the shape of a
rate limiter to reuse.

---

## Suggested order of work

1. **A1** — nothing runs in the enclave until this is fixed, and the tempting
   workaround destroys the partition.
2. **B1** and **B4** — cross-account effects, both with small, chokepoint fixes.
3. **A3**, **A2** — the enclave's two unverified trust edges.
4. **B3**, **C1**, **C3** — the deletion path, best done as one handoff
   operation.
5. **A5**, **B2**, **B5**, **B6**, **A4** — flow bindings and fail-open paths.
6. **D1**, **D4**, **A6**, **A7**, **B7**, **C2**, **C4**, **D5** — hardening.
7. **D2**, **D3** — decide before the web and hook roles are published.
