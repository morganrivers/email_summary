# Plan: split-custody OAuth tokens + Node removal (Tracks I, J, K)

Written 2026-08-05. Read this whole file before touching code; the decisions
section explains why several obvious-looking shortcuts are wrong.

The work is cut into five worktrees — `cosigner-service-1`,
`enclave-custody-2`, `secrets-gate-3`, `onboarding-exchange-4`,
`node-removal-5`. Every section below is tagged with the one that owns it.
§7 has the branch order, the file-ownership table and the places where two
worktrees would otherwise collide.

Status, per track:

- Track I (§4, split custody in the enclave) — **[BUILT, phase 1, merged]**.
  `feat/enclave-custody-2` absorbed `onboarding-exchange-4` as well: I5 and I6
  are in it. I6 is written but not executed; the wipe happens at Phase 5.
- Track J (§5, the co-signer service) — **[BUILT, phase 1, merged]**
  `cosigner/`, `deploy/hetzner/cosigner.service`, `tests/test_cosigner.py`.
  Runs with attestation stubbed (`mode: dev-insecure` in
  `cosigner/allowlist.json`); §7 phase 4 is what turns it on, and
  `cosigner/attest.py` refuses the stub once the allowlist names a measurement
  or `TEE_REQUIRED` is set.
- Track K (§6, Node removal) — **[BUILT, merged]**.
- §8 (Barrier A gaps) — **[BUILT, merged]** for four of the five items: the
  `.env` mount, the boot gate's secret list, the eight `load_dotenv` call sites
  and the duplicate dependency manifest. The `gcp-oauth.keys.json` injection
  belongs to `onboarding-exchange-4`; §8 says what is already wired for it.
- §10 (front-end copy) — **[TODO]**, and each edit needs its own confirmation.
  `/about` at `web_server.py:383-386` is factually wrong as of Track I and
  says so about an arrangement that is now stronger than the claim.

---

## 0. What problem this solves

Today a Gmail refresh token sits in cleartext at
`database/<email>/.gmail-mcp/credentials.json`, 0600, on the app volume.
`gmail_lib.mjs:84` reads it, google-auth-library refreshes it internally, and
line 127 writes new tokens back. Anyone who reads that volume, or reads the
process memory of the enclave, gets permanent unattended access to every
user's mailbox.

Phala TEE (Track F) fixes the *operator* threat: the host cannot read the
volume, and dstack's KMS only releases `app_secret` to an approved code hash.
It does not fix the *enclave-compromise* threat. `docs/tee_enclaves_and_upgrades.md`
§5.4 already names this as the weakest link.

Goal, in the user's words: "even if they broke into Phala, and into the
enclave, they would have to request my server to see user data still", and
"I can't read people's mail and neither can Vault."

The design below achieves:

- Enclave alone (full memory + volume compromise): **reads no mail.**
- Co-signer alone (full compromise): **reads no mail.**
- Operator (the human): **reads no mail**, at either box.
- Both together: one token per request, rate limited and logged.

It does **not** prevent a live enclave attacker from draining mailboxes one
user at a time at whatever rate the co-signer permits. Nothing can; the
enclave is what talks to Google, so plaintext must exist in its RAM at the
moment of use. The rate limit, the aggregate ceiling and the audit log are
what bound the breach. Set the ceiling low enough that draining the user base
takes longer than noticing.

---

## 1. The design: nested wrapping

Two encryption layers, operator's on the **outside**.

### Onboarding (inside the enclave, once per user)

```
K_inner = HKDF(app_secret, salt = uid || key_version, info = "gmail-refresh")
inner   = AESGCM(K_inner, refresh_token, aad = uid)
```

`app_secret` comes from dstack KMS (`DstackClient.get_key()`), so `K_inner`
exists only inside an attested enclave. Send `inner` to the co-signer. The
co-signer wraps it under its own per-user key and returns `outer`. The enclave
stores `outer` on its volume. **The co-signer stores nothing.**

### Every use

```
enclave --{uid, outer}--> co-signer     mTLS; policy check; rate limit; log
enclave <----- inner ----- co-signer    still ciphertext
enclave: refresh_token = AESGCM_open(K_inner, inner, aad = uid)
enclave: POST oauth2.googleapis.com/token  (refresh_token grant + DPoP proof)
enclave: use access token; zeroize refresh token
```

The co-signer only ever handles `inner`. It cannot open it, has never seen a
refresh token, and cannot read mail even if it logs every byte that crosses
the wire.

### Who holds what

| Party | Holds | Alone can |
| --- | --- | --- |
| Enclave | `K_inner` (derived), all `outer` ciphertexts | nothing — cannot strip the outer layer |
| Co-signer | outer wrapping key, DPoP private key | nothing — has no ciphertexts, and unwrapping yields `inner` |
| Both | one token, one user, per request | that one mailbox |

### Why adding a second box does not add exposure

The intuition to argue against is "more machines, more to attack." For
**confidentiality** that is false here, and the reason is worth stating
precisely because it is checkable.

A new component widens the attack surface only if compromising it yields
something. Enumerate what the co-signer can yield:

- It receives `inner` — ciphertext under `K_inner`, a key derived from
  `app_secret`, which dstack's KMS releases only to an attested enclave. The
  co-signer has never held it and cannot derive it.
- It returns `inner` — the same ciphertext.
- It signs DPoP proofs, which cover `htm`, `htu`, `iat`, `jti`, `nonce`. No
  token material.
- It stores nothing. The `outer` ciphertexts live on the enclave volume.

So an attacker with total control of the co-signer holds a wrapping key with
nothing to unwrap, a signing key that signs no secrets, and a log. Reading one
mailbox still requires separately compromising the enclave. The set of paths to
plaintext does not grow; it shrinks, because the pre-existing path (read the
volume, or read enclave RAM at rest) stops working on its own.

That makes the confidentiality surface **monotonically smaller**: every attack
that worked before still needs everything it needed before, plus a live
compromise of a second machine under a different operator, on a per-request
basis.

The claim is not unconditional. It rests on four invariants, and a
convenient-looking refactor that breaks any one of them silently destroys the
guarantee:

1. **Layer order.** The operator's wrap is *outside*, the enclave's is *inside*.
   Reverse them and the co-signer's unwrap yields plaintext — it becomes the
   single box that can read every mailbox, which is the arrangement this design
   exists to avoid.
2. **The co-signer never receives plaintext.** Not for "validation", not for
   logging, not for a health check.
3. **No bypass.** Fail closed. A cached local key or a "co-signer unreachable,
   proceed anyway" fallback collapses the whole property to the status quo.
4. **The co-signer persists no ciphertext.** If it ever stores `outer`
   alongside its own key, one compromise gives both halves.

**The two-machine claim is only half true until Phase 4.** Everything above
describes the Phase 4 end state. Until the enclave moves to Phala, both halves
run on one box, so a host compromise gets both regardless of how the processes
are separated. What *is* true from Phase 1 is separation of privilege: the
co-signer runs as its own `cosigner` account rather than as `letterlock` (§J9),
so compromising the web UI or the mail daemon does not hand over the outer
wrapping key. That is worth having and it is not the claim §1 makes. No
user-facing copy (§10) may state the two-machine property before Phase 4.

**Where it is not a reduction: availability.** The co-signer is a new hard
dependency, and by design there is no way around it. Down means no mail
processed for anyone. That is a deliberate trade — a denial-of-service
possibility accepted in exchange for removing a confidentiality one — and it
should be stated plainly rather than glossed, including in any user-facing
copy. Monitoring and a fast restart path matter more here than they did before.

### Why the DPoP key lives on the co-signer

Google binds a **refresh token** to a DPoP key at the authorization-code
exchange; issued access tokens stay `Bearer` and are *not* DPoP-bound
(verified against Google's own docs, see §9). So:

- Without DPoP, a refresh token lifted out of enclave RAM during one legitimate
  use works **offline, forever**, with no further co-signer round trip. The
  nested wrapping would then only protect tokens at rest.
- With the DPoP private key on the co-signer, every refresh needs a signed
  proof from the co-signer. A stolen refresh token is inert without it. This is
  what makes the second barrier *permanent* rather than one-shot.

A DPoP proof covers `htm`, `htu`, `iat`, `jti` and `nonce`. No token material.
The co-signer still learns nothing from signing one.

Because the proof and the token must be combined, the flow is two co-signer
calls per refresh (unwrap + sign), or one combined call. Use one combined RPC
(`POST /unwrap-and-sign`) — fewer round trips, and it makes the rate limit
count refreshes rather than half-refreshes.

### Still no MPC / threshold crypto

The original sketch (in the user's diagram) split an ECDSA key across the two
boxes with two-party signing. **Do not build this.** Neither party can act
alone *already*, by asset division: the enclave has the ciphertext and no
signature, the co-signer has the signature key and no ciphertext. Threshold
ECDSA adds no property on top of that and costs an audited two-party protocol.
Delete `SHARE_A` / `SHARE_B` from any diagram.

Threshold *decryption* is also wrong here: the plaintext appears at whichever
party combines the partial decryptions (the enclave), which is exactly where
nested wrapping already puts it, and the available Python libraries
(`threshold-crypto`, `threshold-elgamal`) carry explicit "not for production"
warnings.

---

## 2. Attestation checking on the co-signer

**Cadence: per TLS connection, not per request.**

RA-TLS already embeds the TDX quote in the enclave's certificate, so
verification happens at handshake with no extra round trip. Per-request
re-verification buys nothing: the quote is a *boot-time* measurement (MRTD +
RTMR0-3 are fixed when the TD launches), so asking a thousand times an hour
returns identical bytes.

The enclave generates a **new** RA-TLS keypair and quote at each boot, and a
boot is exactly when the measurement can change. So an unseen certificate is
the correct trigger for full verification.

- **First sight of a cert fingerprint:** run all five checks from
  `docs/tee_enclaves_and_upgrades.md` §4.3 — (1) signature chain to Intel root,
  (2) TCB status, (3) QE identity, (4) measurements against the allowlist,
  (5) `report_data` == SHA-256 of the leaf cert. Cache the verdict by
  fingerprint.
- **Subsequent connections:** cache hit, no work.
- **Daily re-check of cached verdicts.** TCB status is the one input that
  changes without a reboot: Intel raises the required level after a
  vulnerability ("TCB recovery"), so an `UpToDate` verdict can become
  `OutOfDate`. A few times a year, so daily is generous.

Library: [`dcap-qvl`](https://github.com/Phala-Network/dcap-qvl) — Phala's own
pure-Rust QVL, published to PyPI as `dcap-qvl`, supports SGX + TDX, fetches
collateral from Intel PCS/PCCS or verifies offline. Not a port.

**The allowlist is the point.** `EXPECTED_COMPOSE_HASH` in
`deploy/phala/docker-compose.yml` is env-supplied to the container and
therefore advisory (its own comment says so). The co-signer's copy is
different in kind: the enclave cannot edit it, and it sits under a different
operator than Phala's KMS. That independence is the whole reason this check
exists given the KMS already gates `app_secret`.

**Deploy ordering consequence:** add the new `compose_hash` to the co-signer
allowlist *before* deploying, or every unwrap fails and no mail moves.
`docs/tee_enclaves_and_upgrades.md` §6.6 step 5 currently says "authorize the
new compose_hash in your AppAuth contract" — amend it to authorize in **both**
places.

Limit: this detects a wrong image, not a correct image subverted at runtime
(side channel, injection, ROP). Same wall as §0.

---

## 3. Decisions already taken (do not relitigate)

| Decision | Choice | Why |
| --- | --- | --- |
| Co-signer host | existing `hezner.morganrivers.com`, new systemd unit, own loopback port behind Caddy | picks up unit derivation in `deploy/deploy.sh` for free |
| Outer key custody | **own service**, not Vault | Vault Community has the transit engine free, but Shamir seal means it starts *sealed* on every reboot; fail-closed design ⇒ no mail until a human unseals. Auto-unseal needs a cloud KMS (awskms/gcpckms/azurekeyvault are Community; only PKCS11 HSM is Enterprise), which adds a third party that can cause an outage. ~80 lines of `AESGCM` + SQLite avoids all of it. |
| Master key delivery | systemd `LoadCredentialEncrypted=` | seals to host TPM, unseals at unit start, no human, no third party |
| DPoP | **in from the start**; wipe all accounts | Google binds at code exchange; cannot retroactively bind an existing token. User is the only account and has not configured it — wiping is *preferred* so account creation gets tested properly. |
| Migration script | **none** | see above; no plaintext `credentials.json` to migrate |
| Node | **removed entirely** (Track K), sequenced after custody lands | see §7 |
| Phala | not yet rented; build dev-first, cut over later | §8 |

---

## 4. Track I — split custody (the spine)

Worktrees: I1–I4 are `enclave-custody-2`; I5–I6 are `onboarding-exchange-4`,
which branches after `enclave-custody-2` merges.

### I1. `backend/custody/wrapping.py` (new, ~120 lines) — `enclave-custody-2`

Single source of truth for the enclave-side crypto.

- `inner_key(uid)` → `HKDF(app_secret, salt=uid||key_version, info=b"gmail-refresh")`.
  `app_secret` from `DstackClient().get_key(APP_KEY_PATH, purpose="seal")`.
  Outside a CVM (dev), fall back to a dev key from env **only** when
  `TEE_REQUIRED` is unset; assert loudly otherwise.
- `seal_inner(uid, refresh_token) -> bytes` — AES-GCM, `aad=uid.encode()`.
- `open_inner(uid, inner) -> str` — inverse. Assert on tag failure with a
  message that does not leak the ciphertext.
- `key_version` constant, stored alongside each record, so rotation is possible
  without a schema change.

Asserts: uid non-empty and matching the manifest; `len(inner) > 28` (nonce+tag);
never log plaintext.

### I2. `backend/custody/client.py` (new, ~150 lines) — `enclave-custody-2`

The enclave's mTLS client to the co-signer. Sole network boundary.

- `CoSignerClient.wrap(uid, inner) -> outer` (onboarding only)
- `CoSignerClient.unwrap_and_sign(uid, outer, htu, htm, nonce) -> (inner, dpop_proof)`
- Client cert/key from `DstackClient.get_tls_key(client_auth=True)`.
  **Note:** `backend/tee/dstack_client.py:100` currently defaults
  `client_auth=False` — flip the call site, not the default.
- Dev mode: self-signed cert from a path in env when no dstack socket.
- Fail closed. A co-signer that is down means no mail processed. **Do not build
  a bypass.** Alert via `telegram.operator_target()` (box-level failure — this
  is exactly what that channel is for; never the per-account path).

### I3. `backend/custody/tokens.py` (new, ~180 lines) — `enclave-custody-2`

The replacement for what google-auth-library used to do internally.

- `access_token_for(account) -> (token, expiry)`:
  1. check in-process cache (tokens last ~1h; do not refresh per subprocess)
  2. read `outer` from `database/<uid>/token.bin`
  3. `client.unwrap_and_sign(...)`
  4. `wrapping.open_inner(...)`
  5. POST `https://oauth2.googleapis.com/token`, `grant_type=refresh_token`,
     with the `DPoP` header
  6. handle the `DPoP-Nonce` retry: Google returns a nonce, you retry once with
     it in the proof's `nonce` claim. **This is mandatory, not optional** —
     first attempt without a cached nonce will fail with `use_dpop_nonce`.
  7. zeroize the refresh token; cache and return the access token
- `refresh_handler_for(account)` → a callable matching google-auth's
  `refresh_handler` signature `(request, scopes) -> (token, expiry)`.

**Why `refresh_handler`:** `google.oauth2.credentials.Credentials` accepts it,
and at `google/oauth2/credentials.py:371` the refresh path is
`if self._refresh_token is None and self.refresh_handler:`. Constructing
`Credentials` with **no refresh token** routes every acquisition through our
handler. The library docstring describes exactly this case ("tokens are
obtained by calling some external process on demand"). This is a supported
extension point, not a hack, and everything downstream stays official code.

Verified: `google-auth` 2.41.1 in the `py311` env has this. Neither
`google-auth-library` (JS, checked 10.9.1 — matches the `^10.5.0` pin) nor
`google-auth` (Python) implements DPoP; grepped both builds, zero hits. DPoP is
a bring-your-own-library item in **either** language, so it is not a reason to
stay in Node.

### I4. DPoP proofs — `enclave-custody-2` (proof construction: `cosigner-service-1`)

Use [`requests-oauth2client`](https://pypi.org/project/requests-oauth2client/)
1.8.0 (Apache-2.0, py3.9–3.14, beta). It generates proofs, handles the
`DPoP-Nonce` round trip, defaults to ES256. Confirmed installable.

The **private key stays on the co-signer** — the enclave never holds it. So the
enclave sends `(htm, htu, nonce)` and receives a finished proof JWT. On the
co-signer side that is `requests_oauth2client`'s proof construction with a
fixed key; on the enclave side it is just an HTTP header value.

Add to `requirements.txt`: `requests-oauth2client==1.8.0`, `cryptography`, and —
even though nothing in this worktree imports it — `google-api-python-client`,
which Track K needs. `enclave-custody-2` is the only worktree that edits
`requirements.txt`; adding K's pin here in the same pass is what keeps
`node-removal-5` out of the file entirely (§7).

### I5. Onboarding rewrite (the risky part) — `onboarding-exchange-4`

`backend/onboarding/provisioning.py` currently shells to `oauth_helper.mjs`
(`run_helper`, lines 49–73). The code exchange must move to Python so the DPoP
proof can be attached at the moment Google binds the token.

- `build_auth_url()` → Python, add `code_challenge` (PKCE) + `dpop_jkt`
  (thumbprint of the co-signer's DPoP public key, fetched once at startup).
- `exchange_code()` → Python `requests` POST with the DPoP header. Returns
  profile + refresh token **in memory only** — it must never touch disk.
- `provision()` (line 79): replace the staging-directory dance
  (lines 87–103, which exists only because the owning email is unknown before
  the exchange) with: exchange → `seal_inner` → `client.wrap` → write
  `database/<email>/token.bin` (0600). The `AccountLimitReached` cleanup at
  line 112 becomes "delete the record", still correct.
- `handle_callback()` (line 128) is unchanged in shape — keep it HTTP-free and
  directly tested, per its docstring.
- Delete `oauth_helper.mjs` (112 lines) and `manual_auth.mjs` (70 lines).
  `manual_auth` was the interactive laptop path; `browserAuth()` and
  `INTERACTIVE_AUTH` in `gmail_lib.mjs` go with it.

### I6. Wipe + re-onboard — `onboarding-exchange-4`

- `database/accounts.json` and `database/<email>/` deleted on the box.
- Re-run `python -m backend.accounts.seed_owner`, then sign in through
  `/auth/callback` like a real user. This is the first proper test of account
  creation.
- `deploy/deploy.sh` `EXCLUDES` already protects `database/` — the wipe is
  manual and deliberate, not something the deploy does.

### I7. As built: what the spec left open

- **PKCE verifiers are derived, not stored.** Keyed off the enclave's own secret
  by the `state` value, so a restart between the two halves of a sign-in does
  not strand the user mid-consent. There is no server-side session table to
  lose, and nothing to clean up on an abandoned sign-in.
- **`creds_dir` became `token_file` in the manifest,** as §6 predicted. Less
  predictably, the `creds_dir=` parameter threaded through the drafter became
  `account=`, and `identity=` was removed with it: passing both made it possible
  to draft under one user's identity while searching another user's mail. That
  is a multi-tenant isolation bug the port closed. Do not reintroduce a second
  identity parameter alongside `account=`.
- **The MIME port was verified against the implementation it replaced,** running
  both builders over five payloads (unicode headers, quote and no-quote, each
  half of the attribution) to byte-identical output before `create_draft.mjs`
  was deleted. `tests/test_draft_mime.py` pins it now that the comparison target
  is gone. Any future change to draft assembly is checked only against that
  file.
- **`deploy/phala/docker-compose.yml` passes `LETTERLOCK_COSIGNER_URL`,** while
  `backend/site.py` also has `COSIGNER_HOST` and `cosigner_url()`. Confirm at
  integration which one wins; two ways to name the same endpoint is exactly the
  drift `site.py` exists to prevent.

---

## 5. Track J — co-signer service — `cosigner-service-1`

Whole track, J1–J6, is one worktree. It imports nothing from `backend/`, so
apart from one constant in `backend/site.py` it only adds files.

New top-level `cosigner/` (own module, imports nothing from `backend/` so it
can be deployed independently later). ~250 lines total.

### J1. `cosigner/server.py`

- `POST /wrap` `{uid, inner}` → `{outer}`. Onboarding only; refuse if a record
  for `uid` already exists (idempotency; a second wrap is either a bug or an
  attack).
- `POST /unwrap-and-sign` `{uid, outer, htm, htu, nonce?}` → `{inner, proof}`.
- `POST /sign-dpop` `{htm, htu, nonce?, uid?}` → `{proof}`. Not in the original
  list and not optional: at the authorization-code exchange no uid exists yet,
  because which mailbox consented is unknown until Google answers, so
  `/unwrap-and-sign` cannot serve that proof — there is nothing to unwrap. The
  `DPoP-Nonce` retry needs a second proof over the same request without paying
  for a second unwrap. The uid is advisory (audit attribution only), which is
  what forces the separate ceiling in J3.
- `GET /dpop-jwk` → `{jwk, jkt}`. The public half, so the enclave can send
  `dpop_jkt` at the code exchange. Asserts `d` is absent before serving.
- `GET /health`.
- mTLS required. Client cert verified per §2.

### J2. `cosigner/keys.py`

- Master key from `$CREDENTIALS_DIRECTORY/cosigner-master` (systemd
  `LoadCredentialEncrypted=`).
- `outer_key(uid) = HKDF(master, salt=uid, info=b"outer")` — per-user, so the
  audit log and any future per-user revocation are meaningful.
- DPoP EC P-256 private key, also from `LoadCredentialEncrypted=`.

### J3. `cosigner/policy.py`

- Per-user rate limit (default: 60 unwraps/hour — a mailbox wake needs one).
- Aggregate ceiling across all users per hour. **This is the number that bounds
  a live enclave breach.** Start at ~3× expected peak.
- Separate ceiling for bare `/sign-dpop`. It carries no uid, so the per-user
  limit cannot reach it, and without one it is the unmetered path around the
  metered one: an enclave-side attacker skips `/unwrap-and-sign` entirely, uses
  a refresh token they already lifted, and asks here for the proof that makes it
  work. Defaults to the unwrap ceiling, since the legitimate pattern is at most
  one retry proof per unwrap plus onboarding.
- Kill switch: a file or env flag that refuses everything.
- On refusal, alert the operator. A refusal is either a bug or a breach; both
  want a human.

### J4. `cosigner/attest.py`

Per §2: `dcap-qvl` verification, fingerprint-keyed verdict cache, daily TCB
re-check, measurement allowlist in a config file (not env).

### J5. `cosigner/audit.py`

SQLite, append-only by convention (no UPDATE/DELETE in the code; separate
`.backup` off-box). One row per request: timestamp, uid, decision, cert
fingerprint, measurement. **Never** the ciphertext or any token material.

The enclave cannot rewrite this. That is the point: attestation says "the right
code booted", the log says "here is what happened afterwards". Neither prevents
anything; they give detection and evidence.

### J6. `deploy/hetzner/cosigner.service`

With `[Install]`, so `deploy/deploy.sh` picks it up automatically (line 138
derives the service list by grepping for `[Install]`). Add a `preflight.py`
check that the credentials load and the allowlist parses. Add the loopback port
to `backend/site.py` and regenerate the Caddyfile
(`python -m deploy.render_caddyfile`) — never hand-edit it.

### J7. As built: what the spec left open

Recorded because a future stage will hit each of these and the reasoning is not
recoverable from the code alone.

- **mTLS terminates at Caddy, so the attestation check cannot live there.** §3
  says "behind Caddy" and §5 says "client cert verified per §2", which conflict:
  an RA-TLS certificate is self-signed and Caddy has no way to judge it.
  Resolved with `client_auth { mode require }` (demand a cert, verify nothing)
  plus `header_up X-Client-Cert-Der {…certificate_der_base64}`, leaving
  `attest.py` to run the five checks on the DER. **A request arriving without
  that header is what a bypassed proxy looks like and is refused.** Anything
  that later changes the proxy must preserve that header or the service fails
  closed, which is correct but will look like an outage.
- **The co-signer needs its own hostname.** `client_auth` is per-site, so
  folding it onto `API_HOST` would demand a client certificate from Google's
  Pub/Sub push as well. `COSIGNER_HOST` is separate and needs a DNS A record
  before Phase 3. TLS-ALPN must be disabled for that site or ACME cannot renew
  through `mode require`.
- **`quote_oid` and the `report_data` binding are deliberately blank.** dstack's
  certificate extension OID and what its guest agent binds `report_data` to
  could not be confirmed from documentation, and a guessed value produces a
  check that passes on nothing in particular. `attest.configured()` reports the
  service unconfigured while `mode: required` and those are empty, so preflight
  refuses to start it rather than let it fail open. Both get filled from a live
  RA-TLS certificate at the Phala cutover; see the runbook Stage 2.
- **The audit log is the rate limiter's state.** Grants are counted out of the
  log rather than an in-memory dict, so the budget survives a restart and the
  number enforced is the number the log shows. `/wrap` idempotency reads the
  same log, which keeps invariant 4 (the co-signer stores no ciphertext)
  intact.
- **`cosigner/alerts.py` imports `backend.integrations.telegram` inside the
  function.** This bends "imports nothing from `backend/`"; the alternative was
  a second copy of the Bot API, against the single-source rule. It is the only
  crossing, and it is the only thing to rewrite when the co-signer moves to its
  own box.

### J8. The wire contract, reconciled

§7a said to freeze this before either worktree started. That did not happen, and
the two branches shipped different contracts. **Neither merges until this is
settled.** The union, with the enclave side's reasoning, is authoritative:

| Endpoint | Notes |
| --- | --- |
| `POST /wrap` | as specced |
| `POST /unwrap-and-sign` | as specced |
| `GET /health` | as specced |
| `GET /dpop-jwk` | built as `/dpop-key` on the co-signer; **rename to `/dpop-jwk`**. Returns the public JWK; the enclave computes the `dpop_jkt` thumbprint from the key rather than trusting a stated field, and refuses a JWK containing `d`. |
| `POST /sign-dpop` | **missing from the co-signer entirely.** Not optional: at code-exchange time there is no uid yet, because the mailbox is unknown until Google answers, so `/unwrap-and-sign` cannot serve it — there is nothing to unwrap. The `DPoP-Nonce` retry (§I3 step 6) also needs a second proof without a second unwrap. |

`/sign-dpop` is a bare signing oracle with no uid attached, so the per-user rate
limit in `policy.py` cannot apply to it. It needs its own aggregate limit and
its own audit rows, or it becomes the unmetered path around the metered one.
This is the only place the built system can be made to sign without being
counted; **[DONE]** — `/sign-dpop` enforces `COSIGNER_RATE_SIGN_HOUR`, a ceiling
separate from the unwrap budget so neither can be spent through the other. The
`uid` on that route is optional and advisory, recorded for audit attribution
only: metering per user would meter only the callers honest enough to name one.

**Who fixed it: `cosigner-service-1`, entirely.** The rename and the new
endpoint were `cosigner/server.py`, `policy.py` and `audit.py`, all owned by that
worktree. `/dpop-key` now 404s, and `dpop_public_jwk()` asserts `d` is absent
before serving, so a library change cannot publish the signing key.

**Root cause, still open on the other branch.** Both worktrees wrote a contract:
`cosigner/protocol.py` on one side, an equivalent inside
`backend/custody/client.py` on the other. Paths and field names were reconciled
by hand, but the encodings were not, and that is what two definitions costs:
`protocol.py` spells binary as standard padded base64 and decodes with
`validate=True`, while `client.py` used base64url with the padding stripped. The
co-signer therefore rejects every `/wrap` and `/unwrap-and-sign` the enclave
sends, and per this service's own design that failure looks like a tampering
alert rather than a bug. `cosigner/protocol.py` is the single definition;
`backend/custody/client.py` imports `b64`/`unb64` from it and keeps no codec of
its own. That direction is allowed: §5's rule is that the co-signer must not
import `backend/`, and it is one-directional. The fake co-signer in
`tests/test_custody.py` is built on the same import, so a future contract change
breaks a test rather than production.

### J9. Its own account, not `letterlock`

`hardening.conf` is fanned out to every unit and sets `User=letterlock`; a
drop-in beats the unit file, so shipping the service without an override would
put the outer wrapping key and the DPoP key inside the blast radius of the web
UI and the mail daemon, and the split would be decorative on this box.
`deploy/hetzner/cosigner.service.d/20-cosigner.conf` overrides `User=`/`Group=`
to `cosigner`, takes read access to the source through
`SupplementaryGroups=letterlock` (the app directory is 750; the paths holding
user data are 700/600, so group membership does not reach them), and resets
`ReadWritePaths=` to empty because everything it writes is in
`StateDirectory=cosigner`. `deploy.sh` installs any `<unit>.d/*.conf`, deletes
drop-ins the repo no longer has, and creates the accounts by reading `User=`
back out of them, so the account name has one definition.

This is separation of privilege on one machine, not separation of operator.
Phase 4 is where the second half becomes true, and §10 copy must not claim it
before then.

---

## 6. Track K — remove Node — `node-removal-5`

Whole track is one worktree, branched after `enclave-custody-2` merges (it
needs `tokens.refresh_handler_for()`). Largest of the five by a wide margin.

1001 lines of `.mjs` across 11 files. After Track I, ~595 of those lines are
already being rewritten (`gmail_lib.mjs` credential handling, `oauth_helper`,
`manual_auth`), so the marginal cost is the nine thin command wrappers.

### Why it is worth doing

- **The security argument for Node dies with Track I.** Node was privileged
  because it held the OAuth client. Afterwards it holds a bearer access token
  and makes API calls — nothing about it is safer than the Python equivalent.
- **Shrinks the measured image.** `node_modules` with `googleapis` is a large
  dependency tree inside `compose_hash`, i.e. inside the trust story. Removing a
  whole language runtime makes AppAuth-signer review of what goes into the hash
  possible rather than notional.
- **Per-call subprocess spawn.** Every Gmail operation forks Node and imports
  `googleapis`. On a 2 GB box that is latency and peak RSS on every draft.
- **Closes a split seam.** `draft_replies.build_draft_payload()` builds a
  payload in Python purely so `create_draft.mjs` can execute it.

### Port order (easiest → riskiest)

`google-api-python-client` is already present in `py311` (verified). Add it to
`requirements.txt`.

1. **`backend/integrations/gmail_gcal/gmail_api.py`** — the Python
   `gmail_lib.mjs`. `client_for(account)` builds
   `Credentials(token=None, refresh_token=None, refresh_handler=...)` from I3,
   then `googleapiclient.discovery.build('gmail','v1')`. Port the pure helpers
   first: `extractText` → `extract_text`, `normalizeBody` → `normalize_body`.
2. **Thin wrappers** (25–32 lines each): `search_gmail`, `get_thread`,
   `find_thread`, `list_calendar`, `create_event`, `watch_register`. Mechanical.
   `tool_executors._run_node` (line 21) becomes a direct call — all four tool
   executors already route through it.
3. **`fetch_emails.mjs`** (86 lines) — history parsing, `stale` 404 handling,
   `annotateThreadParticipation`. Fiddly. Port with `tests/test_routing.py`
   watching.
4. **`create_draft.mjs`** (155 lines) — MIME multipart/alternative assembly,
   `=?UTF-8?B?` header encoding, the gmail_quote HTML block, and the
   `drafts.update` path that **progressive drafts depend on** (see CLAUDE.md
   "Progressive drafts"). Highest bug risk. Golden-test the RFC822 output
   against the current `.mjs` before deleting it.

### Seams that make it contained

- `node_runner.node_env(creds_dir)` — every subprocess env goes through here.
  It disappears; `creds_dir` on the account becomes unused (the token is no
  longer a directory of files) and should be removed from `account.py` in the
  same pass.
- `draft_replies.submit_draft(payload, draft_id=None)` — sole boundary to
  `create_draft.mjs`. Its signature does not change; only its body.
- `draft_replies.build_draft_payload()` — stays as the canonical payload shape,
  now consumed in-process.
- `tool_executors._run_node` — sole boundary for the four tool scripts.

### Deletions when done

`package.json`, `package-lock.json`, `node_modules/`, all of
`backend/integrations/gmail_gcal/*.mjs`, `paths.node_script()`,
`node_runner.py`. Remove the npm branch from `deploy/deploy.sh` and the
`node_modules/` exclude. Remove Node from the Docker image in
`deploy/phala/` — this is where the image shrink lands.

---

## 7. Sequencing

Two independent orderings. **Worktrees** are how the code gets written and are
gated only on each other. **Phases** are how it gets switched on and are gated
on Phala procurement. A worktree can be finished and merged long before the
phase that turns its production path on.

### 7a. Worktrees

Five branches. Wave 1 starts together; wave 2 branches from `main` after
`enclave-custody-2` merges.

| Worktree | Wave | Scope | Size |
| --- | --- | --- | --- |
| `cosigner-service-1` | 1 | Track J entire (§5) | ~250 lines + tests |
| `enclave-custody-2` | 1 | I1–I4 (§4) | ~450 lines + tests |
| `secrets-gate-3` | 1 | §8 items 1, 2, 4 | ~150 lines across ~10 files |
| `onboarding-exchange-4` | 2 | I5, I6 (§4), §8 item 3 | ~150 changed |
| `node-removal-5` | 2 | Track K entire (§6) | ~600 new, ~1000 deleted |

File ownership. A path appears under exactly one worktree; that is what makes
the merges boring.

| Worktree | Owns |
| --- | --- |
| `cosigner-service-1` | `cosigner/**`, `deploy/hetzner/cosigner.service`, the co-signer port constant in `backend/site.py`, regenerated `deploy/hetzner/Caddyfile`, its `deploy/preflight.py` check |
| `enclave-custody-2` | `backend/custody/**`, `requirements.txt`, the `client_auth` call site in `backend/tee/dstack_client.py`, `tests/test_custody.py` |
| `secrets-gate-3` | `backend/secrets.py`, the eight `load_dotenv(paths.ENV_FILE)` call sites, `backend/tee/tee_boot.py`, `deploy/phala/docker-compose.yml` |
| `onboarding-exchange-4` | `backend/onboarding/provisioning.py`, deletion of `oauth_helper.mjs` + `manual_auth.mjs`, `gcp-oauth.keys.json` custody, `tests/test_onboarding.py` |
| `node-removal-5` | `backend/integrations/gmail_gcal/**`, `node_runner.py`, `paths.node_script()`, `tool_executors.py`, the body of `draft_replies.submit_draft()`, `account.creds_dir`, `package*.json`, the npm branch of `deploy/deploy.sh`, the Node layer of `deploy/phala/` |

Three things to settle before wave 1 opens, because each is a place two
worktrees would otherwise write the same lines:

1. **Freeze the wire contract first.** `cosigner-service-1` and
   `enclave-custody-2` are parallel only because §5's two request shapes
   (`POST /wrap`, `POST /unwrap-and-sign`) are fixed in advance. Write them
   down as a schema before either branch starts, and have `enclave-custody-2`
   test against a fake co-signer rather than the real one. Changing the
   contract mid-flight serializes the two branches.
2. **`requirements.txt` belongs to `enclave-custody-2` alone,** including
   Track K's `google-api-python-client` pin (§I4). Two branches appending to
   the same file conflict for no reason.
3. **`gmail_lib.mjs` belongs to `node-removal-5` alone.**
   `onboarding-exchange-4` would naturally strip `browserAuth()` and
   `INTERACTIVE_AUTH` from it (§I5); it must not. Leave the file untouched and
   let `node-removal-5` delete it whole — a delete/edit conflict on a file
   being removed anyway is pure noise.

`secrets-gate-3` touches few lines but many files. Merge it early rather than
letting it sit; it is the one branch that goes stale against everything.

`node-removal-5` is big enough to want splitting. The seam is `gmail_api.py`
plus the six mechanical wrappers, then `fetch_emails` plus `create_draft`. That
is a sequence, not a parallel pair — the second half imports the first — so
split it only if the branch becomes unwieldy, not for throughput. Its golden
tests against the current `.mjs` output (§6) are the first commit on the
branch, before any port lands.

The §10 front-end copy edits are **not** a worktree. Each one is gated on
individual user confirmation and several depend on which tracks have actually
shipped.

### 7b. Phases

Phala is not rented yet. Build dev-first so procurement never blocks.

Phases 3–5 have an operator runbook with the actual commands:
`docs/runbook_provisioning.md`. It assumes every worktree in 7a has merged, and
it opens with the one decision (which KMS) that must be settled before any
account is onboarded, because changing it later invalidates every sealed token.

**Phase 1 — dev, no TEE.** `TEE_REQUIRED` unset, no dstack socket. Co-signer on
localhost with a self-signed cert, attestation verification stubbed behind a
flag that **asserts it is only ever off in dev**. Everything else real: nested
wrapping, DPoP, rate limits, audit log. Tracks I + J complete and tested here,
i.e. `cosigner-service-1`, `enclave-custody-2`, `secrets-gate-3` and
`onboarding-exchange-4` all merged.

**Phase 2 — Node removal.** `node-removal-5`, entirely local, no TEE
dependency. Golden tests carry it.

**Phase 3 — deploy co-signer to Hetzner.** Real systemd unit, real
`LoadCredentialEncrypted=`, real Caddy route. Enclave side still dev.

**Phase 4 — Phala cutover.** Rent the 2 GB instance. Flip `client_auth=True`,
turn on RA-TLS, populate the measurement allowlist, set `TEE_REQUIRED=1`,
remove the dev-mode escape hatches. Amend §6.6 checklist to authorize the
compose hash in both AppAuth and the co-signer allowlist.

**Phase 5 — re-onboard.** Wipe `database/`, seed the owner, sign in through the
real flow. This is I6, written in `onboarding-exchange-4` but only executed
against the box here.

---

## 8. Also fix while in here (Barrier A gaps)

Found during this review; small, and they belong to the same threat model.
Four of the five are `secrets-gate-3` and have landed; the
`gcp-oauth.keys.json` move is `onboarding-exchange-4`, because it lands in the
same file as the code exchange it belongs to.

- **`secrets-gate-3`, done** — ~~`deploy/phala/docker-compose.yml:32` mounts
  `/app/.env` with `required: false`.~~ Mount removed. `tee_boot.run_gate()`
  now fails closed if `.env` exists on the volume at all, so putting the mount
  back stops the enclave booting rather than silently weakening it.
- **`secrets-gate-3`, done** — ~~`tee_boot.REQUIRED_SECRETS` lists four
  values.~~ Replaced by `secrets.missing()`, which covers the LLM keys,
  Telegram, `SESSION_SECRET` and the Polar API + webhook credentials, and
  decides presence by calling the services' own code (`PolarBilling()`,
  `telegram.operator_target()`) so the list cannot drift from what the services
  need.
- **`secrets-gate-3`, done** — ~~eight modules call
  `load_dotenv(paths.ENV_FILE)` independently.~~ Collapsed to
  `secrets.load()`: one read of the file, injected environment always wins over
  it, `file_backed()` names anything that came off disk, and under
  `TEE_REQUIRED` the file is never opened.
- **`onboarding-exchange-4`** — `gcp-oauth.keys.json` holds the Google
  `client_secret`, read off the volume rather than from injected env. It is the
  single value with the widest blast radius and the one **not** going through
  the KMS path. Every reader is now behind `oauth_app.py`, so this is a
  one-file change.

  **Correction to the original instruction, which said to move it to the
  co-signer.** That cannot work. Google's token endpoint requires
  `client_secret` and `refresh_token` in the *same* POST, and the enclave is
  what makes that POST (§I3 step 5). So either the co-signer performs the
  exchange and sees the refresh token, violating invariant 2, or it hands the
  secret back to the enclave, which is the status quo with extra round trips.
  Neither is worth doing.

  Do this instead: inject it as a dstack encrypted environment variable and
  delete the volume file. That fixes the actual stated defect — a secret read
  off disk instead of released post-attestation — without touching the custody
  split. There is no marginal loss from the enclave holding it, since an
  attacker with enclave memory already has refresh tokens.

  Half of the wiring is already in place, so this is smaller than it reads.
  `backend/secrets.py` names the pair (`GOOGLE_CLIENT_ID_ENV`,
  `GOOGLE_CLIENT_SECRET_ENV`), exposes `google_oauth_client()` and has
  `google_oauth_configured()` written and tested. It is deliberately **not** in
  `REQUIRED`: while `oauth_app.load_keys()` still reads the file, requiring the
  injected form would refuse boot over a value nothing consults. Make
  `load_keys()` prefer the injected pair and refuse the file under
  `TEE_REQUIRED`, then add `google_oauth_configured` to `REQUIRED` in the same
  commit.
- **`secrets-gate-3`, done** — ~~`deploy/phala/pyproject.toml` is a second
  dependency list and has already drifted from `requirements.txt`.~~
  `requirements.txt` is now the source and the pyproject dependency array is
  generated from it (`python -m deploy.render_pyproject`, then `cd deploy/phala
  && uv lock`), the same arrangement `render_caddyfile.py` has with `site.py`.
  `tests/test_requirements.py` fails on drift in either direction, verified by
  inverting it. Fixing the existing drift dropped the spaCy tree from the
  measured image: 84 locked packages to 61, which is the ~1.6 GB the analyzer
  costs and the reason it is off by default on a 2 GB CVM.

---

## 9. Verified facts (checked 2026-08-05, do not re-derive)

- **Google DPoP:** supported at `oauth2.googleapis.com/token`. Refresh tokens
  are DPoP-bound when a valid proof is used at the exchange; **access tokens
  remain `Bearer` and are not bound**. Google returns a `DPoP-Nonce` header
  which must be cached and echoed in the `nonce` claim of subsequent proofs.
  Source: [Google OAuth best practices](https://developers.google.com/identity/protocols/oauth2/resources/best-practices),
  [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449).
- **No DPoP in either Google auth library.** Grepped `google-auth-library@10.9.1`
  build output (0 hits) and `google-auth` 2.41.1 in `py311` (0 hits).
- **`refresh_handler` exists** in `google-auth` 2.41.1,
  `google/oauth2/credentials.py:87,371`.
- **`google-api-python-client` already installed** in `py311`.
- **`requests-oauth2client` 1.8.0** — Apache-2.0, beta, DPoP + nonce handling,
  downloads cleanly.
- **Vault Community** includes the transit engine and rate-limit quotas;
  **lease-count quotas, `group_by` identity rate limits, HSM seal and seal
  wrapping are Enterprise**. Auto-unseal via cloud KMS is Community; only
  PKCS11 is not. BUSL-1.1 since Aug 2023; OpenBao is the MPL-2.0 fork.
- **No off-the-shelf broker with this threat model exists.** Every OAuth token
  broker found holds the refresh token itself, which is the arrangement that
  gives one compromised box everything.

## 10. Front-end copy — no worktree

Deliberately not assigned to any of the five. Each edit is gated on separate
user confirmation, and `frontend/web_server.py` would otherwise be a shared
file across branches for changes that are one or two lines each. Do these on
`main` after the tracks they describe have merged.

**Rule: ask the user about each change individually and get confirmation before
editing.** Do not batch these, do not apply them as a set, and do not rewrite
surrounding prose while in the file. Every edit below is a factual correction
to a claim this work changes; anything beyond that is out of scope.

Copy is inline in `frontend/web_server.py` (no templates). Minimal set:

- **`web_server.py:383-386` (/about, "Your Gmail refresh token…").** The only
  passage that becomes **untrue**. It currently says the token "lives inside the
  enclave, in an encrypted volume whose key is released by the KMS only after
  the attestation report passes verification." After Track I the token is
  nested-wrapped and unusable without the co-signer, which is a stronger claim
  than the one being made. Must change. Propose the smallest edit that states
  both layers.
- **`web_server.py:308-310` (landing, "How secure is Letterlock?").** Already
  says "Email access tokens requires simultaneous access to an encrypted secure
  enclave as well as Letterlock's EU-based verifier server" — i.e. it already
  describes this design. Check for accuracy once built; it may need **no
  change at all**. There is a grammar slip ("tokens requires"); ask separately
  rather than fixing it silently as part of a security edit.
- **`web_server.py:823-825` (dashboard Attestation row).** Reads
  `STUB (Hetzner)` / `Live on Phala TEE`. Only touch this at Phase 4 cutover,
  when it stops being a stub. Not part of Tracks I-K.

Explicitly **not** in scope: the comparison table (`~815`), the PII/masking demo
(`~423-553`), the open-source section (`~392`), taglines, pricing. None of their
claims change.

Ask before writing anything new about the co-signer. Describing a second
independent barrier in marketing copy raises the stakes on getting the
rate-limit and audit behaviour right, and it is the user's call whether to
advertise it at all. If it is advertised, the defensible claim is the narrow one
argued in §1 ("Why adding a second box does not add exposure"): the co-signer
holds no readable copy of anything, so it removes a way to read mail without
adding one. Do not stretch that into "more secure because there are two
servers" — the argument is about which paths to plaintext exist, not about
count. The availability trade named at the end of that section is part of the
honest version of the claim.

## 11. Line-count estimate

| Piece | Worktree | Lines |
| --- | --- | --- |
| `backend/custody/` (I1–I3) | `enclave-custody-2` | ~450 |
| onboarding rewrite (I5) | `onboarding-exchange-4` | ~150 changed |
| `cosigner/` (J1–J5) | `cosigner-service-1` | ~250 |
| Node → Python port (K) | `node-removal-5` | ~600 new, ~1000 deleted |
| secrets accessor + gate (§8) | `secrets-gate-3` | ~150 changed |
| tests | split across all five | ~300 |

Net roughly break-even on line count, one language and one dependency tree
lighter, with the trust story testable end to end.
