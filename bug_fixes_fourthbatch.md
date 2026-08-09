# Fourth batch: enclave-affecting findings

Scope as asked: categories 5 (data egress), 6 (verification that fails open),
7 (web tier fundamentals), 8 (deployment and process boundaries), 9 (retention
and deletion), restricted to code that runs in or governs the Phala enclave —
`deploy/phala/docker-compose.yml`, `flake.nix`, `backend/tee/`,
`backend/custody/`, `cosigner/attest.py`,
`backend/integrations/inference_attestation.py`, `backend/secrets.py`,
`backend/paths.py`, and the three role entrypoints.

Ordered by the triage rules: who can trigger it, what it yields, what must
already be true. Confidence is stated separately from severity.

---

## 1. The boot gate demands secrets no role is given, so no gated role can start

**Category 6/8. Confirmed by reading. Blocks the enclave outright.**

`backend/tee/tee_boot.py:124` calls `secrets.missing()`, which runs the whole of
`secrets.REQUIRED` (`backend/secrets.py:288`): every inference key, Telegram,
`SESSION_SECRET`, the Polar API credentials, the Polar **webhook** secret, and
the Google OAuth client pair.

`deploy/phala/docker-compose.yml` deliberately hands each role a subset:

- `web` gets no `DEEPSEEK_API_KEY`, no `NEARAI_API_KEY`, no `TELEGRAM_*`, no
  `GOOGLE_OAUTH_CLIENT_*`. It fails four of the six checks.
- `mail` gets no `SESSION_SECRET`. It fails one.
- **No role anywhere gets `POLAR_WEBHOOK_SECRET`**, and there is no Polar
  receiver in the enclave by design. Both gated roles fail
  `polar_webhook_configured()` (`billing.webhook_secret()` reads
  `POLAR_WEBHOOK_SECRET` / `_SANDBOX`, `backend/billing/billing.py:118`).

So `gate()` in `flake.nix` exits 1 in both `mail` and `web`, and `restart:
always` turns that into a permanent crash loop. `tests/test_enclave_boundary.py`
pins what each role must *not* hold and nothing pins that what it does hold is
enough.

Why this is a security finding and not only an outage: the cheapest way to make
the enclave boot is to delete the `gate` call from the entrypoint or to trim
`secrets.REQUIRED`, and either one removes the fail-closed check on secrets
provisioning for every role at once. `deploy/preflight.py` already has the right
shape — per-unit config checks (`CONFIG_CHECKS`, `_mail_configured`,
`_web_configured`) — and the gate is the one caller that ignores it.

The two docstrings are already in disagreement about this:
`preflight._mail_configured` says "the enclave gates on the same OAuth pair
through `secrets.REQUIRED`", which is only true for a role that is handed the
pair.

**Fix (chokepoint).** Make the required set a function of the role, in
`backend/secrets.py`, and have both callers read it:

- add `REQUIRED_BY_ROLE = {"mail": (...), "web": (...), "hook": ()}` beside
  `REQUIRED`, with `missing(role=None)` defaulting to the union for the box.
- `preflight.CONFIG_CHECKS` composes from the same mapping instead of its own
  `_mail_configured` / `_web_configured` tuples.
- the entrypoint already knows the role; pass it:
  `python -m backend.tee.tee_boot --role "$role"`.
- add to `tests/test_enclave_boundary.py`: for each service block, every name in
  that role's required set is either interpolated in its `environment:` block or
  not required for it. That test is what stops the next partition edit from
  reintroducing this.

Drop `polar_webhook_configured` from any enclave role's set: nothing in the
image verifies a Polar signature, which the compose file and CLAUDE.md both
already state.

---

## 2. Nothing couples the enclave's `TEE_REQUIRED` to the co-signer's attestation mode

**Category 6. Confirmed. Reachable by anyone who can reach the co-signer port
without a client certificate.**

`cosigner/allowlist.json` currently ships `"mode": "dev-insecure"`,
`"quote_oid": null`, `"measurements": []`. Under that mode
`attest.verify_client()` returns a passing verdict for a request carrying **no
client certificate at all** (`cosigner/attest.py:171`), so `/unwrap`,
`/unwrap-and-sign` and `/sign-dpop` are gated by the rate limiter alone.

The only thing meant to stop that surviving into production is
`attest.mode()`'s check that `TEE_REQUIRED` is not set — but it reads
`TEE_REQUIRED` **from the co-signer's own environment**, and the co-signer runs
on the Hetzner box where that variable is never set. The enclave can be deployed
with `TEE_REQUIRED=1`, believing it is authenticating itself by measurement to a
second operator, while the co-signer accepts anyone. The enclave never asks.

This is the exact "verification that fails open" shape: the switch that is
supposed to force `required` lives in a process that cannot observe the
condition it is switching on.

**Fix (chokepoint, two halves, both cheap).**

- Enclave side: `cosigner/server.py` already reports `attestation` on
  `GET /health`. Have `backend/custody/client.py` fetch `/health` once per
  process, cache it beside `_jwk_cache`, and raise `CustodyError` when
  `secrets.tee_required()` and the co-signer answers `dev-insecure`. Same
  refusal shape as the existing `TEE_REQUIRED but COSIGNER_CLIENT_CERT` check at
  `client.py:125`, which is the precedent.
- Co-signer side: give `dev-insecure` an expiry date in `allowlist.json` and
  make `Policy.mode()` assert on a date in the past, the same pattern
  `deploy/audit_ignores.toml` already uses for advisories. A mode that stays
  wrong forever because nobody re-read a JSON file is the failure here.

Also fill `quote_oid` and confirm `binding` against a live RA-TLS certificate
before the cutover — `attest.configured()` reports both, but only under
`required`, which is the mode this box is not in.

---

## 3. The enclave enforces no egress allowlist

**Category 5/8. Confirmed. Post-compromise reach.**

`backend/egress.py` is a list; the enforcement is entirely
`deploy/hetzner/hardening.conf` — `IPAddressDeny=any`, `IPAddressAllow=localhost`
and the four `HTTP(S)_PROXY` variables pointing at
`backend/daemons/egress_proxy.py`. None of that exists in
`deploy/phala/docker-compose.yml`: no proxy service, no proxy environment, no
network restriction. `tools/reachability.py` correctly does not ship the proxy,
since no role starts it.

So in the enclave, `mail` and `web` — both with `database/` mounted, both
holding an opened data key — have unrestricted outbound network. The control
that CLAUDE.md describes as "the machine's reachable set is exactly
`backend/egress.py`" is true of the box and false of the CVM, and nothing says
so.

**Fix.** Pick one and write it down:

- run the egress proxy as a fourth container on an internal-only compose network,
  put `mail` and `web` on that network with no default route, and set the proxy
  variables in their `environment:` blocks (this is a partition change: it
  changes `compose-hash`, which is the point); or
- accept the gap explicitly, state it in the compose header and in CLAUDE.md's
  `backend/egress.py` entry, and add a test that fails if anyone claims otherwise
  in product copy.

Doing nothing is the bad option, because the current text reads as though the
control applies everywhere.

---

## 4. Opening the audit log narrows `state/` and cuts off the push receiver

**Category 8. Confirmed by reading. Silent; symptom is "Gmail push stopped".**

`backend/audit.py:135` calls `paths.shared_dir(path.parent)` with the default
mode, which is `DIR_MODE_SHARED` (`2770`). `state/` is deliberately
`DIR_MODE_TRAVERSABLE` (`2771`, `backend/paths.py:120`) because the `hook` uid —
and on the box the billing uid — is not in `letterlock-data` and needs the
execute bit to reach its own spool file.

`chmod_if_owned` acts when the process owns the directory. The mail role owns
`/app/state` (seeded `chown 10001` in `flake.nix`), and the mail role opens the
audit log on every account mutation and every applied billing event. So the
first audit write after a boot silently drops `o+x` from `state/`, and
`gmail_hook_server` (uid 10003, `letterlock-wake` only) can no longer open
`state/wake.fifo` or `wake_queue.jsonl`. Every Gmail push is then dropped at the
receiver. Same mechanism on the box for `letterlock-hook` and
`letterlock-billing`.

**Fix (chokepoint).** `state/`'s mode has exactly one correct answer and
`paths.ensure_run_dir()` is it. Either call it from `audit.connect()`, or —
better, since this is a default that is wrong for one of the two directories it
serves — make `mode` a required positional argument of `paths.shared_dir()` so
no caller can inherit the wrong one. Two call sites to update
(`backend/accounts/account.py:241` passes shared, correctly).

Add a test that creates `state/`, calls `audit.connect()`, and asserts the mode
is still `0o2771`.

---

## 5. The measurement self-check is a no-op and the image reference is a mutable tag

**Category 8 (supply chain). Confirmed.**

Two halves of one gap:

- `tee_boot._assert_expected_measurement()` returns immediately when
  `EXPECTED_COMPOSE_HASH` is empty, and the compose sets
  `EXPECTED_COMPOSE_HASH: "${EXPECTED_COMPOSE_HASH:-}"` — empty unless someone
  remembers to provision it and to add the name to `allowed_envs`. As written
  the check is off by default and nothing reports that it is off. (It is
  advisory either way — the enclave is checking a value it hands itself — which
  the co-signer's allowlist comment already says. That is a reason to make it
  loud, not a reason to let it be silent.)
- `deploy/phala/docker-compose.yml` still carries `image: tee-email-bot:latest`
  in the `x-common` anchor. The comment under `mail` says a literal `@sha256`
  digest is required in production, `build_and_publish.sh --push` writes one,
  and `IMAGE_HASH.txt` records `<not pushed>` with a `STALE after feat/teespike
  merge` banner. Nothing fails if the file is deployed with the tag.

**Fix.**
- `_assert_expected_measurement`: when `secrets.tee_required()` and the variable
  is empty, print a `FAIL-CLOSED` line and return nonzero, like every other
  branch of the gate. An unset expected measurement inside a CVM is a
  provisioning gap, not a default.
- `tests/test_enclave_boundary.py`: assert the effective `image:` value matches
  `@sha256:[0-9a-f]{64}` and contains no `${`. That is the durable form of the
  comment that is already there.
- Regenerate `IMAGE_HASH.txt` before any push; it currently documents its own
  staleness.

Note in passing: the "This line is rewritten..." comment sits under `mail:`,
which has no `image:` line. The `sed` in `build_and_publish.sh` rewrites the
first `image:` in the file, which is the `x-common` anchor — correct behaviour,
misplaced comment.

---

## 6. Private keys are written world-readable, then chmodded, onto a 0777 tmpfs

**Category 8. Confirmed. Narrow window, single-process container — low, but the
fix is one line each.**

- `tee_boot._write_attestation_record()` (`backend/tee/tee_boot.py:49`) writes
  `ra_tls.key` with `write_text`, writes two more files, and only then chmods
  `0600` (line 64).
- `custody/client._client_identity()` (`backend/custody/client.py:156`) writes
  `cosigner_client.key` with `write_text` and chmods afterwards.

The target is `/app/attestation`, mounted `tmpfs` with `mode: 0777` in all three
service blocks. The compose comment justifies 0777 by "nothing else runs in
here to read it", which is true today and is a property of the container's
process list rather than of the code.

**Fix.** Write with the mode, not after it: `os.open(path, O_WRONLY|O_CREAT|
O_EXCL, 0o600)` (or `path.touch(mode=0o600)` before `write_text`). Then drop the
tmpfs to `mode: 0700` with `uid=` set per role, so the directory's mode stops
depending on the file's.

---

## 7. The `web` role is unreachable, and the obvious fix breaks audit origin

**Category 7. Confirmed for the compose file; the consequence is conditional.**

`web` publishes no port and `frontend/web_server.py:69` binds
`WEB_HOST` defaulting to `site.LOOPBACK`, so the product UI is not reachable
inside the CVM at all. Whoever notices will set `WEB_HOST=0.0.0.0` and publish
`8790`. At that point the peer is the docker bridge / dstack gateway, not
`127.0.0.1`, so `_source_ip()` (`frontend/web_server.py:1572`) correctly refuses
to read `X-Forwarded-For` — and every audit row records the gateway's address
instead of the browser's, permanently and silently.

Not forgeable (the code fails in the safe direction, which is why this is here
and not higher), but it is a detectability loss: `backend/audit.py` exists to
answer "who did this from where", and in the enclave it will answer with one
address for everyone.

**Fix.** `site.TRUSTED_PROXIES` is a frozenset literal. Make it derivable from
one env name (`LETTERLOCK_TRUSTED_PROXIES`), keep `upstream()`'s assert, and add
a second assert on the same fact: if the bind address is not in `LOOPBACK`, the
trusted-proxy set must be non-empty and must not be the loopback default. Then
set both variables in the `web` service block, where they are measured.

---

## 8. Invariants stated in comments but not tested

**Category 8. Preventive.**

`deploy/phala/docker-compose.yml`'s header names two rules that nothing
enforces:

- never bind-mount `/dstack/.host-shared` into a container (it holds the whole
  decrypted secret set);
- every interpolated name must appear in `allowed_envs` in `app-compose.json`
  (that file is not in this repository, so half the rule is unverifiable here —
  but the first half is one regex).

`tests/test_enclave_boundary.py` already parses the service blocks. Add:

- no service mounts anything under `/dstack/` except `/var/run/dstack.sock`;
- `hook` mounts no `dstack.sock` (present) **and** no secret file path;
- the set of `${...}` names interpolated in the file, printed by the test on
  failure, so the `allowed_envs` list can be diffed against it by hand at deploy
  time.

---

## 9. Retention notes (no action required, stated so the gap is on the record)

**Category 9. Confirmed, all three are accepted trades — worth writing down
because none of them is currently stated in one place.**

- `keyring.destroy()` crypto-shreds before `rmtree`, so an interrupted deletion
  leaves ciphertext. Correct. Inside the CVM the `database` volume is a docker
  named volume on the dstack encrypted disk, so `unlink` is not an erase; the
  shred is what makes that fine.
- `cosigner/retention.py` prunes `requests` only. `grants` — the wrap-once state
  — is never deleted, so a deleted account's opaque handle persists on the
  co-signer forever. Opaque and unlinkable without the enclave's manifest, which
  is the design; but it means "delete my account" does not empty every table.
- `backend/audit.py` keeps a departed user's address for `RETENTION_DAYS`, by
  design, and the prune only runs when something calls `record()`. In the
  enclave the mail role writes rows on every billing apply, so it does run —
  but an enclave whose mail role is down for longer than the retention period
  prunes nothing. A cron line beside the existing three in `flake.nix` would
  make that independent of traffic.
