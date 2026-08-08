# CLAUDE.md

Email drafting + daily summary system running on a Hetzner host
(`hezner.morganrivers.com`, app dir `/opt/letterlock`), managed by systemd.

## Deployment

The server has no git repo. Never `scp` individual files or edit remote files in
place — both drift from git. Instead:

```bash
./deploy/deploy.sh              # rsync + systemd daemon-reload + restart services
DRY_RUN=1 ./deploy/deploy.sh    # preview only
SERVICES="email-daemon.service" TIMERS="" ./deploy/deploy.sh   # subset
```

`deploy/deploy.sh` (SSH key `~/.ssh/hezner`, user `root`) rsyncs the repo root to
`root@hezner.morganrivers.com:/opt/letterlock/`, syncs `deploy/hetzner/*.service`
and `*.timer` to `/etc/systemd/system/`, syncs the operator prompts named in
`CONFIG_FILES` (`~/.system_files/prompt_for_email`, `voice-dna-email.md`) into
`/opt/letterlock/config/`, then reloads systemd and restarts what it deployed.

The sync is authoritative: `--delete-after` removes remote files the repo no
longer has, so `EXCLUDES` is the protected set and must stay in step with the
server-only files below. A changed `requirements.txt` triggers
`venv/bin/pip install -r requirements.txt`. No Node on the box: Gmail and
Calendar are called from Python.

Which units deploy is derived from `deploy/hetzner/`: every `.service` with an
`[Install]` section plus every `.timer`. `deploy/preflight.py` runs on the box
first and checks per unit that its entry module imports and its configuration is
present (through `backend/secrets.py`, the same code the service runs); a failing
unit is reported and left alone rather than restarted into a crash loop. After
the restart it verifies each unit is active and exits nonzero if not.

Nothing runs as root. The deploy creates the `letterlock` system user, chowns the
app directory, and installs `deploy/hetzner/hardening.conf` as
`/etc/systemd/system/<unit>.d/10-hardening.conf` for every unit it touches —
systemd has no include directive, so one file fans out to per-unit drop-ins. A
unit needing an exception says so in `deploy/hetzner/<unit>.d/*.conf`, numbered
above `10-hardening.conf`; exceptions live beside their unit rather than
loosening the common sandbox. The deploy deletes drop-ins the repo no longer has.

`cosigner.service.d/20-cosigner.conf` is the only one: the co-signer holds the
outer wrapping key and the DPoP key, so it must not share the app's uid. It runs
as `cosigner`, reads the source through `SupplementaryGroups=letterlock` (app dir
750; `database/`, `state/`, `config/`, `.env` are 700/600, so group membership
does not reach user data), with `ReadWritePaths=` emptied since it writes only to
`StateDirectory=cosigner`. The deploy derives accounts to create by reading
`User=` out of the drop-ins. Until the enclave moves to Phala this is separation
of privilege on one box, not separation of operator, and no product copy may say
otherwise.

Caddy config is not synced. `deploy/hetzner/Caddyfile` is generated from
`backend/site.py`, so change the host or port there and regenerate:

```bash
python -m deploy.render_caddyfile > deploy/hetzner/Caddyfile
scp deploy/hetzner/Caddyfile root@hezner.morganrivers.com:/tmp/Caddyfile.new
ssh root@hezner.morganrivers.com \
  'caddy validate --adapter caddyfile --config /tmp/Caddyfile.new \
   && install -m 0644 /tmp/Caddyfile.new /etc/caddy/Caddyfile && systemctl reload caddy'
```

Typical loop: edit → commit → `./deploy/deploy.sh`.

## Dependencies and advisories

`requirements.txt` is the only list of what ships, for the box and the measured
enclave image alike. `deploy/phala/pyproject.toml` is generated from it:

```bash
python -m deploy.render_pyproject      # rewrite the pyproject dependency array
(cd deploy/phala && uv lock)           # re-pin the lock uv2nix builds from
```

`tests/test_requirements.py` fails if the committed pyproject drifts.
`requirements-dev.txt` (pytest, pip-audit, uv) is the only other list, installed
on neither the box nor the image; the same test fails if one of its pins reaches
a shipped list. `deploy/requirements.py` owns parsing and name-stripping.

`python -m deploy.audit` says whether anything we ship has a known
vulnerability. It audits `deploy/phala/uv.lock`, not `requirements.txt`: the lock
is the full transitive closure. It runs from `tests/test_dependency_audit.py`
gated on `LETTERLOCK_AUDIT=1`, because a test that fails offline gets deleted
rather than debugged. An advisory with no fixed version goes in
`deploy/audit_ignores.toml` with an expiry date; an entry past its date fails the
audit exactly as the advisory did.

Three workflows, kept separate because they fail for different reasons and one
exit code for both trains you to ignore the one that matters:

- `tests.yml` — the suite on every push and PR, plus the `regenerate` job that
  re-renders the pyproject and re-locks on Dependabot's branch (Dependabot cannot
  know those files are generated, so without it every one of its PRs fails
  `tests/test_requirements.py`).
- `dependency-audit.yml` — daily, blocking. The pins do not change daily; the
  advisory database does.
- `dependency-latest.yml` — weekly, non-blocking. Direct dependencies unpinned,
  answering whether the next security bump will break the code.

`deploy/testenv.sh` builds the environment for all three (`locked` = the image's
closure, `latest` = the same distributions unpinned).

Dependabot is security-updates-only (`open-pull-requests-limit: 0`) and points at
`requirements.txt` alone. Never point it at the `uv` ecosystem: it would edit the
generated pyproject and the next render reverts its work.

The PII analyzer (Presidio + spaCy + `en_core_web_lg`) is commented out of
`requirements.txt` and off by default: ~1.6 GB resident per masking process, and
confidential VMs are priced by the GB. Uncomment the three pins and install the
model to switch it on; `pseudonymizer.analyzer_available()` detects it. pip never
uninstalls, so a box that already has it keeps it until the venv is rebuilt. The
image inherits the default, since a commented-out pin is not rendered.

## Server-only files (never overwritten or deleted by deploy)

Each has a matching `--exclude` in `deploy/deploy.sh`.

- `.env` — API keys, not in git: `DEEPSEEK_API_KEY`, and `NEARAI_API_KEY` for the
  confidential routes (one key serves both NEAR AI providers). Read once through
  `secrets.load()`. Inside the enclave this file must not exist; the same values
  arrive as injected environment.
- `.gmail-mcp/` — `gcp-oauth.keys.json`, the OAuth *app*'s client_id/secret. One
  app serves every user; no per-user token lives here. Read only through
  `gmail_gcal/oauth_app.py`, which prefers the injected
  `GOOGLE_OAUTH_CLIENT_ID`/`GOOGLE_OAUTH_CLIENT_SECRET` and refuses this file
  entirely under `TEE_REQUIRED`. The box's fallback, not the enclave's.
- `state/` — daemon scratch: `state.json`, `wake.fifo`, `wake_queue.jsonl`,
  `wake_queue.lock`, `restart.flag`. Created by `paths.ensure_run_dir()`.
- `database/` — multi-tenant account store. `database/accounts.json` is the
  manifest (identity, opaque handle, token file, telegram targets, timezone, plan
  status) and the only plaintext left: it maps a handle back to a person, and
  encrypting it per account would need the account list to find the account.
  Everything under `<id>/` is ciphertext — `dek.bin`, `token.bin`,
  `voice-dna.enc`, `personal-context.enc` — and opening any of it costs a
  co-signer round trip that is rate limited and logged. Git-ignored, 0600 inside
  0700, but the modes are not the isolation: all six units share the `letterlock`
  uid, so the key is. Seed the owner once with
  `python -m backend.accounts.seed_owner`, then have them sign in through
  `/auth/callback`.
- `config/` — operator prompts pushed from `~/.system_files`.
  `paths.config_file()` falls back to `~/.system_files` so a laptop checkout
  works unchanged.
- `venv/` — Python virtualenv at `/opt/letterlock/venv`.

## Runtime paths

- `daemon_loop.py` — FIFO listener, `email-daemon` service (`Restart=always`). On
  wake routes each email through `manual_draft.is_bot_request(email, account)` to
  either `manual_draft.process_draft_request()` or
  `draft_replies.process_emails()`. The bot alias is derived per account
  (`user+bot@…`), not a global constant.
- `gmail_hook_server.py` — HTTPS webhook, `email-webhook` service behind Caddy
  (`127.0.0.1:8787`). Verifies the Pub/Sub OIDC JWT and wakes the daemon.
- `email_summary.py` — daily summary, `email-summary.timer` (05:00 UTC). Sweeps
  every active account via `mailbox.fetch_daily(account)`, delivers to
  `account.telegram`, skips accounts with no linked chat.
- `watch_renew.py` — weekly per-account `users.watch` renewal, `gmail-watch.timer`.
- `frontend/web_server.py` — product web UI, `letterlock-web` service behind
  Caddy (`127.0.0.1:8790` on `APP_HOST`): sign-in, dashboard, voice DNA, personal
  info, settings, billing. `/voice` generates a profile on a background thread
  (`voice_dna.start()`, page polls by meta refresh); `/personal` is the second
  box (`personal_context`), kept apart because generating a profile overwrites
  the profile. Telegram is linked by a round trip through the bot
  (`/settings/telegram/*`), never by typing a chat id. The old `/onboard` flow was
  removed; its OAuth sequence lives in `backend/onboarding/provisioning.py`.
- `cosigner/server.py` — split-custody co-signer, `cosigner` service behind Caddy
  (`127.0.0.1:8791` on `COSIGNER_HOST`, the one site block demanding a client
  certificate). Holds the outer wrapping key and the DPoP signing key and no
  ciphertext, so compromising it alone reads no mail; the enclave holds the
  ciphertext and cannot strip the outer layer alone. A hard dependency by design:
  if it is down no mail is processed, and there is deliberately no bypass. Its
  two keys come from `LoadCredentialEncrypted=` (sealed to the host TPM),
  provisioned by hand once — see the header of `deploy/hetzner/cosigner.service`.
  Design: `docs/plan_token_custody.md`.
- `backend/daemons/egress_proxy.py` — egress allowlist proxy, `egress-proxy`
  service (`127.0.0.1:8792`, not behind Caddy). An HTTP CONNECT proxy and the
  only process with unrestricted network access; every other unit runs under
  `IPAddressDeny=any` / `IPAddressAllow=localhost` pointed here, so the machine's
  reachable set is exactly `backend/egress.py`. Runs as `egress`, its own
  account: the process holding the network must not be the one holding the API
  keys. Hard dependency with no bypass — a fallback to direct connections would
  silently turn the control off. Written in-repo rather than tinyproxy/squid
  because it faces an attacker with code execution and a memory-unsafe C parser
  is the wrong thing there.

Code changes take effect on service restart, which `deploy/deploy.sh` does. The
daemon also honors `restart.flag`; the webhook needs a real service restart.

## Single sources of truth

Keep these centralized. If you need behavior that lives here, import — don't copy.

- `backend/secrets.py` — how a secret reaches the process. `secrets.load()` is
  the only read of `.env` (idempotent; injected environment wins). The
  `*_configured()` checks are the only definition of "this value is present",
  answered by calling the same code the services call (`PolarBilling()`,
  `telegram.operator_target()`) and owning the variable name where presence is a
  lookup — `frontend/session.py` reads `SESSION_SECRET_ENV` and
  `SESSION_SECRET_PREVIOUS_ENV` from here, not the reverse. `tee_boot.run_gate()`
  and `deploy/preflight.py` both build on them, so the enclave's fail-closed set
  and the deploy's skip set cannot drift. `fingerprint()` names a secret in a log
  without printing it. Under `TEE_REQUIRED` no file is read at all;
  `volume_secrets()` is the one list of files whose mere presence fails the boot
  gate (`.env`, `oauth_app.keys_path()`), so the gate refuses exactly what the
  loaders refuse, and `google_oauth_configured()` answers through
  `oauth_app.load_keys()` so it cannot approve a source the reader rejects.
- `frontend/session.py` — the two signed cookies (session, OAuth state) and the
  keyring verifying them. Each is `kid:value:iat:mac`, the `kid` naming the
  signing key, so several keys are live at once and verification still has one
  key to try. That is what makes the secret rotatable: new value in
  `SESSION_SECRET`, outgoing one in `SESSION_SECRET_PREVIOUS`, restart, nobody
  signed out; only the current key mints, so the old drains as cookies re-issue.
  Drop `SESSION_SECRET_PREVIOUS` later to retire them; `SESSION_TTL` (30 days) is
  how long that takes by itself. The OAuth state inherits all of it, which is why
  a restart mid-consent is no longer a CSRF alarm.
- `backend/site.py` — public hostnames (`APP_HOST` = product, `API_HOST` =
  Pub/Sub push + Polar webhook), loopback ports, and every externally visible URL
  built from them. Overridable via `LETTERLOCK_HOST`, `LETTERLOCK_API_HOST`,
  `LETTERLOCK_ALIAS_HOSTS`. `deploy/render_caddyfile.py` renders the Caddy site
  blocks from it. `LOOPBACK` / `TRUSTED_PROXIES` / `upstream()` are the same fact
  for the peer: the only address whose `X-Forwarded-For` `web_server._source_ip()`
  reads, so `upstream()` asserts the address it renders is one the app trusts —
  drift means every audit row records the proxy instead of a browser.
  `COSIGNER_PORT` is re-exported from `cosigner/protocol.py`, not defined here.
- `backend/egress.py` — every hostname anything on this box may connect to, and
  the check that decides one connection. Derived, not typed: each entry comes
  from the module that already names the host (`llm_client.PROVIDERS`,
  `oauth_app`, `telegram.API_ROOT`, `polar_api`'s two bases, both TDX
  allowlists' `pccs_url`, `site.COSIGNER_HOST`). Exact matches only — a suffix
  rule for `near.ai` is what permits `evil.near.ai`. `GOOGLE_API_HOSTS` holds the
  one pair no constant of ours produces (googleapiclient reads them from bundled
  discovery documents); `tests/test_egress.py` reads those documents and fails if
  one is missing. Names only, no addresses, so no bare IP is reachable.
  This does not defend against prompt injection: the drafter's tools fetch no
  URLs. It is for the post-compromise case and for a dependency that phones home.
  `deploy/check_egress.py` proves it is on — `IPAddressDeny=` needs cgroup v2
  with BPF, and without it systemd logs a line and starts the unit anyway.
- `cosigner/` — imports nothing from `backend/` except the Telegram call in
  `alerts.py`, so it can move to its own box under its own operator; the
  dependency points the other way (`backend/site.py` and the custody client
  import `cosigner.protocol`, the wire contract). `keys.py` is the only place the
  outer key is derived or the DPoP proof signed, and the only written-down
  rotation procedure: a master key per version, `master_name()` owning credential
  file names, `known_versions()` derived from which credentials actually load so
  retiring one fails closed, `/rewrap` moving a record between versions without
  opening it. `policy.py` is the only place a request is decided and the same
  call writes its audit row, so the limit enforced and the log cannot disagree —
  including `_sweep_refusal`, which meters how many *different* accounts were
  unwrapped in a window (bulk exfiltration is one request per account, which
  every per-account rule reads as normal) and counts across
  `policy.KEY_RELEASING` so a sweep cannot split itself across both unwrap paths.
  `audit.py` keeps `grants` (wrap-once state, never deleted) apart from
  `requests` (the log, every reader windowed), which is what lets `retention.py`
  prune; that module is the only code in the package that deletes a row, runs on
  a thread inside the co-signer (a second process would VACUUM under the one
  answering requests), and derives its floor from `policy.longest_window()`.
  `attest.py` holds this box's measurement allowlist — the point of the second
  machine, since the enclave cannot edit it. `cosigner/__init__.py` states the
  four invariants; read them before refactoring anything in that package.
  An account is named by an opaque handle the enclave minted, never an address
  (`account.new_handle`); nothing here parses it, which is why
  `tests/test_handle_boundary.py` reads the tree for a call passing the wrong one
  — an account id would work at every layer, derive a different key, and surface
  later as a record that will not open. The mapping back to a person exists only
  in the enclave's manifest; `python -m backend.accounts.whois <handle>` reads it,
  deliberately a command rather than a route.
- `backend/onboarding/provisioning.py` — the Google consent sequence: auth URL
  (PKCE + `dpop_jkt`), code exchange, `tokens.take_custody`, `register_account`,
  watch registration, checkout redirect. `handle_callback()` is the whole
  decision path, HTTP-free and directly tested; any future sign-in surface
  imports this rather than reimplementing token custody. The exchange is in
  Python because Google binds the refresh token to the co-signer's DPoP key at
  that one request. Google's screen lets a user untick a permission, so
  `oauth_app.REQUIRED_SCOPES` is the set the code calls and `missing_scopes()`
  the one comparison, applied twice: in `handle_callback()` off the redirect's
  `scope` (refusing before a code is exchanged or anything wrapped) and in
  `exchange_code()` off the token response (the grant itself), before anything is
  stored. Absent counts as granting nothing. Identity scopes are deliberately not
  required — the address comes from the Gmail profile and `split_name()` falls
  back.
- `backend/custody/` — split custody of everything an account owns
  (docs/plan_token_custody.md Track I, docs/plan_security_hardening.md Track G).
  One random 32-byte data key per account. `keyring.py` owns it: minting, the
  record, the TTL cache, and `read_encrypted`/`write_encrypted`, the one path
  every per-account file goes through (token, voice profile, personal context).
  `wrapping.py` is the inner AES-GCM layer from the dstack KMS `app_secret`;
  `client.py` the sole network boundary to the co-signer; `tokens.py` the only
  path from a stored record to a usable access token; `rotate.py` moves every
  record onto a new co-signer key without opening one.
  Layer order is the guarantee: ours inside, theirs outside. Reversed, the
  co-signer's unwrap would yield a usable key and it would become the one box
  that can read every mailbox. No bypass, ever: a co-signer that is down means no
  mail is processed, the availability cost accepted for the confidentiality gain.
  The data key is what makes rotation 32 bytes an account and makes
  `keyring.destroy()` a destruction rather than an unlink (a backup taken
  beforehand stays ciphertext); neither is possible when the key is a function of
  a salt. Two ways out, metered apart on purpose: `release_for_refresh()` is the
  mail path, never cached, one round trip per token refresh, which is what makes
  the per-account rate limit a limit on mail access; `dek_for()` is the document
  path, cached for `DEK_TTL`, a security parameter and not a tuning knob — it
  must stay under `cosigner.policy.DISTINCT_WINDOW_SECONDS` or a slow sweep hides
  behind the cache. Nothing here takes a bare account id: `keyring.identify()`
  returns the pair (id names the directory, handle names the account everywhere
  else), because a function accepting either would accept the wrong one and
  derive a different key without raising.
- `backend/integrations/gmail_gcal/` — the only code talking to Google's mail and
  calendar APIs: `oauth_app.py` (keys, scopes, endpoints), `google_client.py`
  (credentials + per-thread service cache), `gmail_api.py`, `calendar_api.py`,
  `mailbox.py` (the two fetch shapes), `drafts.py` (RFC822 + create/update).
  Credentials carry no refresh token at all, so every acquisition goes through
  `tokens.refresh_handler_for()`. One consent covers both APIs, so credentials
  and the service cache belong to `google_client` rather than either API module,
  and `forget_services()` lives there since one cache is what a re-consent
  invalidates.
  Calendar reads take a `calendar_id` (the daily summary reads a community
  calendar too). `create_event()` does not: the calendar is
  `calendar_api.WRITE_CALENDAR`, no attendees, `sendUpdates="none"` — what gets
  written is decided by a model reading outside mail, so a `calendar_id`
  parameter is one a future caller could fill from that model. Text fields are
  capped by `MAX_SUMMARY`/`MAX_LOCATION`/`MAX_DESCRIPTION`, asserted at that
  boundary and truncated to the same constants in
  `schedule_from_sent._normalize()`, so a long draft is an ugly event rather than
  an operator alert.
  Pinning the calendar answers which calendar, not who reads it, so
  `create_event()` reads the ACL first (`write_calendar_audience()`) and refuses
  when anyone but the owner can read event contents: scope `default` or `domain`
  at role `reader`/`writer`/`owner`. `freeBusyReader` is allowed — it exposes
  that a span is taken and no field of the event. This is what
  `calendar.acls.readonly` is for, read-only on purpose: the code refusing to
  write to a public calendar must not be able to make one private and proceed.
  Cached per account for `SHARING_TTL`. It fails closed even when the question
  cannot be asked: a token minted before that scope answers 403, as does an
  outage, and `CalendarSharingUnknown` is a subclass so every caller refusing on
  one refuses on the other while the user still gets the right remedy. Existing
  users lose scheduling from sent mail until they sign in again at `/auth/login`;
  `tokens.take_custody()` reuses the account's data key so a returning user works.
  `tests/test_calendar_boundary.py` enforces all of it by reading the tree: no
  `calendarId` outside `calendar_api` and none that is not `WRITE_CALENDAR`, no
  `calendars`/`calendarList` call, no ACL read outside `calendar_api` and no ACL
  write at all, no calendar write tool in `tool_executors.TOOL_REGISTRY`, and a
  model-supplied `calendar_id` dropped on the read path.
  Gmail's search takes one opaque string with no parameterized form and no escape
  character, so `find_thread_by_from_subject()` puts exactly one header value in
  a query — the sender, and only after `ADDRESS_QUERY_RE` checks it into the
  shape of a bare address; anything else is refused and the caller drafts on a
  new thread. The subject never enters the query: candidates come back as
  metadata and `comparable_subject()` matches them here, which is also tighter
  than `subject:"…"`. `strip_reply_prefixes()` strips repeatedly because a
  forwarded reply carries more than one prefix; `manual_draft.reply_subject()`
  uses the same helper.
- `llm_client.py` — the inference client + `complete()`: provider catalog
  (`PROVIDERS`), model, thinking mode, reasoning effort, masking boundary. Three
  providers ship: `deepseek` (default) and `nearai-glm` / `nearai-gpt-oss`, both
  on NEAR AI's *per-model* completions endpoints
  (`glm-5-2.completions.near.ai`, `gpt-oss-120b.completions.near.ai`) rather than
  the `cloud-api.near.ai` gateway — only a per-model endpoint's attestation can
  say which model it serves. A provider whose key is absent is not offered in
  Settings. `make_client(account)` is the only constructor, `resolve(account)` the
  only chooser; a stated preference is honored or it raises, never substituted.
  `confidential=True` costs something: the `Provider` constructor asserts such a
  provider names an attestation endpoint, and `make_client()` returns nothing
  until `inference_attestation.require()` passes. Masking applies on every
  provider. Every call is `/v1/chat/completions`, never `/v1/responses` (stateful,
  persists content server-side); `tests/test_llm_boundary.py` reads the tree as an
  AST and fails if anything reaches for it or calls `chat.completions.create`
  elsewhere. LangSmith tracing is off unless `LANGSMITH_TRACING=1`.
  `ProviderUnavailable` names the ordinary failure that is not a bug: 401/402/403
  mean the provider keeps refusing until a human tops up a balance or fixes a key,
  unlike 429 and 5xx which propagate untouched. It alerts through
  `telegram.notify_error` once per provider per six hours, not once per email. It
  still does not fall back.
- `backend/tee/quote_policy.py` — the five checks deciding whether a TDX quote is
  one we authorized: parse and is-TDX, report_data binding, measurements against
  an allowlist, signature chain to the Intel root through PCCS collateral, TCB
  status and advisories. Two callers verify in opposite directions and must not
  drift: `cosigner/attest.py` (inbound RA-TLS client cert) and
  `inference_attestation.py` (outbound provider). `Policy.match()` takes a `scope`
  so one allowlist file serves several things without one entry authorizing
  another; `mr_td` may never be null. `fetch_collateral()` exists because
  `dcap_qvl.get_collateral` is a pyo3 builtin that grabs the running loop when
  called, so `asyncio.run(...)` reads as a refused attestation rather than a
  broken one.
- `backend/integrations/inference_attestation.py` — whether the enclave about to
  read a user's mail is one we authorized, and the only thing making
  `confidential=True` mean anything. Fetches the provider's report with a fresh
  nonce and requires three bindings: report_data carries the response signing
  address, report_data carries our nonce (so a captured report cannot be
  replayed), and the enclave's stated `model_name` matches the model requested
  (so a silent reroute fails even with valid signatures).
  `inference_allowlist.json` is the committed pin list, so authorizing an image
  is a reviewed diff. `rt_mr3` moves whenever NEAR redeploys the bootstrap and a
  drift fails closed; re-pin with
  `python -m backend.integrations.inference_attestation <provider>`, read the
  diff, commit. `deploy/preflight.py` calls `configured()` so an unpinned image
  is reported at deploy time.
  **RTMR3 does not measure the model server.** NEAR's TD boots a bootstrap
  compose; the manager brings model containers up and down afterwards without
  RTMR3 moving. `ComposeLog` closes that: the endpoint publishes a second quote
  over `actions_hash || nonce`, SHA-256 of the manager's action log as compact
  sorted-key JSON. The hash is recomputed from the actions, so appending a line
  fails; and because the quote signs the published hash, re-hashing a forged log
  fails the binding instead. Replaying the log gives every compose brought up and
  not since brought down, each with its `file_sha256`, and every one must appear
  in the allowlist's `composes` rows — pinned by file content, not filename. That
  set includes housekeeping and models left from earlier deployments.
  **One hostname is a pool.** `glm-5-2.completions.near.ai` fronts two CVMs with
  different compose histories sharing a signing address, so the verdict cache
  keys on `Report.identity()` (signing address + instance id + actions_hash);
  otherwise a load balancer is the bypass. Pinning is therefore a sampling job —
  `test_live_pins_cover_the_whole_instance_pool` fetches repeatedly.
  Still unclosed: a compose names images by digest, and digest → reviewed source
  needs the build's Sigstore/SLSA provenance (`cosign verify-attestation`). Until
  then the pins say which bytes ran, not what was in them, and NEAR is both image
  publisher and machine operator.
- `backend/audit.py` — the web tier's record of what a person changed: one SQLite
  row per sign-in, setting, document edit, plan flip and deletion, under `state/`
  at 0600. Deliberately not the co-signer's log and sharing no code with it,
  because `cosigner/` must not learn who its users are; the duplicated connection
  boilerplate is the price of that boundary. Rows are written by the account
  mutators in `backend/accounts/account.py`, not the route handlers, so a second
  caller of a manifest writer cannot forget to log. Request origin is ambient:
  `frontend/web_server.py` wraps each request in `audit.request_context()`, so
  nine mutators do not grow a parameter, and anything outside a request
  (background voice generation, billing webhook, seed) writes a row with no
  origin. Nothing in a row can carry content: `detail` takes short name tokens
  checked against `TOKEN` (`timezone`, `chars:2048`, `provider:deepseek`).
  `RETENTION_DAYS` is the only bound on how long a departed user's address stays
  — deleting an account does not delete its rows, since the row saying it was
  deleted is the one most worth keeping — and the prune rides on `record()`
  behind `PRUNE_INTERVAL` with `secure_delete` on.
- `backend/integrations/telegram.py` — `TelegramTarget`, sends, chat linking.
  `send_telegram(msg, target)` always takes an explicit target;
  `operator_target()` (env) is only for box-level failures, never a user's mail.
  Deliberately no env fallback on the per-account path.
- `draft_replies.drafting_instructions()` — everything the drafter is told about
  an account before it sees an email: voice profile, then personal information.
  One assembly, so the auto-reply and forwarded-email paths cannot hand the model
  different briefs.
- `backend/drafting/voice_dna.py` — every voice profile question: where a profile
  lives, which one applies (`resolve()`), and how one is generated from the
  account's own sent mail. The operator's profile is reachable only through their
  manifest entry; everyone else gets `backend/drafting/default_voice.md` until
  they generate or write their own, which lands encrypted in
  `database/<id>/voice-dna.enc` (never `config/`, which the deploy overwrites).
  `load()` decides which pointer it holds by comparing against `profile_path()`:
  the account's own document is decrypted, the operator's `config/` file is read
  in the clear, since encrypting a file rsync replaces with plaintext is theatre.
  `DEFAULT_CONSTRAINTS` is written into a document by `with_constraints()` when
  it is first created, never appended at prompt time, so a rule the user edits or
  deletes is a rule the drafter stops following. The em-dash ban is deliberately
  not one of them, because it rejects finished drafts rather than asking: it is
  the `ban_dashes` Settings switch, read only by
  `agentic_drafter.dashes_banned(account)`, consulted in `draft()` (which also
  puts the PUNCTUATION RULE in the prompt), `draft_replies` and `manual_draft`.
  `account.set_voice()` is the sole writer of the manifest pointer.
- `backend/drafting/personal_context.py` — the second document: facts the owner
  writes about themselves, read into every draft prompt beneath the voice
  profile. Separate because `voice_dna.generate()` overwrites that one wholesale.
  The path is derived (`database/<id>/personal-context.enc`) with no manifest
  pointer, which is why `account._owned_paths()` owns the account's directory
  rather than a list of manifest keys: a key list would have left a deleted
  user's personal information on disk.
- `agentic_drafter.Fence` — the fence around anything from outside the account
  (email bodies, tool results) before it reaches the model. One fence per model
  conversation: `new_fence()` mints it, `wrap()` fences the content, and `rule`
  is the sentence naming those delimiters that goes in the system message. The
  two travel together because either alone is nothing — a rule quoting markers
  the prompt does not carry describes no text, and markers no rule explains are
  punctuation. `draft()` takes the caller's fence rather than making its own for
  exactly that reason, and asserts it was given one.

  The delimiters carry a per-conversation nonce (`new_nonce()`, 16 uppercase
  alphanumerics, never leading with a digit) and `wrap()` removes the nonce from
  the content before fencing it. Both halves are needed. The delimiters used to
  be two fixed strings in this file, so the closing marker was published in this
  repository and a sender who wrote it in an email body put the rest of their
  message outside the fence: the entire mitigation, defeated by a literal anyone
  could read. The nonce makes that unguessable and the stripping makes a lucky
  guess useless, which is the stronger of the two. The alphabet is not
  cosmetic — the assembled prompt goes through `pseudonymizer`, and an all-digit
  nonce is what `_PHONE_RUN` matches, so it would come back as a predictable
  `[PHONE_NUMBER_1]`. `tests/test_prompt_fence.py` pins all of it, including
  that both masking modes leave the nonce alone and that nothing outside
  `agentic_drafter` builds a marker by hand; `harness.stable_fence_nonces()` is
  what lets the golden files hold a prompt whose delimiters are random.
- `backend/masking/pseudonymizer.py` — masking runs in one of two modes and
  `new_state()` decides which. With the Presidio + spaCy analyzer installed it
  does NER; without it, or for an account that switched it off,
  `_pseudonymize_patterns()` covers the same text with secret, email and phone
  regexes. Both modes run the deterministic layers first (`identity.mask_user()`,
  `_scrub_contacts()`, `_mask_names()`) and both allocate tags through
  `_tag_value()`, so a restore works either way. `analyzer_available()` answers by
  module lookup and never imports (`import presidio_analyzer` drags in ~470 MB
  before a model loads; `en_core_web_lg` is another ~1.1 GB). Measured recall is
  96% with the analyzer and 74% without, the whole gap being PERSON. The stated
  preference is stored even where it cannot run.
- `billing.PLAN_PRICE_EUR` — the quoted price, rendered as `web_server.PRICE`.
  Landing copy, pricing page, comparison table, sign-up button and billing table
  each held their own literal and drifted from the Polar product. Polar is what
  charges, so changing the product there means changing this constant too.
- `PolarBilling.resolve_account()` — which local account a Polar object belongs
  to, for webhook, reconcile poller and checkout return alike. It resolves in one
  direction only, which is what lets the checkout return use it as an ownership
  test on an id the browser handed it: `confirm_checkout()` refuses a checkout
  that does not resolve back to the signed-in account, before linking a customer
  or flipping a plan. Without it any signed-in user who learned a paid checkout
  id took the subscription. `checkout_url()` stamps
  `billing.CHECKOUT_ACCOUNT_KEY` into the session metadata to make the binding
  exact; `customer_email` is buyer-editable, so it is the fallback, not the test.
- `draft_replies.build_draft_payload()` — canonical draft payload shape.
- `draft_replies.submit_draft(account, payload, draft_id=None)` — sole boundary to
  `gmail_gcal.drafts`. Pass `draft_id` to update in place.
- `draft_replies.gmail_thread_link()` — Gmail deep-link builder.
- `draft_replies.format_draft_line()` — Telegram notification line item.
- `tools/render_brand.py` — the brand mark (envelope + padlock) and every icon cut
  from it; geometry and the two brand colours live there. Run
  `python -m tools.render_brand` to rewrite `frontend/static/`. The PNGs and
  `.ico` are committed, so the server never renders at runtime and Pillow is not
  a deploy dependency. `frontend/web_server.STATIC_TYPES` is the allow-list of
  what `/static/` serves; add an asset to both.

## Progressive drafts

`manual_draft.process_draft_request()` creates a placeholder Gmail draft
immediately, overwrites it on every `agentic_drafter` iteration with a status
body (tools called + partial output + queued next tool), then overwrites once
more with the final reply. `drafts.submit()` takes an optional `draft_id` to make
this work via `drafts.update`.
