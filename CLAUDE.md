# CLAUDE.md

Email drafting + daily summary system running on a Hetzner host
(`hezner.morganrivers.com`, app dir `/opt/letterlock`), managed by systemd.

## Deployment

The server has no git repo. Never `scp` individual files or edit remote files
in place — both will drift from git. Instead:

```bash
./deploy/deploy.sh              # rsync + systemd daemon-reload + restart services
DRY_RUN=1 ./deploy/deploy.sh    # preview only
```

`deploy/deploy.sh` (SSH key `~/.ssh/hezner`, user `root`) rsyncs the repo root
(its own parent directory) to `root@hezner.morganrivers.com:/opt/letterlock/`,
syncs the systemd units in `deploy/hetzner/*.service` and `*.timer` to
`/etc/systemd/system/`, syncs the operator prompts named in `CONFIG_FILES`
(`~/.system_files/prompt_for_email`, `voice-dna-email.md`) into
`/opt/letterlock/config/`, then reloads systemd and restarts what it deployed.

The repo sync is authoritative: `--delete-after` removes remote files the repo
no longer has, so a rename or a restructure leaves no stale copy behind. The
`EXCLUDES` list in the script is therefore the protected set (rsync never
deletes an excluded path) and must stay in step with the server-only files
below.

Dependencies are installed automatically when their manifests change in a push:
`requirements.txt` triggers `venv/bin/pip install -r requirements.txt`. There is
no Node on the box: Gmail and Calendar are called from Python, so there is one
language and one dependency tree.

`requirements.txt` is also the only dependency list. The enclave image's
`deploy/phala/pyproject.toml` is generated from it, so adding a pin is:

```bash
python -m deploy.render_pyproject      # rewrite the pyproject dependency array
(cd deploy/phala && uv lock)           # re-pin the lock uv2nix builds from
```

`tests/test_requirements.py` fails if the committed pyproject drifts.

The PII analyzer (Presidio + spaCy + `en_core_web_lg`) is commented out of
`requirements.txt` and off by default, because it costs ~1.6 GB resident per
masking process and the confidential VMs this runs on are priced by the GB.
Uncomment the three pins and install the model to switch it on; nothing else
changes, since `pseudonymizer.analyzer_available()` detects it. Note that pip
never uninstalls: a box that already has it keeps it until the venv is rebuilt.
The enclave image inherits the same default, because a commented-out pin is one
the renderer above does not emit. Putting the analyzer in the image needs the
model too, which is a URL rather than a pin; `requirements.txt` says how.

Which units get deployed is derived from `deploy/hetzner/`: every `.service`
with an `[Install]` section plus every `.timer`. Adding a unit file is all it
takes to deploy it. Before restarting anything, `deploy/preflight.py` runs on the
box and checks, per unit, that its entry module imports and its configuration is
present — through `backend/secrets.py`, which answers with the same code the
service runs (`PolarBilling()`). A unit that fails is reported and left alone
rather than restarted into a crash loop, so an unprovisioned service never fails
the whole deploy. After the restart the script verifies each unit is actually
active and exits nonzero if not.

Nothing runs as root. The deploy creates the `letterlock` system user, chowns
the app directory to it, and installs `deploy/hetzner/hardening.conf` as
`/etc/systemd/system/<unit>.d/10-hardening.conf` for every unit it touches. That
file is the only copy of the sandbox settings (`User=`, `ProtectSystem=strict`,
`NoNewPrivileges`, `UMask=0077`, …); systemd has no include directive, so the
deploy fans one file out to per-unit drop-ins rather than repeating the block in
seven `.service` files.

A unit that must differ from that common sandbox says so in
`deploy/hetzner/<unit>.d/*.conf`, numbered above `10-hardening.conf` so it wins.
One unit's exception belongs beside that unit rather than in a loosened
`hardening.conf` every other unit then inherits. The deploy installs those
drop-ins and deletes any the repo no longer has, so a setting that still runs is
always a setting you can read in git.

`cosigner.service.d/20-cosigner.conf` is the only one so far, and it exists
because the co-signer must not share the application's account: it holds the
outer wrapping key and the DPoP key, and `User=letterlock` would put them inside
the blast radius of the web UI and the mail daemon. It runs as `cosigner`,
reaches the source read-only through `SupplementaryGroups=letterlock` (the app
directory is 750; `database/`, `state/`, `config/` and `.env` are 700/600, so
group membership does not reach user data), and gets `ReadWritePaths=` reset to
empty since everything it writes lives in `StateDirectory=cosigner`. The deploy
derives the accounts it must create by reading `User=` back out of the drop-ins,
so the name is defined in one file. Until the enclave moves to Phala this is
separation of privilege on one box, not separation of operator, and no product
copy may say otherwise.

`SERVICES` / `TIMERS` override the derived lists when you want to touch a subset:

```bash
SERVICES="email-daemon.service" TIMERS="" ./deploy/deploy.sh
```

Caddy config is not synced by `deploy/deploy.sh`. `deploy/hetzner/Caddyfile` is
generated from `backend/site.py` (see "Single sources of truth"), so change the
host or port there and regenerate rather than editing the Caddyfile:

```bash
python -m deploy.render_caddyfile > deploy/hetzner/Caddyfile
scp deploy/hetzner/Caddyfile root@hezner.morganrivers.com:/tmp/Caddyfile.new
ssh root@hezner.morganrivers.com \
  'caddy validate --adapter caddyfile --config /tmp/Caddyfile.new \
   && install -m 0644 /tmp/Caddyfile.new /etc/caddy/Caddyfile && systemctl reload caddy'
```

The typical loop: edit → commit → `./deploy/deploy.sh`.

## Server-only files (never overwritten or deleted by deploy)

Each entry here has a matching `--exclude` in `deploy/deploy.sh`; that exclusion
is what protects it from `--delete-after`.

- `.env` — API keys, not in git. `DEEPSEEK_API_KEY` and, to offer the
  confidential routes, `NEARAI_API_KEY` (see `llm_client.PROVIDERS`; one key
  serves both NEAR AI providers). Read once,
  through `secrets.load()`. Inside the enclave this file must not exist at all;
  the same values arrive as injected environment.
- `.gmail-mcp/` — `gcp-oauth.keys.json`, the OAuth *app*'s client_id and
  client_secret. One app serves every user; no per-user token lives here any
  more (see `database/`). Read only through
  `backend/integrations/gmail_gcal/oauth_app.py`, which takes the injected
  `GOOGLE_OAUTH_CLIENT_ID` / `GOOGLE_OAUTH_CLIENT_SECRET` pair first and refuses
  this file entirely under `TEE_REQUIRED`. It is the box's fallback, not the
  enclave's: the CVM mounts no such directory and the boot gate will not start
  with one present.
- `state/` — daemon runtime scratch: `state.json`, `wake.fifo`,
  `wake_queue.jsonl`, `wake_queue.lock`, `restart.flag`. Created on first write
  by `paths.ensure_run_dir()`.
- `database/` — multi-tenant account store (`database/accounts.json`: per-user
  identity, token file, telegram targets, timezone, plan status) plus each
  user's `<id>/token.bin`, the nested-wrapped refresh token. Holds PII, so it is
  git-ignored and written 0600 inside a 0700 directory; the token records are
  useless to anyone who reads them without the co-signer. A manifest is
  required; seed the owner once with `python -m backend.accounts.seed_owner`,
  then have them sign in through `/auth/callback` to grant Gmail access.
- `config/` — operator prompts pushed from `~/.system_files` (see above).
  `paths.config_file()` reads these, falling back to `~/.system_files` so a
  laptop checkout works unchanged.
- `venv/` — Python virtualenv at `/opt/letterlock/venv`.

## Runtime paths

- `daemon_loop.py` — long-running FIFO listener run by the `email-daemon`
  systemd service (`Restart=always`). On wake, routes each fetched email
  through `manual_draft.is_bot_request(email, account)` and either
  `manual_draft.process_draft_request()` (bot-request path) or
  `draft_replies.process_emails()` (auto-reply path). The bot alias is derived
  per account (`user+bot@…`), not a global constant.
- `gmail_hook_server.py` — HTTPS webhook receiver run by the `email-webhook`
  systemd service, behind Caddy (`127.0.0.1:8787`). Verifies the Pub/Sub OIDC
  JWT and wakes the daemon via the FIFO.
- `email_summary.py` — daily summary run by the `email-summary.timer`
  (05:00 UTC). Sweeps every active account, fetching each user's mailbox through
  `mailbox.fetch_daily(account)` and delivering to `account.telegram`. Accounts
  with no linked chat are skipped.
- `watch_renew.py` — weekly per-account Gmail `users.watch` renewal run by the
  `gmail-watch.timer`; iterates every active account and calls
  `gmail_api.register_watch()` for each.
- `frontend/web_server.py` — the product web UI run by the `letterlock-web`
  service, behind Caddy (`127.0.0.1:8790` on `APP_HOST`). Sign-in with Google,
  dashboard, voice DNA, settings, billing. `/voice` generates a profile from the
  user's sent mail on a background thread (`voice_dna.start()`, page polls by
  meta refresh) and shows it as editable plaintext.
  The standalone `/onboard` flow it superseded was
  removed; its OAuth sequence now lives in `backend/onboarding/provisioning.py`.
  Telegram is linked by a round trip through the bot (`/settings/telegram/*`),
  never by typing a chat id.
- `cosigner/server.py` — the split-custody co-signer run by the `cosigner`
  service, behind Caddy (`127.0.0.1:8791` on `COSIGNER_HOST`, the one site block
  that demands a client certificate). Holds the outer wrapping key and the DPoP
  signing key and no ciphertext at all, so compromising it alone reads no mail;
  the enclave holds the ciphertext and cannot strip the outer layer alone. It is
  a hard dependency by design: if it is down, no mail is processed for anyone,
  and there is deliberately no bypass. Its two keys come from
  `LoadCredentialEncrypted=` (sealed to the host TPM) and must be provisioned by
  hand once — see the header of `deploy/hetzner/cosigner.service`. Design and
  sequencing: `docs/plan_token_custody.md`.

Code changes take effect when the systemd services restart, which `deploy/deploy.sh`
does via `systemctl restart`. The daemon also honors `restart.flag` (it exits
and `Restart=always` respawns it), but restarting the webhook requires a
service restart.

## Single sources of truth

Keep these centralized. If you need behavior that lives here, import — don't
copy.

- `backend/secrets.py` — how a secret reaches the process. `secrets.load()` is
  the only read of `.env` (idempotent, and injected environment always wins over
  the file), and the `*_configured()` checks are the only definition of "this
  value is present", answered by calling the same code the services call
  (`PolarBilling()`, `telegram.operator_target()`) wherever presence is a
  judgement rather than a lookup, and owning the variable name itself where it
  is not: `frontend/session.py` reads `SESSION_SECRET_ENV` from here rather than
  the reverse, so nothing in `backend/` reaches up into `frontend/` to ask. `tee_boot.run_gate()` and
  `deploy/preflight.py` both build on them, so the enclave's fail-closed set and
  the deploy's skip set cannot drift apart. `fingerprint()` is the third: how a
  secret is named in a log, so a startup line can say which value the process
  captured without printing it, and a `.env` edited under a running service is
  visible rather than silent — the old gate listed four names and
  so booted happily without `SESSION_SECRET` or the Polar keys. Under
  `TEE_REQUIRED` no file is read at all: secrets are injected post-attestation,
  the compose file mounts no `.env` and no `.gmail-mcp`, and `volume_secrets()`
  is the one list of files whose mere presence fails the boot gate — it names
  `.env` and `oauth_app.keys_path()`, so the gate refuses exactly what the
  loaders refuse. `google_oauth_configured()` is in `REQUIRED` and answers by
  calling `oauth_app.load_keys()`, which is what decides between the injected
  pair and the volume file, so the gate cannot approve a source the reader
  rejects.
- `backend/site.py` — public hostnames (`APP_HOST` = the product,
  `API_HOST` = the Pub/Sub push + Polar webhook box), loopback ports, and every
  externally visible URL built from them (OAuth callbacks, Polar webhook, the
  Pub/Sub `aud`). Overridable from `.env` via `LETTERLOCK_HOST`,
  `LETTERLOCK_API_HOST`, `LETTERLOCK_ALIAS_HOSTS`.
  `deploy/render_caddyfile.py` renders the Caddy site blocks from it, so the
  proxy and the app cannot disagree about a host or a port. `COSIGNER_PORT` is
  the exception it re-exports rather than defines: it belongs to
  `cosigner/protocol.py`, next to the server that binds it.
- `cosigner/` — the co-signer, which imports nothing from `backend/` except the
  single Telegram seam in `alerts.py`, so it can be moved to its own box under
  its own operator. The dependency points the other way: `backend/site.py` and
  the enclave's custody client import `cosigner.protocol`, the wire contract.
  `keys.py` is the only place the outer key is derived or the DPoP proof signed;
  `policy.py` is the only place a request is decided, and the same call writes
  its audit row, so the rate limit it enforced and the log cannot disagree;
  `attest.py` holds this box's own measurement allowlist, which is the point of
  the second machine — the enclave cannot edit it, so a new `compose_hash` must
  be authorized here *and* in the AppAuth contract before deploying, or every
  unwrap fails. `cosigner/__init__.py` states the four invariants the whole
  design rests on; read them before refactoring anything in that package.
- `backend/onboarding/provisioning.py` — the Google consent sequence: auth URL
  (PKCE + `dpop_jkt`), code exchange, `tokens.take_custody`, `register_account`,
  watch registration, checkout redirect. `handle_callback()` is the whole
  decision path, HTTP-free and directly tested. Any future sign-in surface
  imports this rather than reimplementing token custody. The exchange is in
  Python because Google binds the refresh token to the co-signer's DPoP key at
  that one request and nowhere else.
- `backend/custody/` — split custody of every Gmail refresh token
  (docs/plan_token_custody.md Track I). `wrapping.py` owns the inner AES-GCM
  layer, keyed by HKDF from the dstack KMS `app_secret`; `client.py` is the sole
  network boundary to the co-signer, which holds the outer wrapping key and the
  DPoP private key and stores nothing; `tokens.py` is the only path from a
  stored record to a usable access token. The layer order is the guarantee:
  ours inside, theirs outside. Reversed, the co-signer's unwrap would yield
  plaintext and it would become the single box that can read every mailbox.
  There is no bypass and must never be one: a co-signer that is down means no
  mail is processed, which is the availability cost the design accepts in
  exchange for removing a confidentiality risk.
- `backend/integrations/gmail_gcal/` — the only code that talks to Google's
  mail and calendar APIs. `oauth_app.py` (client keys, scopes, endpoints),
  `gmail_api.py` (credentials + messages/threads/history/watch),
  `calendar_api.py`, `mailbox.py` (the two fetch shapes), `drafts.py` (RFC822
  assembly + create/update). Credentials are constructed with no refresh token
  at all, so every acquisition goes through `tokens.refresh_handler_for()`;
  putting one in that object would defeat split custody for as long as the
  object lives.
- `llm_client.py` — the inference client + `complete()`. The provider catalog
  (`PROVIDERS`), model, thinking mode, reasoning effort, and the masking
  boundary all live here. Three providers ship: `deepseek` (direct, the
  default), and `nearai-glm` / `nearai-gpt-oss`, both keyed by `NEARAI_API_KEY`
  and both reaching NEAR AI's *per-model* direct completions endpoints
  (`glm-5-2.completions.near.ai`, `gpt-oss-120b.completions.near.ai`) rather
  than the `cloud-api.near.ai` gateway — a per-model endpoint is the only shape
  whose attestation can say which model it serves, and the gateway's
  attestation endpoint is authenticated and answers for the fleet. A provider
  whose key is absent from `.env` is not offered in Settings and cannot be
  selected. `make_client(account)` is the only constructor and `resolve(account)`
  the only chooser; a stated per-account preference is honored or it raises,
  never substituted, because standing in a different provider would send that
  user's mail somewhere they did not agree to. `confidential=True` now costs
  something: the `Provider` constructor asserts such a provider names an
  attestation endpoint, and `make_client()` will not return a client until
  `inference_attestation.require()` has passed. Masking applies on every
  provider. Every call is `/v1/chat/completions` and none is `/v1/responses`,
  which is stateful and persists content server-side; `tests/test_llm_boundary.py`
  reads the tree as an AST and fails if anything reaches for it, or if
  `chat.completions.create` is called anywhere but here. LangSmith tracing is
  off unless `LANGSMITH_TRACING=1`: it ships prompts to a third party, outside
  whatever enclave the chosen provider runs in.
- `backend/tee/quote_policy.py` — the five checks that decide whether a TDX
  quote is one we authorized: parse and is-TDX, report_data binding,
  measurements against an allowlist, signature chain to the Intel root through
  PCCS collateral, TCB status and advisories. Two callers verify quotes in
  opposite directions and must not drift: `cosigner/attest.py` checks an inbound
  RA-TLS client certificate, `backend/integrations/inference_attestation.py`
  checks an outbound inference provider. Each supplies only what is its own —
  where the quote came from, and what report_data must bind. `Policy.match()`
  takes a `scope` so one allowlist file can serve several verified things
  without an entry for one silently authorizing another; `mr_td` may never be
  null. `fetch_collateral()` exists because `dcap_qvl.get_collateral` is a pyo3
  builtin that grabs the running loop when *called*, so `asyncio.run(get_...())`
  raises "no running event loop" every time and reads as a refused attestation
  rather than a broken one.
- `backend/integrations/inference_attestation.py` — whether the enclave about to
  read a user's mail is one we authorized, and the only thing that makes
  `confidential=True` mean anything. Fetches the provider's report with a nonce
  we generated seconds ago and requires three bindings: report_data carries the
  response signing address (so the key that signs completions is the key the
  quote vouches for), report_data carries our nonce (so a captured report from a
  previously-good image cannot be replayed), and the enclave's stated
  `model_name` matches the model the provider asks for (so a silent reroute to
  another model fails even though every signature checks out). Verdicts cache on
  the signing address, which changes when the enclave reboots, and a reboot is
  when the measurement can change. `backend/integrations/inference_allowlist.json`
  is the committed pin list, so authorizing an image is a reviewed diff.
  `rt_mr3` moves whenever NEAR redeploys the bootstrap — NEAR runs several
  images behind one hostname, so expect to pin more than one per model — and a
  drift fails closed. Re-pin with
  `python -m backend.integrations.inference_attestation <provider>`, read the
  diff, commit. `deploy/preflight.py` calls `configured()` so an unpinned image
  is reported at deploy time rather than by every draft failing.

  **RTMR3 does not measure the model server.** NEAR's TD boots a bootstrap
  compose (compose-manager, certbot, an otel collector); the manager brings
  model containers up and down afterwards, from separate files, without RTMR3
  moving. So the measurement pins the launcher, not what is serving tokens.
  `ComposeLog` closes that: the endpoint publishes a second quote over
  `actions_hash || nonce`, where `actions_hash` is SHA-256 of the manager's
  action log as compact JSON with sorted keys. The hash is *recomputed* from the
  actions rather than read, so appending a line fails; and because the quote
  signs the published hash, re-hashing a forged log fails the binding instead,
  which is the stronger of the two refusals. Replaying the log gives every
  compose brought up and not since brought down, each with its `file_sha256`,
  and every one must appear in the allowlist's `composes` rows — pinned by file
  content, not filename. That set includes housekeeping and models left from
  earlier deployments, because they ran in the same TD.

  Still unclosed above this: a compose names container images by digest, and
  digest → reviewed source needs the build's Sigstore/SLSA provenance
  (`cosign verify-attestation`). Until that is checked, the pins say which bytes
  ran, not what was in them, and NEAR is both the image publisher and the
  machine operator.
- `backend/integrations/telegram.py` — `TelegramTarget`, sends, and chat
  linking. `send_telegram(msg, target)` always takes an explicit target;
  `operator_target()` (env) is only for box-level failures, never for a user's
  mail. There is deliberately no env fallback on the per-account path.
- `backend/drafting/voice_dna.py` — every voice profile question: where a
  profile lives, which one applies (`resolve()`, called by
  `draft_replies.voice_profile_for()`), and how one is generated from the
  account's own sent mail. The operator's personal profile is reachable only
  through their own manifest entry; everyone else gets
  `backend/drafting/default_voice.md` until they generate or write their own,
  which lands in `database/<id>/voice-dna.md` (never in `config/`, which the
  deploy overwrites). `DEFAULT_CONSTRAINTS` is the Constraints section a profile
  starts with (the em-dash ban among them), written into the document by
  `with_constraints()` when one is first created, never appended at prompt time:
  `resolve()` hands the drafter exactly what the /voice box shows, so a rule the
  user edits or deletes is a rule the drafter stops following. That includes the
  em-dash rejection, which `agentic_drafter.dashes_banned()` gates on the
  instructions it was actually given, in `draft()`, `draft_replies` and
  `manual_draft` alike. `account.set_voice()` is the sole writer of the manifest
  pointer.
- `agentic_drafter.untrusted()` — the fence put around anything that came from
  outside the account (email bodies, tool results) before it reaches the model,
  paired with `INJECTION_RULE` in the system prompt.
- `backend/masking/pseudonymizer.py` — masking runs in one of two modes and
  `new_state()` is where that is decided. With the Presidio + spaCy analyzer
  installed it does NER; without it, or for an account that switched it off in
  Settings, `_pseudonymize_patterns()` covers the same text with the secret,
  email and phone regexes. Both modes run the deterministic layers first
  (`identity.mask_user()`, `_scrub_contacts()`, `_mask_names()`) and both
  allocate tags through `_tag_value()`, so a restore works either way.
  `analyzer_available()` answers by module lookup and never imports:
  `import presidio_analyzer` drags spaCy in at ~470 MB before a model loads,
  and `en_core_web_lg` is another ~1.1 GB at first use, which is what makes the
  mode worth choosing on a small box. Measured recall on the public corpus is
  96% with the analyzer and 74% without, the whole gap being PERSON. The
  account's stated preference is stored even where it cannot run, so installing
  the model later restores the behaviour without touching the manifest.
- `billing.PLAN_PRICE_EUR` — the quoted price, rendered as
  `web_server.PRICE`. The landing copy, pricing page, comparison table, sign-up
  button and billing table each held their own literal and drifted from the
  Polar product, quoting €20 for a €25 subscription. Polar is what actually
  charges, so changing the product there means changing this constant too.
- `draft_replies.build_draft_payload()` — canonical draft payload shape. All
  draft callers route through this.
- `draft_replies.submit_draft(account, payload, draft_id=None)` — sole boundary
  to `gmail_gcal.drafts`. Pass `draft_id` to update in place.
- `draft_replies.gmail_thread_link()` — Gmail deep-link builder.
- `draft_replies.format_draft_line()` — Telegram notification line item
  (linked sender + subject, optional reason + trace url).
- `tools/render_brand.py` — the brand mark (envelope + padlock) and every icon
  cut from it. Geometry and the two brand colours live there; run
  `python -m tools.render_brand` to rewrite `frontend/static/`. The generated
  PNGs and the `.ico` are committed, so the server never renders at runtime and
  Pillow is not a deploy dependency. `frontend/web_server.STATIC_TYPES` is the
  allow-list of what `/static/` will serve; add an asset to both.
- `requirements.txt` — the one dependency list, for the box and for the measured
  enclave image alike. `deploy/requirements.py` parses it and
  `deploy/render_pyproject.py` renders `deploy/phala/pyproject.toml` from it, so
  a pin cannot be present on Hetzner and absent from the image. Maintained
  separately they had already drifted: the image carried presidio and spaCy,
  which are off by default because they do not fit a 2 GB confidential VM, and
  lacked `standardwebhooks` and `certifi`.

## Progressive drafts

`manual_draft.process_draft_request()` creates a placeholder Gmail draft
immediately, then overwrites it on every `agentic_drafter` iteration with
a status body (tools called + partial output + queued next tool), then
overwrites once more with the final reply. `drafts.submit()` takes an optional
`draft_id` to make this work via `drafts.update`.
