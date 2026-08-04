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
`requirements.txt` triggers `venv/bin/pip install -r requirements.txt`,
`package.json` / `package-lock.json` trigger `npm install --omit=dev`. The spaCy
model `en_core_web_lg` remains a separate one-time install (see the comment in
`requirements.txt`).

Which units get deployed is derived from `deploy/hetzner/`: every `.service`
with an `[Install]` section plus every `.timer`. Adding a unit file is all it
takes to deploy it. Before restarting anything, `deploy/preflight.py` runs on the
box and checks, per unit, that its entry module imports and its configuration is
present — using the same code the service runs (`PolarBilling()`,
`session.secret_configured()`). A unit that fails is reported and left alone
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

- `.env` — API keys, not in git.
- `.gmail-mcp/` — Gmail OAuth tokens.
- `state/` — daemon runtime scratch: `state.json`, `wake.fifo`,
  `wake_queue.jsonl`, `wake_queue.lock`, `restart.flag`. Created on first write
  by `paths.ensure_run_dir()`.
- `database/` — multi-tenant account store (`database/accounts.json`: per-user
  identity, creds dirs, telegram targets, timezone, plan status) plus each
  user's `<id>/.gmail-mcp/credentials.json`. Holds PII + refresh tokens, so it
  is git-ignored and written 0600 inside a 0700 directory. A manifest is
  required; seed the owner once with `python -m backend.accounts.seed_owner`.
- `config/` — operator prompts pushed from `~/.system_files` (see above).
  `paths.config_file()` reads these, falling back to `~/.system_files` so a
  laptop checkout works unchanged.
- `node_modules/` — installed by deploy when the package manifests change.
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
  `node_env(account.creds_dir)` and delivering to `account.telegram`. Accounts
  with no linked chat are skipped.
- `watch_renew.py` — weekly per-account Gmail `users.watch` renewal run by the
  `gmail-watch.timer`; iterates every active account and drives the per-account
  `watch_register.mjs` worker under each account's creds dir.
- `frontend/web_server.py` — the product web UI run by the `letterlock-web`
  service, behind Caddy (`127.0.0.1:8790` on `APP_HOST`). Sign-in with Google,
  dashboard, settings, billing. The standalone `/onboard` flow it superseded was
  removed; its OAuth sequence now lives in `backend/onboarding/provisioning.py`.
  Telegram is linked by a round trip through the bot (`/settings/telegram/*`),
  never by typing a chat id.

Code changes take effect when the systemd services restart, which `deploy/deploy.sh`
does via `systemctl restart`. The daemon also honors `restart.flag` (it exits
and `Restart=always` respawns it), but restarting the webhook requires a
service restart.

## Single sources of truth

Keep these centralized. If you need behavior that lives here, import — don't
copy.

- `backend/site.py` — public hostnames (`APP_HOST` = the product,
  `API_HOST` = the Pub/Sub push + Polar webhook box), loopback ports, and every
  externally visible URL built from them (OAuth callbacks, Polar webhook, the
  Pub/Sub `aud`). Overridable from `.env` via `LETTERLOCK_HOST`,
  `LETTERLOCK_API_HOST`, `LETTERLOCK_ALIAS_HOSTS`.
  `deploy/render_caddyfile.py` renders the Caddy site blocks from it, so the
  proxy and the app cannot disagree about a host or a port.
- `backend/onboarding/provisioning.py` — the Google consent sequence: auth URL,
  code exchange, per-user creds custody, `register_account`, watch registration,
  checkout redirect. `handle_callback()` is the whole decision path, HTTP-free
  and directly tested. Any future sign-in surface imports this rather than
  reimplementing token custody.
- `llm_client.py` — DeepSeek client + `complete()`. Model, thinking mode,
  reasoning effort, and the masking boundary all live here. LangSmith tracing is
  off unless `LANGSMITH_TRACING=1`: it ships prompts to a third party.
- `backend/integrations/telegram.py` — `TelegramTarget`, sends, and chat
  linking. `send_telegram(msg, target)` always takes an explicit target;
  `operator_target()` (env) is only for box-level failures, never for a user's
  mail. There is deliberately no env fallback on the per-account path.
- `draft_replies.voice_profile_for(account)` — which voice profile applies. The
  operator's personal profile is reachable only through their own manifest
  entry; everyone else gets `backend/drafting/default_voice.md`.
- `agentic_drafter.untrusted()` — the fence put around anything that came from
  outside the account (email bodies, tool results) before it reaches the model,
  paired with `INJECTION_RULE` in the system prompt.
- `draft_replies.build_draft_payload()` — canonical payload shape for
  `create_draft.mjs`. All draft callers route through this.
- `draft_replies.submit_draft(payload, draft_id=None)` — sole subprocess
  boundary to `create_draft.mjs`. Pass `draft_id` to update in place.
- `draft_replies.gmail_thread_link()` — Gmail deep-link builder.
- `draft_replies.format_draft_line()` — Telegram notification line item
  (linked sender + subject, optional reason + trace url).

## Progressive drafts

`manual_draft.process_draft_request()` creates a placeholder Gmail draft
immediately, then overwrites it on every `agentic_drafter` iteration with
a status body (tools called + partial output + queued next tool), then
overwrites once more with the final reply. `create_draft.mjs` accepts an
optional `draftId` to make this work via `drafts.update`.
