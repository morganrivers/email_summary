# CLAUDE.md

Email drafting + daily summary system running on a Hetzner host
(`hezner.morganrivers.com`, app dir `/opt/email_summary`), managed by systemd.

## Deployment

The server has no git repo. Never `scp` individual files or edit remote files
in place — both will drift from git. Instead:

```bash
./deploy.sh              # rsync + systemd daemon-reload + restart services
DRY_RUN=1 ./deploy.sh    # preview only
```

`deploy.sh` (SSH key `~/.ssh/hezner`, user `root`) rsyncs the repo to
`root@hezner.morganrivers.com:/opt/email_summary/`, syncs the systemd units in
`deploy/hetzner/*.service` and `*.timer` to `/etc/systemd/system/`, syncs
`~/.system_files/prompt_for_email` to `/root/.system_files/`, then runs
`systemctl daemon-reload && systemctl restart email-daemon email-webhook`.

Caddy config (`deploy/hetzner/Caddyfile`) is not synced by `deploy.sh`; update
`/etc/caddy/Caddyfile` and reload Caddy manually if it changes.

The typical loop: edit → commit → `./deploy.sh`.

## Server-only files (never overwritten by deploy)

- `.env` — API keys, not in git.
- `state.json`, `wake.fifo`, `restart.flag`, `process_push.lock`, `push.log`
  — daemon runtime state.
- `node_modules/` — installed via `npm install` on the server.
- `venv/` — Python virtualenv at `/opt/email_summary/venv`.
- `.gmail-mcp/` — Gmail OAuth tokens.

If `package.json` changes, `ssh` in and run `npm install` in
`/opt/email_summary/` manually. Python deps live in `venv/`.

## Runtime paths

- `daemon_loop.py` — long-running FIFO listener run by the `email-daemon`
  systemd service (`Restart=always`). On wake, routes each fetched email
  through `manual_draft.is_bot_request()` and either
  `manual_draft.process_draft_request()` (bot-request path) or
  `draft_replies.process_emails()` (auto-reply path).
- `gmail_hook_server.py` — HTTPS webhook receiver run by the `email-webhook`
  systemd service, behind Caddy (`127.0.0.1:8787`). Verifies the Pub/Sub OIDC
  JWT and wakes the daemon via the FIFO.
- `email_summary.py` — daily summary run by the `email-summary.timer`
  (05:00 UTC): fetches unread + calendar, summarises, sends Telegram.
- `watch_register.mjs` — weekly Gmail `users.watch` renewal run by the
  `gmail-watch.timer`.

Code changes take effect when the systemd services restart, which `deploy.sh`
does via `systemctl restart`. The daemon also honors `restart.flag` (it exits
and `Restart=always` respawns it), but restarting the webhook requires a
service restart.

## Single sources of truth

Keep these centralized. If you need behavior that lives here, import — don't
copy.

- `llm_client.py` — DeepSeek client + `complete()`. Model, thinking mode,
  and reasoning effort all live here.
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
