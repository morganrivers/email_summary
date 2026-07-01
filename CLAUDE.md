# CLAUDE.md

Email drafting + daily summary system running on NearlyFreeSpeech.

## Deployment

The server has no git repo. Never `scp` individual files or edit remote files
in place — both will drift from git. Instead:

```bash
./deploy.sh              # rsync + arm daemon restart
DRY_RUN=1 ./deploy.sh    # preview only
```

`deploy.sh` rsyncs the repo to
`morganrivers_morganrivers@ssh.nyc1.nearlyfreespeech.net:/home/protected/email_summary/`,
syncs `~/.system_files/prompt_for_email` to `/home/private/.system_files/`,
and touches `restart.flag` so the daemon reloads on next wake.

The typical loop: edit → commit → `./deploy.sh`.

## Server-only files (never overwritten by deploy)

- `.env`, `.env.bak` — API keys, not in git.
- `state.json`, `wake.fifo`, `restart.flag`, `process_push.lock`, `push.log`
  — daemon runtime state.
- `node_modules/` — installed via `npm install` on the server.

If `package.json` changes, `ssh` in and run `npm install` in
`/home/protected/email_summary/` manually.

## Runtime paths

- `daemon_loop.py` — long-running FIFO listener supervised by NFS. On wake,
  routes each fetched email through `manual_draft.is_bot_request()` and
  either `manual_draft.process_draft_request()` (bot-request path) or
  `draft_replies.process_emails()` (auto-reply path).
- `process_push.py` — fresh per-webhook process spawned by
  `/home/public/gmail-hook.php`. Same routing as `daemon_loop`.
- `email_summary.py` — daily cron: fetches unread + calendar, summarises,
  sends Telegram.

Python code changes only take effect after the daemon reloads
(`restart.flag` handles this). `.mjs` files and per-webhook scripts pick up
new code on their next invocation.

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
