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

Five units name their own account. `cosigner.service.d/20-cosigner.conf`: the
co-signer holds the outer wrapping key and the DPoP key, so it must not share the
app's uid. `egress-proxy.service.d/20-egress-proxy.conf`: the process holding the
network must not be the one holding the API keys. Both run with
`ReadWritePaths=` emptied and reach the source through
`SupplementaryGroups=letterlock` alone (app dir 750), which is why the account
store and `.env` are **not** that group — see `backend/paths.py`.

`letterlock-web.service.d/20-web.conf` is the third and the newest.
`frontend/web_server.py` parses HTTP from the open internet, and while it ran as
`letterlock` a parsing bug in it read every account's `database/<id>/` and could
ask the co-signer to unwrap any of them: compromise of the web tier was
compromise of every mailbox. It now runs as `letterlock-web` with
`SupplementaryGroups=letterlock letterlock-data letterlock-secrets`, writing only
`database/` and `state/`. What makes that more than a change of file owner is
what the account cannot reach: `token.bin` is written mail-uid-only at 0600, and
the two operations needing a Google token happen in the daemon over
`backend/custody/handoff.py`. Still reachable and stated so nobody reads more
into it: `database/accounts.json` is writable there, so a compromised web tier
can still edit its own settings and its plan. It can no longer move the telegram
target, which was the one field that reached mail content — see
`backend/accounts/chat_link.py`.

The two webhooks are the fourth and fifth, and they are the cheap ones: both
parse HTTP from the open internet and neither needs an account's data.
`email-webhook.service.d` runs `letterlock-hook` in `letterlock letterlock-wake`
— no `database/` at all, since the receiver spools the address Google names and
the daemon resolves it. `billing-webhook.service.d` runs `letterlock-billing` in
`letterlock letterlock-billing-queue letterlock-billing-secrets`: it verifies the
Polar signature, spools the event for the daemon to apply, and so writes neither
the manifest nor anything else under `database/`. It reads `.env.billing` (the
webhook signing secret alone) and not `.env`, so a compromise there does not
hold `SESSION_SECRET` and cannot mint a login cookie.

Four groups, because four different sets of units share four different things:
`letterlock-data` (`database/`, `state/`), `letterlock-secrets` (`.env`),
`letterlock-wake` (the FIFO and wake spool — writing there starts a drafting
pass against a named account and spends that account's co-signer budget, so the
web and billing uids are kept out) and `letterlock-billing-queue` (the billing
spool). `state/` is `2771` rather than `2770`: four uids open a file in it and
are deliberately not all in one group, so traversal is open and each file's own
mode is the grant. `database/` does not get that bit, since who has an account
is itself worth keeping.

The deploy derives accounts to create by reading `User=` out of the drop-ins, and
group membership by reading `SupplementaryGroups=` out of the same file, so the
unit is the statement of which accounts reach user data. Until the enclave moves
to Phala this is separation of privilege on one box, not separation of operator,
and no product copy may say otherwise.

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
`requirements-dev.txt` (pytest, pip-audit, uv, flake8, isort) is the only other
list, installed on neither the box nor the image; the same test fails if one of
its pins reaches a shipped list. `deploy/requirements.py` owns parsing and
name-stripping.

flake8 and isort run from `tests/test_lint.py`, configured in `setup.cfg`, over
the packages `tools/reachability.py` names — a linter in a contributing guide is
a linter nobody runs. pyflakes is not pinned beside flake8 because it *is*
flake8's engine, and two pins for one analyzer is two versions that can disagree
about what a warning is. There is no formatter: `black` would reflow the tree in
one commit and bury every diff under it.

bandit runs from the same module and asks the third question: is this call one
of the known-dangerous ones (`yaml.load`, `verify=False`, `shell=True`, an
insecure hash, a request with no timeout). It reads no `setup.cfg`, so its one
piece of configuration is `test_lint.SKIPS`, a check id to the reason it is
wrong here every time — `B101` above all, since asserts in this tree are the
control rather than a note about one and `runtime_guard` already refuses to
start under `-O`. Anything not in that list is a `# nosec <id>  # reason` on the
line, the way `# noqa` is already used; there are four. It scans the shipped
packages and not `tests/`, where fake credentials and swallowed exceptions are
the point.

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

## How the enclave is split

Four containers, one per role, and four images — one per role, each carrying
only the code that role's entry points reach. Not four processes under one uid,
and no longer one shared image either.
`deploy/phala/docker-compose.yml` names a role per service (`mail`, `web`,
`hook`, `egress`) and a distinct image per service
(`tee-email-bot-{mail,web,hook,egress}`),
`flake.nix` bakes the four accounts and the two shared groups
(`letterlock-data`, `letterlock-wake`) into `/etc/passwd` and `/etc/group` under
the same names `backend/paths.py` resolves, so one piece of code sets modes on
the box and in every image. TDX answers the host operator; it does nothing about
a bug in our own code, which is what this answers. The per-role image split adds
one more thing it answers: the code that reads mail is not even present in the
container the open internet posts to (`tests/test_image_manifest.py` pins the
receiver's image against the custody and inference modules), so a bug in the
receiver has no custody stack in its address space to reach for — belt to the
uid/group/secret suspenders, not a replacement for them.

`egress` is the newest and is the box's `egress-proxy.service` in here: same
module, same allowlist, its own uid and no group at all, no volume, no
guest-agent socket and so no gate. What makes it enforcement rather than
configuration is the pair of compose networks. `inner` is `internal: true`, so
docker installs no route off the host for it; `mail` is on it alone and reaches
the internet through the proxy or not at all. `web` and `hook` are on `edge`
too, because a published port on an internal-only network never receives
forwarded ingress and both of them have to be reached from outside the CVM — so
for those two the allowlist is configuration, and saying otherwise in product
copy is the thing to refuse. Closing it for them means an ingress container in
front of them holding no data, which is what Caddy is on the box and is not in
this repository. `web` publishes 8790 and binds `0.0.0.0`; the cost of that is
in `backend/site.py` below.

The compose file is the partition and not merely its description. dstack
decrypts `.encrypted-env` to the guest filesystem, `app-compose.service` reads
it with `EnvironmentFile=` and `app-compose.sh` runs `docker compose up` with no
`--env-file`, so the full secret set lives in the compose *process* environment
and a container gets exactly what its own `environment:` block interpolates.
Since that file's hash is the dstack `compose-hash` measured into RTMR3, the
partition is attested: move `SESSION_SECRET` to the mail container and
`cosigner/attest.py` stops accepting the client certificate. Two rules follow —
never bind-mount `/dstack/.host-shared` (it holds the whole decrypted set), and
every interpolated name must also be in `allowed_envs` in `app-compose.json`.
Both are now tested rather than only stated: `tests/test_enclave_boundary.py`
refuses that mount, refuses any host path but the guest-agent socket, refuses
`privileged`/`cap_add`/`network_mode`, and holds the list of interpolated names
so adding one fails a test whose message is what gets pasted into
`allowed_envs`. `EXPECTED_COMPOSE_HASH` is interpolated and must be set:
`tee_boot` refuses a boot that cannot say which compose it is supposed to be.

`hook` gets no `database/` and no guest-agent socket, and so runs no attestation
gate: that socket is unauthenticated and `GetKey` takes a caller-supplied
derivation path, so anything able to open it derives the app's sealing key
whatever uid it is. `web` does need it — `open_dek` and the co-signer client
cert are both a document render away — so its isolation is the box's:
`token.bin` at 0600 to the mail uid. Membership is spelled as `group_add:`
because a numeric `user:` skips the `/etc/group` lookup a username triggers.
`tests/test_enclave_boundary.py` pins all of it, and there is deliberately no
role that starts everything.

No role is a Polar receiver, so entitlement inside the enclave is exactly two
things: `confirm_checkout()` in `web`, which settles the buyer on the return
page synchronously, and the 3-hourly `billing_poller` reconcile in `mail`'s
crontab. The reconcile is in the mail role because it writes `plan_status` and
that is the role that writes the manifest; on the box the same sweep is a
`.timer` and merely a safety net, here it is the only thing a renewal or a
cancellation travels through. Adding a receiver container would need a fourth
account, the billing spool group, its own slice of the compose environment and
public ingress to a port — a partition change, and one nobody should make by
adding a service block alone.

`web` carries no inference key. Which providers Settings offers is decided by
whether their keys are present, and answering that yes/no question was the only
reason that process held two live keys; `handoff.providers()` asks the mail role
and gets catalog names back, never a key, cached for the process lifetime since
a key cannot change under a running one. `llm_client.available_provider_names()`
and `providers_named()` are the two halves. The cost is that `/settings` returns
503 while the mail role is down, in both directions: the POST validates the
submitted provider against the same answer, so an outage refuses the save rather
than accepting a value nothing checked.

## What the enclave image carries

`deploy/phala/image_files.nix` is the file list **per role** — a
`{ mail; web; hook; egress; }` attrset — and `flake.nix` builds one image per role
copying exactly that role's list. Generated, like the pyproject and the
Caddyfile:

```bash
python -m deploy.render_image_manifest          # rewrite the per-role lists
python -m deploy.render_image_manifest --check  # exit 1 if it is stale
```

`tests/test_image_manifest.py` fails on drift, so a new import that pulls a new
module into a role's image is caught there rather than in a CVM.

Derived from what actually starts, per role: `tools/reachability.py` walks
imports from each role's `python -m` entry points, so a module ships into a
container because something *that container starts* imports it — mail from the
daemon plus its crontab and gate, web from the web server plus the gate, hook
from the receiver alone, egress from the proxy alone.
`render_image_manifest.ROLE_ROOTS` is that partition (the flake's `case` cannot
be one grep), asserted to union to `reachability.enclave_roots()` so a
`python -m` added to the flake without a home fails the render. The reachability
walk counts function-local imports the same as top-level ones, because a lazy
import can still execute and the image must carry what could run; that is why
cutting a role's reach means moving code off its import graph, not deferring the
import (see `backend/secrets_checks.py`). It replaced a filter over file
extensions that was wrong both ways — it shipped `cosigner/` whole (the outer key
derivation, the request policy, the audit store) plus the billing webhook and
poller and `tools/` into an image that starts none of them, and shipped no data
file at all, because `.py`-or-`.css` matches neither `default_voice.md` nor
`inference_allowlist.json` nor a favicon. Only the co-signer's wire contract
(`cosigner/protocol.py`) belongs in any enclave image; a test asserts that, per
role.

The receiver (`hook`) is the payoff: its image is 11 modules — the JWT verifier,
the wake spool, paths/secrets-core/site and the wire contract — and carries none
of the inference client, Telegram, billing or custody code the mail role's
imports reach. A test pins that absence.

`egress` is the counter-example and is stated here so nobody reads the split as
more than it is. Its image is 39 files, not 11: `backend/egress.py` derives the
allowlist from the modules that already name the hosts, and `calendar_public`
reaches `account`, which reaches the co-signer client, `secrets_checks`, billing
and the inference client. Those edges execute — the proxy really does build the
allowlist at startup — so it is a description of the process, not a manifest bug.
It still holds no key, because the compose hands it `TEE_REQUIRED` and
`EGRESS_PROXY_BIND` and nothing else. What it does not carry is the drafting
stack, the Gmail and Calendar clients and `custody.tokens`, and
`tests/test_image_manifest.py` pins that pair: the proxy ships into exactly one
image and reads no mailbox from it. Shrinking the rest of that fan-out is
outstanding work.

That test is also why `backend/egress.py` asks `find_spec` before reading the
co-signer's allowlist for its PCCS host: a plain `from cosigner import attest`
is an import edge, and the edge would drag the co-signer's allowlist reader into
the image the moment the enclave started running the proxy.

Two lists in that module cannot be derived and carry a reason each.
`EXTRA_MODULES` is commands nothing starts that must still be there because
their data is only there, each tagged with the role that holds the data
(`accounts.whois`, `custody.rotate` — both `mail`). `DATA_FILES` is what a
module reads at runtime; a data file ships into a role's image when that role
reaches its reader, and the renderer asserts each exists.

`python -m tools.reachability --coverage <cov.json>` is the report behind it,
and answers the question coverage alone cannot: unreachable (nothing calls it)
and untested (something calls it and no test does) need opposite responses, and
a coverage-only pruner deletes working code the moment a test errors during
collection. It classifies against four root sets — the systemd units, the flake
entry points, the hand-run commands, the suite — and never deletes anything.

## Server-only files (never overwritten or deleted by deploy)

Each has a matching `--exclude` in `deploy/deploy.sh`.

- `.env` — API keys, not in git: `DEEPSEEK_API_KEY`, and `NEARAI_API_KEY` for the
  confidential routes (one key serves both NEAR AI providers). Read once through
  `secrets.load()`. Inside the enclave this file must not exist; the same values
  arrive as injected environment.
- `.env.billing` — `POLAR_WEBHOOK_SECRET` (and its `_SANDBOX` twin), and nothing
  else. Split out of `.env` so the unit verifying Polar signatures does not also
  hold `SESSION_SECRET` and the inference keys; `secrets.secret_files()` is the
  ordered list `load()` reads, each best-effort, so a process entitled to one
  file and not the other gets what it is entitled to. The Polar API token stays
  in `.env`: the receiver no longer calls Polar's API. Moving the value is a
  manual step, and until it moves the receiver has no secret and
  `deploy/preflight.py` reports the unit rather than restarting it.
- `.env.alerts` — `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`, and nothing else.
  No Python reads it: `cosigner.service.d/20-cosigner.conf` takes it as
  `EnvironmentFile=`, which systemd reads as root before dropping to that unit's
  account, so the co-signer gets an alert channel without getting `.env` or the
  group that opens it. Before this the unit was in `letterlock` alone, so
  `TELEGRAM_BOT_TOKEN` was unset and every refused unwrap alerted nobody. The
  `-` prefix means a box without the file still boots, since a co-signer that
  refuses to start stops all mail. Create it by hand with those two values;
  `chmod 600` is the deploy's job.
- `.gmail-mcp/` — `gcp-oauth.keys.json`, the OAuth *app*'s client_id/secret. One
  app serves every user; no per-user token lives here. Read only through
  `gmail_gcal/oauth_app.py`, which prefers the injected
  `GOOGLE_OAUTH_CLIENT_ID`/`GOOGLE_OAUTH_CLIENT_SECRET` and refuses this file
  entirely under `TEE_REQUIRED`. The box's fallback, not the enclave's.
- `state/` — daemon scratch: `state.json`, `wake.fifo`, `wake_queue.jsonl`,
  `wake_queue.lock`, `billing_queue.jsonl`, `billing_queue.lock`, `restart.flag`.
  Created by `paths.ensure_run_dir()`.
- `database/` — multi-tenant account store. `database/accounts.json` is the
  manifest (identity, opaque handle, token file, telegram targets, timezone, plan
  status) and the only plaintext left: it maps a handle back to a person, and
  encrypting it per account would need the account list to find the account.
  Everything under `<id>/` is ciphertext — `dek.bin`, `token.bin`,
  `voice-dna.enc`, `personal-context.enc` — and opening any of it costs a
  co-signer round trip that is rate limited and logged. Git-ignored, and the
  modes are now part of the isolation rather than decoration: `letterlock-data`
  is setgid on the directories and holds exactly the mail uid and the web uid, so
  `cosigner` and `egress` (in `letterlock` only) reach none of it, and `token.bin`
  is 0600 to the mail uid alone so the web tier cannot read the one file its data
  key would open. `backend/paths.py` owns all of it. Seed the owner once with
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
  (`user+bot@…`), not a global constant. Also runs `handoff_server.start()` on a
  thread: this loop is serial by design, so the work the web tier hands over
  cannot wait behind a drafting pass. Also calls `process_billing()` each pass,
  which is where a spooled Polar event is applied.
- `gmail_hook_server.py` — HTTPS webhook, `email-webhook` service behind Caddy
  (`127.0.0.1:8787`). Verifies the Pub/Sub OIDC JWT, spools the address on
  `wake_queue` and pokes the FIFO. It does not resolve the address: that reads
  the manifest, and this process holds none of it.
- `backend/spool.py` — the one append-and-drain file protocol, under one lock,
  behind both `daemons/wake_queue.py` and `billing/billing_queue.py`. Each spool
  names its own group, since waking the daemon and settling a subscription are
  different capabilities.
- `billing_queue.py` — between the Polar receiver and the daemon. The receiver
  used to flip `plan_status` itself, which made a signature verifier a writer of
  the manifest. Two costs, both deliberate: Polar is acked on spool rather than
  on apply, and activation lands within `WAKE_POLL_SECONDS` instead of instantly
  (`confirm_checkout()` already settles the buyer watching the return page,
  synchronously and independent of this path).
  Acking early means nothing upstream resends, so a failed event is put back
  with its attempt count (`retry()`, `MAX_ATTEMPTS`) and the drop after that
  alerts rather than logs — the alert is on the drop and not the attempts, or a
  timed-out Polar call pages someone every five minutes. Under that sits the
  3-hourly `billing-poller` reconcile, reading entitlement from Polar rather
  than from an event body. What it re-derives is *subscription status*, so a
  lost `subscription.*` event heals within one sweep; an `order.paid` carrying
  no `subscription_id` is the one grant it cannot re-derive, and `apply_event()`
  logs that rather than refusing it. The sweep visits customers Polar names, so
  an account Polar never heard of (the seeded owner) is never touched by it.
- `email_summary.py` — daily summary, `email-summary.timer` (05:00 UTC). Sweeps
  every active account via `mailbox.fetch_daily(account)`, delivers to
  `account.telegram`, skips accounts with no linked chat.
- `watch_renew.py` — weekly per-account `users.watch` renewal, `gmail-watch.timer`.
- `frontend/web_server.py` — product web UI, `letterlock-web` service behind
  Caddy (`127.0.0.1:8790` on `APP_HOST`): sign-in, dashboard, voice DNA, personal
  info, settings, billing. Runs as its own uid; `/voice` generation, the consent
  URL and the OAuth callback are handed to the daemon over
  `backend/custody/handoff.py` (page still polls by meta refresh, the job now
  lives in the daemon's memory); `/personal` is the second
  box (`personal_context`), kept apart because generating a profile overwrites
  the profile. Telegram is linked and unlinked by a round trip through the bot
  (`/settings/telegram/start` for either direction, then `/confirm`), never by
  typing a chat id and never decided here. The old `/onboard` flow was
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

## Asserts and refusals

An `assert` states an invariant that is a programmer error if false. Anything
validating a value that crossed a trust boundary is an explicit `raise`, because
it is not a bug to catch in testing, it is a hostile or malformed input to
refuse in production. Concretely: an argument handed in by our own caller stays
an assert (`assert handle and inner`); a value that came back from Google, the
co-signer, the KMS, a web form, a model, or a file on disk raises
(`raise CustodyError(...)`). The types each module refuses with are
`account.InvalidAccountData`, `pseudonymizer.MaskingFailed`,
`quote_policy.AllowlistInvalid`, `keyring.DataKeyExists`,
`wrapping.CustodyError` and its subclasses, `attest.AttestationRefused`,
`gmail_hook_server.HookError`. `docs/plan_assert_conversion.md` is the
conversion's own record of which checks are in which class and why.

Two reasons it is not a style preference. An `AssertionError` reaching a request
handler is an unhandled 500, while a named type is something a caller converts
into a status code — `onboarding/provisioning.py` turns `CustodyError` into a
502/503 and `InvalidAccountData` into a 502. And in a log an `AssertionError` is
indistinguishable from a genuine bug, where the type says which control fired.
A converted check caught into a fallback is worse than the assert was, because
it reads as handled: `MaskingFailed` in particular must never become "send it
unmasked", and `tests/test_prompt_fence.py` pins that.

`runtime_guard.py` is why an assert is still an acceptable way to spell a
control here. Several of them are the control rather than a note about one — the
path guard in `custody.tokens.token_path`, the `"d" not in jwk` check standing
between a library change and the co-signer publishing its signing key, the
length and version checks in `cosigner.keys.unwrap` — and under `-O` or
`PYTHONOPTIMIZE=1` every one disappears while the process keeps running.
`require_asserts()` refuses that boot, called from `backend/__init__.py` and
`cosigner/__init__.py` so no entry point can miss it, and it protects the asserts
written after today as well as the ones written before. It is not a substitute
for the rule above: it is one file, and a check that raises on its own does not
depend on an entry point still importing the package it lives in.

## Single sources of truth

Keep these centralized. If you need behavior that lives here, import — don't copy.

- `backend/secrets.py` — how a secret reaches the process. `secrets.load()` is
  the only read of `.env` (idempotent; injected environment wins). It owns the
  variable-name constants where presence is a lookup — `frontend/session.py`
  reads `SESSION_SECRET_ENV` and `SESSION_SECRET_PREVIOUS_ENV` from here, not the
  reverse. `fingerprint()` names a secret in a log without printing it. Under
  `TEE_REQUIRED` no file is read at all. It imports nothing heavy, which is the
  point: a role that needs only `load()` (the Pub/Sub receiver) reaches nothing
  through it.
- `backend/secrets_checks.py` — the `*_configured()` presence checks, the only
  definition of "this value is present", answered by calling the same code the
  services call (`PolarBilling()`, `telegram.operator_target()`). Split out of
  `secrets` because each check imports the module that owns its judgement
  (`llm_client`, `telegram`, `billing`, `oauth_app`) and the enclave image ships
  every module a role imports, function-local imports included — so a receiver
  whose one use of `secrets` is `load()` used to carry the whole inference,
  alerting, billing and custody fan-out behind those checks. Its two callers are
  `tee_boot.run_gate()` and `deploy/preflight.py`, so the enclave's fail-closed
  set and the deploy's skip set cannot drift; neither is the receiver.
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
  `LETTERLOCK_TRUSTED_PROXIES` adds to that set and never replaces it, which is
  what keeps that assert true; it exists for the enclave, where the web role is
  published on a port and reached over a docker network, so the peer is dstack's
  ingress. It ships empty, because an unnamed proxy costs a useless audit row
  and a wrongly named one costs a forgeable one — the web server says which it
  is doing at startup. `COSIGNER_PORT` is re-exported from
  `cosigner/protocol.py`, not defined here.
- `backend/egress.py` — every hostname anything on this box may connect to, and
  the check that decides one connection. Derived, not typed: each entry comes
  from the module that already names the host (`llm_client.PROVIDERS`,
  `oauth_app`, `telegram.API_ROOT`, `polar_api`'s two bases, the TDX
  allowlists' `pccs_url` of every verifier that runs here,
  `site.COSIGNER_HOST`). "Runs here" is why the co-signer's allowlist is read
  behind a `find_spec`: that service is a separate box and the enclave image
  carries only its wire contract, so where its code is absent the process that
  would fetch that collateral is absent too. Exact matches only — a suffix
  rule for `near.ai` is what permits `evil.near.ai`. `GOOGLE_API_HOSTS` holds the
  one pair no constant of ours produces (googleapiclient reads them from bundled
  discovery documents); `tests/test_egress.py` reads those documents and fails if
  one is missing. Names only, no addresses, so no bare IP is reachable.
  This does not defend against prompt injection: the drafter's tools fetch no
  URLs. It is for the post-compromise case and for a dependency that phones home.
  `deploy/check_egress.py` proves it is on — `IPAddressDeny=` needs cgroup v2
  with BPF, and without it systemd logs a line and starts the unit anyway.
  In the enclave the same module runs as the `egress` container and the
  enforcement is docker's `internal: true` network rather than systemd's, which
  covers the `mail` role alone: see "How the enclave is split" for which roles
  it is enforced for and which it is merely configured for.
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
  machine, since the enclave cannot edit it. Its `dev-insecure` mode passes a
  request carrying no client certificate at all, so it now costs two things: a
  `dev_insecure_expires` date in the allowlist, without which
  `quote_policy.Policy.mode()` refuses to answer and the service refuses to
  start, and an enclave that can see it — `/health` answers `attestation` and
  `backend/custody/client.py` refuses to use a co-signer that is not verifying
  its clients. Before both, the only guard read `TEE_REQUIRED` out of this box's
  own environment, which is a variable the other box cannot set.
  `cosigner/__init__.py` states the four invariants; read them before
  refactoring anything in that package.
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
  `oauth_app.required_scopes()` is the set the code calls and `missing_scopes()`
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
  `client.py` the sole network boundary to the co-signer, and the one place that
  decides whether the co-signer is one to use at all: under `TEE_REQUIRED` it
  reads `/health`'s `attestation` once per process and raises
  `CoSignerNotAttesting` unless it says `required`, since a co-signer in
  `dev-insecure` accepts a connection with no client certificate and only its
  own box could otherwise tell. `tokens.py` is the only path from a stored
  record to a usable access token; `rotate.py` moves every record onto a new
  co-signer key without opening one.
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
- `backend/custody/handoff.py` — the wire contract and the client for the work
  the web tier is no longer allowed to do itself, with `handoff_server.py` the
  listener the daemon runs on a thread. Most of the operations are the ones
  needing a Google token or the credential that obtains one: the consent URL
  (reads the OAuth client secret's file), the OAuth callback (the one moment a
  plaintext refresh token exists), and starting/reading a voice generation job
  (reads sent mail). The three `chat-*` operations cross for a different reason
  and the difference is worth keeping straight — they need no token, they cross
  because the *decision* is not the web tier's to make (`chat_link`). The two
  action names live here because they are what the answer is called on the wire,
  and because the asking side must be able to read them without importing the
  module holding the bypass. `providers` is a third reason again: the answer is
  a function of the inference API keys, and holding two live keys to answer a
  yes/no question was the only thing keeping them in the web tier. Everything
  else the web UI does with an account needs the data key and not a token, and
  it gets that from the co-signer directly.
  A unix socket rather than the wake spool because the spool is one way: a
  synchronous sign-in would poll for a result file, and that file would hold a
  live authorization code at rest. It is `state/custody.sock` at 0660 in a setgid
  directory, so the two uids in `letterlock-data` are the only ones that can
  open it.
  The mode is the grant and `_may_connect()` is a second check of the same fact,
  not a replacement: every way that mode can widen is silent (`file_mode()`
  reads a group that may not exist, the group comes from a setgid bit on
  `state/`, `chmod_if_owned` no-ops on a file owned by someone else), and the
  operations behind it mint consent URLs and exchange authorization codes. So
  the listener reads `SO_PEERCRED` and admits our own uid and `paths.web_uid()`
  alone. A kernel that will not answer is refused rather than assumed, and root
  is refused because no correct caller is root — not as a security claim, since
  root reads this process's memory anyway. What the socket does **not** do is
  authenticate the end user: the daemon takes `account_id` as an argument and
  acts on it, because the web tier is what decides who is signed in. That is why
  `chat_link` exists for the one field where trusting it was too much.
  `HandoffUnavailable` is never caught into a fallback that does the work
  locally: a web process that exchanges the code itself is a web process holding
  a refresh token, which is the whole thing this removes. It renders a 503.
  `tests/test_web_boundary.py` reads the tree for a `frontend/` module importing
  `keyring`/`tokens`/`wrapping`/`chat_link` or calling any of those functions
  directly, and pins that `keyring.write_encrypted(..., shared=False)` has
  exactly one caller. `chat_link` is on that list without holding a key: a web
  tier that imports it calls `force_unlink` in-process, which is the rule undone.
- `backend/paths.py` — on-disk locations *and* their modes, since the answer
  stopped being "0600, owner only" when the web tier moved to its own uid.
  `DATA_GROUP`/`SECRETS_GROUP` are read back by `deploy/deploy.sh` rather than
  spelled twice. `data_gid()` returning None (a laptop, or the box before the
  deploy that creates the group) falls back to owner-only, so this code landing
  ahead of its deploy is never a widening. `_chmod_if_owned` is why the second
  uid to reach a shared directory does not raise EPERM on its first write.
  `shared_dir` takes its mode as a required argument, because `audit.py` took
  the old default and re-set `state/` from 2771 to 2770 on the first row of
  every boot, which locked the push receiver out of its own spool silently.
  `write_private` is the other half of "the mode is the grant": it creates a
  file at 0600 rather than writing it and narrowing it afterwards, which is what
  the enclave's RA-TLS keys need on a tmpfs mounted 0777.
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
  `create_event()` asks who can read it first (`write_calendar_audience()`) and
  refuses when anyone but the owner can read event contents. Cached per account
  for `SHARING_TTL`, one cache whichever way it asked.
  There are two ways to ask and `oauth_app.acl_scope_registered()`
  (`LETTERLOCK_CALENDAR_ACL_SCOPE=1`) is the one place that picks. It also
  decides whether the consent asks for the scope, since requesting one the
  console does not carry fails at Google — `scopes()` and `required_scopes()`
  are functions for that reason, and there is no `SCOPES` constant any more.
  **On (`calendar.acls.readonly`):** read the calendar's ACL, refuse scope
  `default` or `domain` at role `reader`/`writer`/`owner`. `freeBusyReader` is
  allowed — it exposes that a span is taken and no field of the event. The scope
  is read-only on purpose: the code refusing to write to a public calendar must
  not be able to make one private and proceed. Existing users lose scheduling
  from sent mail until they sign in again at `/auth/login`;
  `tokens.take_custody()` reuses the account's data key so a returning user works.
  Registering it is manual and outside this repo: Google Cloud console → Google
  Auth Platform → Data Access, and being a sensitive scope it puts a published
  app back into verification.
  **Off (the default):** `calendar_public.is_public()` fetches the calendar's
  public iCal feed with no credentials, as a stranger would; 200 refuses, 404
  proceeds. Deliberately weaker in two named ways, both in that module's
  docstring: a Workspace `domain` share is not public and passes, and public
  free/busy-only is refused where the ACL path allows it. It holds no
  credentials and imports no Google client, which is why it is its own module
  and why `backend/egress.py` can read `ICS_ROOT` off it — the feed host is on
  the allowlist unconditionally, since the proxy cannot read this switch.
  Either way it fails closed when the question cannot be answered: a token
  minted before the scope answers 403, an outage answers nothing, the feed
  answers a status that is neither 200 nor 404, and only those two codes are an
  answer at all. `CalendarSharingUnknown` is a subclass so every caller refusing
  on one refuses on the other, and `schedule_from_sent.render_not_private()`
  reads the same switch so it does not send a user to `/auth/login` for a grant
  that would fix nothing.
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
  elsewhere. There is no tracing integration and no hook for one.
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
  deleted is the one most worth keeping — and the prune rides on `record()` and
  on the daemon's pass (`audit.maybe_prune`) behind `PRUNE_INTERVAL` with
  `secure_delete` on. The daemon is what makes the period a period: rows age out
  on a clock, and while a write was the only thing that pruned, a box nobody
  signed in to kept them past `RETENTION_DAYS`.
- `backend/integrations/telegram.py` — `TelegramTarget`, sends, and the bot's
  inbox. `send_telegram(msg, target)` always takes an explicit target;
  `operator_target()` (env) is only for box-level failures, never a user's mail.
  Deliberately no env fallback on the per-account path. `posts_of(code)` is the
  one read of the inbox, returning chat id *and* timestamp; it answers who
  posted a code and never who may act on it.
- `backend/accounts/chat_link.py` — who may change an account's telegram target.
  The daily summary carries mail content and the daemon delivers it to whatever
  chat id the manifest names, so that field is the one setting that turns a
  compromise of the web tier into a standing subscription to someone else's
  mail, and the daemon's co-signer traffic stays exactly what it is every
  morning. Moving the write behind the handoff does not close it: this process
  cannot tell a forged request from a real one, because the web tier is what
  decides who is signed in. The rule that does close it asks the chat being
  replaced — nothing linked, link freely; a chat linked, unlinking needs a code
  posted from *that* chat. Changing a target is therefore unlink then link.
  Unlink needs the proof for the same reason link does not, or an attacker
  unlinks first and falls into the case that asks for nothing. The code is
  minted here and the message must be newer than the request, both against the
  same replay: the user's own linking code sits in the bot's 24h inbox, posted
  from precisely the chat an unlink wants to hear from. `account.set_telegram()`
  stays the sole writer and now has exactly one caller, which is what makes this
  a rule rather than a suggestion; `force_unlink()` is the operator's way out
  for a user who has lost the Telegram account, reachable only from
  `python -m backend.accounts.unlink_telegram` and deliberately never a route.
  `tests/test_chat_link.py` pins the refusals and both caller sets.
- `draft_replies.drafting_instructions()` — everything the drafter is told about
  an account before it sees an email: voice profile, then personal information.
  One assembly, so the auto-reply and forwarded-email paths cannot hand the model
  different briefs.
- `backend/drafting/voice_dna.py` — where a profile lives and which one applies
  (`resolve()`), plus the load and save behind it. *How* one is generated from
  the account's own sent mail lives in `backend/drafting/voice_generation.py`,
  split off because generating reads mail (`tool_executors`→`gmail_api` and the
  token path) and runs inference (`llm_client`), which the web tier neither does
  nor should carry the code for: web shows and saves through `voice_dna` and
  hands generation to the mail role over the handoff, and `voice_dna` imports
  nothing from `voice_generation` so the web image carries neither the
  mail-reading nor the token stack. The dependency points one way, mail-ward.
  The operator's profile is reachable only through their
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
  profile. Separate because `voice_generation.generate()` overwrites that one wholesale.
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

  `protect(state, token)` names text masking must leave byte-identical, and
  `pseudonymize()` asserts the count on the way out. It exists because spaCy
  read the fence's closing marker `<nonce>_EXTERNAL_CONTENT` as a PERSON for
  about one nonce in sixty and the anonymizer replaced it, so the fence never
  closed and everything after the email body sat inside the untrusted region.
  A token and not a shape: a protected span is a span PII is *not* masked out
  of, so a pattern an email body could write would let the sender choose what
  stays in the clear. The nonce cannot be written by a sender because
  `Fence.wrap()` strips it from the content first. Registered by whoever pairs a
  fence with a state — `agentic_drafter.draft()` directly, and
  `llm_client.complete(protect=…)` for callers whose state is built inside it.
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
