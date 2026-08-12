# Configuration, from the beginning

Where every security-relevant setting lives, what reads it, what enforces it,
and what is currently wrong or unfinished. Written by reading the tree at commit
`c9342b9` plus the working-tree changes present on that day (2026-08-12).

Two deployments are configured from this one repository and they are not the
same shape:

* **The box.** `hezner.morganrivers.com`, `/opt/letterlock`, systemd units, one
  Caddy in front, six long-running services and three timers. Partition is by
  unix account, unix group, file mode and systemd sandbox.
* **The enclave.** Phala dstack CVM, five containers from five Nix-built images,
  one compose file. Partition is by container, uid, docker network and
  interpolated environment, and that partition is measured into RTMR3.

The same Python runs in both. Anything that differs between them is a
configuration file, and this document is the list of those files.

Verification run while writing: `tests/test_enclave_boundary.py`,
`test_image_manifest.py`, `test_egress.py`, `test_requirements.py`,
`test_preflight.py`, `test_secrets.py`, `test_optimized_controls.py` — 98
passed. Every drift guard described in §10 is currently green. The findings in
§11 are things no test asks about.

---

## 1. Inventory: every configuration file that decides something about security

| File                                                           | Decides                                                                                                 | Read by                                 | Guarded by                                                                  |
| -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- | --------------------------------------- | --------------------------------------------------------------------------- |
| `backend/roles.py`                                             | the five role names, which hold data, which hold network, which ports the ingress forwards              | everything below                        | asserts in the module, `test_enclave_boundary`                              |
| `deploy/phala/docker-compose.yml`                              | uid per role, group per role, secret per role, network per role, volume per role, published ports       | dstack; hashed into RTMR3               | `test_enclave_boundary` (22 tests)                                          |
| `flake.nix`                                                    | image contents, uid/gid numbers, `/etc/passwd` and `/etc/group`, entrypoint, volume seed modes, crontab | `nix build`, `build_and_publish.sh`     | partly: see finding F1                                                      |
| `deploy/phala/image_files.nix`                                 | which source files each role's image carries                                                            | `flake.nix`                             | `test_image_manifest` (generated, `--check`)                                |
| `deploy/phala/IMAGE_HASH.txt`                                  | published tarball hash and registry ref per role                                                        | humans                                  | nothing; currently a placeholder                                            |
| `app-compose.json` (**not in this repo**)                      | `allowed_envs`, i.e. which secret names decrypt at all                                                  | the phala CLI at deploy time            | only `test_enclave_boundary:312` records the expected list                  |
| `backend/tee/tee_boot.py`                                      | the attest-before-run gate and its per-role capability checks                                           | the container entrypoint                | `test_enclave_boundary`, `test_optimized_controls`                          |
| `backend/secrets_checks.py`                                    | `REQUIRED`, `REQUIRED_BY_ROLE`, `ROLE_EXEMPT`                                                           | the boot gate and `deploy/preflight.py` | module asserts; boundary test compares against compose                      |
| `backend/secrets.py`                                           | where a secret may come from at all (`TEE_REQUIRED` switches the file off)                              | every service                           | `test_secrets`                                                              |
| `backend/site.py`                                              | hostnames, ports, URLs, `TRUSTED_PROXIES`                                                               | app, `render_caddyfile`                 | asserts; see finding F2                                                     |
| `backend/paths.py`                                             | on-disk locations **and their modes**, the four group names                                             | app, `deploy.sh` reads the names back   | used by both sides, so drift is a runtime failure                           |
| `backend/egress.py` + `backend/egress_allowlist.json`          | every hostname anything may connect to                                                                  | egress proxy                            | `test_egress` compares the JSON against the live constants                  |
| `deploy/hetzner/hardening.conf`                                | the common systemd sandbox for every unit                                                               | installed as `10-hardening.conf`        | `deploy/check_egress.py` proves the network half on the running box         |
| `deploy/hetzner/<unit>.d/20-*.conf`                            | per-unit account, supplementary groups, writable paths, network exceptions                              | systemd                                 | `deploy.sh` reads `User=`/`SupplementaryGroups=` back out of them           |
| `deploy/hetzner/Caddyfile`                                     | TLS termination, routing, client-certificate demand                                                     | Caddy                                   | generated by `deploy/render_caddyfile.py` from `site.py`; installed by hand |
| `cosigner/allowlist.json`                                      | which enclave measurements may unwrap a token                                                           | `cosigner/attest.py`                    | `test_cosigner`; expiry date enforced in `quote_policy`                     |
| `backend/integrations/inference_allowlist.json`                | which inference enclaves may see mail                                                                   | `inference_attestation.py`              | `test_inference_attestation`                                                |
| `requirements.txt` → `deploy/phala/pyproject.toml` → `uv.lock` | what the image installs                                                                                 | `flake.nix` via uv2nix                  | `test_requirements` fails on drift, `deploy/audit.py` on advisories         |
| `setup.cfg`, `tests/test_lint.py`                              | flake8/isort/bandit policy, including the shipped-vs-operator bandit split                              | CI                                      | `test_lint`                                                                 |
| `.github/dependabot.yml`, `.github/workflows/*`                | security-only bumps, daily advisory audit, weekly latest-resolve                                        | GitHub                                  | n/a                                                                         |

Server-only files, never in git, never in an image, each with a matching
`--exclude` in `deploy/deploy.sh:45`: `.env`, `.env.billing`, `.env.alerts`,
`.gmail-mcp/gcp-oauth.keys.json`, `state/`, `database/`, `config/`, `venv/`.

---

## 2. Layer 0: how a secret reaches a process

There is exactly one reader of `.env`: `backend/secrets.py:119` `load()`. Eight
modules used to call `load_dotenv` themselves, which made "did this value come
off the volume or out of the KMS" unanswerable.

The switch is `TEE_REQUIRED`:

* Unset (box, laptop): `load()` reads `.env` and `.env.billing`, best effort, and
  never overwrites something already in the environment. A `PermissionError` is
  treated as absence (`secrets.py:93`), which is what lets the egress proxy and
  the co-signer import modules that reach for a constant without being taken down
  for being correctly sandboxed.
* Set (`docker-compose.yml:78`, every role including the two that hold nothing):
  `load()` reads no file at all. `secrets.file_backed()` is then empty by
  construction. The boot gate additionally refuses to start if any of those files
  exists on the volume (`secrets_checks.volume_secrets()`, `tee_boot.py:191`).

Inside the enclave the values arrive as dstack's `.encrypted-env`, decrypted to
`/dstack/.host-shared/.decrypted-env` **outside** every container, read by
`app-compose.service` as an `EnvironmentFile=`, and handed to containers only
through `${NAME}` interpolation in the compose file. Two rules follow, both
stated in the compose header and both now tested:

1. Never bind-mount `/dstack/.host-shared`. That file is the whole set, written
   with no mode. Pinned by `test_nothing_mounts_the_decrypted_environment`.
2. Every interpolated name must also be in `allowed_envs` in `app-compose.json`,
   or it decrypts to nothing and the role starts unconfigured. Pinned by
   `test_the_interpolated_names_are_the_deploy_time_checklist`,
3. which is the
   only copy of that list in the repository (see finding F6).

The current list is exactly 20 names: `EXPECTED_COMPOSE_HASH`, `DEEPSEEK_API_KEY`,
`NEARAI_API_KEY`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`,
`GOOGLE_OAUTH_CLIENT_ID`, `GOOGLE_OAUTH_CLIENT_SECRET`, `POLAR_API_TOKEN`,
`POLAR_ORGANIZATION_ID`, `POLAR_PRODUCT_ID`, `POLAR_CHECKOUT_URL`,
`POLAR_SANDBOX`, `SESSION_SECRET`, `SESSION_SECRET_PREVIOUS`, `LETTERLOCK_HOST`,
`LETTERLOCK_API_HOST`, `LETTERLOCK_COSIGNER_URL`, `WEB_TRUSTED_PROXIES`,
`WEBHOOK_AUD`, `PUBSUB_SERVICE_ACCOUNT`.

On the box the same partition is done with files and groups instead:

| File | Mode | Group | Who can read it |
|---|---|---|---|
| `.env` | 640 | `letterlock-secrets` | mail units, web UI |
| `.env.billing` | 640 | `letterlock-billing-secrets` | Polar receiver (and mail, see F4) |
| `.env.alerts` | 600 | root | systemd only, handed to `cosigner.service` as `EnvironmentFile=` before it drops privilege |

---

## 3. Layer 1: roles, accounts and groups

`backend/roles.py` is the only place role names are written. Everything else
either imports it or is asserted against it: `flake.nix` derives `roleNames`
from the generated manifest keyed by those names, `build_and_publish.sh` reads
the same file, `secrets_checks.REQUIRED_BY_ROLE` and
`tee_boot.CAPABILITIES_BY_ROLE` are asserted to have exactly those keys.

```
ROLES         = mail, web, hook, egress, ingress
DATA_ROLES    = mail, web, hook        (hold data or a key)
NETWORK_ROLES = egress, ingress        (hold network position and nothing else)
```

A role in both sets is refused by an assert at import. `INGRESS_ROUTES` maps
published port to internal service, and every target must be a data role.

Numeric identities are fixed in `flake.nix:107-122` because a shared docker
volume carries only numbers:

| Role | uid | supplementary gids | groups |
|---|---|---|---|
| mail | 10001 | 10010, 10011 | letterlock-data, letterlock-wake |
| web | 10002 | 10010 | letterlock-data |
| hook | 10003 | 10011 | letterlock-wake |
| egress | 10004 | none | none |
| ingress | 10005 | none | none |

The compose file repeats the numbers in `group_add:` (lines 121, 211, 273) and
must, because a numeric `user:` makes the runtime skip the `/etc/group` lookup a
username would trigger. `test_supplementary_groups_are_spelled_out_and_match_the_image`
compares the two.

Deliberate omission: `web` is not in `letterlock-wake`. Writing the wake spool
starts a drafting pass against an account of the writer's choosing and spends
that account's co-signer budget, which is an availability boundary the web tier
is kept outside of. The same decision is made on the box in
`letterlock-web.service.d/20-web.conf`.

The box's equivalent, one account per exposed unit, all derived by `deploy.sh`
from `User=` and `SupplementaryGroups=` in the drop-ins:

| Unit | Account | Supplementary groups |
|---|---|---|
| `email-daemon`, `email-summary`, `gmail-watch`, `billing-poller` | `letterlock` | data, secrets, wake, billing-queue, billing-secrets |
| `letterlock-web` | `letterlock-web` | letterlock, data, secrets |
| `email-webhook` | `letterlock-hook` | letterlock, wake |
| `billing-webhook` | `letterlock-billing` | letterlock, billing-queue, billing-secrets |
| `cosigner` | `cosigner` | letterlock |
| `egress-proxy` | `egress` | letterlock |

`letterlock` reaching every shared group is `deploy.sh:111-124`, and one of those
memberships is not intended: see F4.

---

## 4. Layer 2: images

`deploy/phala/image_files.nix` is generated, not written:

```
python -m deploy.render_image_manifest [--check]
```

It walks each role's entry points with `tools/reachability.py` and lists exactly
the files reachable from them. Function-local imports count exactly like
top-level ones, because a lazy import still executes, so narrowing a role's reach
means moving code and never deferring an import. That is the whole reason
`secrets_checks.py` exists as a separate module from `secrets.py`: the Pub/Sub
receiver imports `secrets` for `load()` alone, and while the presence checks
lived there the receiver's image carried the inference client, the Telegram
client, billing and the custody stack.

`tests/test_image_manifest.py` fails on drift and additionally refuses any
`deploy/`, `tests/`, `tools/` or `docs/` file, and any shipped `subprocess` or
`eval`.

`flake.nix` turns each manifest into an image: content-addressed Nix paths, so a
file shared by two roles is stored once; `chown -R 0:0 ./app` so no role can
rewrite its own code; `/etc/passwd` and `/etc/group` written from the `accounts`
attrset; `supercronic` and the crontab only in the mail image.

`deploy/phala/build_and_publish.sh` builds every role from the manifest's key
list, optionally builds twice and asserts identical hashes, pushes to
`${REGISTRY}-${role}`, and rewrites each `image:` line to a literal
`@sha256:` digest keyed on the `command: ["<role>"]` line beneath it.
`test_every_image_is_pinned_by_digest_or_is_the_pre_publish_placeholder` allows
only a literal digest or the pre-publish `:latest` placeholder, never a tag and
never a `${VAR}`. 

Current state: all five `image:` lines are the placeholder, and
`IMAGE_HASH.txt` says "regenerate before any push". Nothing is published yet.

---

## 5. Layer 3: the compose file is the secret partition

`deploy/phala/docker-compose.yml` is not a convenience. dstack embeds it in
`app-compose.json`, whose hash is extended as the `compose-hash` launch event and
measured into RTMR3, so which uid runs which image with which secrets is
attested rather than configured. An operator who moves `SESSION_SECRET` into the
mail container changes the measurement and `cosigner/attest.py` stops accepting
the client certificate.

What each role is handed:

| Role | Secrets | Volumes | Guest-agent socket | Gate |
|---|---|---|---|---|
| mail | inference keys, Telegram, Google OAuth pair, all Polar, hosts, co-signer URL | database, state, tmpfs attestation | yes | yes |
| web | `SESSION_SECRET(_PREVIOUS)`, hosts, co-signer URL, `WEB_HOST`, trusted proxies | database, state, tmpfs attestation | yes | yes |
| hook | `WEBHOOK_AUD`, `PUBSUB_SERVICE_ACCOUNT`, bind/port | state only | **no** | no |
| egress | `TEE_REQUIRED`, bind | none | no | no |
| ingress | `TEE_REQUIRED`, bind | none | no | no |

Three points are worth restating because they are the ones a well-meaning edit
undoes:

* **`hook` gets no guest-agent socket on purpose.** That socket is
  unauthenticated and `GetKey` takes a caller-supplied derivation path, so any
  process that can open it derives this app's sealing key. Withholding it is why
  the role runs no gate: it holds nothing to unseal.
* **`web` needs the socket** (it obtains a data key to render a user's own
  documents), so its isolation from a Google token is a file mode instead:
  `token.bin` is 0600 to the mail uid, and the consent URL, the code exchange and
  voice generation all cross to `mail` over `custody/handoff.py`.
* **No role is a Polar receiver.** There is no correct value of
  `POLAR_WEBHOOK_SECRET` to inject, which is why `secrets_checks.ROLE_EXEMPT`
  names that check by name rather than the gate quietly demanding it of somebody.
  Entitlement in the enclave is `confirm_checkout()` plus the 3-hourly poller,
  both in `mail`.

`egress` and `ingress` deliberately do **not** inherit `*common-env`: they
override `environment:` wholesale, so they get `TEE_REQUIRED` and a bind address
and nothing else. A proxy pointed at itself is the bug that avoids.

`EXPECTED_COMPOSE_HASH` is interpolated rather than written, because the value is
the hash of the file that would contain it. Empty is refused
(`tee_boot._measurement_gap`, `tee_boot.py:76`): an unset value used to return
silently, so the check was on only for whoever remembered to set it. Read that
docstring for what the check is worth, which is bounded: the value comes from
the enclave's own environment, so it catches the deploy that published one
compose and booted another. The statement no operator can forge is
`cosigner/allowlist.json`, on the other box.

---

## 6. Layer 4: the network

### In the enclave

Two networks and five containers:

```
edge (ordinary bridge)      ingress, egress            <- the only route off the host
inner (internal: true)      mail, web, hook, ingress, egress
```

`inner` has `internal: true`, so docker installs no route off the host for it. A
container on `inner` alone reaches the internet through `egress` or not at all,
and is reached from outside through `ingress` or not at all. `mail`, `web` and
`hook` are on `inner` alone. Every container holding a token, a session secret,
an inference key or an account's data is therefore unroutable outward.

That is recent and it matters: `web` and `hook` used to sit on `edge` because a
published port on an internal-only network never receives forwarded ingress. On
`edge` they had a route out, so for exactly the two roles facing the internet the
egress allowlist was a pair of environment variables their own HTTP clients chose
to honour. `backend/daemons/ingress_proxy.py` took the published ports (8790,
8787), and both roles moved to `inner`. The forwarder parses nothing: its routing
table comes from `roles.INGRESS_ROUTES` and is fixed before it accepts a
connection. The one cost is that `web` sees the ingress container as its peer
rather than a browser, which is why `LETTERLOCK_TRUSTED_PROXIES` ships empty (an
unnamed proxy costs a useless audit row; a wrongly named one costs a forgeable
one).

`backend/daemons/egress_proxy.py` is CONNECT-only on 8792, publishes no port, and
authenticates no caller. The boundary is over destinations, not callers, and
`inner` is what stops a role going around it.

### On the box

Same shape in systemd instead of docker. `hardening.conf:131-132` gives every
unit `IPAddressDeny=any` plus `IPAddressAllow=localhost`, and lines 152-157 point
all four HTTP client libraries at `http://127.0.0.1:8792` in both cases of every
variable. `egress-proxy.service.d/20-egress-proxy.conf` resets all of it for the
one unit that must have the internet, and also resets `Wants=`/`After=` so the
unit does not order after itself.

Consequence worth knowing before it is diagnosed as an outage: these units get no
DNS at all, and need none, because with a proxy configured every client hands the
hostname to the proxy in the CONNECT line. Anything added that resolves a name
itself will fail looking like a network problem.

### The allowlist

`backend/egress_allowlist.json` is generated by
`python -m deploy.render_egress_allowlist` from the modules that already name
each host (`llm_client.PROVIDERS`, `oauth_app`, `telegram.API_ROOT`,
`polar_api`'s two bases, both TDX allowlists' `pccs_url`, `site.COSIGNER_HOST`).
There is nothing to forget to edit. `backend/egress.py` reads that file and
imports nothing else, so the one process with a route off the host does not carry
the custody stack in its filesystem to compute thirteen strings.

Current contents, 13 hosts: `accounts.google.com`, `api.deepseek.com`,
`api.polar.sh`, `api.telegram.org`, `calendar.google.com`,
`cosigner.morganrivers.com`, `glm-5-2.completions.near.ai`,
`gmail.googleapis.com`, `gpt-oss-120b.completions.near.ai`,
`oauth2.googleapis.com`, `pccs.phala.network`, `sandbox-api.polar.sh`,
`www.googleapis.com`.

Exact matches only, names and never addresses, port 443 only. A redirect from an
allowlisted host to one that is not is refused, because the client opens a second
tunnel and the proxy judges that one on its own.

### TLS and routing on the box

`deploy/hetzner/Caddyfile` is generated whole from `backend/site.py`:

```
python -m deploy.render_caddyfile > deploy/hetzner/Caddyfile
scp ... && caddy validate && install -m 0644 ... && systemctl reload caddy
```

`deploy.sh` deliberately does not touch Caddy. Because the renderer emits the
whole config, `site.CO_TENANT_ROUTES` exists to keep another product's
`/polar/webhook` on 8788 alive across a regenerate; deleting that entry deletes
that service's route.

The co-signer's site block is the only one with `client_auth { mode require }`.
`require` demands a certificate and does **not** check it against a CA pool,
because the enclave's certificate is RA-TLS, self-signed, and vouched for by the
TDX quote inside it. Caddy passes it up as base64 DER in
`protocol.CLIENT_CERT_HEADER` and `cosigner/attest.py` does the five checks.
`disable_tlsalpn_challenge` is there because the TLS-ALPN challenge is a
handshake Let's Encrypt performs without a client certificate, which `require`
would reject.

---

## 7. Layer 5: file permissions

`backend/paths.py` is the single source of truth for locations **and** modes,
because the answer stopped being "0600, owner only" when the web tier got its own
uid. The modes:

```
DIR_MODE_PRIVATE     0700
DIR_MODE_SHARED      2770   database/, config/
DIR_MODE_TRAVERSABLE 2771   state/ only
FILE_MODE_PRIVATE    0600
FILE_MODE_SHARED     0660
```

`state/` is 2771 and `database/` is not, and the extra bit is execute for others,
never read. Four uids open a file in `state/` and they are deliberately not all
in one group, so traversal is what lets a file's own mode be the grant. It
confers nothing by itself, since every file in there is 0600 or 0660 to a named
group, and x without r is not listing. `database/` does not get the bit because
who has an account is itself worth keeping.

Behaviour that keeps multi-uid directories from turning permission decisions into
crashes:

* `_gid()` returning None (laptop, or a box before the deploy that creates the
  group) falls back to owner-only. Every fallback narrows, never widens.
* `chmod_if_owned` and `_adopt_group` are silent for a non-owner, because the
  owner set the mode when it created the path.
* `shared_dir(path, mode)` has no default mode, after `audit.py` took the default
  for `state/` and re-set it from 2771 to 2770, silently cutting the Pub/Sub
  receiver off from its own spool.
* `write_private` creates at 0600 with `O_TRUNC` and an explicit `fchmod`, rather
  than writing and then narrowing. That is not academic: the enclave writes its
  RA-TLS private keys onto a tmpfs mounted at 0777.

The one file that is `shared=False`: `database/<id>/token.bin`, the wrapped
refresh token, 0600 to the mail uid. The web tier legitimately holds an account's
data key while rendering a document, and that key would open the token, so the
mode is what makes the two paths different capabilities.

`deploy/deploy.sh:126-188` is the same statement applied to the box from outside,
and reads the group names back out of `paths.py` rather than spelling them twice:

* `chmod 750 /opt/letterlock`, then `chmod -R g-w` over the whole tree. rsync
  reproduces the checkout's 775 directories and every unit carries
  `SupplementaryGroups=letterlock` to reach the source, so without that blanket
  pass the co-signer's account could rewrite `daemon_loop.py` and wait for a
  restart. It runs before the loop that puts group-write back on the two
  directories that need it.
* `database/` and `state/`: `chgrp -R letterlock-data`, dirs 2770, files 660,
  then `state/` back to 2771 and every `token.bin` back to 600.
* wake files (`wake.fifo`, `wake_queue.jsonl`, `wake_queue.lock`) sideways to
  `letterlock-wake`; billing spool files sideways to `letterlock-billing-queue`.
* `.gmail-mcp/` 700, `.env` 640 to secrets group, `.env.billing` 640 to billing
  secrets group, `.env.alerts` 600.
* `database/` and `state/` are created rather than skipped when absent, because
  they are named in `ReadWritePaths=` and systemd refuses to start a unit whose
  `ReadWritePaths` does not exist.

In the enclave the equivalent is `flake.nix:279-283`: each image seeds the volumes
it mounts to mail uid, `letterlock-data` gid, 2770 for `database` and 2771 for
`state`. Docker seeds a named volume from the first container to mount it,
ownership and mode included, so every image seeds identically and the result does
not depend on start order. `hook` mounts `state` only, so the account store is
not in its filesystem at all.

The unix socket in `custody/handoff_server.py` is 0660 plus a second check:
`SO_PEERCRED` and `_may_connect(uid)` admit our own uid and `paths.web_uid()` and
nothing else, so a future widening from a path change is a refusal in a log
rather than an open door.

---

## 8. Layer 6: attestation configuration

Three separate pin files, in two directions.

**`backend/tee/quote_policy.py`** holds the five checks both directions share:
the quote parses and is TDX; report_data carries the binding the caller demands;
measurements match an authorized entry; the signature chains to the Intel root;
TCB status and advisories are allowed. `dev-insecure` is refused if the
allowlist names any measurement, and the `dev_insecure_expires` date is
mandatory, because the failure mode of a verification switch left off is silence.

**`cosigner/allowlist.json`** (inbound, the other box): which enclave may unwrap.
This is the file the enclave cannot edit, which is the point of the second box.
Current state:

```json
"mode": "dev-insecure", "dev_insecure_expires": "2026-11-30",
"quote_oid": null, "binding": "pem-sha256", "measurements": []
```

**`backend/integrations/inference_allowlist.json`** (outbound): which inference
enclave may see mail. `mode: required`, three NEAR AI measurements pinned
(recorded 2026-08-05 against dstack-nvidia-0.5.5) plus ten `composes` entries
pinned by `file_sha256`. The composes list exists because RTMR3 measures the
bootstrap compose and not the model server the manager brings up afterwards, so
replaying the attested action log has to yield only compose files that appear
here. `rt_mr3` is the pin that will fail first, and failing is the point.

**The gate**, `tee_boot.run_gate(role)`, in order: `TEE_REQUIRED` unset means
no-op; unknown role refused; any secret file on the volume refused; no guest
agent refused; `EXPECTED_COMPOSE_HASH` unset or mismatched refused; `GetTlsKey`
plus `GetKey` plus `GetQuote` (a KMS refusal here is the F2 wrong-measurement
signal); then `secrets_checks.missing(role)` and `CAPABILITIES_BY_ROLE[role]`.
Only then does it write `boot_info.json` and the RA-TLS material into the tmpfs.

The enclave checks the co-signer back: `custody/client.py:185`
`_require_attesting_cosigner()` refuses, under `TEE_REQUIRED`, to talk to a
co-signer that reports anything but `required`. So the current `dev-insecure`
setting is not a hole that survives the cutover; it is a hard stop that must be
cleared before the enclave can do anything at all. It is, however, the current
posture of the box today: see F5.

---

## 9. Layer 7: the box's systemd sandbox

`deploy/hetzner/hardening.conf` is installed as `<unit>.d/10-hardening.conf` for
every long-running service and every timer's oneshot, so the settings live in one
file instead of seven that drift. The parts that are doing work:

* `User=letterlock`, `UMask=0077`, `NoNewPrivileges`, `ProtectSystem=strict`,
  `ProtectHome`, `PrivateTmp`, `PrivateDevices`, `PrivateMounts`,
  `RestrictNamespaces`, `RestrictSUIDSGID`, `LockPersonality`, `RemoveIPC`,
  `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`.
* `ReadWritePaths=/opt/letterlock/state /opt/letterlock/database` and nothing
  else. It used to be the whole app directory, which handed every unit write
  access to the code every other unit runs.
* `NoExecPaths=/` with `ExecPaths=/usr /opt/letterlock/venv`, plus
  `MemoryDenyWriteExecute` and `SystemCallArchitectures=native`. Nothing in
  `backend/`, `frontend/` or `cosigner/` spawns anything, so the sandbox can
  forbid what the code never does. A seccomp denial of `execve` would be tighter
  and is not available, because systemd installs the filter in the forked child
  and then execs the service binary.
* `ProtectProc=invisible`, `ProcSubset=pid`, `TasksAccounting`, `TasksMax=128`.

Each exception is a numbered drop-in beside its unit, never a weakened common
file. The four that exist are `cosigner` (own account, `ReadWritePaths=` emptied,
`EnvironmentFile=-/opt/letterlock/.env.alerts` read as root before dropping
privilege), `egress-proxy` (own account, network deny list emptied, proxy
variables emptied, `PATH` restored), `email-webhook` (own account, wake group
only, `state/` only) and `letterlock-web` and `billing-webhook` in the same
shape.

`deploy/deploy.sh` derives everything from those files: which units to restart
(`grep -l '^\[Install\]'`), which accounts to create (`User=`), which groups to
join (`SupplementaryGroups=`), and it deletes any drop-in on the box that the
repo no longer has, because a setting that still runs and cannot be read in git
is a unit quietly left on the wrong user.

Two gates run at the end of a deploy:

* `deploy/preflight.py` imports each unit's `ExecStart` module in a throwaway
  process and runs that module's configuration check, using the same
  `secrets_checks` functions the boot gate uses. A unit that fails is left alone
  rather than restarted into a crash loop.
* `deploy/check_egress.py` asks the running box three questions by doing rather
  than by reading config: is an unlisted host refused, is a listed one tunnelled,
  and can a process under the same drop-in open a direct connection at all. This
  is the only evidence that `IPAddressDeny` is in effect; without cgroup v2 and
  BPF, systemd logs one line and starts the unit anyway, so every service comes
  up healthy with the whole internet reachable.

---

## 10. What the tests actually pin

Green as of this writing (98 passed):

* `test_enclave_boundary.py` (22 tests): each role gets exactly the secrets its
  gate demands and no more; no role asks for the Polar webhook secret; the gate
  runs per role and the entrypoint says which; every role names this
  deployment's hostnames; no role runs as root; each role runs its own image; the
  receiver reaches no account data and no KMS; supplementary groups match the
  image's `/etc/group`; no role is provisioned for another role's work; no role
  starts everything; nothing mounts `.host-shared`; the interpolated names are
  the `allowed_envs` checklist; the only host path mounted is the guest-agent
  socket; no `privileged:`, `cap_add:`, `network_mode:`, `pid:`, `userns_mode:`,
  `devices:` or `security_opt:`; every image is a digest or the placeholder; the
  push actually writes a digest; no data role has a route off the host; only the
  ingress is reachable from outside; the ingress holds nothing; every role
  running our HTTP clients is pointed at the proxy.
* `test_image_manifest.py`: the manifest matches a fresh render, and no
  `deploy/`, `tests/`, `tools/`, `docs/`, `subprocess` or `eval` ships.
* `test_egress.py`: the committed allowlist equals the live constants.
* `test_requirements.py`: `pyproject.toml` has not drifted from
  `requirements.txt`.
* `test_optimized_controls.py`: no control is spelled as an assert, so running
  under `-O` costs invariant checking and nothing else.
* `test_preflight.py`, `test_secrets.py`: the unit-to-module mapping and the
  loader's `TEE_REQUIRED` behaviour.

---

## 11. Findings

Ordered by what I would fix first. None of these is caught by a current test.

### F1. `flake.nix` has no `image-ingress` output, so the ingress image cannot be built or pushed

`flake.nix:325-337` names `image-mail`, `image-web`, `image-hook`,
`image-egress`, the `images` link farm and `default`. There is no
`image-ingress`. `deploy/phala/build_and_publish.sh:73` runs
`nix build ".#image-$1" --no-link --print-out-paths 2>/dev/null | tail -1` for
every role in the manifest, ingress included; stderr is discarded, so the failure
surfaces as an empty path and then a `sha256sum` error under `set -euo pipefail`.
The whole publish run dies partway through, after having pushed and re-pinned some
roles.

This is exactly the failure mode `roles.py` was written to prevent (a role that
exists in four places and is missing from the fifth), and it survived because
the packages block is the one list not derived from the manifest.

Fix: derive the per-role attributes instead of listing them, e.g.

```nix
packages.${system} = {
  inherit venv;
  images = pkgs.linkFarm ...;
  default = images.mail;
} // lib.mapAttrs' (role: img: lib.nameValuePair "image-${role}" img) images;
```

and add an assertion in `test_enclave_boundary.py` that every name in `ROLES` has
an `image-<role>` attribute in `flake.nix`.

### F2. An empty `LETTERLOCK_HOST` passes the boot gate and mints hostless URLs

`site.py:35-36` uses `os.environ.get("LETTERLOCK_HOST", DEFAULT_APP_HOST)`, which
returns `""` when the variable is present and empty, not the default.
`tee_boot._host_overridden()` (`tee_boot.py:120-139`) only asks whether the value
**equals** the compiled-in default. The compose file interpolates
`"${LETTERLOCK_HOST}"` with no `:-` fallback (`docker-compose.yml:147-148`,
`218-219`), and docker compose substitutes an empty string for an unset variable
rather than failing. So a name missing from `allowed_envs`, or simply not set at
deploy time, produces a container that passes the gate and then mints
`https:///auth/callback`.

Verified:

```
$ LETTERLOCK_HOST= LETTERLOCK_API_HOST= TEE_REQUIRED=1 python -c ...
APP_HOST='' API_HOST=''
oauth callback: https:///auth/callback
_host_overridden -> None
```

Compare `gmail_hook_server.py:92`, `assert EXPECTED_AUD.startswith("https://")`,
which turns the same class of mistake into a crash loop at import.

Fix at the single source, `site.py`, so the gate keeps catching it:

```python
APP_HOST = os.environ.get("LETTERLOCK_HOST", "").strip() or DEFAULT_APP_HOST
API_HOST = os.environ.get("LETTERLOCK_API_HOST", "").strip() or DEFAULT_API_HOST
```

An empty value then reads as the default and `_host_overridden()` refuses, which
is the correct answer: nobody set it.

### F3. The containers get none of the in-container hardening the box's units get

The systemd side is thorough: `NoNewPrivileges`, `NoExecPaths=/`,
`MemoryDenyWriteExecute`, `ProtectSystem=strict`, `TasksMax`, `ProtectProc`. The
compose file sets none of the container equivalents. Missing, cheapest first:

* `security_opt: ["no-new-privileges:true"]`
* `cap_drop: [ALL]` (docker's default set still includes `CHOWN`, `SETUID`,
  `SETGID`, `NET_RAW`, `MKNOD`; no role needs any of them, they all run as a
  fixed non-root uid)
* `read_only: true` plus an explicit `tmpfs: [/tmp]` (every writable path a role
  needs is already a named volume or the attestation tmpfs)
* `pids_limit`, the analogue of `TasksMax=128`

Note that `test_no_role_asks_for_privilege_the_partition_would_not_survive`
(`test_enclave_boundary.py:356-364`) currently forbids the substring
`security_opt:` outright, so adding the first item means teaching that test to
allow `no-new-privileges:true` specifically and keep refusing everything else
(`seccomp=unconfined`, `apparmor=unconfined`, `label:disable`). The intent of
that test is to forbid privilege, and a blanket string match is currently
forbidding the setting that removes it.

None of these is a hole on its own. Together they are the difference between the
enclave's containers matching the box's units and being noticeably weaker than
them, on the deployment that is supposed to be the stronger of the two.

### F4. `letterlock` is in `letterlock-billing-secrets`, which `paths.py` says has one member

`deploy/deploy.sh:111` puts all five shared groups in `SHARED_GROUPS` and lines
116-124 add `SERVICE_USER` to every one of them. Four are correct: data, secrets,
wake, billing-queue (the daemon drains the billing spool). The fifth,
`letterlock-billing-secrets`, is not: the mail account has no reason to read
`.env.billing`, and `paths.py:105-106` states plainly that "its only member is
the Polar receiver".

Impact is small, since the file holds `POLAR_WEBHOOK_SECRET` alone and the mail
account already holds the strictly stronger `POLAR_API_TOKEN`. It is worth fixing
because a stated boundary that is not true is worse than one that was never
claimed, and because the fix is three lines: split the loop into the groups the
mail account needs and the ones only a drop-in's account joins.

### F5. Today, the co-signer authenticates nobody

`cosigner/allowlist.json` is `mode: dev-insecure` with no measurements and a
null `quote_oid`. Caddy's `client_auth { mode require }` demands a certificate
and checks it against no CA. `attest.verify_client` under `dev-insecure` returns
`Verdict(True, ...)` for any certificate presented, and `attested=False` is
written into every audit row, which is the intended record.

So the current control on `POST /unwrap-and-sign` is not identity. It is: reach
`cosigner.morganrivers.com` with any self-signed certificate, possess the outer
blob for a uid (which lives in `database/` on the box), and stay under
`policy.py`'s rate limits, which alert and refuse on a sweep.

This is the deliberate pre-cutover posture, it expires on 2026-11-30, and
`custody/client.py:185` makes it impossible to carry into the enclave. It is
listed here because it is the single largest gap between what the architecture
documents describe and what is enforced on the box right now, and because 110
days is long enough to forget. The remedy is Stage 2.5 of
`docs/runbook_provisioning.md`: populate `measurements`, set `quote_oid` from a
live dstack RA-TLS certificate, confirm `binding`, flip `mode` to `required`.

### F6. `allowed_envs` exists only as a Python test's expected set

The 20 names in §2 must appear in `app-compose.json`, a file the phala CLI writes
at deploy time and which is not in this repository. Nothing renders it, and
nothing can check it after the fact; the failure mode is a role that starts
"successfully" with an empty secret. For `SESSION_SECRET` that is a web tier
signing cookies with nothing, and per F2 for `LETTERLOCK_HOST` it is a whole
deployment minting hostless URLs.

The list is already computed inside
`test_the_interpolated_names_are_the_deploy_time_checklist`. Lift it into
`deploy/render_allowed_envs.py` that prints the JSON fragment, have the test
compare against that renderer instead of a literal, and make pasting it a
numbered step in the provisioning runbook.

### F7. Stale build metadata

`deploy/phala/IMAGE_HASH.txt` still carries the pre-merge placeholder text
("STALE after feat/teespike merge", `nix-store-path: <regenerate...>`), and
`appauth-contract` is unfilled. `build_and_publish.sh:4-5` and `flake.nix`'s
comments still say "four roles" and "four images" in several places, and
`flake.nix:332` says "`nix build .#images` builds all four". Cosmetic next to F1,
but it is the same miscount, and it is what makes F1 easy to miss on a read.

---

## 12. Residual risks that are accepted, not defects

Listed so they are not rediscovered as findings.

* **The box's source is owned by `letterlock`.** The co-signer and the egress
  proxy run code out of `/opt/letterlock`, which the application account owns.
  `chmod -R g-w` stops the *group* route and `ProtectSystem=strict` with a
  narrowed `ReadWritePaths` stops every sandboxed unit from writing there at
  runtime, so the exposure needs a process outside the sandbox. It is not zero.
  `egress_proxy.py`'s docstring says so explicitly.
* **Separation of privilege, not of operator.** One machine, one root. The
  co-signer's keys are sealed to its TPM and the app cannot read them; root can.
  No product copy may say otherwise before the enclave actually moves to Phala.
* **The web tier can read `POLAR_API_TOKEN` on the box**, because it shares
  `.env` with `SESSION_SECRET` and one file is one grant. No code there uses it
  (all three Polar calls cross the handoff socket) and the enclave's `web`
  container is simply not handed it. Closing it on the box means giving
  `SESSION_SECRET` its own file the way `POLAR_WEBHOOK_SECRET` got one.
* **The web tier can still write `database/accounts.json`**, so it can repoint an
  account's telegram target. Changing that means the manifest stopping being a
  file that unit can write.
* **The egress proxy does not authenticate callers.** The boundary is over
  destinations; `IPAddressAllow=localhost` and `inner` are what stop anything
  going around it.
* **The attestation tmpfs is mounted 0777**, because the runtime creates it as
  root and the container's process is not. `paths.write_private` is what makes
  that safe, and it is why the create-at-0600 rule is not stylistic.
* **`egress` and `ingress` run no gate.** They hold no key to unseal and are
  deliberately given no guest-agent socket to run one with.
* **A single co-signer is a hard dependency with no bypass.** The enclave
  processes no mail while it is unreachable, by design.

---

## 13. Cutover checklist

In order, because several of these gate each other.

1. Fix F1, or the ingress image never reaches the registry.
2. Fix F2, or a missing `allowed_envs` entry produces an attested, broken
   deployment instead of a refusal.
3. Decide F3 and either apply the container hardening or write down why not.
4. `python -m deploy.render_image_manifest --check`, `python -m
   deploy.render_egress_allowlist`, `python -m deploy.render_pyproject` and
   `cd deploy/phala && uv lock`. Run the suite.
5. `REGISTRY=<repo> deploy/phala/build_and_publish.sh --verify --push`. Confirm
   every `image:` line in the compose file is now a literal `@sha256:` digest and
   `IMAGE_HASH.txt` carries five real rows.
6. Deploy with the phala CLI. Put all 20 names in `allowed_envs`, including
   `EXPECTED_COMPOSE_HASH`, and set every one of them. Record the AppAuth
   contract address and chain id in `IMAGE_HASH.txt`.
7. Compute the compose hash, set `EXPECTED_COMPOSE_HASH`, redeploy, and confirm
   `tee_boot` prints `attested role=<role>` for `mail` and `web`.
8. Take a live RA-TLS certificate off the CVM. Confirm the `binding`
   (`pem-sha256` vs `spki-sha256`) and read the quote extension's OID.
9. Fill `cosigner/allowlist.json`: `quote_oid`, `measurements` (one entry per
   authorized image, `mr_td` never null), then `mode: required`. Deploy the
   co-signer. `deploy/preflight.py` will refuse it if `dcap-qvl` is absent or the
   list is empty.
10. Watch each role's first boot in the CVM. None of this has been run in a CVM
    yet; the compose file's own header says so.
