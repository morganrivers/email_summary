# Enclave and co-signer configuration

What every security relevant setting in the enclave is, what enforces it, and
what is still wrong. Written by reading the working tree on 2026-08-12, and
updated the same day when the scheduler change landed (crontab and supercronic
replaced by a thread in the mail daemon, which cleared what was F5).

Scope: the Phala enclave and the co-signer it depends on. The Hetzner server is
mentioned only where the enclave's behaviour depends on it, which is twice: the
co-signer runs there today, and `backend/site.py` compiles the Hetzner
hostnames in as defaults, so an enclave that fails to override them sends its
users to the wrong machine.

Nothing here has run in a real CVM yet. Every statement below is about
configuration that is committed and tested, not about observed behaviour.

---

## 1. How to read the numbers

Three kinds of number appear throughout: account ids, file modes, and ports.

### Account ids (uid and gid)

The kernel does not know names. Every process runs as a numeric **uid** (user
id) and belongs to one primary **gid** (group id) plus any number of
supplementary groups. Every file on disk stores one owner uid and one group
gid. `/etc/passwd` and `/etc/group` map those numbers to names for humans, and
each container image carries its own copy of both files, written by `flake.nix`.

The numbers are pinned rather than allocated because two containers share the
`database` and `state` docker volumes, and a shared volume stores only numbers.
If the mail image called itself uid 10001 and the web image called the same name
uid 500, the two would be different users to the kernel and the shared files
would be unreadable to one of them.

| Number | Name | What it is |
|---|---|---|
| 10001 | `letterlock-mail` | the uid the mail container runs as |
| 10002 | `letterlock-web` | the uid the web container runs as |
| 10003 | `letterlock-hook` | the uid the hook container runs as |
| 10004 | `letterlock-egress` | the uid the egress proxy runs as |
| 10005 | `letterlock-ingress` | the uid the ingress forwarder runs as |
| 10010 | `letterlock-data` | shared group over `database/` and `state/` files |
| 10011 | `letterlock-wake` | shared group over the wake FIFO and the wake spool |

Each uid also gets a personal group of the same number (uid 10001 has group
10001), which is what `user: "10001:10001"` in the compose file says: run as
that uid, with that gid as the primary group.

Supplementary group membership is baked into each image's `/etc/group`, but the
container runtime skips reading that file when `user:` is numeric. That is why
the compose file repeats the numbers in `group_add: ["10010", "10011"]`. Without
that line, the mail container would run in no shared group and could not read
its own database.

### File modes

A file's mode answers "who may do what" for three sets of people: the file's
**owner** (the uid that owns it), the file's **group** (anyone whose gid list
includes the file's group), and **others** (everybody else). Each set gets one
digit, and that digit is the sum of read (4), write (2), execute (1). Modes are
written in octal, which is why they look like `600` rather than `384`.

A leading fourth digit carries special bits: 2 is setgid, 1 is sticky.

The modes used here, all defined once in `backend/paths.py`:

| Mode | Meaning |
|---|---|
| `0600` | owner may read and write. Group and others may do nothing. |
| `0660` | owner and group may read and write. Others may do nothing. |
| `0700` | a directory only its owner may list, write in, and enter. |
| `2770` | a directory the owner and group may list, write in and enter. The leading 2 is setgid: a file created inside inherits the directory's group rather than the creator's, so a file written by the web uid stays readable to the mail uid. |
| `2771` | the same, plus 1 for others: execute on a directory means "may enter it to reach a path you already know", not "may list it". |
| `1777` | used for `/tmp` in each container. Everyone may read, write and enter; the leading 1 is the sticky bit, which means only a file's own owner may delete it. |

`database/` is 2770 and `state/` is 2771, and the difference is deliberate. Four
uids open files in `state/` and they are not all in one group, so entering the
directory is what lets each file's own mode be the grant. Entering confers
nothing by itself, because every file in there is 0600 or 0660 to a named group.
`database/` does not get that bit, because who has an account is itself worth
keeping.

### Ports

| Port | Listener | Reachable from |
|---|---|---|
| 8787 | hook role, Gmail Pub/Sub push webhook | outside the CVM, through ingress |
| 8790 | web role, the product UI | outside the CVM, through ingress |
| 8792 | egress role, the outbound CONNECT proxy | other containers only |
| 8791 | the co-signer, on separate hardware | the enclave, over the public internet, client certificate required |

Only 8787 and 8790 are published, and only by the ingress container.

---

## 2. The five roles

`backend/roles.py` is the only place role names are written. `flake.nix`,
`build_and_publish.sh`, `deploy/render_image_manifest`,
`secrets_checks.REQUIRED_BY_ROLE` and `tee_boot.CAPABILITIES_BY_ROLE` all derive
from it or are asserted against it, because a role added to five of six places
is a role that ships with no image, or no boot gate, or no push.

```
ROLES         = mail, web, hook, egress, ingress
DATA_ROLES    = mail, web, hook        hold data or a key
NETWORK_ROLES = egress, ingress        hold network position and nothing else
```

A role in both sets is refused by an assert at import. `INGRESS_ROUTES` maps a
published port to the internal service that answers it, and every target must be
a data role.

| Role | Job | Holds |
|---|---|---|
| `mail` | opens mailboxes, drafts, summarises, runs the schedule, answers the web role over the handoff socket | Google client credentials, inference keys, Telegram token, the Polar API token, both volumes |
| `web` | the product UI on 8790 | `SESSION_SECRET`, both volumes, a data key while rendering a person's own documents. No Google token, no inference key, no Polar token. |
| `hook` | verifies the Pub/Sub OIDC token Google posts and appends one address to the wake spool | `state/` only. No account list, no key, no guest agent socket. |
| `egress` | the only container allowed to open a connection to the internet | nothing at all |
| `ingress` | the only container the outside world connects to; forwards TCP inward | nothing at all |

One container per role, one image per role.

---

## 3. How a secret reaches a container

`backend/secrets.py` `load()` is the only reader of a `.env` file anywhere in
the tree. Eight modules used to call `load_dotenv` themselves, which made "did
this value come off a disk or out of the KMS" unanswerable.

`TEE_REQUIRED` is the switch. Every enclave container sets it to `1`, including
the two that hold no secret. Under it, `load()` reads no file at all, and the
boot gate additionally refuses to start if any secret file is present on the
volume (`.env`, `.env.billing`, `.env.alerts`, the Google OAuth key file). A
file on the volume is a copy the KMS does not gate and the measurement does not
cover.

Where the values actually come from:

1. dstack decrypts `.encrypted-env` to `/dstack/.host-shared/.decrypted-env` on
   the guest filesystem, keeping only names listed in `allowed_envs`.
2. `app-compose.service` reads that file with `EnvironmentFile=`, so the whole
   set lives in the compose process environment, outside every container.
3. A container receives exactly what its own `environment:` block interpolates
   with `${NAME}`.

Interpolation is the partition, which gives two rules:

* **Never bind-mount `/dstack/.host-shared` into a container.** That file is the
  whole set, written with no mode.
  `test_nothing_mounts_the_decrypted_environment` pins this.
* **Every interpolated name must also be in `allowed_envs`**, or it decrypts to
  nothing and the role starts unconfigured.

The current list is 20 names: `EXPECTED_COMPOSE_HASH`, `DEEPSEEK_API_KEY`,
`NEARAI_API_KEY`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`,
`GOOGLE_OAUTH_CLIENT_ID`, `GOOGLE_OAUTH_CLIENT_SECRET`, `POLAR_API_TOKEN`,
`POLAR_ORGANIZATION_ID`, `POLAR_PRODUCT_ID`, `POLAR_CHECKOUT_URL`,
`POLAR_SANDBOX`, `SESSION_SECRET`, `SESSION_SECRET_PREVIOUS`, `LETTERLOCK_HOST`,
`LETTERLOCK_API_HOST`, `LETTERLOCK_COSIGNER_URL`, `WEB_TRUSTED_PROXIES`,
`WEBHOOK_AUD`, `PUBSUB_SERVICE_ACCOUNT`.

`app-compose.json` is written by the Phala CLI at deploy time and is not in this
repository. See finding F4.

What each role is handed:

| Role | Secrets | Volumes | Guest agent socket | Boot gate |
|---|---|---|---|---|
| mail | inference keys, Telegram, Google OAuth pair, all Polar, hostnames, co-signer URL | database, state | yes | yes |
| web | `SESSION_SECRET` and its previous value, hostnames, co-signer URL, bind address, trusted proxies | database, state | yes | yes |
| hook | `WEBHOOK_AUD`, `PUBSUB_SERVICE_ACCOUNT`, bind address and port | state | no | no |
| egress | `TEE_REQUIRED`, bind address | none | no | no |
| ingress | `TEE_REQUIRED`, bind address | none | no | no |

Three decisions in that table that a well meaning edit undoes:

* **`hook` is given no guest agent socket on purpose.** That socket is
  unauthenticated and its `GetKey` call takes a caller supplied derivation path,
  so any process that can open it derives this app's sealing key. Withholding it
  is also why the role runs no boot gate: it has nothing to unseal.
* **`web` does need the socket**, because it obtains a data key to render a
  person's own documents. Its isolation from a Google refresh token is therefore
  a file mode instead: `database/<id>/token.bin` is 0600 owned by the mail uid.
  The consent URL, the code exchange and voice generation all cross to `mail`
  over `backend/custody/handoff.py`.
* **No role is a Polar receiver.** There is no correct value of
  `POLAR_WEBHOOK_SECRET` to inject, so `secrets_checks.ROLE_EXEMPT` names that
  check by name rather than the gate quietly demanding it of somebody.
  Entitlement in the enclave is `confirm_checkout()` plus the 3-hourly reconcile,
  both executed in `mail`.

`egress` and `ingress` deliberately do not inherit the common environment block.
They override `environment:` wholesale, so they get `TEE_REQUIRED` and a bind
address and nothing else. A proxy pointed at itself is the bug that avoids.

`EXPECTED_COMPOSE_HASH` is interpolated rather than written, because its value is
the hash of the file that would contain it. Empty is refused by
`tee_boot._measurement_gap`: an unset value used to return silently, so the
check was on only for whoever remembered to set the variable. Its worth is
bounded, and the docstring says so: the value comes from the enclave's own
environment, so it catches the deploy that published one compose and booted
another. The statement no operator can forge is `cosigner/allowlist.json`, on
the other machine.

---

## 4. The compose file is the partition, and it is measured

`deploy/phala/docker-compose.yml` is not a convenience file. dstack embeds it in
`app-compose.json`, whose hash is extended as the `compose-hash` launch event
and measured into RTMR3, one of the TDX runtime measurement registers. So which
uid runs which image with which secrets is attested rather than merely
configured. An operator who moves `SESSION_SECRET` into the mail container
changes the measurement, and `cosigner/attest.py` stops accepting that enclave's
client certificate.

`tests/test_enclave_boundary.py` pins the file: each role gets exactly the
secrets its gate demands and no more, no role runs as root, each role runs its
own image, supplementary groups match the image's `/etc/group`, nothing mounts
the decrypted environment, the only host path mounted is the guest agent socket,
no `privileged:`, `cap_add:`, `network_mode:`, `pid:`, `userns_mode:` or
`devices:` appears, every `image:` line is a literal digest or the pre-publish
placeholder, no data role has a route off the host, and every role running our
HTTP clients is pointed at the proxy.

---

## 5. The two networks

```
edge   ordinary bridge     ingress, egress                    the only route off the host
inner  internal: true      mail, web, hook, ingress, egress
```

`inner` is declared `internal: true`, so docker installs no route off the host
for it. A container attached to `inner` alone reaches the internet through
`egress` or not at all, and is reached from outside through `ingress` or not at
all. `mail`, `web` and `hook` are on `inner` alone, which is every container
holding a token, a session secret, an inference key or an account's data.

That arrangement is recent and it is what makes the egress allowlist
enforcement. `web` and `hook` used to sit on `edge`, because a published port on
an internal only network never receives forwarded ingress and both roles must be
reachable. On `edge` they had a route out, so for exactly the two roles facing
the internet the allowlist was a pair of environment variables their own HTTP
clients chose to honour, which an attacker with code execution does not.
`backend/daemons/ingress_proxy.py` now holds the published ports and forwards
inward over `inner`. It parses nothing: its routing table comes from
`roles.INGRESS_ROUTES` and is fixed before it accepts a connection.

The one cost is that `web` sees the ingress container as its peer rather than a
browser, which is why `LETTERLOCK_TRUSTED_PROXIES` ships empty. An unnamed proxy
costs a useless audit row; a wrongly guessed one costs a forgeable one.

`backend/daemons/egress_proxy.py` is a CONNECT only proxy on 8792. It publishes
no port and authenticates no caller. The boundary is over destinations, not
callers, and `inner` is what stops a role going around it. TLS is end to end
between the calling role and the destination, so the proxy holds no decrypted
byte.

### The allowlist

`backend/egress_allowlist.json` is generated by `python -m
deploy.render_egress_allowlist` from the modules that already name each host:
`llm_client.PROVIDERS`, `oauth_app`, `telegram.API_ROOT`, both Polar API bases,
both TDX allowlists' PCCS URL, and `site.COSIGNER_HOST`. There is nothing to
forget to edit. `backend/egress.py` reads that file and imports nothing else, so
the one process with a route off the host does not carry the custody stack in
its filesystem in order to compute thirteen strings.

Current contents, 13 hosts: `accounts.google.com`, `api.deepseek.com`,
`api.polar.sh`, `api.telegram.org`, `calendar.google.com`,
`cosigner.morganrivers.com`, `glm-5-2.completions.near.ai`,
`gmail.googleapis.com`, `gpt-oss-120b.completions.near.ai`,
`oauth2.googleapis.com`, `pccs.phala.network`, `sandbox-api.polar.sh`,
`www.googleapis.com`.

Exact matches only, hostnames and never addresses, port 443 only. A redirect
from an allowlisted host to one that is not is refused, because the client opens
a second tunnel and the proxy judges that one on its own.

---

## 6. Volumes, file modes and the handoff socket

`backend/paths.py` is the single source of truth for locations and their modes.
The same module decides modes in the enclave and on the Hetzner server, which is
why `flake.nix` bakes in the group names `letterlock-data` and `letterlock-wake`
verbatim: `paths.py` resolves them with `grp.getgrnam` and sets every mode from
the answer.

Two named volumes:

* `database` at `/app/database`, seeded 2770, owned by uid 10001, group 10010.
  `accounts.json` is the manifest and the only plaintext in it. Every
  `database/<id>/` file is ciphertext.
* `state` at `/app/state`, seeded 2771, same owner and group. Daemon scratch,
  the wake FIFO and both spools.

Docker seeds a named volume from the first container that mounts it, ownership
and mode included, so every image seeds identically and the result does not
depend on start order. `hook` mounts `state` alone, so the account store is not
in its filesystem at all. `egress` and `ingress` mount neither.

The one file that is owner only rather than group readable is
`database/<id>/token.bin`, the wrapped Google refresh token, 0600 to uid 10001.
The web role legitimately holds an account's data key while rendering a
document, and that key would open the token, so the file mode is what makes the
two paths different capabilities.

Behaviour in `paths.py` that keeps multi uid directories from turning permission
decisions into crashes:

* A group lookup that fails, which happens on a laptop, falls back to owner
  only. Every fallback narrows, never widens.
* `chmod_if_owned` and `_adopt_group` are silent for a non owner, because the
  owner set the mode when it created the path.
* `shared_dir(path, mode)` has no default mode, because `audit.py` once took the
  default for `state/` and re-set it from 2771 to 2770, silently cutting the
  Pub/Sub receiver off from its own spool.
* `write_private` creates at 0600 with an explicit `fchmod`, rather than writing
  and then narrowing.

Writable paths that are not volumes are tmpfs mounts, declared per role and all
`noexec,nosuid,nodev`:

* `/tmp` at `1777`, size 64m, in every role. `read_only: true` on the container
  leaves a process nowhere else to put a temporary file, and the standard
  library will reach for one.
* `/app/attestation` at `0700`, owned by that role's own uid, size 4m, in `mail`
  and `web` only. It holds the RA-TLS private key and the boot record. It used
  to be `0777`, because the long `volumes:` syntax takes only `size` and `mode`
  and the directory therefore arrived owned by root. The service level `tmpfs:`
  key takes `uid` and `gid` as mount options, which is the fix.

`noexec` on both, because a writable path a payload can be executed from is the
path it will be written to.

The handoff socket in `backend/custody/handoff_server.py` is a unix socket at
0660 plus a second check: the server reads the connecting process's uid with
`SO_PEERCRED` and admits its own uid and `paths.web_uid()` and nothing else. It
carries the operations the web role may not perform itself: Google token
operations, the chat link flow, the provider list, account deletion, and the
three Polar calls. `HandoffUnavailable` renders 503 and never a local fallback.

---

## 7. Images: what each container carries

`deploy/phala/image_files.nix` is generated, not written:

```
python -m deploy.render_image_manifest [--check]
```

It walks each role's entry points with `tools/reachability.py` and lists exactly
the files reachable from them. Current sizes: mail 72 files, web 52, hook 15,
egress 14, ingress 13.

Function local imports count exactly like top level ones, because a lazy import
still executes. Narrowing a role's reach means moving code, never deferring an
import. That is why `secrets_checks.py` exists as a separate module from
`secrets.py`: the Pub/Sub receiver imports `secrets` for `load()` alone, and
while the presence checks lived in that module the receiver's image carried the
inference client, the Telegram client, billing and the whole custody stack.

`tests/test_image_manifest.py` fails on drift, and additionally refuses any
`deploy/`, `tests/`, `tools/` or `docs/` file, and any shipped `subprocess`,
`os.exec*`, `os.fork` or `eval`.

`flake.nix` turns each manifest into an image: content addressed Nix paths, so a
file shared by two roles is stored once; `chown -R 0:0 ./app` so no role can
rewrite its own code; `/etc/passwd` and `/etc/group` written from the `accounts`
attribute set described in section 1.

`deploy/phala/build_and_publish.sh` builds every role in the manifest, optionally
builds twice and asserts identical hashes, pushes to `${REGISTRY}-${role}`, and
rewrites each `image:` line to a literal `@sha256:` digest.
`test_every_image_is_pinned_by_digest_or_is_the_pre_publish_placeholder` allows
only a literal digest or the pre-publish `:latest` placeholder, never a mutable
tag and never a `${VAR}`, because the compose file is measured and a mutable tag
would let the operator swap the image without changing the measurement.

Current state: all five `image:` lines are still the placeholder. Nothing has
been published.

---

## 8. Process containment

Three layers, in order of strength.

**`execguard.py`**, the seccomp filter each service installs in its own process
from its `if __name__ == "__main__":` block. It sets `PR_SET_NO_NEW_PRIVS` and
then a filter that kills the process on `execve`, `execveat`, `fork`, `vfork`,
`ptrace`, and any `clone` that is not creating a thread. The action is
`SECCOMP_RET_KILL_PROCESS` rather than an errno, because by the time it fires
the process is presumed compromised and an errno is something an attacker
retries around. `restart: always` is what brings the service back. `execveat`
matters as much as `execve`, because without it a payload writes itself to a
`memfd` and never touches a filesystem.

The filter cannot be shipped as a docker `security_opt` profile: dstack ships
and measures `app-compose.json` alone, and `security_opt: seccomp=<path>` is
resolved as a file by the compose client, so a profile named there is a file
that does not exist in the guest. Inline JSON in that field is read as a path
too. So the filter ships inside the measured image instead.

**The container flags**, which cover the processes the filter is not installed
in, currently the entrypoint shell:

* `read_only: true`, so the image's own filesystem cannot be written and a
  payload cannot land beside the code it wants to be mistaken for.
* `cap_drop: [ALL]`. A non root uid has no ambient capability anyway; stating it
  means a future edit to `user:` does not quietly grant fifteen of them.
* `security_opt: ["no-new-privileges:true"]`, which stops a setuid binary
  raising privilege across an exec.
* `pids_limit`, per role: mail 256, web 128, egress 128, ingress 128, hook 64.
  It bounds a fork bomb. It is deliberately not the exec control, because
  `os.execv` in place creates no new task and would pass any ceiling.

**`backend/procwatch.py`**, the detection half. It reads the container's cgroup
rather than scanning `/proc`, because the cgroup is exactly this container's
processes. A process that should not be there is reported to
`backend/intrusion.py`, which the mail daemon drains to Telegram, and then the
process exits with `os._exit` rather than `sys.exit`, because this runs on a
thread where `SystemExit` would end the thread and leave the compromised process
serving.

Every container is now single process, which is what makes that rule one line.
`backend/daemons/scheduler.py` runs the daily summary, the weekly `users.watch`
renewal and the 3-hourly Polar reconcile on a thread inside the mail daemon.
The enclave previously ran supercronic, which started a shell per job, and a
shell is a process the seccomp filter was never installed in. `expected()` is
now `pid == os.getpid()` for all five roles, with no argv allowlist behind it.

What this does not cover: the filter is installed by the service process, so a
kernel or runtime that refuses it leaves a container that can still `execve`.
That is the case procwatch is now the backstop for, and `lock_down` is fatal
under `TEE_REQUIRED` precisely so the enclave is not silently in it.

---

## 9. The boot gate

The entrypoint runs `python -m backend.tee.tee_boot "$role"` before anything
else. `run_gate(role)` checks, in this order:

1. `TEE_REQUIRED` unset means no operation, so a laptop runs.
2. An unknown role is refused. The gate cannot know what to require of a
   container it cannot name.
3. Any secret file present on the volume is refused, listed by path.
4. No guest agent is refused.
5. `EXPECTED_COMPOSE_HASH` unset, or not equal to the running `compose_hash`, is
   refused.
6. `GetTlsKey`, then `GetKey`, then `GetQuote`. `GetTlsKey` is KMS gated, so
   success proves attestation passed and yields the RA-TLS keypair whose
   certificate the guest agent binds to the quote. A refusal here is the
   wrong measurement signal.
7. `secrets_checks.missing(role)`, the secrets that role needs, and
   `CAPABILITIES_BY_ROLE[role]`, the properties of the build and of this
   deployment's configuration.

Only then does it write `boot_info.json` and the RA-TLS material into the
attestation tmpfs and print `attested role=<role>`.

The two tables the gate consults are per role because the compose file answers
per role. A gate applying one whole-deployment set would refuse `web` for having
no inference key and `mail` for having no `SESSION_SECRET`, both by design, and
the obvious fix under time pressure is to give every container every variable,
which is the partition undone.

```
REQUIRED_BY_ROLE     mail: inference, telegram, polar api, google oauth
                     web:  session secret
                     hook, ingress, egress: nothing

CAPABILITIES_BY_ROLE mail: inference attestable, hostnames overridden
                     web:  hostnames overridden
                     hook, ingress, egress: nothing
```

`_host_overridden` exists because `backend/site.py` compiles in the Hetzner
hostnames as defaults. A CVM that does not override them redirects Google's
consent to the other machine's `/auth/callback`, which holds a different session
secret, so either sign-in is refused as "did not start in this browser" or, if
the two ever shared a session secret, the other machine exchanges the
authorization code and takes custody of the refresh token. See finding F2 for
the case this check misses.

`_inference_attestable` asks whether the `dcap-qvl` wheel made it into the image
and whether the provider's enclave is pinned. Without it, a build that dropped
the wheel starts cleanly and refuses every confidential draft at the first email,
with the reason buried in a per draft log line.

---

## 10. The co-signer

The co-signer is a separate service on separate hardware, and separateness is
the point: it holds a file the enclave cannot edit.

**What it holds.** The outer wrapping key and the DPoP signing key, both loaded
through systemd's `LoadCredentialEncrypted=`, which seals them to that host's
TPM and decrypts them into a directory readable only by that unit. It holds no
ciphertext of ours and cannot open one. The outer key is derived per account:
`HKDF(master, salt=handle, info="outer")`, where the handle is an opaque value
the enclave minted and which this service cannot turn back into a person.

**The custody layering**, which is the reason it exists. A record is wrapped
twice. The inner layer is AES-GCM under a data key the dstack KMS releases only
to an attested enclave. The outer layer is the co-signer's. Neither side can
open a record alone. If a change ever makes the co-signer's `unwrap()` return
something the caller can read as a data key, the layer order has been reversed
and that machine has become the single point that can read every mailbox.

**Its surface**, on port 8791, bound to loopback behind a TLS terminator:

```
POST /wrap             {uid, inner}                   -> {outer}
POST /unwrap-and-sign  {uid, outer, htm, htu, nonce?} -> {inner, proof}
POST /sign-dpop        {htm, htu, nonce?, uid?}       -> {proof}
POST /rewrap                                          -> re-wrap under a new key version
GET  /dpop-jwk
GET  /health
```

`/unwrap-and-sign` is one call rather than an unwrap followed by a sign, so the
rate limit counts refreshes instead of half refreshes. `/sign-dpop` exists
because at the authorization code exchange there is no account id yet, so there
is nothing to unwrap and nobody to charge.

**How the enclave authenticates.** TLS is terminated by a proxy configured with
`client_auth { mode require }`, which demands a client certificate and
deliberately checks it against no certificate authority, because the enclave's
certificate is RA-TLS: self signed, with the TDX quote inside it. The proxy
passes it up as base64 DER in `protocol.CLIENT_CERT_HEADER` and
`cosigner/attest.py` verifies the quote. Verification is per TLS connection
rather than per request, because a quote is a boot time measurement and a fresh
RA-TLS keypair is minted at each boot, so an unseen certificate fingerprint is
the correct trigger.

**What it refuses.** `cosigner/policy.py` decides every request and writes its
own audit row, in a log that shares no code with the enclave's. The ceilings:

| Limit | Value | What it is for |
|---|---|---|
| per account per hour | 60 unwraps | a single account being hammered |
| all accounts per hour | 200 unwraps | aggregate volume |
| distinct accounts per 15 minutes | 40 | bulk exfiltration, which looks like every account touched once and reads as normal to both ceilings above |
| `/sign-dpop` per hour | 200 | otherwise the unmetered path around the metered one |
| `/rewrap` per hour | 500 | several complete rotation passes, so an endpoint with no ceiling is not free to use as an oracle |

The distinct account ceiling refuses and alerts rather than tripping a kill
switch, because there is deliberately no bypass in this design and a false
positive would stop mail for everyone until a human cleared it.

`cosigner/retention.py` is the only deleter: allow rows are kept 30 days, deny
rows 365, pruned once a day, with an assert that the allow retention outlives
the rate limiter's own window.

**The enclave checks back.** `backend/custody/client.py`
`_require_attesting_cosigner()` refuses, under `TEE_REQUIRED`, to talk to a
co-signer whose `/health` reports anything but `required` mode. It is not a
proof, since a co-signer that has been taken over answers whatever it likes. It
closes the misconfiguration: the deploy that pins measurements on one machine
and leaves the other in the mode it was built in.

**Availability.** A single co-signer is a hard dependency with no bypass. The
enclave processes no mail at all while it is unreachable, by design.

---

## 11. The three attestation pin files

**`backend/tee/quote_policy.py`** holds the five checks both directions share:
the quote parses and is TDX; report_data carries the binding the caller demands;
measurements match an authorized entry; the signature chains to the Intel root;
TCB status and advisories are allowed. `dev-insecure` mode is refused if the
allowlist names any measurement, and an expiry date is mandatory whenever that
mode is set, because the failure mode of a verification switch left off is
silence.

**`cosigner/allowlist.json`**, inbound: which enclave may unwrap. This is the
file the enclave cannot edit, which is the whole reason for a second machine.
Current state:

```json
"mode": "dev-insecure", "dev_insecure_expires": "2026-11-30",
"quote_oid": null, "binding": "pem-sha256", "measurements": []
```

See finding F1.

**`backend/integrations/inference_allowlist.json`**, outbound: which inference
enclave may see mail. `mode: required`, three NEAR AI measurements pinned
(recorded 2026-08-05 against dstack-nvidia-0.5.5) plus ten `composes` entries
pinned by SHA-256 of the file. The composes list exists because RTMR3 measures
the bootstrap compose and not the model server the manager brings up afterwards,
so replaying the attested action log has to yield only compose files that appear
here. `rt_mr3` is the pin that will fail first, and failing is the point.

---

## 12. Configuration file inventory

| File | Decides | Read by | Guarded by |
|---|---|---|---|
| `backend/roles.py` | the five role names, which hold data, which hold network, which ports the ingress forwards | everything below | module asserts, `test_enclave_boundary` |
| `deploy/phala/docker-compose.yml` | uid, group, secrets, network, volumes, published ports and container hardening per role | dstack; hashed into RTMR3 | `test_enclave_boundary` |
| `flake.nix` | image contents, uid and gid numbers, `/etc/passwd` and `/etc/group`, entrypoint, volume seed modes | `nix build`, `build_and_publish.sh` | partly; see F3 |
| `deploy/phala/image_files.nix` | which source files each role's image carries | `flake.nix` | `test_image_manifest`, generated with `--check` |
| `deploy/phala/IMAGE_HASH.txt` | published tarball hash and registry reference per role | humans | nothing; currently a placeholder |
| `app-compose.json` (not in this repo) | `allowed_envs`, which is which secret names decrypt at all | the Phala CLI at deploy time | only a test's expected list; see F4 |
| `backend/tee/tee_boot.py` | the attest before run gate and its per role checks | the container entrypoint | `test_enclave_boundary`, `test_optimized_controls` |
| `backend/secrets_checks.py` | `REQUIRED`, `REQUIRED_BY_ROLE`, `ROLE_EXEMPT` | the boot gate | module asserts; the boundary test compares against the compose file |
| `backend/secrets.py` | where a secret may come from at all | every service | `test_secrets` |
| `backend/site.py` | hostnames, ports, URLs, trusted proxies | app | asserts; see F2 |
| `backend/paths.py` | on disk locations and their modes, the group names | app and `flake.nix` | shared by both deployments, so drift is a runtime failure |
| `backend/egress.py`, `backend/egress_allowlist.json` | every hostname anything may connect to | the egress proxy | `test_egress` compares the JSON against the live constants |
| `cosigner/allowlist.json` | which enclave measurements may unwrap a token | `cosigner/attest.py` | `test_cosigner`; expiry enforced in `quote_policy` |
| `backend/integrations/inference_allowlist.json` | which inference enclaves may see mail | `inference_attestation.py` | `test_inference_attestation` |
| `requirements.txt`, `deploy/phala/pyproject.toml`, `uv.lock` | what the image installs | `flake.nix` via uv2nix | `test_requirements` fails on drift, `deploy/audit.py` on advisories |
| `setup.cfg`, `tests/test_lint.py` | flake8, isort and bandit policy | CI | `test_lint` |

---

## 13. Open findings

Ordered by what to fix first. None of these is caught by a current test.

### F1. The co-signer currently authenticates nobody

`cosigner/allowlist.json` says `mode: dev-insecure`, with no measurements and a
null `quote_oid`. The TLS terminator demands a client certificate and checks it
against no certificate authority. `attest.verify_client` under `dev-insecure`
returns a passing verdict for any certificate presented, and writes
`attested=0` into every audit row, which is the intended record.

So the control on `POST /unwrap-and-sign` today is not identity. It is: reach
`cosigner.morganrivers.com` with any self signed certificate, possess the outer
blob for an account, and stay under the rate limits, which alert and refuse on a
sweep.

This is the deliberate pre-cutover posture, it expires on 2026-11-30, and
`custody/client.py` makes it impossible to carry into the enclave. It is listed
first because it is the largest gap between what the architecture documents
describe and what is enforced right now, and because the expiry is far enough
out to forget. The remedy is Stage 2.5 of `docs/runbook_provisioning.md`:
populate `measurements`, set `quote_oid` from a live dstack RA-TLS certificate,
confirm `binding`, then set `mode: required`.

### F2. An empty `LETTERLOCK_HOST` passes the boot gate and mints hostless URLs

`backend/site.py` line 35 uses `os.environ.get("LETTERLOCK_HOST",
DEFAULT_APP_HOST)`, which returns an empty string when the variable is present
and empty, not the default. `tee_boot._host_overridden()` only asks whether the
value **equals** the compiled-in default, so an empty value passes.

The compose file interpolates `"${LETTERLOCK_HOST}"` with no fallback, and
docker compose substitutes an empty string for an unset variable rather than
failing. So a name missing from `allowed_envs`, or simply not set at deploy
time, produces a container that passes the gate and then mints
`https:///auth/callback`.

Fix at the single source, so the gate keeps catching it:

```python
APP_HOST = os.environ.get("LETTERLOCK_HOST", "").strip() or DEFAULT_APP_HOST
API_HOST = os.environ.get("LETTERLOCK_API_HOST", "").strip() or DEFAULT_API_HOST
```

An empty value then reads as the default, and `_host_overridden()` refuses,
which is the correct answer: nobody set it.

Compare `gmail_hook_server.py`, whose `assert EXPECTED_AUD.startswith("https://")`
turns the same class of mistake into a crash at import.

### F3. `flake.nix` has no `image-ingress` output, so that image cannot be built or pushed

`flake.nix` names `image-mail`, `image-web`, `image-hook`, `image-egress`, the
`images` link farm and `default`. There is no `image-ingress`.
`build_and_publish.sh` runs `nix build ".#image-$1" --no-link --print-out-paths
2>/dev/null | tail -1` for every role in the manifest, ingress included. stderr
is discarded, so the failure surfaces as an empty path and then a `sha256sum`
error under `set -euo pipefail`. The publish run dies partway through, after
having pushed and re-pinned some roles.

This is exactly the failure `roles.py` was written to prevent, and it survived
because the packages block is the one list not derived from the manifest.

Fix: derive the per role attributes rather than listing them.

```nix
packages.${system} = {
  inherit venv;
  images = pkgs.linkFarm ...;
  default = images.mail;
} // lib.mapAttrs' (role: img: lib.nameValuePair "image-${role}" img) images;
```

Then add an assertion in `test_enclave_boundary.py` that every name in `ROLES`
has an `image-<role>` attribute.

### F4. `allowed_envs` exists only as a Python test's expected set

The 20 names in section 3 must appear in `app-compose.json`, a file the Phala
CLI writes at deploy time and which is not in this repository. Nothing renders
it, and nothing can check it after the fact. The failure mode is a role that
starts successfully with an empty secret. For `SESSION_SECRET` that is a web
tier signing cookies with nothing, and per F2 for `LETTERLOCK_HOST` it is a
whole deployment minting hostless URLs.

The list is already computed inside
`test_the_interpolated_names_are_the_deploy_time_checklist`. Lift it into
`deploy/render_allowed_envs.py` that prints the JSON fragment, have the test
compare against that renderer rather than a literal, and make pasting it a
numbered step in the provisioning runbook.

### F5. Stale references to supercronic and to the crontab (cleared)

Kept as a numbered entry so the references below still resolve. The scheduler
change landed: `flake.nix` has no crontab and no supercronic, `procwatch.py`
expects one process in every role and defines no command allowlist, and the
docstrings in `procwatch.py`, `execguard.py` and the compose file say so.

### F6. Stale build metadata

`deploy/phala/IMAGE_HASH.txt` still carries the pre-merge placeholder text and
an unfilled `appauth-contract` line. `build_and_publish.sh` and several
`flake.nix` comments still say "four roles" and "four images", including "`nix
build .#images` builds all four". Cosmetic next to F3, but it is the same
miscount, and it is what makes F3 easy to miss on a read.

---

## 14. Accepted risks, not defects

Listed so they are not rediscovered as findings.

* **The egress proxy does not authenticate its callers.** The boundary is over
  destinations. The `inner` network is what stops a role going around it.
* **`egress` and `ingress` run no boot gate.** They hold no key to unseal and are
  deliberately given no guest agent socket to run one with.
* **A single co-signer is a hard dependency with no bypass.** The enclave
  processes no mail while it is unreachable, by design.
* **Attestation says which code booted, and nothing about runtime.** A correct
  image subverted by an injection or a side channel still measures correctly.
  The rate limits, the audit log, `execguard.py` and `procwatch.py` are what
  bound that case.
* **`EXPECTED_COMPOSE_HASH` is a claim the enclave hands itself.** It catches a
  deploy mismatch and forges nothing. `cosigner/allowlist.json` is the statement
  an operator cannot forge.
* **The web role can write `database/accounts.json`**, so it can repoint an
  account's Telegram target. Changing that means the manifest stopping being a
  file that role can write.

---

## 15. Cutover checklist

In order, because several of these gate each other.

1. Fix F3, or the ingress image never reaches the registry.
2. Fix F2, or a missing `allowed_envs` entry produces an attested, broken
   deployment instead of a refusal.
3. Rebuild the images. The compose file, `flake.nix` and `image_files.nix` all
   changed with the scheduler, so every measurement in `IMAGE_HASH.txt` and the
   compose hash extended into RTMR3 are stale until this runs.
4. `python -m deploy.render_image_manifest --check`, `python -m
   deploy.render_egress_allowlist`, `python -m deploy.render_pyproject`, then
   `cd deploy/phala && uv lock`. Run the test suite.
5. `REGISTRY=<repo> deploy/phala/build_and_publish.sh --verify --push`. Confirm
   every `image:` line in the compose file is now a literal `@sha256:` digest and
   that `IMAGE_HASH.txt` carries five real rows.
6. Deploy with the Phala CLI. Put all 20 names in `allowed_envs`, including
   `EXPECTED_COMPOSE_HASH`, and set every one of them. Record the AppAuth
   contract address and chain id in `IMAGE_HASH.txt`.
7. Compute the compose hash, set `EXPECTED_COMPOSE_HASH`, redeploy, and confirm
   `tee_boot` prints `attested role=<role>` for `mail` and for `web`.
8. Take a live RA-TLS certificate off the CVM. Confirm the binding
   (`pem-sha256` against `spki-sha256`) and read the quote extension's OID.
9. Fill `cosigner/allowlist.json`: `quote_oid`, then `measurements`, one entry
   per authorized image with `mr_td` never null, then `mode: required`. Deploy
   the co-signer. Its preflight refuses to start if `dcap-qvl` is absent or the
   measurement list is empty.
10. Watch each role's first boot in the CVM. None of this has been run in a CVM
    yet.
