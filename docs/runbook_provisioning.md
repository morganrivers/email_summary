# Runbook: provisioning the co-signer and the Phala CVM

Operator runbook for Phases 3–5 of `docs/plan_token_custody.md` §7b. Follow it
top to bottom with a terminal open. It assumes all five worktrees from §7a have
merged to `main`.

CLI facts here were checked against Phala's live docs on 2026-08-05. The repo
predates a CLI rename: `phala auth login` is **deprecated**, the command is now
`phala login`. `phala deploy` both creates and updates, so
`docs/tee_enclaves_and_upgrades.md` §6.6 step 6 is still correct but assumes a
CVM that already exists.

## Starting state this assumes

- Hetzner box `hezner.morganrivers.com` already running: Caddy installed,
  `/opt/letterlock/.env` populated, `venv/` built, existing units live.
- A Phala Cloud account that has **never been paid for or deployed to**. No
  CVM, no AppAuth contract, no measurements in existence yet.

Consequence of that second point: the co-signer's measurement allowlist has
nothing to put in it until Stage 2 produces the first quote. Stage 1 therefore
brings the co-signer up in dev-accept mode, and Stage 2 closes it. Do not stop
between them and call it done.

---

## Stage 0. The decision, taken: `--kms base`

**Which KMS governs the app.** Decided: **`--kms base`**, an AppAuth contract on
Base under a key the operator holds. Recorded at the top of
`deploy/phala/IMAGE_HASH.txt` and in `docs/plan_token_custody.md` §3. What
follows is why, and what the choice costs at every deploy; it is background now,
not an open question.

### What the choice is between

Something has to hold the list of code versions allowed to run as this app and
receive its keys. The KMS reads that list before releasing anything. The only
question is where the list lives and who may add a line.

- `--kms phala` (the CLI default) — the list is managed by Phala. You sign
  nothing, hold no key, pay no gas and deploy no contract; Phala's CLI only
  demands `--private-key` when a chain is involved, and its own help calls
  Ethereum and Base "on-chain KMS" as against this. Phala can add a line.
- `--kms base` — an AppAuth contract deployed through the KMS factory and owned
  by a wallet key you hold. Adding a version is a transaction you sign. Nobody
  without that key can add one, Phala included, and the list plus every change
  to it is publicly readable. This is what §5 of the TEE doc describes and what
  §6.6 was written against.

The dstack KMS is governed on-chain either way: there is a `KmsAuth` contract,
and the authorization backend answers every release with a live contract read.
What `base` changes is whose contract and whose key decide for *this* app.

### Why it is worth the extra key

Whoever can authorize a measurement can authorize an image that receives
`app_secret`, and `app_secret` derives `K_inner` (plan §I1), which opens the
inner layer of every stored token.

It does not open a mailbox by itself, and that is the co-signer's whole purpose:
the outer layer only comes off for a measurement on the co-signer's own
allowlist, which lives on the Hetzner box and which the enclave cannot edit
(plan §2). So a hostile or compelled Phala still reads no mail. `--kms base` is
depth on the first gate, not the difference between safe and broken. What it
buys is that Phala leaves the set of parties who can run code under this app's
identity, and that the history of authorized versions is something a user can
check rather than something to be taken on trust.

### What it costs, every time

- A funded wallet on Base and gas per authorization. Also one more key whose
  loss matters: lose the AppAuth owner key and no further version can ever be
  authorized, and recovery depends entirely on how the contract is written.
- Two authorizations per upgrade rather than one: the contract, and the
  co-signer allowlist. The co-signer one always comes **first**, or every unwrap
  fails and no mail moves. This is the amendment plan §2 asks for and the reason
  §6.6 step 5 names both places.
- A dependency on the chain being reachable when keys are released. Verified in
  the dstack source rather than assumed: `get_app_key` calls
  `ensure_app_boot_allowed` -> `auth_api.is_app_allowed()` on every request, and
  the Ethereum backend answers with a live `readContract` against `ETH_RPC_URL`,
  with no authorization cache on that path. The blast radius is bounded, though:
  the guest agent fetches the app key once at CVM boot and derives afterwards
  from it locally, so an RPC outage cannot stall a running enclave. It can stop a
  restart or a redeploy from coming back. Plan for that the way the co-signer
  dependency is planned for.

### The part that cannot be changed later

`app_secret` is derived from the KMS root, so changing KMS changes
`app_secret`, which changes `K_inner`, which makes every `token.bin` written
under the old KMS impossible to open. The recovery is a full wipe and
re-onboard. That is why this is settled before anyone but the owner is
onboarded, and it is why moving off `base` later is not a configuration change.

---

## Stage 1. Co-signer on Hetzner (plan Phase 3)

Everything here runs against the existing box. Nothing in this stage touches
the mail path, so it is safe to do while the current system keeps running.

### 1.1 DNS, then the Caddy route

The co-signer needs its **own hostname**, not a path on `API_HOST`: Caddy's
`client_auth` is per-site, so sharing a site would demand a client certificate
from Google's Pub/Sub push too. Create the A record for `COSIGNER_HOST`
(`cosigner.morganrivers.com`) pointing at the box and let it propagate before
anything below.

That record is a manual step at the DNS host and nothing in this repo creates
it. The zone is served by NearlyFreeSpeech (`ns.phx4/phx7.nearlyfreespeech.net`);
add `cosigner` as an A record to `89.167.32.174`, the same address
`letterlock.` and `hezner.` already carry, with no AAAA since neither of those
has one. Confirm with `dig +short cosigner.morganrivers.com` before reloading
Caddy: reloading against a name that does not resolve leaves the site failing
ACME rather than serving.

TLS-ALPN must be disabled for that site or ACME cannot renew a certificate
through `client_auth { mode require }`. The rendered Caddyfile handles this;
confirm it survives any hand-editing you are tempted to do, and note that the
failure shows up 60 days later as an expired certificate rather than
immediately.

The port constant lives in `cosigner/protocol.py` (8791) and is re-exported by
`backend/site.py`, which is what the renderer reads. Never hand-edit the
Caddyfile. As of this writing the committed `deploy/hetzner/Caddyfile` already
matches the renderer, so the first command below should be a no-op; if it is
not, something drifted and that is the thing to look at before scp'ing.

```bash
python -m deploy.render_caddyfile > deploy/hetzner/Caddyfile
scp deploy/hetzner/Caddyfile root@hezner.morganrivers.com:/tmp/Caddyfile.new
ssh root@hezner.morganrivers.com \
  'caddy validate --adapter caddyfile --config /tmp/Caddyfile.new \
   && install -m 0644 /tmp/Caddyfile.new /etc/caddy/Caddyfile \
   && systemctl reload caddy'
```

### 1.2 The two credentials

`cosigner/keys.py` reads both from `$CREDENTIALS_DIRECTORY`, populated by
`LoadCredentialEncrypted=` in the unit. Generate them **on the box**: a
systemd-creds credential only decrypts on the host that encrypted it, so
generating them on your laptop produces files the server cannot open.

The paths are fixed by the two `LoadCredentialEncrypted=` lines in
`deploy/hetzner/cosigner.service`, and the formats by `cosigner/keys.py`: the
master is **base64 text** (`master_key()` rejects raw bytes), the DPoP key a PEM
EC P-256 private key. The commands below are the ones in that unit's header and
that module's docstring; if they ever disagree, the code is right.

```bash
ssh root@hezner.morganrivers.com

# /etc/credstore.encrypted already exists here, 0700 root. Create it if it does not.

# Outer wrapping master key (32 bytes, base64). Never leaves this host.
head -c 32 /dev/urandom | base64 | \
  systemd-creds encrypt --with-key=host --name=cosigner-master \
  - /etc/credstore.encrypted/cosigner-master

# DPoP signing key, EC P-256 (plan §J2).
openssl ecparam -genkey -name prime256v1 -noout | \
  openssl pkcs8 -topk8 -nocrypt | \
  systemd-creds encrypt --with-key=host --name=cosigner-dpop \
  - /etc/credstore.encrypted/cosigner-dpop

chmod 600 /etc/credstore.encrypted/cosigner-*
```

**`--with-key=host` is explicit because this box has no TPM.** It is a Hetzner
vServer; `systemd-creds has-tpm2` answers `partial` with `-firmware -driver`.
The default (`auto`) does not fail on that, it quietly encrypts with the host
key alone and produces files that look TPM-sealed and are not. Naming the mode
makes the weaker guarantee something chosen rather than inherited. What it
means:

- The decrypting key is `/var/lib/systemd/credential.secret`, a file on disk.
  Anything that restores that file restores both credentials: a disk image, a
  snapshot, a backup of `/var`. The master key therefore **is** recoverable, and
  is also exposed wherever those images live. Back the box up accordingly, and
  no product copy may claim hardware sealing for the co-signer while it runs
  here.
- Moving the co-signer to a box with a vTPM is the fix, and it costs no
  re-onboarding: `systemd-creds decrypt` the two files as root, re-encrypt with
  `--with-key=host+tpm2` on the new host. The key material is unchanged, so no
  `outer` ciphertext and no Google-bound refresh token is invalidated. That is
  the point at which the stronger claim (lose the box, lose every token) becomes
  true. Decide which of the two you want before you have users, not after.

The DPoP public key thumbprint (`dpop_jkt`) is needed by the onboarding flow
(plan §I5). Do not derive it by hand from the PEM: the running service publishes
the JWK and the thumbprint together, and that is the copy the enclave uses.

```bash
# after Stage 1.4, on the box
curl -sS http://127.0.0.1:8791/dpop-jwk
```

### 1.3 Allowlist, in dev-accept mode — already in the repo

`cosigner/attest.py` reads its measurement allowlist from a config file, not env
(plan §J4). That file is `cosigner/allowlist.json`, **committed and shipped by
the deploy**, and it already holds `"mode": "dev-insecure"` with
`"measurements": []`. There is nothing to create on the box. Confirm rather than
write:

```bash
grep -n '"mode"\|"measurements"' cosigner/allowlist.json
```

`$COSIGNER_ALLOWLIST` overrides the path if the co-signer ever needs a copy
outside the tree; nothing sets it today, and the unit does not.

Two consequences of it living in the repo. First, Stage 2.6 is a **git commit
plus a deploy**, not an edit on the server: `deploy.sh` rsyncs the tree with
`--delete-after`, so a hand-edited allowlist on the box is reverted by the next
push and every unwrap starts failing. Second, `attest.mode()` asserts
`dev-insecure` is impossible once `measurements` is non-empty or `TEE_REQUIRED`
is set, so the dev window closes itself when the file is populated.

This is the one window where the co-signer will unwrap for an unattested
client. Keep it short and do not deploy the enclave side against it.

### 1.4 Deploy

`deploy/hetzner/cosigner.service` has an `[Install]` section, so `deploy.sh`
derives it automatically. No `SERVICES=` override needed.

```bash
DRY_RUN=1 ./deploy/deploy.sh    # read the unit list, confirm cosigner.service is in it
./deploy/deploy.sh
```

`deploy/preflight.py` checks the credentials load and the allowlist parses
before it restarts anything. A failing preflight leaves the unit alone rather
than restarting it into a loop, so read its output rather than the exit code
alone.

Note what an unprovisioned co-signer costs the rest of the deploy:
`preflight._mail_configured()` calls `_custody_available()`, so if 1.2 was
skipped or botched, `email-daemon`, `email-webhook`, `email-summary` and
`gmail-watch` are all reported unconfigured and left alone too. They keep
running their old code rather than breaking, which is easy to misread as a
successful deploy. Do 1.2 first and read the skip list.

### 1.5 Verify

```bash
ssh root@hezner.morganrivers.com 'systemctl status cosigner.service --no-pager'
ssh root@hezner.morganrivers.com 'journalctl -u cosigner.service -n 50 --no-pager'
ssh root@hezner.morganrivers.com 'curl -sS http://127.0.0.1:8791/health'
```

Health goes over loopback, not the public name: the co-signer's site block is
`client_auth { mode require }`, so `curl https://cosigner.morganrivers.com/health`
cannot complete a handshake without a client certificate, and this laptop holds
none. That failure is the site working. To see the public side is actually up,
check that Caddy asks for a certificate and that ACME issued one:

```bash
openssl s_client -connect cosigner.morganrivers.com:443 </dev/null 2>&1 \
  | grep -i 'Acceptable client certificate\|Verify return code'
```

The startup log line names the mode; `attestation=dev-insecure` plus the
WARNING is expected until Stage 2.6 and nowhere else.

Then confirm the failure mode is the designed one: stop the co-signer and check
the mail path refuses rather than falling back (plan §I2, "no bypass").

```bash
ssh root@hezner.morganrivers.com 'systemctl stop cosigner.service'
# trigger a wake; expect a hard failure and an operator Telegram alert
ssh root@hezner.morganrivers.com 'systemctl start cosigner.service'
```

If mail still gets drafted with the co-signer down, stop. A bypass exists and
the entire design is void.

### 1.6 Exercise custody end to end, still on Hetzner

Optional in the sense that Stage 2 does not depend on it, and worth doing
anyway: it debugs the wire contract, the layer order and the DPoP binding
before a CVM is rented, so the Phala cutover has one new variable instead of
four. Read 1.6a before deciding, because it costs a second re-onboard.

Two values in `/opt/letterlock/.env`, which is server-only and which the deploy
never overwrites:

```bash
LETTERLOCK_DEV_APP_SECRET=<32+ random chars>
LETTERLOCK_COSIGNER_URL=http://127.0.0.1:8791
```

The first stands in for the KMS `app_secret`, since there is no guest agent
here; `wrapping.app_secret()` asserts one or the other exists and refuses both
when `TEE_REQUIRED` is set. The second points the custody client at the loopback
port rather than the public name. That is necessary, not lazy: `cosigner_url()`
would otherwise resolve to `https://cosigner.morganrivers.com`, whose site block
demands a client certificate, and the only thing that can produce one is a
dstack guest agent. Going through Caddy on this box is not a test you can pass.

Then run Stage 3 now rather than later: the old `database/` holds cleartext
tokens in the pre-custody format and nothing reads it any more.

What passing this proves: the protocol codec agrees on both sides, `wrap` and
`unwrap-and-sign` round trip, Google accepts a DPoP-bound refresh at the code
exchange, the rate limit and audit rows behave, no `credentials.json` is written
anywhere, and a draft still appears in Gmail.

What it does not prove, and cannot: anything about attestation. `dev-insecure`
accepts every client, so no measurement is checked, no quote is parsed, and
`dcap-qvl` is not even exercised. The KMS is not involved either. Those are
Stage 2's job and this stage says nothing about them.

Two things to hold in view while it is on. `COSIGNER_BIND` defaults to
127.0.0.1, but on loopback HTTP with `dev-insecure` there is no client
authentication of any kind, so any local process can ask for an unwrap. The
`cosigner` / `letterlock` user split does not help against that; it only keeps
the app from reading the credentials directly. And the dev app secret sits in
`.env` beside `database/<id>/token.bin`, so during this window one disk image
contains both layers and reads every token. That is the whole reason the window
is for your own mailbox and not for anyone else's.

#### 1.6a The second re-onboard, which is not optional

`K_inner` derives from `app_secret`. Under this stage that is
`LETTERLOCK_DEV_APP_SECRET`; after the cutover it is the value the dstack KMS
releases. Different seed, different key, so every `token.bin` written here is
unreadable inside the enclave and cannot be migrated. Stage 3 therefore runs
twice: once now against the dev secret, once again after 2.7 against the KMS.
Fine for one owner account, and the reason not to onboard anyone else before the
cutover.

Delete `LETTERLOCK_DEV_APP_SECRET` from `.env` at the cutover rather than
leaving it. It is dead weight in the enclave (`TEE_REQUIRED` makes
`wrapping.app_secret()` refuse it) but a live key on any box where that flag is
not set.

---

## Stage 2. First Phala CVM (plan Phase 4)

### 2.1 CLI and account

```bash
npm install -g phala
phala login          # NOT `phala auth login`, which is deprecated
phala status
```

Stage 0 chose `--kms base`, so this stage also needs a wallet before anything is
deployed: an EOA on Base holding enough ETH for the AppAuth deployment and for
one authorization per future upgrade. The CLI reads `PRIVATE_KEY` and
`ETH_RPC_URL` (flags `--private-key` and `--rpc-url` win over them), following
the foundry convention:

```bash
export ETH_RPC_URL=https://mainnet.base.org
export PRIVATE_KEY=0x...        # the AppAuth owner key; back it up before use
```

That key is the authority over which code may run as Letterlock. Losing it means
no version can ever be authorized again; a copy of it in the CVM or on the
Hetzner box would put that authority inside a blast radius this design spends
two machines to avoid. It belongs neither place.

Verified accounts get a small CVM credit and one free instance; that may cover
the first deploy without a card, but add payment before relying on it, because
an unpaid instance stopping means no mail moves for anyone. Check real sizes
and prices against the account rather than trusting any number written here:

```bash
phala instance-types
phala nodes
```

The plan sizes this at 2 GB, which assumes the PII analyzer stays off
(CLAUDE.md: Presidio plus spaCy costs about 1.6 GB resident). If you intend to
run the analyzer, size up here and expect the masking mode choice in Settings
to be the thing that decides it.

### 2.2 Regenerate the published hashes

`deploy/phala/IMAGE_HASH.txt` currently holds placeholders invalidated by the
`feat/teespike` merge, and regeneration was previously blocked on build-host
disk space. It must be regenerated before any push or the published-hash claim
is false on day one.

```bash
df -h /nix                                   # this is what blocked it last time
deploy/phala/build_and_publish.sh --verify   # builds twice, asserts identical
```

A non-reproducible result here is a stop condition, not a warning. Fix it
before deploying; the whole audit story rests on it.

### 2.3 Push and pin

```bash
docker login ghcr.io
REGISTRY=ghcr.io/<you>/tee-email-bot deploy/phala/build_and_publish.sh --push
git diff deploy/phala/docker-compose.yml   # confirm image: now carries @sha256:
```

The compose `image:` line must carry a literal digest. A tag or a `${VAR}` there
lets the operator swap the image, which breaks the measurement story.

### 2.4 Sanity-check that measurement actually moves

```bash
deploy/phala/f2_wrong_measurement_test.sh
```

### 2.5 Deploy

Secrets go in as encrypted env, not as a mounted file. `secrets-gate-3` removed
the `env_file: /app/.env` mount from the compose (plan §8), so `-e` is now the
only path in. Phala encrypts these client-side and they decrypt only inside the
CVM.

```bash
phala deploy \
  -n letterlock \
  -c deploy/phala/docker-compose.yml \
  -e .env.tee \
  --kms base                  \
  --private-key "$PRIVATE_KEY" \
  --rpc-url "$ETH_RPC_URL"    \
  --instance-type <from 2.1>  \
  --wait
```

Build `.env.tee` deliberately rather than reusing the server's `.env`. It needs
everything `secrets.REQUIRED` gates on: the LLM keys, the Telegram pair,
`SESSION_SECRET`, the Polar API and webhook credentials, and
`GOOGLE_OAUTH_CLIENT_ID` / `GOOGLE_OAUTH_CLIENT_SECRET`. Run
`venv/bin/python -c 'from backend import secrets; print(secrets.missing())'`
against the same environment if you want the list checked rather than recited.

That last pair is the contents of `gcp-oauth.keys.json`, injected rather than
mounted (plan §8; it did **not** move to the co-signer, and that section says
why). Copy the two values out of the file on the Hetzner box. There is no
`/app/.gmail-mcp` volume in the compose any more, and the boot gate refuses to
start if a key file turns up on the enclave volume at all.

This is where the AppAuth contract is deployed through the KMS factory and the
first `compose_hash` is authorized under your key, and it is where §6.6 step 5
starts applying to every later deploy. Record the contract address next to the
KMS choice in `deploy/phala/IMAGE_HASH.txt`: it is what anyone verifying the
app has to read to see which versions were ever allowed.

```bash
phala apps
phala logs -f
```

### 2.6 Close the allowlist — do this before any mail moves

```bash
phala cvms attestation --json > attestation.json
```

Take the measurement registers out of that file and write them into
`cosigner/allowlist.json` **in the repo**, then commit and deploy. One entry per
authorized image, `mr_td` always pinned, `rt_mr0`–`rt_mr3` pinned or explicitly
`null`; set `"mode": "required"` in the same commit, which is what closes the
dev window (`attest.mode()` refuses `dev-insecure` the moment `measurements` is
non-empty).

```bash
$EDITOR cosigner/allowlist.json
git commit -am 'Authorize the first enclave measurement'
./deploy/deploy.sh                      # restarts cosigner.service
```

Editing the file on the server instead is the trap: `deploy.sh` rsyncs with
`--delete-after`, so the next push reverts it and every unwrap fails.

`mode: required` also needs `dcap-qvl` present in the box's venv —
`attest.configured()` reports the service unconfigured without it and preflight
will refuse to start it. It is pinned in `requirements.txt` and installed by the
deploy when that manifest changes, so verify rather than assume:

```bash
ssh root@hezner.morganrivers.com \
  '/opt/letterlock/venv/bin/python -c "import dcap_qvl; print(dcap_qvl.__name__)"'
```

Two fields in `cosigner/allowlist.json` are deliberately blank and can only be
filled now, from a live certificate: `quote_oid` (dstack's X.509 extension OID
carrying the quote) and `binding`, whatever the guest agent ties `report_data`
to. They were left empty rather than guessed, because a guessed OID yields a
check that passes on nothing. While they are blank and `mode: required`,
`attest.configured()`
reports the service unconfigured and preflight refuses to start it, so this is a
hard gate rather than a silent fail-open. Pull one RA-TLS certificate from the
running CVM, read the extension, and fill both.

Ordering is not negotiable, and it is the single most likely way to break this
system: **the allowlist entry must exist before the enclave tries to unwrap.**
Get it wrong and every unwrap fails and no mail moves. This is also the step
that recurs on every future upgrade, which is why §6.6 step 5 needs amending to
name both places. Add the new hash to the co-signer allowlist *before*
deploying the new image, not after.

### 2.7 Flip the enclave side to real

- `client_auth=True` at the `DstackClient.get_tls_key()` call site (plan §I2
  notes the default stays `False`; change the call, not the default).
- `TEE_REQUIRED=1` is already set in the compose.
- Remove the dev-mode escape hatches: the dev key fallback in
  `wrapping.inner_key()`, the self-signed cert path in `custody/client.py`, the
  attestation stub flag in `cosigner/attest.py`. Each asserts it is only ever
  off in dev; confirm each assert would now fire.

### 2.8 DNS

The webhook receiver moves from the Hetzner loopback port behind Caddy to the
CVM's exposed 8787. `API_HOST` in `backend/site.py` is the only place that
name is written. Cut it over, and confirm the Pub/Sub push subscription's OIDC
`aud` still matches what `gmail_hook_server.py` verifies, since that value is
derived from the same constant.

Do this last. A DNS change while the allowlist is still empty means the webhook
is unreachable and the co-signer is refusing, and you will be debugging two
things at once.

---

## Stage 3. Re-onboard (plan Phase 5)

There is no migration script and deliberately so: Google binds a refresh token
to a DPoP key at the code exchange and cannot bind an existing one
retroactively (plan §3). Every account starts over. Today that is one account.

```bash
# on the box, deliberately and by hand -- deploy.sh never does this
ssh root@hezner.morganrivers.com
systemctl stop email-daemon.service email-webhook.service
mv /opt/letterlock/database /opt/letterlock/database.pre-custody
```

Keep the old directory until the new flow works end to end, then destroy it. It
holds live refresh tokens in cleartext, which is the exact exposure this whole
project removes, so it is not something to leave lying around for a week.

```bash
cd /opt/letterlock && venv/bin/python -m backend.accounts.seed_owner
systemctl start email-daemon.service email-webhook.service
```

Then sign in through `/auth/callback` in a browser like a real user. This is
the first proper test of account creation, which is why the plan prefers the
wipe over a migration.

Verify, in order: the account appears in `database/accounts.json`; a
`token.bin` exists at `database/<email>/token.bin` with mode 0600; **no**
`credentials.json` anywhere under `database/`; one row per unwrap in the
co-signer's audit database; a draft actually appears in Gmail.

```bash
rm -rf /opt/letterlock/database.pre-custody   # only after all of the above
```

---

## Rollback

Stage 1 is reversible: `systemctl stop cosigner.service`, revert the Caddyfile,
redeploy. Nothing depends on it until Stage 2.7.

Stage 2 is reversible up to 2.7 by deploying the previous pinned digest, since
the old measurement is still authorized. Note the trap in
`docs/tee_enclaves_and_upgrades.md` §6.4: rolling back to a measurement you
have since de-authorized means the KMS will not release `app_secret` and the
data is unreadable until you re-authorize it.

Stage 3 is **not** reversible. Once `database/` is wiped and re-onboarded under
the new scheme, the old cleartext tokens are the only way back, and you should
have destroyed them.

---

## What recurs

Everything above is one-time except the upgrade path, which is §6.6 of the TEE
doc plus one amended step:

1. `deploy/phala/build_and_publish.sh --verify`
2. `REGISTRY=... deploy/phala/build_and_publish.sh --push`
3. `deploy/phala/f2_wrong_measurement_test.sh`
4. publish `IMAGE_HASH.txt` and the compose file, tagged as a release
5. authorize the new measurement **in `cosigner/allowlist.json` first (commit
   and `./deploy/deploy.sh`, never a hand edit on the box), then in the AppAuth
   contract on Base** — both, every time, and the allowlist before the deploy or
   every unwrap fails
6. `phala deploy -c deploy/phala/docker-compose.yml --wait` (with
   `--private-key` / `--rpc-url`, as at Stage 2.5)
7. fetch a fresh quote, check the chain and the measurement against published
   values
