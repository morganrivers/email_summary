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

## Stage 0. One decision to make before anything is deployed

**Which KMS governs the app.** `phala deploy` takes `--kms`, with values
`phala` (default), `ethereum`/`eth`, or `base`. This is not a preference:

- `--kms phala` — Phala's own KMS decides which measurement gets `app_secret`.
  No wallet, no gas, no contract to deploy. There is **no AppAuth contract you
  sign**, so `docs/tee_enclaves_and_upgrades.md` §6.6 step 5 does not exist for
  you and the "authorize in both places" amendment (plan §2) collapses to
  authorizing in the co-signer allowlist only.
- `--kms base` or `--kms eth` — your own AppAuth contract on-chain, authorizing
  measurements under a key you hold, with `--private-key` for the signing
  transactions. This is the arrangement §5 of the TEE doc describes and the one
  §6.6 was written against.

Decide now, not later. `app_secret` is derived from the KMS root, so changing
KMS changes `app_secret`, which changes `K_inner` (plan §I1), which makes every
`token.bin` written under the old KMS impossible to open. The recovery is a
full wipe and re-onboard. That is survivable today, when the owner is the only
account, and it is not survivable once real users exist.

If you want to be running this week, `--kms phala` is the smaller step, and the
plan's core property still holds: the co-signer is on a machine Phala does not
operate, so enclave and co-signer remain separately compromised. What you give
up is control over *who authorizes a measurement*. Move to `--kms base` before
onboarding anyone but yourself, and do it while a wipe is still cheap.

Record the choice at the top of `deploy/phala/IMAGE_HASH.txt` so the next
person does not have to infer it.

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

TLS-ALPN must be disabled for that site or ACME cannot renew a certificate
through `client_auth { mode require }`. The rendered Caddyfile handles this;
confirm it survives any hand-editing you are tempted to do, and note that the
failure shows up 60 days later as an expired certificate rather than
immediately.

The port constant lives in `backend/site.py` (worktree `cosigner-service-1`).
Never hand-edit the Caddyfile.

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
`LoadCredentialEncrypted=` in the unit. Generate them **on the box**: TPM-backed
credentials only decrypt on the host that encrypted them, so generating them on
your laptop produces files the server cannot open.

```bash
ssh root@hezner.morganrivers.com
mkdir -p /etc/letterlock && chmod 700 /etc/letterlock

# Outer wrapping master key (32 bytes). Never leaves this host.
head -c 32 /dev/urandom | systemd-creds encrypt --name=cosigner-master \
  - /etc/letterlock/cosigner-master.cred

# DPoP signing key, EC P-256 (plan §J2).
openssl ecparam -name prime256v1 -genkey -noout -out /dev/shm/dpop.pem
systemd-creds encrypt --name=cosigner-dpop \
  /dev/shm/dpop.pem /etc/letterlock/cosigner-dpop.cred
shred -u /dev/shm/dpop.pem

chmod 600 /etc/letterlock/*.cred
```

`systemd-creds encrypt` defaults to `host+tpm2`, which is what you want and
also what makes this unrecoverable if the box dies. Two consequences:

- The master key cannot be backed up in usable form. Losing the box means every
  `outer` ciphertext is dead and every user re-onboards. That is the intended
  security property, not a bug, but decide deliberately whether you accept it
  before you have users. The alternative is `--with-key=host`, weaker and
  restorable from a disk image.
- The DPoP public key thumbprint (`dpop_jkt`) must be extractable for the
  onboarding flow (plan §I5). Print it once and record it:

```bash
openssl ec -in /dev/shm/dpop.pem -pubout   # before you shred, if you need it now
```

### 1.3 Allowlist, in dev-accept mode

`cosigner/attest.py` reads its measurement allowlist from a config file, not
env (plan §J4). No measurements exist yet. Create the file with an empty list
and the dev flag set, and confirm the flag's assert fires if it is ever set on
a box where `TEE_REQUIRED` is on.

```bash
install -m 600 /dev/null /etc/letterlock/cosigner-allowlist.toml
# populate in Stage 2.6, not now
```

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

### 1.5 Verify

```bash
ssh root@hezner.morganrivers.com 'systemctl status cosigner.service --no-pager'
ssh root@hezner.morganrivers.com 'journalctl -u cosigner.service -n 50 --no-pager'
curl -sS https://<cosigner-host>/health
```

Then confirm the failure mode is the designed one: stop the co-signer and check
the mail path refuses rather than falling back (plan §I2, "no bypass").

```bash
ssh root@hezner.morganrivers.com 'systemctl stop cosigner.service'
# trigger a wake; expect a hard failure and an operator Telegram alert
ssh root@hezner.morganrivers.com 'systemctl start cosigner.service'
```

If mail still gets drafted with the co-signer down, stop. A bypass exists and
the entire design is void.

---

## Stage 2. First Phala CVM (plan Phase 4)

### 2.1 CLI and account

```bash
npm install -g phala
phala login          # NOT `phala auth login`, which is deprecated
phala status
```

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
  --kms <phala|base>          \
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

If `--kms base`, this is where `--private-key` and the on-chain authorization
happen, and where §6.6 step 5 applies.

```bash
phala apps
phala logs -f
```

### 2.6 Close the allowlist — do this before any mail moves

```bash
phala cvms attestation --json > attestation.json
```

Take the compose hash and the measurement registers out of that file, write
them into the co-signer's allowlist on Hetzner, clear the dev flag, restart the
co-signer.

Two fields in `cosigner/attest.py` are deliberately blank and can only be filled
now, from a live certificate: `quote_oid` (dstack's X.509 extension OID carrying
the quote) and whatever the guest agent binds `report_data` to. They were left
empty rather than guessed, because a guessed OID yields a check that passes on
nothing. While they are blank and `mode: required`, `attest.configured()`
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
5. authorize the new compose hash **in the AppAuth contract if you chose an
   on-chain KMS, and in `/etc/letterlock/cosigner-allowlist.toml` always** —
   the allowlist first, before the deploy
6. `phala deploy -c deploy/phala/docker-compose.yml --wait`
7. fetch a fresh quote, check the chain and the measurement against published
   values
