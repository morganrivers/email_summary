# TEEs, enclaves, and how you change things without breaking them

**Audience:** you, after this document, should be able to explain to a skeptical
stranger exactly why an attacker (including us, the operator) cannot read user
mail out of the running server, and exactly what happens, cryptographically,
when we ship a new version, move to a bigger machine, or run more than one
machine.

**How to read it.** Sections 1 to 3 are vocabulary and mechanism. Section 4 is
attestation end to end. Section 5 is key management, which is the hinge the
whole thing turns on. Sections 6 to 8 are the parts you actually asked about:
updating code, growing the server, running several of them, and moving data
between enclaves. Section 9 is the honest list of what this does not protect
against. Section 10 is a verification playbook. Section 11 is a glossary you
can skim back to.

**A note on the links.** Links marked with a dagger (†) were collected during
this project's own research pass and appear in `docs/plan.md` and
`docs/R_results.txt`. The rest are canonical primary sources cited by title as
well as URL, so if a URL rots you can still find the document by name. Where I
am citing a paper by title without a stable URL, I say so.

---

## 1. The problem, stated precisely

The product's promise has two halves.

1. **Confidentiality.** Raw email, the pseudonym mapping, and above all the
   Gmail OAuth refresh token are readable only by the program, never by the
   machine's owner, the hypervisor, another tenant, or someone with physical
   access to the DIMMs.
2. **Code identity.** The user can verify that the program holding those
   secrets is byte-for-byte the published open source, not a modified build
   that quietly copies the mailbox somewhere.

Half 1 without half 2 is worthless: a perfectly confidential box running
attacker-chosen code is just an attacker with good hygiene. Half 2 without half
1 is also worthless: proving the code is honest does not help if the operator
can read the memory it runs in.

The refresh token is the load-bearing asset. It grants full raw mailbox access
and bypasses every downstream control we have, including the PII masking in
`backend/masking/pseudonymizer.py`. Everything below exists to keep that one
value inside a boundary.

### The trust substitution

Classic hosting asks the user to trust the operator's promises and processes.
A TEE swaps that for a different, smaller set of trusted parties:

- Intel (or AMD), for the silicon and the signed firmware that implements the
  boundary.
- Intel's attestation service, for the certificate chain that says "this quote
  came from genuine, up-to-date hardware."
- The published source, because you can rebuild it and compare hashes.
- On this stack, additionally Phala's dstack key-management service, for
  refusing to hand keys to unpublished code.

That is a real reduction, not a magic trick. You still trust somebody. The
point is that you no longer trust *us*, and that the parties you do trust are
subject to public scrutiny rather than private assurances.

---

## 2. Cryptography vocabulary, defined as used here

Skip if these are familiar. Each definition is written for how the term is used
later in this document, not in full generality.

**Hash / digest.** A function that eats any number of bytes and emits a
fixed-size fingerprint, e.g. SHA-256 (32 bytes) or SHA-384 (48 bytes). Three
properties matter. It is deterministic (same input, same output, forever). It
is one-way (you cannot go back to the input). It is collision resistant (nobody
can find two different inputs with the same digest). Because of these, a digest
is a usable *name* for a blob of data. When this document says "measurement" or
"hash of the image," it means a digest computed this way.

**Nonce.** A number used once. Its job is freshness. If I ask you for a
signature and let you pick the message, you can replay a signature you captured
last year. If I supply a random nonce that must appear in the signed message,
you cannot have prepared it in advance, so the signature proves something is
happening *now*.

**Symmetric encryption.** One key both locks and unlocks (AES is the standard
example). Fast, but both parties must already share the key.

**AEAD (Authenticated Encryption with Associated Data).** Symmetric encryption
that also detects tampering. Without it, an attacker who cannot read your
ciphertext may still be able to flip bits in it and cause predictable damage to
the plaintext. AES-GCM is the common instance. "Confidentiality plus
integrity."

**Asymmetric / public-key cryptography.** A keypair: a public key you publish
and a private key you never reveal. Anyone can encrypt *to* the public key so
that only the private-key holder can read it. Conversely the private-key holder
can *sign* a message so that anyone with the public key can check the signature.
This is what lets a stranger send a secret into an enclave.

**Digital signature.** Proof that a specific private key endorsed specific
bytes. Verification requires the corresponding public key and tells you two
things: the bytes are unmodified, and the holder of that private key vouched
for them.

**Certificate.** A signed statement binding a public key to an identity or set
of attributes. "Certificate chain" means a sequence of these, each signing the
next, ending at a *root* you decided in advance to trust. Verifying an
attestation quote is, mechanically, chain verification ending at Intel's root
CA.

**MAC (Message Authentication Code) / HMAC.** A signature's symmetric cousin:
a tag computed over a message with a shared secret key. Anyone with the key can
verify, and anyone with the key could have forged it, so it proves origin only
within a trusted pair. This system uses HMAC-SHA256 for session cookies
(`frontend/session.py`), which is why the session secret is a real secret.

**KDF (Key Derivation Function).** A function that takes one master secret plus
some context labels and deterministically produces a fresh key. `KDF(root,
"user-42-disk")` and `KDF(root, "user-42-tls")` give unrelated-looking keys, and
knowing one tells you nothing about the root or the other. This is how a single
hardware root key becomes thousands of purpose-specific keys, and it is exactly
the mechanism that later lets a *new version of the code* re-derive *the same*
key and therefore read the *existing* data.

**Sealing.** Encrypting data with a key that the hardware will only re-derive
for a program matching a stated policy. "Sealed to the measurement" means only
that exact binary can unseal it. "Sealed to the signer" or "sealed to a policy"
means any binary the designated authority approves can unseal it. This
distinction is the single most important design choice for upgradability, and
Section 5 is about it.

**Key wrapping.** Encrypting a key with another key. Used so that a large
encrypted volume never has to be re-encrypted when its access key changes: you
re-wrap the small volume key instead. LUKS keyslots work this way. ! don't get this

**Attestation.** The hardware producing a signed statement of the form "a
program whose measurement is X is running inside a genuine TEE on this
platform, and it asked me to include these 64 bytes of its choosing." Those 64
bytes are the hook that binds attestation to anything else (see `report_data`).

**Quote.** The concrete, transportable artifact of attestation: a binary blob
containing measurements, platform state, the program-chosen `report_data`, and
a signature chain leading to the silicon vendor. Roughly a few kilobytes.

**TCB (Trusted Computing Base).** The set of components whose failure breaks
your security. Smaller is better. In attestation, "TCB level" specifically
means the version/patch state of the CPU microcode, firmware, and TEE module,
and a verifier can and should reject quotes whose TCB is out of date.

**dm-crypt / LUKS.** Linux disk encryption. `dm-crypt` is the kernel layer that
encrypts blocks on the way to disk; LUKS2 is the on-disk metadata format that
records which cipher is used and holds the wrapped volume key in "keyslots."
Relevant here because the enclave's persistent volume is LUKS2, and because
LUKS2's metadata turned out to be attackable in a confidential-VM setting (see
Section 9).

**Reproducible build.** A build process where the same source produces
bit-identical output for anyone who runs it. Without this, "the published hash
matches" only proves you got the binary we handed you, not that the binary
corresponds to the source we published.

---

## 3. What a TEE actually does, mechanically

### 3.1 The core trick: the memory controller lies to everyone else

On an ordinary VM, the hypervisor owns the machine. It can map any guest page
into its own address space and read it. Nothing in software can prevent this,
because the hypervisor is what implements the guest's illusion of memory in the
first place.

Confidential computing changes the hardware so this is no longer true. On Intel
TDX (Trust Domain Extensions), a guest VM can be launched as a **Trust Domain
(TD)**. Its memory pages are encrypted by the memory controller with an
ephemeral key that exists only inside the CPU package and is selected by a
**private HKID** (Host Key ID) that only the TDX Module may assign. Physical
reads of DRAM return ciphertext. Attempts by the hypervisor to map TD private
pages are refused by the CPU through a separate page-table structure (the Secure
EPT) that the hypervisor can request changes to but cannot unilaterally
subvert. Register state on VM exit is scrubbed rather than handed to the host.

The referee enforcing all this is the **TDX Module**, a piece of Intel-signed
code running in a special CPU mode (SEAM, Secure Arbitration Mode) that is
loaded by an authenticated code module at boot. It is not part of the
hypervisor and the hypervisor cannot modify it.

- Intel TDX documentation hub:
  <https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/documentation.html>
- TDX Module source and specifications: <https://github.com/intel/tdx-module>
- AMD's equivalent, SEV-SNP, for comparison ("SEV-SNP: Strengthening VM
  Isolation with Integrity Protection and More"):
  <https://www.amd.com/system/files/TechDocs/SEV-SNP-strengthening-vm-isolation-with-integrity-protection-and-more.pdf>
- Confidential Computing Consortium, for vendor-neutral definitions:
  <https://confidentialcomputing.io/>

The important consequence for us: **the process boundary moves from "the OS
says so" to "the memory controller says so."** An operator with root on the
host, a malicious co-tenant, and a technician with a screwdriver all end up
looking at ciphertext.

### 3.2 SGX vs TDX, briefly, because the words get mixed

- **SGX** (older) protects a *slice of a process*: you compile a special enclave
  binary, and only that binary's code runs protected. Everything outside,
  including the OS, is untrusted. Very small TCB, very painful to program.
- **TDX** (what we use, through Phala) protects *a whole virtual machine*. You
  run an ordinary Linux guest and ordinary containers inside it. The TCB now
  includes that guest kernel and userland, which is larger, but it means an
  existing application (this one) can be lifted in without rewriting it against
  an enclave SDK.

Both terms get called "enclave" colloquially. In this repo, "enclave" means the
TDX confidential VM (CVM).

### 3.3 Measurement: how the hardware knows what is running

As a TD boots, the hardware records what was loaded into a set of registers that
software cannot arbitrarily set:

- **MRTD** is the measurement of the TD's initial memory contents, computed
  during the build of the TD before it starts executing. Think "hash of the
  initial image."
- **RTMR0 to RTMR3** are runtime-extendable registers, analogous to TPM PCRs.
  Extension is one-way: `RTMR_new = SHA384(RTMR_old || new_value)`. You can add
  to the record, never rewrite it. Early RTMRs cover firmware, kernel, initrd,
  and kernel command line; the last one is available for the application layer.

dstack uses the application-layer register to record its own identity values, so
the quote ends up carrying not just "this is a Linux VM" but "this is app X
running compose file Y." The fields the guest agent exposes (see
`backend/tee/dstack_client.py`) are exactly these:

| Field from `/Info` | Meaning |
| --- | --- |
| `os_image_hash` | which dstack guest OS image booted |
| `compose_hash` | hash of the docker-compose manifest, which pins the app image digest, ports, env, and volumes |
| `app_id` | the stable identity of *this application*, fixed at first deployment |
| `instance_id` | this particular running CVM |
| `mr_aggregated` | a combined measurement rollup for convenient comparison |
| `key_provider_info` | who provisioned the keys (which KMS, or a local provider) |

Note carefully that `compose_hash` covers the compose file, and the compose file
pins the container image **by digest**. That is why
`deploy/phala/docker-compose.yml` carries this comment and why it matters:

> It must carry a literal `@sha256` digest in production (not a tag): the
> compose file is measured into the dstack attestation, so a mutable tag or a
> `${VAR}` would let the operator swap the image and break the trust story.

A tag like `:latest` is a *pointer*, and pointers can be repointed after
measurement. A digest is the content itself. If you take one operational rule
away from this document, take that one.

- dstack architecture writeup †:
  <https://phala.com/posts/dstack-a-zero-trust-framework-for-confidential-containers>
- dstack paper, arXiv:2509.11555 †: <https://arxiv.org/pdf/2509.11555>
- dstack source: <https://github.com/Dstack-TEE/dstack>

---

## 4. Attestation, end to end

This is the part people hand-wave. Here is the actual chain.

### 4.1 Inside the TD

The application asks for a quote and supplies up to **64 bytes of
`report_data`** of its own choosing. In our code:

```python
# backend/tee/dstack_client.py
def get_quote(self, report_data: bytes | str) -> dict:
    rd = report_data if isinstance(report_data, str) else report_data.hex()
    assert len(bytes.fromhex(rd)) <= 64, "report_data must be <= 64 bytes"
    return self._request("POST", "/GetQuote", {"report_data": rd})
```

The TDX Module produces a **TDREPORT**: a structure containing MRTD, the RTMRs,
the TD's attributes, and those 64 bytes, authenticated with a MAC key that only
CPU-internal parties hold. A TDREPORT is locally verifiable only; it proves
nothing to a remote party yet, because a remote party does not have that MAC
key.

### 4.2 Turning a local report into a remotely verifiable quote

A special enclave on the same machine, the **Quoting Enclave**, verifies the
TDREPORT's MAC (it can, being local) and then re-signs the contents with an
**attestation key** using ECDSA. That attestation key's certificate chain leads
to a **PCK certificate** (Provisioning Certification Key) issued by Intel for
that specific CPU at that specific TCB level, and from there to the **Intel SGX
Root CA**.

This is Intel's DCAP (Data Center Attestation Primitives) flow, and it is the
reason attestation works without phoning Intel on every request: the certs can
be cached locally in a PCCS.

- DCAP source and specs: <https://github.com/intel/SGXDataCenterAttestationPrimitives>
- Intel Trusted Services API portal (PCS endpoints, TCB Info, QE Identity):
  <https://api.portal.trustedservices.intel.com/>

### 4.3 What a verifier must check

A quote is not "valid" or "invalid" in one bit. A correct verifier checks all of:

1. **Signature chain** from the quote up to the Intel root CA, with the
   intermediates not revoked.
2. **TCB status** for that platform, fetched as signed TCB Info from Intel. If
   the CPU is missing microcode patches, the quote is genuine but the platform
   is `OutOfDate`. Deciding whether to accept that is policy, and "TCB recovery"
   is the name for the process by which Intel raises the required level after a
   vulnerability.
3. **QE identity**, that the Quoting Enclave itself is the expected Intel-built
   one at an acceptable version.
4. **Measurements**, that MRTD/RTMRs (or the dstack-level `compose_hash` and
   `os_image_hash` derived from them) equal the *published* values.
5. **`report_data`**, that the 64 bytes equal whatever you demanded, typically a
   fresh nonce and/or a hash of the public key you are about to encrypt to.

Steps 1 to 3 prove "genuine, healthy hardware." Step 4 proves "the code we
published." Step 5 proves "this quote is fresh, and it is bound to *this*
channel." All five are needed. Step 4 without step 5 is trivially defeated by
replay; step 5 without step 4 tells you a channel is live but not what is on the
other end.

### 4.4 RA-TLS: binding attestation to a channel

There is a classic attack on naive attestation. The attacker runs a decoy
server, and when challenged, relays the challenge to a genuine honest enclave
elsewhere, returns the honest quote, and thereby "proves" it is trustworthy
while actually holding your data in cleartext. This is the confidential-computing
version of a relay attack on a contactless card.

The fix is to make the quote useless unless you also hold the private key that
terminates the connection. **RA-TLS** does this: the enclave generates a
keypair at boot, the private key never leaves enclave memory, and the *hash of
the public key* is placed in `report_data`. The quote is then embedded in the
X.509 certificate the enclave serves. A client validating the TLS handshake
checks that the certificate's public key hash matches the `report_data` in a
valid quote with the expected measurement. A relayed quote now fails, because
the decoy does not possess the corresponding private key.

Our boot gate does exactly this shape:

```python
# backend/tee/tee_boot.py
tls = client.get_tls_key(subject=RA_TLS_SUBJECT)
client.get_key(APP_KEY_PATH, purpose="seal")
leaf = (tls.get("certificate_chain") or [""])[0]
quote = client.get_quote(_report_data_for_cert(leaf))
```

where `_report_data_for_cert` is `sha256(cert_pem)`. The private key is written
to a **tmpfs** mount, so it lives in RAM and never touches the persistent
volume:

```yaml
# deploy/phala/docker-compose.yml
- type: tmpfs
  target: /app/attestation
```

- RA-TLS, Knauth et al., "Integrating Remote Attestation with Transport Layer
  Security", arXiv:1801.05863: <https://arxiv.org/abs/1801.05863>

### 4.5 Attestation as a gate, not a formality

The design decision recorded in `docs/plan.md` is that attestation is a
**machine-to-machine gate**, not a per-email handshake. There is no human
client in the Gmail Pub/Sub push path, so a per-message quote would be a
signature nobody reads. Instead:

- The KMS refuses to release secrets to an unauthorized measurement. That is the
  enforcement.
- An on-demand endpoint (Track G, not yet built) lets a dashboard or an auditor
  request a fresh quote whenever they like. That is the transparency.

And the gate fails closed. From `flake.nix`:

```bash
if ! python -m backend.tee.tee_boot; then
  echo "tee_boot gate failed; refusing to start services" >&2
  exit 1
fi
```

`tee_boot.run_gate()` returns non-zero if the socket is missing, if the KMS
refuses, or if the post-attestation secrets were not injected. It refuses to
touch a mailbox without proof. That is the correct default for a system whose
whole selling point is custody of a token.

---

## 5. Key management: the hinge

Now the part that determines whether you can ever ship version 2.

### 5.1 The naive design, and why it traps you

The obvious way to protect data at rest in an enclave is to seal it to the
measurement: encrypt with a key the hardware only re-derives for a program whose
hash equals X. This is beautifully tight. It is also a trap, because the moment
you fix a bug, the hash is no longer X, and the new version cannot read a single
byte of the old version's data. Every user's refresh token, every pseudonym
mapping, every voice profile becomes unrecoverable ciphertext. You have built a
system that can never be patched, which in practice means a system that runs
known-vulnerable code forever.

Every real deployment therefore needs indirection: seal to *an authority that
decides which measurements count as "this application"*, rather than to a single
measurement. SGX offered a primitive version of this by letting you seal to
MRSIGNER (the signing key) instead of MRENCLAVE (the exact binary), but that
just moves total power to whoever holds the signing key, with no public record
of what they approved.

### 5.2 What dstack does instead

dstack splits identity into two levels:

- **`app_id`**: the durable identity of the application, established at first
  deployment. It does not change when you ship new code.
- **`compose_hash`**: the identity of the exact configuration and image
  currently running. It changes on every code change.

Keys are derived from a KDF over the KMS root key plus the deployer identity
plus the app identity plus an epoch, roughly:

```
app_key = KDF(RootKey, deployer_id, app_id, ..., epoch)
```

and the derived material lands inside the guest (dstack writes it to
`/dstack/.appkeys.json`), including the `disk_crypt_key` used for the LUKS2
volume. The host never holds that key; it sees LUKS2 ciphertext.

Release is conditional. The KMS itself runs inside its own TEE, and it decides
whether to release `app_key` by checking the requesting CVM's quote against an
authorization policy: is this `compose_hash` on the allowlist for this `app_id`?
The allowlist lives in on-chain contracts, with a `KmsAuth` contract governing
the KMS and OS measurements and a per-application `AppAuth` contract governing
which compose hashes may run as that app. Changes are transactions, which means
they are public and after-the-fact auditable rather than a silent config edit.

- Phala key management protocol †:
  <https://docs.phala.com/phala-cloud/key-management/key-management-protocol>

Three consequences, and they are the whole answer to your question:

1. **Upgrades work.** Add the new `compose_hash` to `AppAuth`, deploy, and the
   new image derives the *same* `app_key`, so it mounts the *same* encrypted
   volume and every user stays logged in and connected.
2. **Attacks do not.** A modified image has a different `compose_hash`, is not
   on the allowlist, and gets a refusal. That is the `FAIL-CLOSED` branch in
   `tee_boot.py` and the thing `deploy/phala/f2_wrong_measurement_test.sh` is
   built to demonstrate empirically.
3. **The allowlist owner is the real trust anchor.** Whoever holds the AppAuth
   owner key can authorize a new measurement that reads all existing data. That
   is not a flaw so much as a relocation: security now rests on custody of that
   key plus the public visibility of changes. `docs/R_results.txt` R2 flags this
   precisely: the guarantee holds "only if you hold the AppAuth owner keys and
   deploy under a contract-owned KMS."

### 5.3 Secrets that are not derived: injection after attestation

Some secrets cannot be derived, because they come from outside: the LLM API key,
the Telegram bot token, the Google OAuth client secret, the Polar keys. These
are **encrypted to the app's KMS key and injected as environment variables that
only decrypt inside an attested CVM**. They are deliberately *not* baked into
the image, because the image is public and its hash is published.

`tee_boot.py` refuses to start if attestation succeeded but the secrets are
absent:

```python
gaps = secrets.missing()
if gaps:
    for reason in gaps:
        print(f"[tee_boot] FAIL-CLOSED: attested but not provisioned: {reason}")
    return 1
```

`backend/secrets.py` is what `missing()` consults, and it decides presence by
calling the same code the services call (`PolarBilling()`,
`telegram.operator_target()`, `oauth_app.load_keys()`) wherever presence is a
judgement rather than a lookup. `deploy/preflight.py` applies those same checks
per unit on the Hetzner box, so a value the deploy skips a unit for is the value
the enclave fails closed on.

Injection is the *only* route in. The compose file mounts neither `.env` nor
`.gmail-mcp`, and `secrets.volume_secrets()` names both files as ones whose mere
presence fails the gate: a cleartext secrets file next to the encrypted ones is
a copy the KMS does not gate and the measurement does not cover. The loaders
agree with the gate rather than restating it -- `secrets.load()` reads no `.env`
under `TEE_REQUIRED`, and `oauth_app.load_keys()` refuses the key file there --
so the Google OAuth client secret, the one value with the widest blast radius,
arrives as `GOOGLE_OAUTH_CLIENT_ID` / `GOOGLE_OAUTH_CLIENT_SECRET` or not at
all.

### 5.4 The one moment the token is exposed

Worth stating plainly because it is the weakest link in the current design and
`docs/plan.md` already flags it: during Google OAuth, the authorization code is
exchanged for a refresh token, and whoever performs that exchange holds the
token in cleartext for an instant. The single-container webapp design in
`docs/plan_webapp.md` resolves this the right way, by doing the exchange
*inside* the enclave (`/auth/callback` in `frontend/web_server.py`), so the
token is born inside the boundary and never exists outside it. If the exchange
were done by an outside control plane, that plane would have to encrypt the
token to the enclave's public key immediately and never persist it, which is
strictly worse because it is a promise rather than a mechanism.

---

## 6. Updating the code without losing the data

This is the routine you will run dozens of times. Each step exists for a
reason; skipping one either breaks the deploy or, worse, silently breaks the
trust story.

### 6.1 The pipeline

```
source change
  -> nix build            (deterministic image tarball; hash H)
  -> docker push          (registry re-packs layers; digest D, different from H)
  -> pin D into compose   (compose file now names exact content)
  -> compose_hash C       (derived from the compose file; this is the measured identity)
  -> publish H, D, C      (so third parties can rebuild and compare)
  -> authorize C in AppAuth  (on-chain, observable)
  -> deploy               (new CVM boots, quotes, KMS checks C, releases app_key)
  -> volume mounts, app resumes with all existing user data
```

`deploy/phala/build_and_publish.sh` already documents the three-hash confusion
explicitly, and it is worth internalizing because people conflate them
constantly:

| Hash | What it is | Who cares |
| --- | --- | --- |
| tarball sha256 | hash of the Nix build output | auditors rebuilding from source |
| registry digest | what the CVM actually pulls | the compose file, pinned |
| dstack measurement / compose_hash | what the KMS gates on | the KMS and the attestation verifier |

They are different values by construction (a registry re-packs layers), and the
job of Track G is to publish the mapping between them so an auditor can walk
from "I rebuilt the source" to "the quote I just fetched matches."

### 6.2 Why reproducibility is load-bearing here, not a nicety

Without a reproducible build, the published hash proves only that the running
code is *the binary we handed you*. With it, an independent party runs `nix
build`, gets a bit-identical tarball, and can therefore assert that the running
measurement corresponds to *the source we published*. That upgrades the claim
from "trust our binary" to "trust the source you can read."

`build_and_publish.sh --verify` builds twice and asserts equality. The honest
caveat recorded in `docs/plan.md` is that this has been verified same-machine
but not yet cross-machine from a clean checkout, and cross-machine is the one
that actually matters, because same-machine reproducibility can be an artifact
of a warm Nix store.

- Reproducible Builds project: <https://reproducible-builds.org/>
- `SOURCE_DATE_EPOCH` specification:
  <https://reproducible-builds.org/docs/source-date-epoch/>

### 6.3 The measurement is more sensitive than you expect

`compose_hash` covers the whole compose manifest. That means these all change
the measurement and all require re-authorization:

- any source file inside the image (a one-byte change is enough, which is what
  `f2_wrong_measurement_test.sh` proves locally),
- a dependency bump, including transitively through `uv.lock` or
  `package-lock.json`,
- a port mapping, a volume, an environment variable name in the compose file,
- the base OS image, i.e. a dstack version upgrade.

Note the entry in `flake.nix` that whitelists file types into `appCode`:

```nix
(lib.hasSuffix ".py" base && !(lib.hasPrefix "test_" base))
|| lib.hasSuffix ".mjs" base
|| lib.hasSuffix ".css" base
|| base == "package.json"
|| base == "package-lock.json"
```

This filter is a security-relevant surface in its own right. Anything not
whitelisted is silently absent from the measured image, which is how you ship a
web UI with no stylesheet, or worse, believe a file is measured when it was
never included. `docs/plan_webapp.md` Track U10 caught exactly this class of
bug before it shipped.

### 6.4 Rollback, and the trap in it

Rolling back is deploying an older `compose_hash` that is still authorized. Two
things to keep in mind.

First, **rollback is only possible if the old hash is still on the allowlist**,
so your authorization policy should not aggressively prune. Second, and more
subtly, **an attacker who can force a rollback can revive a patched
vulnerability**. If version N had a bug that leaked mail and version N+1 fixed
it, leaving N authorized means the fix is optional. Good practice is to
de-authorize measurements with known security defects deliberately, and to treat
that de-authorization as part of the security release, not as cleanup. Because
authorization changes are on-chain, users can see when you do and do not do
this.

### 6.5 Where the epoch comes in

The key derivation includes an epoch. Rotating the epoch re-derives all app
keys, which is what you want after a suspected compromise. It is also
destructive if you do it without a re-encryption plan, since data encrypted
under the old epoch key needs to be read with the old key and rewritten with the
new one. Treat epoch rotation as a migration with a maintenance window, not as a
config flip. See Section 8.3.

### 6.6 A concrete checklist

This is the *update* path and assumes a CVM that already exists, an
authenticated CLI, and (if you chose an on-chain KMS) a deployed AppAuth
contract. First-time provisioning of both boxes is
`docs/runbook_provisioning.md`.

Note also that step 5 gains a second place to authorize once the split-custody
work lands: the co-signer keeps its own measurement allowlist, which the
enclave cannot edit, and an unlisted measurement means every unwrap fails. See
`docs/plan_token_custody.md` §2.

Command note: `phala auth login` is deprecated; the command is now
`phala login`.

```bash
# 1. build reproducibly and record the tarball hash
deploy/phala/build_and_publish.sh --verify

# 2. push and pin the digest into the compose file (rewrites the image: line)
REGISTRY=ghcr.io/<you>/tee-email-bot deploy/phala/build_and_publish.sh --push

# 3. confirm a one-byte change really moves the measurement (sanity, local)
deploy/phala/f2_wrong_measurement_test.sh

# 4. publish IMAGE_HASH.txt + the compose file in the repo, tagged as a release

# 5. authorize the new compose_hash: in the co-signer allowlist ALWAYS (before
#    the deploy), and in your AppAuth contract if you run an on-chain KMS
#    (human, on-chain)

# 6. deploy
phala deploy -c deploy/phala/docker-compose.yml

# 7. verify from outside: fetch a fresh quote, check the chain and the
#    measurement against the published values
```

Step 5 is the one no script can do for you, and it is the one that carries the
security weight. Note also the currently-stale state recorded in
`deploy/phala/IMAGE_HASH.txt`: the hashes there are placeholders invalidated by
the `feat/teespike` merge, and regeneration was blocked on build-host disk
space. Nothing live depends on them yet, but they must be regenerated before any
push, or the published-hash claim is false on day one.

---

## 7. Making the server bigger, and making more of them

### 7.1 Vertical scaling: a bigger CVM

Giving the CVM more vCPUs or more RAM is the easy direction. Points to know:

- The application measurement (`os_image_hash`, `compose_hash`, `app_id`) is
  **independent of machine size**. Resizing does not require re-authorizing your
  app in AppAuth, and it does not change the code identity a user is verifying.
- The quote does, however, describe the TD's configuration, and some of the
  low-level fields (TD attributes, and MRTD, since the initial memory image
  depends on how the VMM constructs the TD) can differ across configurations.
  This matters for how you present verification: a dashboard that compares
  *raw* hardware-level values against a hardcoded expected string will
  false-alarm after a resize. Compare at the app identity level
  (`compose_hash`, `os_image_hash`, `app_id`) and treat platform fields as
  policy checks (genuine, TCB up to date) rather than equality checks.
- You are also changing physical hosts, most likely, since a resize usually
  means a new machine. That is a migration, covered in Section 8.
- Practical ceiling: TDX memory is encrypted and integrity-protected, so there
  is a real, if modest, performance cost versus a plain VM, and the number of
  simultaneously-live TDs on a host is bounded by the number of available HKIDs.
  Neither is likely to bind before your application logic does.

For this specific app, the resource hogs are the spaCy model
(`en_core_web_lg`) held in memory by the masking pipeline and the concurrency of
LLM calls. Vertical scaling handles a surprising amount of load before anything
else needs to change, which is a good reason to exhaust it first.

### 7.2 Horizontal scaling: several CVMs, one app

The cryptographic side is the easy part, and this is the payoff of Section 5.2:
because keys derive from `app_id` and not from `instance_id`, **two CVMs running
an authorized measurement of the same app derive the same `app_key`.** They can
therefore read the same sealed data, terminate sessions signed with the same
secret, and decrypt the same injected environment secrets. No bespoke
enclave-to-enclave key exchange protocol is required. Contrast this with a
design sealed to a per-instance key, where adding a second node would demand a
full mutual-attestation handshake and a hand-rolled secret transfer.

The hard part is the application, and this codebase currently has four
single-writer assumptions that would break immediately under two instances:

1. **The account store is a JSON file.** `backend/accounts/account.py` reads
   the manifest and does `MANIFEST.write_text(json.dumps(data, indent=2))`.
   Two processes doing read-modify-write on the same file will lose updates and
   can produce a truncated file. It is a correct design for one writer and an
   incorrect one for two.
2. **The wake queue is a local spool.** `wake_queue.jsonl` plus a FIFO plus a
   lock file are per-machine constructs.
3. **The per-user cursor** (`historyId`) is per-user state that must have
   exactly one owner, or two instances will both fetch the same Gmail delta and
   double-draft.
4. **The Gmail push webhook is one endpoint.** Fine, but it must route.

The natural design, and it fits what is already built, is **sharding by user**:

- Keep the single Pub/Sub topic and the single-topic fan-in routing already
  decided in `docs/plan.md` (B4). The push payload carries `emailAddress`, and
  the OIDC JWT proves it came from Google.
- Put a thin, stateless front CVM in the push path whose only job is JWT
  verification and routing: `shard = hash(emailAddress) % N`.
- Give each shard exclusive ownership of its users' account entries, cursors,
  and creds directories. Then the existing per-user isolation asserts (B5) do
  double duty: they already assert that a mapping or state object belongs to the
  expected user, and under sharding they additionally catch a misrouted wake.
- Because each user's data has exactly one writer, the JSON-file store remains
  correct, and you have bought horizontal scale without introducing a database
  into the measured image, which would enlarge both the attack surface and the
  measurement.

Two things to fix before this works, both cheap and both worth doing now:

- **`SESSION_SECRET` must be derived, not random per instance.**
  `frontend/session.py` signs cookies with `SESSION_SECRET`, which
  `backend/secrets.py` requires from the environment.
  If each CVM gets a different value, users get logged out whenever they land on
  a different instance, and also on every redeploy. The right source is the KMS:
  `DstackClient.get_key("tee-email-bot/session")` yields the same value for every
  authorized instance of the app and never exists outside an attested CVM. That
  is a one-line change with a large operational payoff. Note the derivation path
  matches the existing `APP_KEY_PATH` prefix in `backend/tee/tee_boot.py` and
  deliberately carries no brand name: changing a derivation path rotates the
  derived key, so anything already sealed under the old path becomes
  unrecoverable. Freeze these strings before the first CVM seals data.
- **The Pub/Sub push target and the browser-facing hostname become one
  load-balanced front.** Note that whatever terminates TLS in front of the
  enclaves is *outside* the attested boundary, which weakens the "the browser
  talks directly to attested code" claim from `docs/plan_webapp.md`. If you care
  about that claim (you should, it is the dashboard green-check), the front tier
  must either be itself an attested CVM doing RA-TLS pass-through, or you accept
  and document that TLS terminates outside and only the *routing* is untrusted.
  This is a genuine design fork, and it deserves an explicit decision rather
  than drifting into it.

### 7.3 What you cannot shard

Anything that is global by nature: the Polar billing webhook, the daily summary
timer, the weekly Gmail watch renewal. These are cron-shaped, low-volume, and
should run in exactly one place. Running `watch_renew.py` on all N shards
simultaneously would re-register watches repeatedly. Simplest correct answer is
to designate shard 0 as the singleton owner of global jobs, since electing a
leader is a distributed-systems problem you do not need to buy at this scale.

---

## 8. Migration: moving an enclave, its data, and its keys

"Migration" covers four different things that get conflated. Separate them.

### 8.1 Moving to a new physical host (the common case)

You stop the CVM on host A and start it on host B. Nothing survives in memory,
by design. What survives is the encrypted persistent volume and the ability to
re-derive the key.

Under dstack this works because the volume key is KMS-derived from `app_id`, not
from host-specific hardware. Host B's CVM boots, attests, presents an authorized
`compose_hash`, receives the same `app_key`, derives the same `disk_crypt_key`,
and mounts the volume. The host operator, on either machine, only ever saw LUKS2
ciphertext.

Contrast with SGX-style hardware sealing, where the sealing key is derived from a
CPU-fused secret. There, data sealed on machine A is *unreadable* on machine B,
full stop, and you need an explicit migration protocol. The choice to centralize
key custody in an attested KMS is what makes host mobility a non-event, and the
price is that the KMS becomes a component you have to trust and would like to see
audited. `docs/R_results.txt` R2 records that the dstack KMS specifically has not
had a dedicated audit, which is the honest gap here.

- dstack audit (zkSecurity, May to June 2025) †:
  <https://phala.com/dstack/dstack-audit.pdf>

### 8.2 Live migration (moving a *running* enclave)

Moving an executing TD, with its encrypted memory, from one machine to another
is a much harder problem: the destination must be proven to be a genuine TEE at
an acceptable TCB level before the source will hand over memory, and the memory
must be re-encrypted under the destination's key without ever appearing in
plaintext to either hypervisor.

Both vendors have answers, and both work by attestation between special-purpose
agents:

- **Intel TDX** uses a **Migration TD (MigTD)**: a minimal TD on each host that
  mutually attests with its peer, agrees a migration session key, and gates the
  transfer. Source: <https://github.com/intel/MigTD>
- **AMD SEV-SNP** uses a **Migration Agent**, an attested guest component that
  performs the equivalent negotiation.

For this product, live migration is a luxury you do not need. The workload is a
mail daemon that already restarts cleanly, keeps its durable state on an
encrypted volume, and coalesces wakes through a spool. Cold migration (Section
8.1) plus a few seconds of downtime is a far smaller trusted-computing-base
addition than a migration agent. Know the mechanism exists; do not adopt it
without a reason.

### 8.3 Migrating the data itself (schema and epoch changes)

Two flavors, both real for this project.

**Schema migration inside the sealed store.** The account store gains fields
constantly (`polar_customer_id`, voice DNA status, calendar-scope flag). The
rule that keeps this safe is already in `docs/plan_webapp.md`: all reads and
writes go through `backend/accounts/account.py`, and nothing edits the JSON
directly. That single source of truth is what lets you write one upgrade
function that runs at boot, inside the enclave, on data only the enclave can
read. Note the sharp edge already recorded in `docs/plan.md`: the
`accounts/` to `database/` rename required a hand-run `mv` on the production
box, because the data is git-ignored and deploy never touches it. Inside an
enclave you cannot do that by hand, because you cannot read the volume. **In a
TEE, every data migration must be code that runs inside the boundary.** Plan for
it explicitly; there is no ssh-in-and-fix-it escape hatch, and that is the
point.

**Key epoch rotation.** Changing the epoch changes every derived key. Data
encrypted under the old key must be read with the old key and rewritten under
the new one, by code that holds both, inside the enclave, once. If you rotate
without that, you have destroyed the data as thoroughly as any attacker could.

### 8.4 Enclave-to-enclave secret transfer (the general pattern)

Even though dstack lets you avoid it, you should understand the pattern, because
it is what you would build if you ever moved off a centralized KMS, and it is
the pattern the KMS itself uses internally.

1. The **destination** enclave generates an ephemeral keypair. The private key
   never leaves.
2. It requests a quote with `report_data = hash(destination_public_key)`, plus a
   nonce supplied by the source for freshness.
3. The **source** enclave verifies the quote: chain to Intel root, TCB
   acceptable, measurement on the authorized list, `report_data` matches the
   presented public key and the nonce it just issued.
4. The source encrypts the secret to that public key and sends it.
5. Optionally the destination confirms receipt, and the source destroys its copy.

Every step maps to a definition in Section 2, and every step is load-bearing.
Drop the nonce and you enable replay. Drop the `report_data` binding and you
enable the relay/decoy attack from Section 4.4. Drop the measurement check and
you will happily hand your users' tokens to an attacker's enclave, which is
genuine hardware running dishonest code.

### 8.5 Backup and disaster recovery, which is where this gets uncomfortable

The property "only attested code can read this" is symmetric: it also means
*you* cannot read it. Consequences worth deciding on before launch, not after:

- **A backup of the encrypted volume is useless without the KMS.** If the app
  keys are unrecoverable, so are all user tokens. Users would need to re-do the
  Google OAuth consent to recover, which is survivable, but you must know that
  is your recovery story and say so.
- **If the KMS root is lost, everything sealed to it is lost.** How dstack's KMS
  handles root-key durability and replication is a question you should answer
  from their docs before depending on it commercially, and it belongs on the same
  checklist as the audit gap.
- **Backups must be re-encrypted for portability, not just copied.** A copy of
  LUKS2 ciphertext plus a key you cannot derive is a paperweight. If you want
  off-platform backups, they need code inside the enclave that exports data
  encrypted to a separately-held recovery public key, and that recovery key then
  becomes the softest target in the entire system. Consider deliberately *not*
  having one, and documenting that as a feature.

---

## 9. What this does not protect against

Being straight about the limits is what makes the strong claims credible.

**Side channels.** Memory encryption hides content, not access patterns. Timing,
cache behavior, page faults, and power/frequency behavior can all leak. The
research record is long and ongoing: Foreshadow (<https://foreshadowattack.eu/>),
Plundervolt (<https://plundervolt.com/>), ÆPIC Leak
(<https://aepicleak.com/>), and for TDX specifically, single-stepping and
instruction-counting work published as "TDXdown" (CCS 2024; cited by title, find
it via the ACM DL). Expect more. TEEs raise cost; they do not make attacks
impossible.

**Physical interposers.** During 2025 a family of attacks demonstrated that
low-cost DDR interposers can break the ciphertext-confidentiality assumptions of
several confidential-computing platforms. Cited by name, since the project pages
are recent and may move: *Battering RAM* and *WireTap*. The takeaway is that
"physically secure against a determined datacenter-resident attacker" is a
weaker claim than the marketing implies, and it should not be the load-bearing
sentence in your copy.

**LUKS2 header malleability.** Directly relevant here, and already tracked in
`docs/plan.md`: CVE-2025-59054 and CVE-2025-58356, found by Trail of Bits. The
LUKS2 metadata header was malleable, so an attacker with disk access could
rewrite the cipher to a null cipher and trick the enclave into writing plaintext
while believing it was encrypting. Fixed in dstack v0.5.4 via header validation.
Two lessons: run a version past the fix (verify at deploy time, R4), and notice
that the durable fix would be to *measure* the header rather than validate it,
because validation is a check while measurement is a proof.

- LUKS2 writeup †:
  <https://securityboulevard.com/2025/10/vulnerabilities-in-luks2-disk-encryption-for-confidential-vms/>
- CVE records: <https://nvd.nist.gov/vuln/detail/CVE-2025-59054> and
  <https://nvd.nist.gov/vuln/detail/CVE-2025-58356>

**Availability.** The operator can always shut it off, refuse to deploy, or
withhold the machine. Attestation gives you integrity and confidentiality, never
availability. There is no cryptographic defense against unplugging.

**The vendor.** Intel signs the TDX module and roots the attestation chain. A
compromised or coerced Intel breaks everything. This is irreducible on this
architecture and should be stated as such rather than buried.

**Bugs inside the enclave.** Attestation proves *which* code runs, not that the
code is correct. A cross-user state bleed in the shared-tenancy design would
leak one user's mail to another with a perfectly valid quote attached. This is
why `docs/plan.md` chose in-process per-user isolation with asserts everywhere,
and why it names the escalation trigger (per-user subprocesses, ultimately
per-user CVMs) rather than pretending the risk is zero.

**The egress path.** The LLM provider sees whatever you send it. The TEE does
not constrain that. **Masking is the actual control**, and it is why
`backend/masking/pseudonymizer.py` and the published recall corpus in
`masking_eval/` matter as much as any of the hardware machinery. A skeptic
should be told the measured recall number, including that it is not 100 percent,
with the deterministic literal-scrub of known identifiers bounding the worst
case.

**Google.** The mailbox lives at Google. The TEE protects the copy in our
custody. It says nothing about the original.

**Pseudonymization is not anonymization.** Under GDPR, masked text whose mapping
still exists is still personal data. The mapping never leaving the enclave is a
strong risk-reduction argument and not a legal exemption.

---

## 10. How a skeptic verifies all of this

The point of the whole architecture is that these steps are available to a
stranger.

1. **Rebuild.** `git clone`, `nix build .#image`, `sha256sum` the output,
   compare to `deploy/phala/IMAGE_HASH.txt`. Two different people on two
   different machines should get the same value.
2. **Read the compose file.** Confirm the `image:` line carries a literal
   `@sha256:` digest, not a tag or a variable. Confirm the digest corresponds to
   the pushed artifact of the build in step 1.
3. **Fetch a live quote** with a nonce of your choosing from the on-demand
   attestation endpoint (Track G).
4. **Verify the quote**: chain to Intel's root, TCB status acceptable, QE
   identity expected, and `report_data` equal to your nonce (and to the hash of
   the TLS certificate you are talking to, for the relay defense).
5. **Compare measurements**: the quote's `compose_hash` and `os_image_hash`
   against the published values for the release you rebuilt.
6. **Read the on-chain AppAuth history.** Which measurements have ever been
   authorized? By whom? Were vulnerable ones de-authorized when patched?
7. **Run the masking evaluator** (`python -m backend.masking.masking_eval.run`)
   against the public corpus and read the recall number yourself.
8. **Run the refusal test.** `deploy/phala/f2_wrong_measurement_test.sh` locally
   proves a one-byte change moves the measurement. The live half, deploying an
   unauthorized measurement and watching the KMS refuse, is the empirical proof
   that the gate is real. Until that has been run once, the gate is a design
   claim rather than a demonstrated behavior. It is currently outstanding.

Steps 1, 2, 5, and 6 together are the actual meaning of "we cannot read your
mail." Not a promise: a chain of comparisons anybody can perform.

---

## 11. Glossary, condensed

| Term | One-line meaning |
| --- | --- |
| AEAD | encryption that also detects tampering |
| `app_id` | durable identity of the application, stable across code updates |
| AppAuth | per-app on-chain contract listing which measurements may run as that app |
| Attestation | hardware-signed statement of what code is running, plus 64 chosen bytes |
| CVM | confidential virtual machine, the whole-VM form of an enclave |
| `compose_hash` | measured hash of the deployment manifest; changes on every code change |
| DCAP | Intel's remote attestation flow using cached certificates |
| Enclave | protected execution region; here, the TDX CVM |
| HKID | host key ID selecting the memory-encryption key for a trust domain |
| KDF | derives many purpose-specific keys from one root secret |
| KMS | key management service; here, itself in a TEE, gating release on attestation |
| KmsAuth | on-chain contract governing the KMS and OS measurements |
| LUKS2 | Linux disk-encryption metadata format holding the wrapped volume key |
| MRTD | measurement of a trust domain's initial memory image |
| Nonce | one-time value proving a response is fresh, not replayed |
| PCK | per-CPU certificate rooting the attestation signature at Intel |
| Quote | the transportable, signed attestation artifact |
| RA-TLS | TLS where the certificate embeds a quote binding the key to the enclave |
| `report_data` | 64 caller-chosen bytes inside a quote; the hook for nonces and key binding |
| RTMR | extend-only runtime measurement register, TPM-PCR-like |
| Sealing | encrypting so only code matching a stated policy can decrypt |
| SEAM | the CPU mode the Intel-signed TDX Module runs in |
| TCB | the set of components whose compromise breaks security; also, patch level |
| TD | trust domain, a TDX-protected VM |
| TDREPORT | locally-verifiable measurement structure, precursor to a quote |

---

## 12. Reference index

Grouped, with the repo-sourced ones marked †.

**Hardware and platform**
- Intel TDX documentation:
  <https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/documentation.html>
- Intel TDX Module: <https://github.com/intel/tdx-module>
- Intel DCAP: <https://github.com/intel/SGXDataCenterAttestationPrimitives>
- Intel Trusted Services API portal (PCS, TCB Info, QE Identity):
  <https://api.portal.trustedservices.intel.com/>
- Intel MigTD (TD live migration): <https://github.com/intel/MigTD>
- AMD SEV-SNP whitepaper:
  <https://www.amd.com/system/files/TechDocs/SEV-SNP-strengthening-vm-isolation-with-integrity-protection-and-more.pdf>
- Confidential Computing Consortium: <https://confidentialcomputing.io/>

**Attestation protocol**
- RA-TLS, arXiv:1801.05863: <https://arxiv.org/abs/1801.05863>

**dstack / Phala**
- Key management protocol †:
  <https://docs.phala.com/phala-cloud/key-management/key-management-protocol>
- Zero-trust framework writeup †:
  <https://phala.com/posts/dstack-a-zero-trust-framework-for-confidential-containers>
- dstack paper, arXiv:2509.11555 †: <https://arxiv.org/pdf/2509.11555>
- dstack audit †: <https://phala.com/dstack/dstack-audit.pdf>
- dstack source: <https://github.com/Dstack-TEE/dstack>

**Vulnerabilities and limits**
- LUKS2 confidential-VM issues †:
  <https://securityboulevard.com/2025/10/vulnerabilities-in-luks2-disk-encryption-for-confidential-vms/>
- <https://nvd.nist.gov/vuln/detail/CVE-2025-59054>
- <https://nvd.nist.gov/vuln/detail/CVE-2025-58356>
- Foreshadow: <https://foreshadowattack.eu/>
- Plundervolt: <https://plundervolt.com/>
- ÆPIC Leak: <https://aepicleak.com/>
- "TDXdown: Single-Stepping and Instruction Counting Attacks against Intel TDX"
  (CCS 2024), cited by title.
- "Battering RAM" and "WireTap" (2025 DDR interposer attacks), cited by title.

**Build reproducibility**
- <https://reproducible-builds.org/>
- <https://reproducible-builds.org/docs/source-date-epoch/>

**Operational context**
- Pub/Sub push authentication:
  <https://cloud.google.com/pubsub/docs/authenticate-push-subscriptions>
- Google API user data policy (restricted scopes):
  <https://developers.google.com/terms/api-services-user-data-policy>
- App Defense Alliance CASA: <https://appdefensealliance.dev/>

**In-repo**
- `docs/plan.md` decisions and track status
- `docs/R_results.txt` research findings R1 to R5
- `backend/tee/dstack_client.py`, `backend/tee/tee_boot.py`
- `deploy/phala/build_and_publish.sh`, `f2_wrong_measurement_test.sh`,
  `docker-compose.yml`, `IMAGE_HASH.txt`
- `flake.nix`

---

## 13. The short version

- Hardware encrypts the VM's memory so the host sees ciphertext. The referee is
  Intel-signed code the hypervisor cannot touch.
- The boot chain records a hash of everything loaded. Attestation is a signed
  export of those hashes plus 64 bytes the app picks.
- Those 64 bytes carry the hash of an enclave-held public key, which is what
  stops a relay attack and gives you RA-TLS.
- Secrets are released by a KMS that is itself in a TEE and checks the
  measurement against an on-chain allowlist first. Refusal is the enforcement
  mechanism, and the app fails closed on refusal.
- Keys derive from `app_id`, not from the exact binary and not from the machine.
  **That single choice is what makes code updates, host moves, and multiple
  instances possible at all**, and it relocates the trust to whoever controls
  the allowlist.
- Updating code means: rebuild reproducibly, pin the digest, publish the hashes,
  authorize the new measurement on-chain, deploy. Data survives because the key
  derivation did not change.
- Scaling up is free from the attestation point of view. Scaling out is free
  cryptographically and costs real work in the app, because the account store,
  the wake queue, and the per-user cursor all assume a single writer. Shard by
  user and derive the session secret from the KMS.
- Migration is mostly a non-event on this stack, because keys follow the app and
  not the hardware. The one thing you cannot do is fix data by hand: every
  migration must be code that runs inside the boundary.
- None of this constrains what you send to the LLM. Masking does. Keep the
  recall number published and honest.
