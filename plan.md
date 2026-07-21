# Plan: monetized, provably-secure email assistant on Phala TEE

## Goal

Turn the current single-tenant email drafting + daily summary system into a
hosted, multi-tenant product whose core promise is: **raw email PII never
reaches the untrusted LLM, and we can prove the server runs exactly the
published open-source code that enforces that.**

Trust model in one line: the user trusts Intel/AMD hardware and public
verifiability, not the operator. Attestation proves code identity; masking is
the technical enforcement; open source + reproducible builds make the masking
auditable.

## Decisions already made

- **Substrate: support BOTH Phala and Scaleway, no preference.** Product code is
  substrate-independent (deploy target is a packaging/config choice, not a code
  change), so both are first-class deployment options the operator/customer can
  choose:
  - *Phala* (Intel TDX, dstack): ~1-day path to attestation + sealed secrets via
    CLI.
  - *Scaleway* (France, EU): EU jurisdiction for raw-email processing.
  - **Verify (parity check, not a tiebreaker):** does Scaleway provide
    confidential computing + hardware attestation? This determines whether both
    deployments carry the same "provably runs the published code" guarantee, or
    whether they are two distinct trust postures — Phala = hardware-attested;
    Scaleway = EU-jurisdiction + open-source trust without a hardware quote.
    Either outcome is acceptable; the marketing for each deployment must match
    what that substrate actually provides.
- **Tenancy: shared.** One TEE instance holds all users' tokens and state.
  Cheaper and simpler; the cost is that per-user isolation becomes a
  correctness property we own in code (attestation says nothing about it).
- **Isolation model: cheapest (in-process) for now.** In-process, per-user
  object ownership + asserts: no mutable module-level globals; token, mapping,
  and state hang off a fresh per-user context object passed explicitly; asserts
  everywhere that an object belongs to the expected user. Chosen for speed of
  build. **Revisit trigger:** if it becomes a target of skepticism (users /
  auditors), or on scale/incident pressure, escalate to per-user subprocess or,
  ultimately, per-user CVMs. Lower-risk here than general shared tenancy because
  all users run the same audited code (no hostile-tenant code injection); the
  dominant risk is plain state-bleed bugs, which the asserts target.
- **Attestation shape: machine-to-machine gate, not per-email handshake.**
  KMS releases each secret into the enclave only if the measurement matches the
  published hash. Plus an on-demand attestation endpoint auditors/dashboard can
  hit anytime. No per-request client exists in the Pub/Sub push path, so a
  per-email handshake would verify a quote nobody consumes.
- **Relay/proxy defense: bind attestation to an enclave-held key (RA-TLS).**
  Enclave generates a keypair at boot, private key never leaves; quote's
  report_data carries the public key; secrets are encrypted to that key. A
  relayed honest quote just delivers secrets to a genuine honest enclave, not to
  a decoy.
- **Token custody is the load-bearing asset.** Per-user Gmail OAuth refresh
  token grants full raw-mailbox access, bypassing masking entirely. It must live
  only inside the enclave, sealed, unsealed post-attestation. This is the thing
  the whole TEE exists to protect.
- **KMS: Phala's KMS.** Not self-run, because the guarantee must hold against the
  operator (us); a self-run gate can be bypassed by the operator. Phala's dstack
  KMS runs in a TEE and gates key release on attestation the node operator can't
  unilaterally override. Follow-up validation (finite checklist, not an open
  design question):
  1. Confirm the KMS itself runs in a TEE and is attestable ("attest the
     attestor"), per Phala/dstack architecture docs.
  2. Find who controls the allowed-measurements release policy; want it under our
     control via a mechanism Phala/node-operator can't silently override (Phala
     uses on-chain governance — read how the allowlist is set and changed).
  3. Read the open-source dstack KMS code/docs for any admin master key, escrow,
     or backdoor; there should be none.
  4. Find published third-party security audits of dstack/Phala KMS.
  5. Empirical test: deploy, confirm normal key release, then change one byte of
     the image (wrong measurement), redeploy, confirm the KMS *refuses* to
     unseal.
  Irreducible residual to document honestly: still trusting Intel hardware + that
  Phala's published KMS code is what runs. The checklist only rules out an
  *additional* operator-controlled bypass on top of that floor.
- **Billing: reuse Polar.** The hosted-subscription surface already exists in
  `~/Code/hetzner_signing_server` (`webhook.py` order.paid handling with
  Standard Webhooks verification, `polar_api.py` backend + portal endpoints,
  `poller.py` reconciliation, `certservice.py` entitlement action). Port the
  entitlement machinery; swap the action from "sign cert into metadata" to "flip
  account active/inactive gating Gmail processing."
- **Pricing: flat monthly subscription with a fair-use cap / tiers.** Not metered
  token markup. Reason: the differentiator is privacy/trust, not cheap inference;
  metered pricing anchors to commodity per-token cost (pennies for email drafts),
  adds billing friction, and invites churn. Subscription prices the value, gives
  predictable revenue, and fits the existing Polar recurring surface. Bound the
  whale-user risk with a usage cap or tiers (base plan up to N drafts/month,
  higher tier above) rather than pass-through metering. No free trial (invites
  token mining); at most a cap so low it is not worth mining. Revisit toward
  metered only if the audience skews developer/API-style.
- **LLM: EU-jurisdiction providers only.**
  - *Managed default (launch): Scaleway Generative APIs (France).* EU company,
    EU jurisdiction (not just residency), EU hosting; serves open-weight models
    (Llama / Mistral / DeepSeek / Qwen class). Clean legal story: no US
    cross-border transfer, no CLOUD Act exposure, no Transfer Impact Assessment.
    Offers no-training / retention controls.
  - *Maximum-control endgame: self-hosted open weights inside TEE GPU (attested
    inference).* No external party sees even masked text; collapses the
    external-LLM trust question entirely and needs no DPA/transfer mechanism.
    Heavier: own the GPU cost and ops.
  - **US providers (e.g. Anthropic) rejected** for the transfer-regime burden:
    Schrems/Chapter-V transfer mechanism (DPF or SCCs) + TIA + ongoing
    legal-challenge risk when serving EU users. Not worth it given Scaleway
    covers the managed slot with an EU-clean posture.
  - Because masking always runs, **every provider only ever sees masked text**,
    so the primary guarantee is provider-independent. The residual-risk axis is
    now "a managed third party (Scaleway) sees masked text — a masking gap leaks
    masked-with-holes text to them" vs. "in-enclave inference where no external
    party sees anything." It is **not** a US-vs-EU jurisdiction gap; both options
    are EU.
  - Scaleway is **OpenAI-compatible**, so it reuses the existing DeepSeek code
    path — near one-line base-URL + key swap in `llm_client.py`, no second
    adapter, single source of truth preserved, no caller touched.
  - Masking stays the core differentiator regardless (belt and suspenders).
- **Data-protection posture: EU-clean by construction.** Keeping all LLM
  processing in EU jurisdiction (Scaleway, or in-enclave) avoids the US-transfer
  regime entirely: no DPF/SCCs, no Transfer Impact Assessment, no CLOUD Act
  exposure. Caveats that remain regardless of provider:
  - Any provider processing personal data still needs a **DPA** (Data Processing
    Agreement) as a sub-processor; Scaleway publishes a standard one to accept.
  - **Pseudonymization is not anonymization** under GDPR — masked text with the
    mapping still living in the enclave is legally still personal data. Strong
    argument that the recipient cannot re-identify (mapping never leaves the
    enclave), which lowers risk, but does not remove the DPA obligation.
  - **Users are worldwide**, so build to GDPR by default (strictest common bar;
    inevitably includes EU users). CCPA/CPRA and others layer on but are largely
    subsumed. This is why EU-clean processing is the default — it avoids per-user
    US-transfer analysis for every EU signup.
  - Sub-processors (Scaleway, Google, Polar, Phala) must be disclosed in the
    privacy policy / sub-processor list.
  - Not legal advice; get counsel for the launch jurisdiction.
- **Sequencing: multi-tenant refactor first, then lift into TEE.** The refactor
  is the larger, riskier, substrate-independent work. Prove it clean
  single-tenant, then wrap in the CVM.

## Current state (what exists)

- `llm_client.complete()` masks via `pseudonymizer.pseudonymize()` before the
  LLM call and restores after. Masked text is the only thing that leaves the
  box. Clean single source of truth.
- `daemon_loop.py` FIFO listener, `gmail_hook_server.py` webhook, calendar +
  draft writers, daily summary, weekly watch renewal. All single-tenant.
- Hardcoded identity: `pseudonymizer.py` bakes in Morgan/Rivers constants;
  `state.json` is one global state; OAuth token sits in `.env` / `.gmail-mcp/`
  in plaintext on the Hetzner box.

Diagrams: `docs/graphviz/arch_current.*` and `arch_target.*`.

## Workstreams

### 1. Multi-tenant refactor (do first, substrate-independent)

- Turn `pseudonymizer.py` hardcoded USER_* constants into per-user config
  loaded from an account store.
- **Deterministic literal-scrub of known identifiers (in the scrubber itself).**
  The pseudonymizer directly scrubs the user's known literal values — name,
  email, phone, and contact names, pulled from the OAuth profile + mapping — via
  literal-string match, not just NER/regex. This makes the highest-stakes,
  finite set (re-identification of the user and their contacts) deterministically
  masked regardless of what the NER model catches. Folded into the one masking
  pass, not a separate outbound verifier. Note: this scrubs (replaces) rather
  than fails-closed, so cover formatting variants (case, spacing, punctuation) in
  the literal match.
- **Public, reproducible masking test corpus + recall metrics.** A test suite of
  emails with labeled PII run against the masker, reporting caught-fraction,
  including adversarial cases (PII in signatures, quoted threads, unusual name
  formats, non-English, obfuscation). Open code + corpus so a skeptic runs it and
  gets a measurable, falsifiable number. Publish the honest recall (won't be
  100%; the literal-scrub above bounds the highest-stakes residual).
- Per-user state (replace global `state.json`), per-user notification target.
- **Pub/Sub routing (decided): single-topic fan-in, route by `emailAddress`.**
  One Google Cloud project, one topic, one push subscription, one webhook. Every
  user's `users.watch()` points at the same topic. On an inbound push:
  `gmail_hook_server.py` verifies the Pub/Sub OIDC JWT, decodes the payload
  (`{emailAddress, historyId}` — no body), looks up the user, and wakes the
  enclave with `(user_id, historyId)`. The enclave unseals *that* user's token
  and fetches the history delta inside the boundary (raw email is PII, never
  pulled in the webhook). Per-user bits that remain: a stored `historyId` cursor
  (replaces global state) and ~7-day watch renewal per user. No per-topic /
  per-project isolation — Gmail's authenticated payload already carries the
  routing key. Security: trust `emailAddress` only because the JWT proves the
  push came from Google, and act only on addresses mapping to a registered user
  with an active watch.
- **Strict per-user isolation**: one user's pseudonym mapping dict must never
  bleed into another user's draft. In a shared enclave this is the highest-risk
  correctness property. Add asserts at every boundary that a mapping/state
  object belongs to the expected user.
- Account store schema: identity -> refresh token -> config -> watch
  subscription -> plan status.

### 2. Identity + onboarding

- "Sign in with Google" only. One consent grants login identity + Gmail/Calendar
  scopes + refresh token. No password form, but this is unavoidably an account
  (persistent server-side credential record).
- Registered redirect URI endpoint to receive the OAuth code, exchange for
  tokens server-side.
- Per-user `users.watch` registration + weekly renewal (multiply
  `watch_register.mjs` by N users).

### 3. Billing (Polar)

- Port `webhook.py` + `poller.py` + `polar_api.py` from hetzner_signing_server.
- order.paid / subscription.active -> account active; cancellation -> inactive.
- Gate Gmail processing on active plan. Polar as Merchant of Record handles EU
  VAT (strengthened by EU LLM/customer focus).

### 4. TEE deployment (Phala)

- Package the whole monolith (daemon, webhook, Presidio/pseudonymizer, token
  store, draft/calendar writers) into one measured image. LLM stays outside.
- Boot -> attest -> KMS unseals secrets only if measurement matches published
  hash -> run.
- Secrets (OAuth tokens, LLM key) injected post-attestation, never baked into
  the measured image.
- RA-TLS: enclave keypair at boot, public key in quote report_data, secrets
  encrypted to it.
- Deploy via `phala deploy -c docker-compose.yml`. Mount dstack socket for
  KMS/attestation.

### 5. Reproducible builds (phased)

- **Phase 1 (launch): binary transparency.** Pin everything by hash (base image
  digest, OS packages, pip hash-pinning, spaCy `en_core_web_lg` by version+hash).
  Publish image + its hash. Auditors confirm running measurement == published
  image hash. Weaker only in that people trust the published binary, not a
  source rebuild.
- **Phase 2 (fast-follow): source reproducibility via Nix (decided).** Move the
  build to Nix so anyone rebuilds from public source and derives the same hash.
  Upgrades the claim from "trust the binary" to "trust the source." Nix's pinned,
  hermetic builds also handle most Python determinism gotchas (.pyc timestamps,
  hash seed, `SOURCE_DATE_EPOCH`) that plain Docker leaks.
- Freeze the image: no auto-updates inside it. Every security patch / Presidio
  bump is a deliberate rebuild -> new hash -> new published release -> KMS
  updated to accept new measurement -> auditors re-verify. Drift only when we
  publish.

### 6. Attestation-verification surface

- On-demand attestation endpoint for dashboard + third-party auditors (fresh
  nonce -> quote -> verify signature chain to Intel cert + measurement ==
  published hash).
- Dashboard "green check" showing live proof the server runs published code.

### 7. Voice DNA + minimal onboarding

Adapted from the MIT-licensed `writing-dna-discovery` skill
(`~/Code/claude-code-toolkit/skills/writing/writing-dna-discovery/`, template
`assets/templates/voice-dna-template.md`). Vendoring the template requires
including Robert Guss's MIT copyright + permission notice.

- **Voice input: paste OR sample.** Preferred flow is to let the user either
  paste a few emails that read as good examples of their voice, or point at a
  few good examples from their Sent folder. Not blanket auto-sampling of Sent
  mail.
- **LLM synthesis.** Masked samples + a short interview (formality, greeting,
  sign-off, phrases/topics to avoid) go to the LLM (Scaleway), which fills the
  voice-dna template and produces per-user `voice-dna.md`.
- **Custody.** `voice-dna.md` is PII-heavy; it lives in the sealed per-user
  store (same custody as the OAuth token), never in the control plane. Samples
  are masked before reaching the LLM during generation. The resulting doc is
  scrubbed so it does not bake raw PII into every future draft prompt.
- **Onboarding surface: webapp (decided).** Chosen over browser extension and
  Google Workspace Marketplace. All three are just front doors to the same
  server-backed flow (Pub/Sub + server-side token custody unchanged), so the
  OAuth consent is unavoidable in every case; the surfaces differ only in what
  they add around it. Webapp adds the fewest clicks (it *is* the consent wrapped
  in a landing page), is the most universally familiar gesture ("Sign in with
  Google"), and needs no install step. Marketplace = unfamiliar to individuals +
  admin-approval gates; extension = adds an install step and a scary
  email-permission prompt *on top of* the same OAuth. Revisit an extension only
  later if an in-Gmail UI surface (drafts/summary shown inside the inbox) is
  wanted — its value would be the ongoing UI, not onboarding.
- **Exact signup + pay flow.**
  1. User visits `yourproduct.com`, one button: "Connect your Gmail."
  2. Redirect to Google's own consent screen (Gmail scope; Calendar deferred to
     first use). User clicks Allow.
  3. Google redirects to the registered redirect URI with a one-time code; server
     exchanges it for identity + refresh token.
  4. Redirect to Polar hosted checkout (Merchant of Record). On `order.paid`
     webhook, account flips active. Or free-trial-no-card: skip, activate with a
     trial flag.
  5. Redirect to a minimal dashboard ("You're connected") showing the attestation
     green-check.
  6. Agent's first action: emails the user in their own inbox asking for pasted
     voice samples / example Sent emails; replies run the masked pipeline.
- **Minimal onboarding principles.** Irreducible steps are only Google consent
  and payment (if charged day one). Everything else moves out of signup into the
  running product:
  - Webapp = auth + billing + attestation dashboard, not a wizard.
  - Settings default to safe (draft-only, human approves every send; never
    auto-send). Zero-config is safe *because* the default is non-destructive.
  - Voice interview happens in-channel (step 6), not a signup wizard.
  - Incremental auth: Gmail scope at signup, Calendar on first scheduling action.
  - Free-trial-no-card makes signup a single Google consent click.
- **Token-custody subtlety at code exchange.** In step 3 the refresh token
  momentarily passes through the control plane. For the strong trust story it
  must be sealed to the enclave key immediately and never persisted in the clear
  outside the TEE — ideally the exchange runs inside the enclave, or the control
  plane encrypts the token to the enclave's public key on receipt. Pin this down;
  it is the moment the load-bearing secret is most exposed.
- **Deferred-voice safeguard.** If the voice step is deferred, first drafts are
  explicitly framed "draft in a guessed voice — reply to correct me," preserving
  the human-in-the-loop review that a signup wizard would otherwise provide.

## Open questions / areas needing more research

Leave these as decisions to resolve before or during the relevant workstream.

### Architecture

- **Sealed per-user token storage (largely resolved on Phala; verify config).**
  Where encrypted refresh tokens live at rest, how the sealing key is derived,
  and how secrets survive legitimate redeploys that change measurement.
  Findings from dstack/KMS docs:
  - **Volume key is KMS-derived and attested, not operator-held.** dstack
    encrypts the persistent volume with dm-crypt LUKS2. The `disk_crypt_key` is
    not stored on the host; at boot the CVM requests app keys from the KMS (or a
    local SGX key provisioner), and the KMS releases them only after verifying
    the remote-attestation quote against an authorized policy. Keys derive via a
    KDF over `RootKey + deployer identity + application hash + epoch`, saved
    inside the guest at `/dstack/.appkeys.json`. The KMS runs in its own TEE and
    enforces authorization the operator cannot bypass. So the operator sees only
    LUKS2 ciphertext at rest — the "is the volume key enclave-sealed" concern is
    answered yes for Phala.
  - **Upgrade / re-sealing is handled by design.** Keys bind to *app identity*
    (application hash) plus on-chain-governed authorization, not to the exact raw
    runtime measurement; key-authorization changes "must be initiated on-chain to
    ensure observability." A legitimate redeploy that changes the measurement can
    still receive the same app keys because the governed KMS release policy admits
    the new image. This is the "seal to a governed policy, not a raw measurement"
    pattern — dstack already implements it, so users don't get logged out on each
    deploy and an attacker-modified image is not admitted.
  - **Caveat — LUKS2 header malleability (CVE-2025-59054, CVE-2025-58356).** Trail
    of Bits found LUKS2 metadata headers are malleable: an attacker with disk
    access could rewrite the header cipher to `cipher_null-ecb` (ignores the key,
    stores plaintext), tricking the enclave into writing unencrypted data while
    believing it's encrypted. dstack v0.5.4 was affected; patched across all eight
    affected projects by Oct 2025 (`cryptsetup` v2.8.1 rejects null keyslot
    ciphers; durable fix is MAC-verifying the LUKS header / measuring it into
    attestation / keeping it in tmpfs).
  - **Remaining verify items:** (1) run a dstack version past the LUKS2 header
    fix; (2) confirm the KMS release policy is bound to our app identity with
    on-chain authorization so upgrades re-key cleanly.
  - Refs: [Phala KMS protocol](https://docs.phala.com/phala-cloud/key-management/key-management-protocol),
    [dstack zero-trust framework](https://phala.com/posts/dstack-a-zero-trust-framework-for-confidential-containers),
    [dstack paper (arXiv 2509.11555)](https://arxiv.org/pdf/2509.11555),
    [dstack audit (May 2025)](https://phala.com/dstack/dstack-audit.pdf),
    [LUKS2 CVE writeup](https://securityboulevard.com/2025/10/vulnerabilities-in-luks2-disk-encryption-for-confidential-vms/).
- **Gmail restricted-scope verification (launch gate).** Reading Gmail is a
  restricted scope: Google requires OAuth app verification + an annual
  third-party security assessment (CASA) before serving beyond ~100 users
  without an "unverified app" warning screen. Backend time/cost burden on the
  timeline, not a UI one. Sequence it early — it gates the smooth one-click
  consent.

## Parallel tracks (what can run concurrently)

Most of the plan parallelizes around one spine: **the account store schema
(B1)**. Once that shape is fixed, identity, billing, and routing fan out
independently. Masking hardening, reproducible-build packaging, the TEE
platform spike, and all research/procurement have **no code dependency on the
spine and start immediately**. Critical path is **B → F3 → G**.

### Track A — Masking hardening (no deps; start now)
Pure `pseudonymizer.py` work on the current single-tenant box. Sources: WS1.
- **A1. Literal-scrub of known identifiers in the scrubber.**
- **A2. Public masking test corpus + recall metrics.**

### Track B — Multi-tenant core (the spine; blocks C, D, F3; source: WS1)
- **B1. Account store schema + per-user context object.** *(unblocks C, D, and
  the rest of B)*
- **B2. De-hardcode `pseudonymizer.py` USER_* constants → per-user config.**
- **B3. Per-user state + per-user notification target (replace global
  `state.json`).**
- **B4. Pub/Sub single-topic routing by `emailAddress`.**
- **B5. Per-user isolation asserts at every mapping/state boundary.**

### Track C — Identity + onboarding OAuth (needs B1; source: WS2)
- **C1. Sign-in-with-Google + redirect-URI token exchange.**
- **C2. Per-user `users.watch` registration + weekly renewal.**

### Track D — Billing (needs only B1 plan-status field; ported code; source: WS3)
- **D1. Port Polar `webhook.py` / `poller.py` / `polar_api.py`.**
- **D2. Plan-gating on Gmail processing (active ↔ inactive).**

### Track E — Reproducible-build packaging (no deps; start now; source: WS5)
- **E1. Phase-1 binary transparency: hash-pinned image + published hash.**
- **E2. Phase-2 Nix source reproducibility (fast-follow).**

### Track F — TEE platform spike (infra spike has no deps; start now; source: WS4)
- **F1. dstack deploy spike: KMS unseal + RA-TLS mechanics (hello-world).**
- **F2. Empirical wrong-measurement KMS-refusal test.** *(also KMS checklist R2)*
- **F3. Package the app into one measured image.** *(needs B complete + E1)*

### Track G — Attestation-verification surface (endpoint code parallel; live proof needs F; source: WS6)
- **G1. On-demand attestation endpoint + signature-chain verification.**
- **G2. Dashboard green-check.**

### Track H — Voice DNA (needs A masking + C identity for in-product flow; source: WS7)
- **H1. Vendor MIT template + LLM synthesis prompt → `voice-dna.md`.**
- **H2. In-product paste/sample voice onboarding + deferred-voice safeguard.**

### Track R — Research / procurement (no code; long lead time; start immediately)
These gate launch but not development, and some have multi-week external
latency — kick off in parallel from day one.
- **R1. Scaleway confidential-computing + hardware-attestation parity check.**
  *(Decisions: substrate)*
- **R2. KMS 5-step validation checklist.** *(Decisions: KMS)*
- **R3. Gmail restricted-scope verification / CASA kickoff.** *(longest lead;
  Open questions)*
- **R4. dstack LUKS2-fix version + KMS app-identity binding verify.** *(Open
  questions: sealed token storage)*
- **R5. Scaleway DPA acceptance + sub-processor list.** *(Decisions:
  data-protection posture)*
