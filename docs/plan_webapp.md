# Faraday web UI — plan (single-container design)

Brand: **Faraday** — domain `faradaymail.ai`. Wedge: privacy ("nothing leaks
out of the cage").

Move the entire Faraday interface (onboarding, accounting, settings, voice DNA)
off email and into a **tiny server-rendered HTML web UI that lives inside the
enclave container**, not a separate webapp.

Reference for look/feel only: `~/Code/davidius/TLDRDR/services/frontdoor`
(we copy its retro CSS, nothing else).

Bot repo (the enclave): `~/Code/TEE_email_bot-worktree/voicedna`.
This plan mostly adds code **to the bot repo**; `~/Code/mailbotwebsite` holds
this plan and any scratch/mockups.

Brand confirmed: **Faraday** (`faradaymail.ai`). "mailbot" retired.

---

## 0. Why single-container (locked)

A separate SvelteKit webapp forced a two-tier split (operator-visible registry
vs sealed enclave store) plus a relay control channel, purely because a fat
Node/npm webapp is too much attack surface to trust with the Gmail refresh
token. Shrinking the web layer to **server-rendered HTML forms** removes that
justification, so folding it into the enclave *removes* complexity:

- **No control channel, no relay.** OAuth code exchange, voice synthesis, and
  settings writes all happen natively where the secrets already live.
- **No Postgres.** The sealed account store (git-ignored `database/` dir, API
  via `backend/accounts/account.py`) is the only datastore. Single source of
  truth for everything the bot acts on.
- **Attestation covers the whole UI.** RA-TLS terminates at the enclave, so the
  browser talks directly to attested code — the green-check is real and total.
- **One deployable, one Nix build, one measurement.** UI changes go through the
  existing reproducible flake, so updates are deterministic and re-attestable
  (a feature: users can verify the exact page they're served).

**Constraints that keep this safe:**
- The web layer stays tiny: Python **stdlib `http.server`** (same pattern as
  `gmail_hook_server.py`), plain HTML + the copied CSS, **no client framework,
  no new heavy deps.** Every dependency added enlarges the enclave measurement
  and attack surface.
- The enclave now terminates public HTTPS (via Caddy, as today). Keep handlers
  minimal and boring.
- **NO AUTOSEND EVER** — drafts only, hardcoded, not a toggle.

---

## Track U1 — Minimal web server inside the enclave

- [ ] New `web_server.py` under `frontend/` (the empty package the layout
      refactor added for exactly this), built on stdlib
      `http.server.ThreadingHTTPServer` + `BaseHTTPRequestHandler` (mirror
      `backend/daemons/gmail_hook_server.py`). Bind `127.0.0.1:<WEB_PORT>`; Caddy
      terminates TLS and reverse-proxies (extend the existing Caddyfile). Run it
      as `python -m frontend.web_server` (needs `frontend/__init__.py`), matching
      the module-invocation convention the refactor established.
- [ ] Tiny routing table (method + path → handler fn). No framework.
- [ ] HTML rendering: plain templates (Python string templates or a single
      minimal helper) — **no Jinja unless the dep cost is justified.** One
      `layout()` wrapper (titlebar/nav/footer) + per-page bodies.
- [ ] Static assets: serve one `app.css` (copied from frontdoor, rebranded) and
      nothing else. No JS bundle.
- [ ] Systemd unit `deploy/hetzner/faraday-web.service`; add to `deploy.sh`
      restart list. In the Nix/Phala image it's just another process in the
      container (add to the supervisor/entrypoint).

---

## Track U2 — Retro theme (copy from frontdoor)

- [ ] Copy `src/app.css` verbatim; rebrand "TLDR"→"Faraday". Verdana 12px,
      #1a237e navy, #7722bb diamonds, gradient titlebar, `.form-row` /
      `.form-submit`.
- [ ] Recreate `+layout.svelte`'s chrome as a static `layout()` HTML wrapper:
      titlebar, nav (public vs authed), footer. UTC clock / visit counter are
      optional flourishes (can be a tiny inline `<script>` or dropped to keep
      zero-JS).
- [ ] Nav: public = {home, about, faq, pricing, contact}; authed =
      {dashboard, voice, settings, billing, account}.

---

## Track U3 — Sessions (in-enclave, no external store)

- [ ] HMAC-signed session cookies (SHA256 over `SESSION_SECRET`), same scheme as
      frontdoor `session.ts` but in Python (`hmac`/`hashlib`, stdlib). Sign
      `{google_sub, iat}`; verify on every request.
- [ ] Auth gate: a `PUBLIC_PATHS` allowlist; everything else requires a valid
      session (mirror `hooks.server.ts`).
- [ ] CSRF: since forms POST to the same origin, add a signed CSRF token in a
      hidden field + cookie, checked on every POST. (No framework to lean on, so
      do it explicitly.)
- [ ] PKCE/state for OAuth: short-lived signed cookies across the round-trip.

---

## Track U4 — Google OAuth (native, in-enclave)

The refresh token never leaves the enclave because the exchange happens here.

- [ ] Build consent URL: scopes `openid profile email` + the **minimal Gmail
      scope the bot needs** (confirm against `gmail_lib.mjs`). Force
      `access_type=offline` + `prompt=consent` so a refresh token is always
      returned. Calendar scope **deferred** to first use (incremental auth).
- [ ] `GET /auth/login` and `/auth/register` → redirect to Google with
      state+PKCE.
- [ ] `GET /auth/callback` → verify state, exchange `code` for tokens **here**
      (enclave holds the Google client secret), **seal the refresh token** into
      the account store via `account.py`, mint a session from the returned
      identity claims (google_sub, email, name).
- [ ] `POST /logout` → clear cookie.
- [ ] Do OAuth token exchange with stdlib `urllib` (same style as
      `gmail_hook_server.py`'s tokeninfo call) — avoid pulling in `arctic`/Node.

---

## Track U5 — Account store is the datastore

No Postgres. Extend the existing sealed account store (git-ignored `database/`
dir; API via `backend/accounts/account.py`).

- [ ] Ensure `Account` / `accounts.json` holds everything the UI needs:
      identity (google_sub, email, name), Gmail refresh token (sealed),
      telegram target, inference provider, calendar-scope flag, plan status,
      `polar_customer_id`, `voice-dna.md` (or path), pseudonym mapping, cursor.
      Most already exist — add only missing fields.
- [ ] All reads/writes go through `account.py` (single source of truth). Add
      accessors for any new field; do not scatter JSON edits.
- [ ] Account creation on first successful OAuth (upsert by google_sub).
- [ ] **Invariant:** the store is the *only* place secrets live; nothing is
      written to disk outside the sealed store or logged.

---

## Track U6 — Voice DNA page (separate from settings)

- [ ] `GET/POST /voice`. Two input modes:
  - **Pull from Sent:** reuse the bot's `search_gmail.mjs` /
    `schedule_from_sent` path to fetch candidate Sent bodies; render them in
    editable textareas.
  - **Paste:** free-text samples.
- [ ] On submit: mask with `pseudonymizer`, synthesize `voice-dna.md` via
      `llm_client.complete()`, seal into the account store. All in-process — no
      relay.
- [ ] Status: `none` / `deferred` / `ready`, shown on the page + dashboard.
- [ ] **Deferred-voice safeguard:** drafts made before a voice is set are framed
      as a guessed voice ("I guessed your voice — reply to correct me"). Surface
      the state here.
- [ ] Bot-repo fix: make `VOICE_PROFILE` **per-account** (today
      `draft_replies.py` / `manual_draft.py` read one global
      `~/.system_files/voice-dna-email.md`). Route both through the account
      store — single source of truth.

---

## Track U7 — Settings + account pages

- [ ] `GET/POST /settings` — telegram target, inference provider, calendar scope
      grant button (triggers incremental Google auth). **No autosend toggle**
      (drafts only). **No voice DNA here** (its own page). Writes via
      `account.py`.
- [ ] `GET/POST /account` — name/email display + **danger-zone delete**
      (confirm-typed). Delete wipes the sealed account entry.

---

## Track U8 — Billing (Polar)

Reuse the bot's existing Polar integration; the UI only drives checkout/portal
and displays status.

- [ ] `GET /pricing` — plans (copy frontdoor `/pricing` layout, subscription
      copy).
- [ ] `GET /billing` — current plan (from account store) + "manage
      subscription" → Polar customer portal link.
- [ ] Checkout: create a Polar checkout session, redirect; entitlement truth is
      reconciled by the **existing** bot-side Polar webhook/poller. UI does not
      own entitlement.
- [ ] `polar_customer_id` + plan status live in the account store
      (`set_plan_status`). Bot processing is already gated on entitlement
      (Track D) — no new gate here.

---

## Track U9 — Public + dashboard pages

- [ ] Public: `home`, `about`, `faq`, `pricing`, `contact` — static HTML,
      rewritten copy.
- [ ] `GET /dashboard` (authed): Gmail connection status, plan status, voice
      status (link to Voice page), **attestation green-check** from the enclave
      quote (stubbed pre-TEE, real on Phala), quick links.

---

## Track U10 — Nix build + attestation

- [ ] Get `web_server.py` + `app.css` into the flake's `appCode`. **This is no
      longer automatic:** after the layout refactor `appCode` is a *filtered*
      tree, not a bare `./.`. Two changes are required or the web assets ship
      missing: (1) remove `"frontend"` from the directory exclude list in
      `flake.nix` (it's excluded today because it's empty), and (2) add a `.css`
      allowance to the file filter — it currently whitelists only
      `.py`/`.mjs`/`package.json`/`package-lock.json`, so `app.css` is dropped.
      No new Python deps ideally; if any is unavoidable, add via the uv workspace
      (`deploy/phala`) so it's pinned.
- [ ] Add the web process to the container entrypoint/supervisor.
- [ ] `GET /attestation/quote` (or inline on dashboard): return the dstack
      attestation quote so the browser can verify. Stub on Hetzner, real on
      Phala.
- [ ] Because every UI change re-measures the enclave, keep changes flowing
      through the flake so the measurement stays reproducible and auditable.

---

## Track U11 — Deployment

- [ ] Hetzner (launch): `web_server.py` as a systemd service behind Caddy,
      wired into `deploy.sh` (never scp/edit remote files — follow bot deploy
      discipline). Update the Caddyfile to route the public hostname to the web
      port.
- [ ] Phala (fast-follow): same code, packaged by the flake into the enclave
      image; Caddy or dstack ingress terminates TLS / RA-TLS. Lifting is config
      (KMS sealing + real quote), not code change.
- [ ] Secrets: Google client secret + session secret + Polar keys in the
      enclave env only (`.env`, never in git, never read by tooling).

---

## Cross-cutting invariants (assert / test)

- No autosend, ever — drafts only. Assert at the draft boundary.
- Secrets live only in the sealed account store; never logged, never written
  elsewhere.
- The account store is the single datastore and single source of truth for
  anything the bot acts on.
- Reuse bot code — `account.py`, `pseudonymizer.py`, `llm_client.complete()`,
  `search_gmail.mjs`, `gmail_lib.mjs`. Do not reimplement masking, accounts, or
  Gmail access in the web layer.
- Keep the web layer dependency-free (stdlib only) to bound the enclave
  measurement and attack surface. Justify any new dep explicitly.

---

## Open items to confirm before build

- Brand name resolved: **Faraday** / `faradaymail.ai`.
- Exact minimal Gmail scope the bot requires (check `gmail_lib.mjs`) — minimize
  for CASA restricted-scope review.
- Whether to add a tiny template helper vs plain string templates (dep vs
  readability).
- CASA / Gmail restricted-scope assessment is a public-launch blocker if the
  bot uses a restricted scope (e.g. `gmail.modify`).
