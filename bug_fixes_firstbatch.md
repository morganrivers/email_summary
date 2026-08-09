# Security review, batch 1 — enclave-deployed code

Scope: the code that ships in the measured image (`deploy/phala/image_files.nix`)
and runs as the three roles in `deploy/phala/docker-compose.yml` (`mail`, `web`,
`hook`). Findings are limited to the four requested classes:

1. authorization / per-object ownership
2. credential handling
3. trust boundary drawn in the wrong place
4. injection at a parser boundary

Ordered by "who can trigger it" then "what it yields". Everything below was read
in the tree; nothing was executed against a live CVM.

---

## L1 — Anyone who knows a user's address can drive the agentic drafter as that user

**Class:** authorization (missing ownership check).
**Where:** `backend/drafting/manual_draft.py:48` (`is_bot_request`),
`backend/daemons/pipeline.py:45`.
**Reachable by:** any sender on the internet who knows the victim's Gmail address.

`is_bot_request()` decides the manual-draft path from one thing:

```python
def is_bot_request(email, account):
    return bot_alias(account) in (email.get("to") or "").lower()
```

`email` is an inbound INBOX message. The `To` header is written by whoever sent
it, and plus-addressing means an outsider can simply address
`victim+bot@gmail.com` — no spoofing needed, and the alias is derivable from the
address. Nothing checks that the message came from the account owner.

Consequences, in order of severity:

- `parse_forward()` splits the body at the `--- Forwarded message ---` marker and
  everything *before* it becomes `parsed["context"]`. In
  `draft_with_context()` that text is placed **outside the fence**, labelled
  `"{owner}'s context for this reply"` — that is, it is fed to the model as the
  account owner's trusted instructions. The fence protects only
  `parsed["original_*"]`. So the one span an attacker fully controls is the one
  span the design treats as trusted.
- The drafter holds `search_emails` over the whole mailbox
  (`tool_executors.TOOL_REGISTRY`), and the attacker chooses what it searches for.
- The resulting draft is addressed to `parsed["original_email"]`, which the
  attacker also writes (the `From:` line of the fake forward block). The draft is
  never auto-sent, but it lands in the victim's Drafts pre-addressed to the
  attacker with whatever the model was told to include.
- `render_progress_body()` writes tool arguments and partial model output into
  that same draft on every iteration.

This is the confused-deputy case: the daemon faithfully executes an untrusted
party's instructions with the victim's mailbox authority.

**Fix.** Require proof the triggering message is the owner's own, and take that
proof from Gmail rather than from a header a sender writes. Gmail labels the
owner's own copy `SENT`; a stranger's mail to `victim+bot@` has no `SENT` label.

- `gmail_api.fetch_message()` currently drops `labelIds` from the `full`
  response — add it there (one place, `mailbox._fetch_ids` inherits it).
- `is_bot_request()` becomes `alias in to-header AND "SENT" in labelIds`. Keep it
  in that one function so `pipeline` cannot forget it; the existing
  `thread_has_user_message()` is the precedent for using the SENT label as the
  participation signal rather than address matching.
- Independently, and as defence in depth: fence `parsed["context"]` in
  `parse_from_thread()`'s output. That fallback path takes the *forwarded
  message's own body* as "owner context", so even with the SENT check it inherits
  whatever the owner pasted in.

---

## L2 — The TEE boot gate demands a box-wide secret set from every role, so no enclave role can start

**Class:** trust boundary (the gate's required set does not match the partition).
**Where:** `backend/tee/tee_boot.py:124` → `backend/secrets.py:288` (`REQUIRED`),
`flake.nix` entrypoint `gate()`, `deploy/phala/docker-compose.yml`.
**Reachable by:** nobody — it fails closed. Listed here because it blocks the
deploy and because the obvious fix destroys the partition.

`run_gate()` ends with `secrets.missing()`, which runs all six checks in
`secrets.REQUIRED`. Both `mail` and `web` run `gate()` before starting. Against
the compose file's environment blocks:

| check | mail | web |
|---|---|---|
| `inference_configured` (needs **every** provider key) | ok | **fails** — no `DEEPSEEK_API_KEY`, no `NEARAI_API_KEY` |
| `telegram_configured` | ok | **fails** |
| `session_configured` | **fails** — no `SESSION_SECRET` | ok |
| `google_oauth_configured` | ok | **fails** |
| `polar_api_configured` | ok | ok |
| `polar_webhook_configured` | **fails** | **fails** |

`POLAR_WEBHOOK_SECRET` is in no container at all, correctly — the enclave runs no
Polar receiver (CLAUDE.md says so). But the gate asks every role for it. With
`restart: always`, both roles crash-loop.

The dangerous repair is to widen each container's `environment:` until the gate
passes. That puts `SESSION_SECRET` in the mail role and the inference keys back
in the web role, which is precisely the split that RTMR3 attests and that
`cosigner/attest.py` enforces.

**Fix.** Give the gate the role's own required set, the way
`deploy/preflight.py:150` already keys checks by unit. Concretely: pass the role
(`mail|web|hook`) to `python -m backend.tee.tee_boot` from the entrypoint, and
add a `secrets.required_for(role)` beside `REQUIRED` that names the same
per-role sets `preflight.CHECKS` names per unit. One table, two readers — the
enclave gate and the Hetzner preflight — so they cannot drift. Drop
`polar_webhook_configured` from any enclave role, since no enclave role verifies
a Polar signature.

Also worth splitting: `inference_configured()` demands a key for *every* catalog
provider, so adding a fourth provider to `llm_client.PROVIDERS` fails the boot of
a box that deliberately does not carry its key.

---

## L3 — Caller-supplied ids are interpolated into Polar API request paths

**Class:** injection at a parser boundary.
**Where:** `backend/billing/polar_api.py:70` (`get_customer`), `:102`
(`get_checkout`), `_request` at `:44`.
**Reachable by:** any signed-in user (the value arrives in a query string).

```python
def get_checkout(checkout_id, token):
    return _request("GET", f"/v1/checkouts/{checkout_id}", token=token)
```

`checkout_id` comes straight off the browser: `web_server._handle_get` reads
`query.get("checkout_id")` from `/billing/return` and hands it to
`billing.confirm_checkout` → here. It is never shape-checked and never
percent-encoded, and `_request` concatenates it onto `api_base()`. A value
containing `?`, `#`, or `../` retargets the request to a different Polar endpoint
— with the organization API token attached in the `Authorization` header.

The response is then parsed as a checkout: `resolve_account(body)` and
`body.get("status")`. The ownership test in `confirm_checkout` is what keeps this
from being a straightforward entitlement theft, but the primitive itself is
"authenticated GET against an attacker-chosen path of the Polar API", which is
worth removing on its own terms. `get_customer` has the same shape with a
less-controlled input.

**Fix.** Do it once, in `_request`, not at each call site: build the path from
`urllib.parse.quote(component, safe="")` components, or assert each id against a
Polar id shape (`[A-Za-z0-9_-]{1,64}`) before it is used. An assert is preferable
here — a malformed checkout id is a request nobody legitimate makes, and encoding
it silently turns an attack into a 404 nobody looks at.

---

## L4 — The web role holds an organization-wide Polar API token

**Class:** credential handling / trust boundary.
**Where:** `deploy/phala/docker-compose.yml` (`web.environment.POLAR_API_TOKEN`),
used by `billing.PolarBilling`, `checkout_url`, `portal_url`, `confirm_checkout`.
**Reachable by:** anyone who finds a bug in the web tier.

The web container is the role that parses HTTP from the open internet. It is
handed `POLAR_API_TOKEN`, which is an org-scoped backend token: it reads every
customer (`get_customer`), lists every subscription (`list_subscriptions`), mints
checkouts, and mints customer-portal sessions **for any customer id**
(`create_customer_session`). A compromise of the web tier is therefore a read of
the whole customer list and a session into any buyer's billing portal — which is
strictly more than the "can edit its own settings and its own plan" residual
CLAUDE.md documents for that role.

This is the same argument that already moved the inference keys out of the web
role: it held two live keys only to answer a yes/no question, so
`handoff.OP_PROVIDERS` was added and the keys stayed in `mail`.

**Fix.** Move the three billing operations the web tier performs behind
`backend/custody/handoff.py`, the way `providers` went:

- `checkout-url(account_id)` → returns a URL
- `checkout-confirm(account_id, checkout_id)` → returns `(paid, detail)`
- `portal-url(account_id)` → returns a URL or None

All three already take only an account and an opaque id, all three are already
performed by a role (`mail`) that holds the token for `billing_poller`, and the
handoff listener already refuses any peer but the web uid. Then drop
`POLAR_API_TOKEN` (and `POLAR_ORGANIZATION_ID`, `POLAR_PRODUCT_ID`) from the web
container. That is a compose change, so the partition change is measured.

If the token must stay for now, the interim mitigation is L3 plus a scoped Polar
token limited to `checkouts:read`/`customer_sessions:write`.

---

## L5 — `account.set_settings()` enforces provider availability in the wrong process

**Class:** trust boundary.
**Where:** `backend/accounts/account.py:726`, called from
`frontend/web_server.py:1837`.
**Reachable by:** any signed-in user, in the enclave only.

```python
assert provider.configured(), (
    f"provider {provider.name!r} cannot be selected: {provider.key_env} "
    f"is not set on this box")
```

`configured()` reads `os.environ[key_env]` **in the calling process**. In the
enclave the web role deliberately holds no inference key, so this assertion is
false for every provider. The POST handler catches only `HandoffUnavailable`, so
the `AssertionError` escapes `do_POST` and the request dies with no response.
Any user who saves Settings with a provider selected hits it. (It does not fire
on the Hetzner box, where the web unit is in `letterlock-secrets` and can read
`.env` — so this is enclave-specific and will not show up in box testing.)

The web tier already asked the right process: `_available_providers()` →
`handoff.providers()` → `llm_client.available_provider_names()` in `mail`. The
manifest writer then re-asks the question locally, where the answer cannot be
known.

**Fix.** In `set_settings`, keep the catalog-membership assert
(`PROVIDERS.get(name) is not None`) and drop the `configured()` assert.
Availability is enforced where it is knowable: the web tier validates against
`handoff.providers()` before writing, and `llm_client.resolve()` in the mail role
raises rather than substituting if a stored preference is unserveable — which is
already the stated behaviour.

---

## L6 — The `hook` role cannot create its own spool file on a fresh volume

**Class:** trust boundary (modes are right, the creation path does not respect them).
**Where:** `backend/spool.py:48` (`_ready`), `backend/daemons/wake_queue.py`,
`flake.nix` (`chmod 2771 ./app/state`), `paths.DIR_MODE_TRAVERSABLE`.
**Reachable by:** nobody — it fails closed, but it silently stops all mail.

`/app/state` is `2771`, owner `letterlock-mail` (10001), group `letterlock-data`
(10010). The hook runs as 10003 in `letterlock-wake` (10011) only, so for that
directory it is *other*: `--x`. Traversal, no write.

`Spool.append()` calls `_ready(self.path)`, which does `path.touch()` when the
file is absent. On a fresh `state` volume nothing has created
`state/wake_queue.jsonl`: `Spool.drain()` (the mail side) creates only the
`.lock` file and returns early on `if not self.path.exists()`. So the hook's
first `wake_queue.enqueue()` raises `PermissionError`, which propagates out of
`route_push` → `do_POST` → 500, and `signal_daemon()` is never reached.

The daemon does not recover from this. `daemon_loop.main()` only sweeps when
`woken` is true (a FIFO poke) or the spool is non-empty; a bare 300-second
timeout with an empty queue processes nothing. Net effect on a fresh enclave: no
mail is ever drafted, and Pub/Sub retries a 500 forever.

This is latent on the Hetzner box too — it is masked there only if
`wake_queue.jsonl` already exists from before the uid split, which is exactly why
a fresh volume is where it shows up.

**Fix.** The owner of the directory pre-creates the files. Add
`Spool.ensure()` (touch + `paths.group_file`) and call it from the draining side
at startup: `daemon_loop.main()` already calls `ensure_fifo()`, so
`wake_queue.ensure()` and `billing_queue.ensure()` belong beside it. Then the
hook only ever opens files that exist, which is what its `--x` on `state/`
permits. Do **not** widen `state/` to `2773`/`2777` — the traversable-only mode
is the grant that keeps the account store out of the hook's reach.

---

## L7 — Model output is sent to Telegram as HTML with no escaping

**Class:** injection at a parser boundary (and the capability behind a prompt
injection).
**Where:** `backend/drafting/email_summary.py:164`, `:35` (the prompt),
`backend/integrations/telegram.py:101` (`parse_mode: "HTML"`).
**Reachable by:** anyone who can get an email into the victim's unread mail.

```python
send_telegram(f"📬 <b>Daily summary for {today_str}</b>\n\n{summary}",
              account.telegram)
```

`summary` is raw model output, sent with `parse_mode=HTML`. The prompt asks for
it: *"Plain text with simple HTML tags only (`<b>`, `<i>`, `<a>`)"*. `<a href>`
is a capability, not a formatting tag — an attacker whose email reaches the
summary can plant a clickable link with an arbitrary href, in a channel the user
trusts, attributed to Letterlock. That is a phishing primitive reachable by
sending mail.

Every other Telegram caller escapes (`draft_replies.format_draft_line`,
`schedule_from_sent.render_telegram`, `manual_draft`, `tokens.notify_reauth_required`);
this is the one that does not.

Second, smaller problem on the same line: an unbalanced `<` in model output (a
quoted address such as `<alice@x.com>`) makes Telegram reject the whole message
with a 400. `telegram.call()` swallows it and `summarise_account()` still returns
`True`, so a failed summary is indistinguishable from a delivered one.

**Fix.** Stop asking the model for HTML. Have it emit plain text, run it through
`html.escape()` before the send, and do any bolding/linking in code from values
the code holds (`gmail_thread_link()` already exists for exactly this and is
already fenced into the prompt as data). If rich text in the summary is worth
keeping, allow-list it: escape everything, then re-introduce `<b>`/`<i>` from a
marker the model writes, and never `<a href>`.

---

## L8 — Exception text from mail processing is delivered to Telegram, with a cross-tenant fallback

**Class:** credential/data handling.
**Where:** `backend/integrations/telegram.py:107` (`notify_error`),
`backend/daemons/daemon_loop.py:67,71`, `backend/drafting/email_summary.py:182`,
`backend/daemons/pipeline.py:53,59,68`.
**Reachable by:** any sender, indirectly (an attacker chooses the content that
provokes the exception).

`notify_error()` formats the full traceback into `<pre>` and sends it. Two
problems:

1. The text can carry mail-derived content. `llm_client.complete_json`'s
   `json.loads(content)` raises `JSONDecodeError` carrying a slice of model
   output; assertion messages in the drafting path carry prompt fragments. All of
   that is derived from an email an outsider wrote and from the mailbox the model
   searched.
2. `if not send_telegram(text, target): send_telegram(text, operator_target())`.
   An account with no linked chat — which is the default state for a new signup —
   sends that traceback to **the operator's** chat. One tenant's mail-derived
   content crossing to the operator is a boundary the rest of this codebase is
   careful about (`telegram.py`'s own docstring: "there is no environment
   fallback on the notification path").

**Fix.** Two changes, both small:

- Give `notify_error` a summary mode for the mail paths: exception *type* plus
  the account id, never `format_exception`. The traceback belongs in the journal,
  which is where the operator can read it without it crossing a chat boundary.
- Remove the operator fallback from the per-account call sites (or gate it on a
  flag the per-account paths do not set). "Operator alerts go to the operator,
  user alerts go to the user, and neither substitutes for the other" is already
  the stated rule; this function is the one place it is not enforced.

---

## L9 — Residuals and lower-severity notes

These are real but either accepted in the design docs or low-yield. Recorded so
the next pass does not re-derive them.

**L9a — Handoff operations take an account id the callee cannot verify.**
`handoff_server` admits the web uid and then acts on whatever `account_id` it is
given (`voice-start`, `chat-begin`, `chat-finish`, `chat-forget`). CLAUDE.md and
`chat_link`'s docstring state this and explain why `chat_link` closes the one
field that matters. The residual is unchanged: a compromised web tier can link
*its own* Telegram chat to any account that has none linked, giving a standing
subscription to that account's daily summary. If tightening is wanted later, the
cheapest step is an audit row per handoff op naming the account, plus a per-uid
rate limit on `chat-begin`, so a sweep across accounts is visible.

**L9b — No CSRF tokens; the sole defence is `SameSite=Lax`.**
`frontend/session.py:173`. Every state-changing route is a cookie-authenticated
POST with no token: `/voice` (writes the text the drafter reads before every
draft), `/personal`, `/settings`, `/account/delete`. Lax blocks cross-site POST
in current browsers, so this is defence-in-depth rather than a live bug — but the
whole protection rests on one cookie attribute, and `/voice` is a prompt-content
write. A signed double-submit token minted by `session.py` (it already owns the
keyring and the `purpose` domain separation) would cost very little.

**L9c — `/billing/return` and `/billing/portal` are state-changing GETs.**
`web_server.py:1730,1757`. The return page writes `polar_customer_id` and flips
`plan_status`; the portal route mints a Polar customer session. Both are reached
by top-level navigation, which `SameSite=Lax` permits. `confirm_checkout`'s
ownership test is what keeps the first one safe — that test is doing real work
and should not be weakened.

**L9d — `web_server._h()` is a second HTML escaper that omits `'`.**
`web_server.py:215`. It escapes `& < > "` only. Nothing today interpolates into a
single-quoted attribute, so there is no live injection, but the CSP allows
`script-src 'unsafe-inline'`, so a future single-quoted attribute is an XSS. Use
`html.escape(x, quote=True)` — already imported in that module and already the
one used by `drafts.escape_html`, whose docstring makes exactly this argument.

**L9e — `gmail_hook_server.route_push` asserts on a verified push.**
`gmail_hook_server.py:262`: `assert email, ...` inside the handler. A verified
push with an empty `emailAddress` becomes an unhandled 500 rather than a logged
drop. Cosmetic next to the rest, but it is on the one public endpoint the enclave
exposes.

**L9f — `web` is unreachable in the enclave as configured.**
`docker-compose.yml` gives `web` no `ports:` and no `WEB_HOST`, so
`web_server.py:69` binds `127.0.0.1` inside its own network namespace. Whatever
change publishes it should be checked against `_source_ip()`
(`web_server.py:1556`): there is no Caddy in the enclave, so the peer will be the
bridge gateway, which is not in `site.TRUSTED_PROXIES`, and every audit row will
record that address instead of the browser's. Decide deliberately whether the
dstack gateway is a trusted proxy and, if so, name it in `site.TRUSTED_PROXIES`
rather than trusting `X-Forwarded-For` unconditionally.

---

## Checked and found sound

Recorded so the next reviewer does not spend time here.

- **Per-object ownership in the web tier.** Every authenticated route derives the
  account from `sess.get_email(self.headers)`; no handler takes an account
  identifier from a path segment, form field, or query string. The one id that
  arrives from the browser (`checkout_id`) is subjected to an ownership test in
  `PolarBilling.confirm_checkout` before anything is written.
- **RFC822 header assembly** (`gmail_gcal/drafts.py`). `strip_folding`,
  `encode_header`, `encode_address` and `message_ids` correctly refuse CR/LF and
  keep only well-formed msg-id tokens, with an assert over the assembled header
  block. No header injection from a sender-controlled `From`/`Subject`/`References`.
- **Gmail search query construction** (`find_thread_by_from_subject`). One header
  value reaches the query, shape-checked by `ADDRESS_QUERY_RE` first; the subject
  is matched in Python over returned metadata.
- **Audit SQL** (`backend/audit.py`). Fully parameterized, including the
  optional `WHERE`; `detail` tokens are shape-checked against `TOKEN`.
- **Cookie signing** (`frontend/session.py`). Domain-separated by purpose, kid in
  the signed payload, constant-time compare, unknown-kid refused by the same
  comparison a bad signature is.
- **Pub/Sub JWT verification** (`gmail_hook_server.verify_jwt` / `check_claims`).
  Signature verified locally against cached certs, exact claim comparisons, the
  refetch path rate-limited and an expired-and-unrefreshable set treated as an
  error rather than served stale.
- **Static file serving.** `STATIC_TYPES` is a filename allow-list; no URL
  component is ever joined onto a directory.
- **Path traversal on account ids.** `account.check_id` is applied at
  `account_dir`, at `provision`, and through `keyring.identify`.
