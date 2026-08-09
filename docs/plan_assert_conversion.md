# Converting boundary asserts to explicit refusals
Done as of 2026-08-09. Every site below is converted; the rule and the
deliberately-still-asserts list at the end are what remains useful. The rule now
also lives in `CLAUDE.md`, so the next person writing a control knows which of
the two classes they are in without finding this file.

Five places the work departed from the plan as written, each with its reason in
the code:

- `custody/tokens.py` (the missing DPoP nonce, the 200 with no `access_token`)
  raises `wrapping.CustodyError`, not `ReauthRequired`. `daemons/pipeline.py`
  catches `ReauthRequired` and tells the user to consent again, and neither of
  these is a refused grant, so that message would send someone through a
  sign-in that fixes nothing.
- `tee/quote_policy.py` converted two sites beyond the four listed:
  `Policy.__init__`'s missing-file and not-an-object checks. Both
  `cosigner/attest.py::configured()` and
  `inference_attestation.py::configured()` caught `AssertionError` around
  `mode()` to report a missing allowlist at deploy time, so leaving those two
  as asserts would have kept an `except AssertionError` alive for exactly the
  class of thing this document is removing.
- `custody/handoff.py::encode()` was converted after all. The judgement call
  below asked whether a payload can grow from user-supplied text: the `sign-in`
  payload carries the OAuth callback's query string, and the request line lets
  a browser run that to about `MAX_BODY` on its own. `call()` now frames the
  payload before it opens the socket, so an over-long one is not reported as a
  daemon that could not be reached.
- `daemons/gmail_hook_server.py::do_POST` now catches `HookError` around
  `route_push`. Raising one there without a handler is an exception escaping
  the request handler, which is not better than the assert was.
- `onboarding/provisioning.py` converts two of the new refusals into
  `ProvisionError(502)`: `check_id` on the address Google returned, and a
  `ValueError` out of `gmail_api.profile_address`. 502 and not 400 because the
  browser did nothing wrong.

## The rule

An `assert` states an invariant that is a programmer error if false. Anything
validating data that crossed a trust boundary must be an explicit `raise`,
because it is not a bug to be caught in testing, it is a hostile or malformed
input to be refused in production.

Concretely, in this tree:

- **Argument handed in by our own caller** -> stays an assert.
  `assert handle and inner, "wrap needs a handle and an inner ciphertext"`.
- **Value that came back from Google, the co-signer, the KMS, a web form, a
  model, or a file on disk** -> raises.
  `if not inner: raise CoSignerUnavailable(...)`.

## Why the runtime guard is not a substitute

`runtime_guard.py` (committed in `01ba733`) makes `python -O` refuse to start,
called from `backend/__init__.py` and `cosigner/__init__.py`, so no entry point
can miss it. That closes the exposure: assertions cannot be stripped out from
under these checks any more.

It does not make the conversion pointless, for three reasons:

1. An `AssertionError` reaching a request handler is an unhandled 500. A typed
   refusal is something a caller can convert into a refusal with a status code.
   `backend/onboarding/provisioning.py` already catches `wrapping.CustodyError`
   in two places and turns it into a 502/503; every check converted to that type
   gets that behaviour for free.
2. `AssertionError` is indistinguishable from a genuine bug in a log. A named
   type says which control fired.
3. The guard is one file. A future refactor that moves an entry point, or a
   vendored copy of a module imported without the package `__init__`, loses it.
   A check that raises on its own does not depend on that.

## What was converted first

15 sites, all in `backend/custody/` and `cosigner/attest.py`:

- `backend/custody/client.py` — both `TEE_REQUIRED` gates, the RA-TLS keypair
  check, the non-object response body, both DPoP JWK checks (including
  `"d" not in jwk`), and the empty `proof` / `outer` / `inner+proof` / `inner` /
  `rewrapped` response checks. All raise `CustodyError` or `CoSignerUnavailable`.
- `backend/custody/wrapping.py` — the `TEE_REQUIRED` gate, the missing dev
  secret, and the app secret length check. All raise `CustodyError`.
- `cosigner/attest.py` — the dev-insecure-with-`TEE_REQUIRED` gate, raising a
  new `AttestationRefused(RuntimeError)` defined in that module.

Three tests were updated from `pytest.raises(AssertionError)` to the specific
types: `tests/test_cosigner.py::test_dev_mode_refuses_to_run_on_a_provisioned_box`,
`tests/test_custody.py::test_a_tee_box_refuses_a_dev_key`,
`tests/test_custody.py::test_a_private_dpop_key_is_refused`.

## How to find the remaining sites

Line numbers below will drift. Relocate by message text, which is stable:

```bash
grep -rn "assert " --include=*.py backend/ cosigner/ frontend/     # all 238
grep -rn "assert " --include=*.py backend/accounts/account.py      # one file
```

To see only the files this document covers:

```bash
grep -n "assert " \
  backend/accounts/account.py \
  backend/masking/pseudonymizer.py \
  backend/integrations/gmail_gcal/calendar_api.py \
  backend/integrations/gmail_gcal/gmail_api.py \
  backend/tee/quote_policy.py \
  backend/billing/billing_webhook.py \
  backend/daemons/gmail_hook_server.py \
  backend/custody/keyring.py \
  backend/custody/tokens.py \
  backend/custody/handoff.py \
  frontend/session.py
```

Tests that pin the current behaviour and will need updating as each site is
converted:

```bash
grep -rn "AssertionError" tests/
```

## The rest

25 checks, all converted. Each row is: where, what it used to say, what crossed
the boundary, and what it raises now.

### `backend/accounts/account.py` — 7 sites, needs one new type

No refusal type exists in this module (`AccountLimitReached` is unrelated). Add:

```python
class InvalidAccountData(ValueError):
    """A value that would name the wrong account, or no account at all."""
```

| Line | Current | Boundary crossed | Raise |
|---|---|---|---|
| ~190 | `assert handle and HANDLE_RE.match(...)` in `check_handle` | Handle read back from the manifest, sent to the co-signer as the account name | `InvalidAccountData` |
| ~252 | `assert (account_id and "/" not in ... and ".." not in ...)` in `check_id` | Account id derived from the Google profile response; a separator puts files outside the account's home | `InvalidAccountData` |
| ~266 | `assert home.parent == ACCOUNTS_DIR` in `account_dir` | Same, one layer down; this is the check that the derived path stayed in the store | `InvalidAccountData` |
| ~511 | `assert email and "@" in email` in `register_account` | Address from Google | `InvalidAccountData` |
| ~515 | `assert not set(email) & {"/", "\\"} and ".." not in email` | Same; its own comment says "Google will not issue one, which is exactly why it must be asserted rather than assumed" | `InvalidAccountData` |
| ~599 | `assert status in ("active", "inactive")` in `set_plan_status` | Status derived from a Polar event body | `InvalidAccountData` |
| ~740 | `assert not calendar or CALENDAR_ID_RE.fullmatch(calendar)` | Calendar id typed into the settings form | `InvalidAccountData` |

The two path guards are the highest value in the whole list: they are what keeps
one account's files out of another's directory.

### `backend/masking/pseudonymizer.py` — 2 sites, needs one new type

No exception type exists in this module. Add:

```python
class MaskingFailed(RuntimeError):
    """Masking did not produce text safe to send. Never caught into a send."""
```

| Line | Current | Boundary crossed | Raise |
|---|---|---|---|
| ~518 | `assert text.count(token) == count` in `pseudonymize` | The email body being masked. This is the check that catches the prompt fence's closing delimiter being swallowed as PII, which puts the rest of an attacker's message outside the fence | `MaskingFailed` |
| ~88 | `assert len(d) >= _MIN_PHONE_DIGITS` | Contact phone numbers from the account's own data | `MaskingFailed` |

**Important for the ~518 conversion:** whoever calls `pseudonymize()` must not
catch this into "send it unmasked". Check `backend/integrations/llm_client.py`
(`complete(protect=...)`) and `backend/drafting/agentic_drafter.py` (`draft()`)
before converting, and add a test that a masking failure stops the request
rather than degrading it.

### `backend/tee/quote_policy.py` — 4 sites, needs one new type

Two callers verify in opposite directions (`cosigner/attest.py` inbound,
`backend/integrations/inference_attestation.py` outbound) and both must fail
closed. Add:

```python
class AllowlistInvalid(RuntimeError):
    """The pin list cannot answer the question. Refuse rather than guess."""
```

| Line | Current | Boundary crossed | Raise |
|---|---|---|---|
| ~218 | `assert expected, "an empty binding would accept a quote bound to nothing"` in `_binds` | The allowlist file. With `expected` empty the function returns `True` for any quote | `AllowlistInvalid` |
| ~93 | `assert value in (REQUIRED, DEV_INSECURE)` | Mode string from the allowlist / environment | `AllowlistInvalid` |
| ~95 | `assert not self.entries()` | Dev-insecure mode on a file that pins production measurements | `AllowlistInvalid` |
| ~121 | `assert entry.get("mr_td")` | An allowlist entry with no `mr_td` pins nothing | `AllowlistInvalid` |

### `backend/custody/` — 4 sites, types already exist

`keyring.py` has `NoDataKey` and `BadRecord`, both `wrapping.CustodyError`
subclasses. `tokens.py` has `ReauthRequired`, same base.

| File / line | Current | Boundary crossed | Raise |
|---|---|---|---|
| `keyring.py` ~181 | `assert not has_key(uid)` in `mint` | Wrap-once. A second wrap orphans every file under the old key. The co-signer refuses this too, so the local check is defence in depth | new `CustodyError` subclass, or `CustodyError` |
| `keyring.py` ~305 | `assert len(blob) > NONCE_LEN + TAG_LEN` in `decrypt` | Ciphertext read off disk; a truncated file | `BadRecord` (already exists and means exactly this) |
| `tokens.py` ~259 | `assert access, "token endpoint returned no access_token"` | Google's token response | `ReauthRequired` |
| `tokens.py` ~205 | `assert nonce, "Google demanded a DPoP nonce without supplying one"` | Google's `DPoP-Nonce` header | `ReauthRequired` |

### `backend/integrations/gmail_gcal/` — 4 sites

`calendar_api.py` has `CalendarNotPrivate`, which does not fit these; use
`ValueError` unless a caller needs to distinguish them.

| File / line | Current | Boundary crossed | Raise |
|---|---|---|---|
| `calendar_api.py` ~206 | `assert len(summary) <= MAX_SUMMARY` | Model-generated event text at the write boundary. `schedule_from_sent._normalize()` truncates to the same constants, so reaching here means that path was bypassed | `ValueError` |
| `calendar_api.py` ~209 | `assert len(location) <= MAX_LOCATION` | Same | `ValueError` |
| `calendar_api.py` ~212 | `assert len(description) <= MAX_DESCRIPTION` | Same | `ValueError` |
| `gmail_api.py` ~73 | `assert address, "Gmail getProfile returned no emailAddress"` | Google's profile response; the address becomes the account id | `ValueError` |

### Three singles

| File / line | Current | Boundary crossed | Raise |
|---|---|---|---|
| `backend/billing/billing_webhook.py` ~108 | `assert secret, "POLAR_WEBHOOK_SECRET required"` in `main()` | Configuration, checked immediately before constructing the signature verifier. Without it the verifier is built over an empty secret | `SystemExit` — it is a startup refusal, and `deploy/preflight.py` already reports the unit |
| `backend/daemons/gmail_hook_server.py` ~186 | `assert email, "verified push carried no emailAddress"` | Google Pub/Sub push body | `HookError` (already defined in this module) |
| `frontend/session.py` ~112 | `assert key, "_mac needs a key"` | Signing key for the session and OAuth-state cookies. An empty key means a MAC anyone can compute | `RuntimeError` |

### One judgement call

`backend/custody/handoff.py` ~128, `assert len(line) <= MAX_BODY` in `encode()`.
This is the **outbound** path encoding a payload we built, so by the rule above
it is an internal invariant and can stay. The inbound limit that matters is
already enforced separately by `read_line(conn, limit=MAX_BODY)`. Convert to
`ValueError` only if a payload can grow from user-supplied text (a voice profile
or a long address), which is worth checking before deciding.

## What deliberately stays an assert

Do not convert these. They are the first class in the rule and converting them
adds noise that makes the converted ones harder to see:

- Caller preconditions: `assert handle and inner`, `assert htm and htu`,
  `assert account is not None`, `assert name`, `assert etype`.
- Manifest-present checks: `assert data is not None, "cannot set ... without an
  accounts manifest"` (7 of these in `account.py`).
- Internal key-length checks on values this process just generated:
  `keyring.py` ~295 and ~303, `assert len(dek) == wrapping.KEY_LEN`.
- `agentic_drafter.py` ~103 and ~198 — the nonce shape and
  `isinstance(fence, Fence)`. The fence is built by `new_fence()` in this
  module and passed by our own callers. The check that matters for the fence
  surviving contact with an email body is `pseudonymizer` ~518 above.
- `cosigner/policy.py` config checks (`assert value > 0`) and the four package
  invariants in `cosigner/__init__.py`, which the runtime guard now protects.

## Verifying a conversion

After each file:

```bash
micromamba run -n py311 python -m pytest -q
micromamba run -n py311 python -m flake8 backend cosigner deploy frontend tests tools
micromamba run -n py311 python -m isort --check-only backend cosigner deploy frontend tests tools
```

For any converted check that a caller might swallow, grep for a handler before
declaring it done:

```bash
grep -rn "except.*CustodyError\|except Exception\|except:" --include=*.py backend/ frontend/
```

A converted check caught into a fallback is worse than the assert was, because
it reads as handled.

## Order it was done in

1. `account.py` path guards — highest consequence, self-contained.
2. `pseudonymizer.py`'s protected-token check, after reading its callers:
   nothing catches `MaskingFailed`, and
   `test_a_masking_failure_stops_the_request_rather_than_degrading_it` now pins
   that a failure reaches no provider.
3. `quote_policy.py`, both attestation callers with it.
4. The rest.
