# Fixing the bandit findings

**Status: all six tracks landed.** With every skip removed, bandit over
`backend/`, `frontend/`, `cosigner/` and `runtime_guard.py` now reports `B101`
and nothing else. `B105` fires seven times and each is a `# nosec` on its line;
`B108`, `B310` and `B608` are absent because the code they described is gone.
`SKIPS` holds one id, and `B404`/`B603`/`B607` are skipped for `deploy/` and
`tools/` alone.

Two things named below are deliberately **not** done here, because they are
owned by other worktrees: the enclave egress allowlist
(`bug_fixes_fourthbatch.md` §3) and pinning the co-signer's certificate
(`bug_fixes_secondbatch.md` §A3), which is why `backend/custody/client.py` is
the one outbound call still on bare `requests`.

The rest of this document is the reasoning each change came from, kept because
the reason a suppression was wrong is the part worth rereading.

bandit was added to `tests/test_lint.py` in one pass, and that pass answered
almost every finding by suppressing it. Seven check ids went into a blanket
`SKIPS` and four lines got a `# nosec`. Three of those suppressions cover checks
that are describing something worth fixing, and one of them (`B101`) was
justified with an argument that is backwards. This is the plan to remove the
suppressions by fixing the code underneath them.

The standing rule this plan installs, and which the first pass did not follow:

* A check id belongs in `SKIPS` only when it is wrong **by construction** in
  this tree: the thing it looks for is not a defect here no matter which line it
  fires on. `B105` matching a variable *name* is that. `B310` is not.
* Anything else is a `# nosec <id>  # reason` on the exact line, so the
  exception is bounded to a line a reviewer can see, and adding a second one
  costs a second reviewed diff.
* A suppression may not be the answer to a check that would be a finding if the
  surrounding code drifted. Fix the code so drift is impossible instead.

## What bandit reports today

Counts from `bandit -r backend frontend cosigner tools deploy tests` with no
skips and with the four committed `# nosec` markers removed.

| id | check | backend | frontend | cosigner | tools | deploy | tests |
|----|-------|---------|----------|----------|-------|--------|-------|
| B101 | assert_used | 183 | 6 | 27 | 13 | 12 | 945 |
| B105 | hardcoded_password_string | 5 | 0 | 1 | 1 | 0 | 31 |
| B106 | hardcoded_password_funcarg | 0 | 0 | 0 | 0 | 0 | 3 |
| B108 | hardcoded_tmp_directory | 0 | 0 | 0 | 1 | 0 | 0 |
| B112 | try_except_continue | 0 | 0 | 0 | 0 | 0 | 1 |
| B310 | urllib_urlopen | 2 | 0 | 0 | 0 | 0 | 0 |
| B404 | import subprocess | 0 | 0 | 0 | 0 | 3 | 2 |
| B603 | subprocess_without_shell | 0 | 0 | 0 | 0 | 4 | 3 |
| B607 | partial_executable_path | 0 | 0 | 0 | 0 | 2 | 0 |
| B608 | hardcoded_sql_expressions | 0 | 0 | 2 | 0 | 0 | 0 |

Nothing is HIGH severity. That is not the same as nothing being worth fixing:
bandit's severity is about the class of bug, and it has no idea that
`cosigner/audit.py` is the rate limiter's counter or that `download_certs()`
fetches the keys that authenticate every inbound webhook.

## Track A: the assert argument is backwards, and it has to go

`SKIPS["B101"]` currently reads "asserts are a control here, not a note about
one", pointing at `runtime_guard.require_asserts()` as the reason that is safe.
That is the wrong way round. A control that vanishes under `-O` is a control
with a global off switch, and `runtime_guard` only refuses the boots that go
through `backend/__init__.py` or `cosigner/__init__.py`. A tool, a REPL, a
future entry point, or anything that imports a submodule directly gets the
optimized-out version with no refusal at all. Depending on it makes
`PYTHONOPTIMIZE` a security setting, which is exactly what it must not be.

The target property: **running under `-O` costs some internal invariant
checking and no security control.** `runtime_guard` stays, because refusing that
boot is still correct, but it stops being the justification for anything.

Work:

1. Finish the conversion `docs/plan_assert_conversion.md` started, using its own
   rule: a value from our own caller stays an assert, a value that crossed a
   trust boundary raises. The known survivors are all in `cosigner/keys.py`, and
   all three take input from the enclave over the wire or from a library:
   * `unwrap()` lines 245 to 252: the type check, the `len(outer) > header + 16`
     length check, and `version in known_versions()`. `outer` is a byte string a
     client posted, so this is textbook trust-boundary input. `cosigner/server.py`
     already has the type for it: `RequestError`, documented there as "a
     malformed request: answered with a status, never with a policy row".
   * `dpop_public_jwk()` line 316: `"d" not in jwk`. This is the check standing
     between a library change and the service publishing its DPoP private key
     over HTTP. Under `-O` today, that check is gone and the key is published.
     It raises.
   * `outer_key()` line 153: the `FIRST_VERSION <= version <= MAX_VERSION`
     range check, on the same wire-supplied version byte.
2. Sweep the rest of `cosigner/` and `backend/custody/` for the same shape: an
   assert whose subject came from a request body, a file, or a dependency's
   return value. `backend/tee/quote_policy._binds` is the model of the converted
   form and is already correct.
3. Add `tests/test_optimized_controls.py`: run the refusal suites
   (`test_custody.py`, `test_cosigner.py`, `test_handle_boundary.py`,
   `test_prompt_fence.py`) in a subprocess under `PYTHONOPTIMIZE=1`, with
   `runtime_guard.require_asserts` patched out for the duration, and require
   they still pass. This is the only check that actually proves the property
   rather than restating it, and it fails the moment someone spells a new
   control as an assert.
4. Only then rewrite the `B101` skip reason to what will by that point be true:
   asserts in this tree state internal invariants, every trust-boundary check
   raises a named type, and `tests/test_optimized_controls.py` pins it.

`B101` stays skipped at the end of this. 216 asserts in the shipped packages is
not a list anyone reads, and per-line markers on all of them would be noise. The
difference is that the skip will be honest.

## Track B: `urlopen` is the wrong call, twice

`B310` is the check that asks which schemes a URL open permits.
`urllib.request.urlopen` will open `file://`, `ftp://` and `data:` as readily as
`https://`, and it returns a file-like object either way, so a URL that ever
becomes caller-influenced turns a fetch into a local file read. The two call
sites do not take a caller URL today. They were suppressed on that basis, which
is a statement about today's callers rather than about the code.

There is a second problem the suppression hid. Outbound HTTP in this tree is
done four different ways:

| site | client | CA bundle | timeout | redirects |
|------|--------|-----------|---------|-----------|
| `backend/daemons/gmail_hook_server.py:182` | `urlopen` | system | 5s | followed |
| `backend/billing/polar_api.py:54` | `urlopen` | `certifi` | 15s | followed |
| `backend/integrations/inference_attestation.py:291` | `requests` | `certifi` | yes | followed |
| `backend/custody/tokens.py:150` | `requests` | system | yes | followed |
| `backend/integrations/telegram.py:67` | `requests` | system | yes | followed |
| `backend/integrations/gmail_gcal/gmail_api.py:66` | `requests` | system | yes | followed |

Six outbound call sites, four spellings, two CA policies, and every one of them
follows redirects to wherever the response points. The one in
`gmail_hook_server.py` fetches Google's OIDC signing certificates, which are
what decide whether an inbound Pub/Sub push is genuine. That is the most
security-relevant fetch on the box and it is the one with the weakest settings.

Work:

1. Add `backend/http_client.py` as the only place this tree makes an outbound
   HTTP request, in the sense `backend/egress.py` is the only place a hostname
   is allowed. It exposes `get(url, ...)` and `post(url, ...)` and:
   * parses the URL and raises unless the scheme is exactly `https`. A named
     refusal, not an assert, since the URL is an input;
   * pins the `certifi` bundle on every call, so one box-level CA store change
     cannot silently widen what six call sites trust;
   * requires an explicit timeout, no default that can be forgotten;
   * sets `allow_redirects=False` by default. A caller that needs a redirect
     asks for one and gets a single hop re-checked against the same rules. A
     303 from an allowlisted host to `http://169.254.169.254/` is the classic
     version of this and every call site above accepts it today.
2. Move all six call sites onto it and delete both `urlopen` uses. `B310` then
   fires nowhere and comes off every list, skips and nosec alike.
3. `tests/test_llm_boundary.py` already reads the tree as an AST to pin that
   nothing calls `/v1/responses`. Add `tests/test_http_boundary.py` in the same
   shape: no `urlopen`, no `requests.get`/`requests.post`, no `http.client`
   outside `backend/http_client.py`.

Two things this track deliberately does **not** touch, because they are being
fixed in other worktrees and doing them here would collide:

* Checking the host against `backend/egress.py` inside the client. That is the
  right belt-and-braces answer and it is what would make the allowlist mean
  something inside the enclave, but it is `bug_fixes_fourthbatch.md` §3 ("the
  enclave enforces no egress allowlist"), and the fix there is a compose
  partition change rather than a client change.
* `backend/custody/client.py`, the seventh outbound call site
  (`requests.request` to the co-signer). `bug_fixes_secondbatch.md` §A3 pins the
  co-signer's certificate, which rewrites how that one call verifies TLS. It
  stays on `requests` until that lands, and moves onto this client afterwards.

`backend/billing/polar_api.py` is touched by `bug_fixes_firstbatch.md` §L3,
which quotes caller-supplied ids into the endpoint path. Different line, same
function; whichever lands second rebases.

## Track C: the SQL is built by concatenation, and does not need to be

`cosigner/audit.py:204` and `:224` build a query by `+`-ing a clause returned
from `_action_clause()`. The clause today is placeholders only, so there is no
injection now. But `granted_since()` and `distinct_uids_since()` are what the
rate limiter counts with: a bug there does not corrupt data, it silently raises
the ceiling on how much of the user base one compromised enclave can unwrap.
That is not a function to leave with a string-building step in it, and a
`# nosec` on the line is an invitation for the next person to append one more
fragment to the same clause.

The set case is the only reason the clause exists, and it exists because
`policy.KEY_RELEASING` counts two actions together. Two static statements
replace it with no loss:

* `granted_since()`: one row has exactly one action, so counts partition. Run
  `SELECT COUNT(*) ... AND action = ?` once per action and sum in Python.
* `distinct_uids_since()`: distinct counts do not partition, so select the uids
  rather than the count. `SELECT DISTINCT uid ... AND action = ?` per action,
  union the sets, return the length. The action sets in this package have two
  elements and `requests_uid_action_ts` indexes the lookup.

Every SQL string in the module then becomes a literal with `?` parameters and
nothing else, `_action_clause()` is deleted, and `B608` comes off the list with
no marker anywhere. `tests/test_cosigner.py` already covers the limiter, and the
sweep-detection tests are what prove the union path counts the same as the old
`COUNT(DISTINCT uid)` did.

The `json_each(?)` form is the other way to get one static string and it works
on the SQLite Python ships. Rejected as the primary approach because it makes
the rate limiter depend on the JSON1 extension being compiled in on whatever box
the co-signer moves to, and this package is the one that has to keep working
when it moves.

## Track D: `/tmp` is not an output directory

`tools/render_pages.py:48` defaults to `Path("/tmp/letterlock-pages")`. `/tmp`
is world-writable and shared: the name is predictable, so anyone with an account
on the box can pre-create the directory or plant symlinks in it, and
`render()` calls `mkdir(parents=True, exist_ok=True)` and then writes through
whatever it finds. On a developer laptop that is a nuisance rather than a
breach, but there is no reason to accept it when the fix is one line.

Change `OUT_DEFAULT` to
`Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "letterlock" / "pages"`.
The directory keeps the property the tool needs, which is a stable name a person
can reopen, and drops the one it does not, which is being in a directory other
users can write. `--out` is unchanged, and the docstring's `/tmp` reference goes
with it. `B108` then fires nowhere and comes off the list.

## Track E: subprocess, and the line it must not cross

`B404`, `B603` and `B607` were skipped for the whole tree with a note that
`B603` fires on the safe list-argv form. Correct about the form, wrong about the
scope: skipping tree-wide means the day something in `backend/` grows a
`subprocess.run` there is no warning at all.

The facts, verified: `subprocess` is imported in exactly five files, all in
`deploy/` (`preflight.py`, `audit.py`, `check_egress.py`) and `tests/`
(`test_lint.py`, `test_runtime_guard.py`). No module under `backend/`,
`frontend/` or `cosigner/` imports it, and there is no `os.system`, `os.popen`,
`eval` or `exec` anywhere in those three packages. The measured enclave image
carries no `deploy/`, no `tests/`, no `tools/` and no `docs/`:
`deploy/phala/image_files.nix` is 73 entries and every one is `backend/`,
`frontend/`, `cosigner/protocol.py` or `runtime_guard.py`.

So the property you asked for holds today. It is not pinned anywhere, which is
the actual gap.

Work:

1. Split the bandit run in `tests/test_lint.py` into two, because the two bodies
   of code have different rules:
   * `test_bandit_finds_nothing_in_shipped_code`, over `backend frontend
     cosigner runtime_guard.py`, with **no** subprocess skips. It passes today
     with zero findings, and the first `subprocess` import in shipped code fails
     the suite.
   * `test_bandit_finds_nothing_in_operator_code`, over `deploy tools`, skipping
     `B404`/`B603`/`B607` with the reason that these run by hand on an
     operator's machine and never inside a unit or the image.
2. Add to `tests/test_image_manifest.py`: no entry in the manifest is under
   `deploy/`, `tests/`, `tools/` or `docs/`. It is one assertion and it states
   the boundary as a rule rather than as a fact that happens to hold.
3. Add to the same file or `tests/test_enclave_boundary.py`: no module listed in
   the manifest imports `subprocess`, `os.system`, `os.popen`, `pty`, or calls
   `eval`/`exec`. Read as an AST, in the shape `tests/test_web_boundary.py`
   already uses. This catches what bandit's per-file view cannot, which is a
   shipped module importing a helper that shells out.
4. Harden the one interpolation that exists. `deploy/preflight.py`
   `imports_cleanly()` runs `[sys.executable, "-c", f"import {module}"]` where
   `module` is scraped from `ExecStart=` in `deploy/hetzner/*.service`. It is a
   list argv so there is no shell, and the input is a repo file rather than a
   request, so this is not a live hole. It is still a string interpolated into
   code that then executes, which is the shape worth removing on sight: validate
   `module` against a dotted-name regex and raise on a mismatch before it is
   interpolated. `tools/reachability.py` already parses the same `ExecStart=`
   lines, so the regex belongs there and both import it, rather than each
   growing its own idea of what a module name looks like.

`B607` stays skipped for `deploy/` only. `uv` and `systemd-run` come from
`PATH`, and pinning absolute paths there would break the developer machines the
scripts run on for no gain, since anyone who can edit that `PATH` can edit the
script.

## Track F: `B105` becomes six named exceptions

`B105` fires when an identifier contains `token`, `secret`, `pass` or `pwd` and
is assigned a string literal. In shipped code it fires seven times and every one
is a name, not a value:

| file:line | identifier | value |
|-----------|-----------|-------|
| `backend/custody/tokens.py:45` | `TOKEN_FILE` | `"token.bin"`, a filename |
| `backend/custody/wrapping.py:55` | `DEV_SECRET_ENV` | the env var's name |
| `backend/secrets.py:53` | `GOOGLE_CLIENT_SECRET_ENV` | the env var's name |
| `backend/secrets.py:58` | `SESSION_SECRET_ENV` | the env var's name |
| `backend/secrets.py:68` | `SESSION_SECRET_PREVIOUS_ENV` | the env var's name |
| `cosigner/protocol.py:57` | `TOKEN_ENDPOINT` | Google's token URL |
| `tools/render_pages.py:31` | `TELEGRAM_BOT_TOKEN` | `""`, a render placeholder |

Drop `B105` and `B106` from `SKIPS` and put `# nosec B105  # <what it is>` on
those seven lines. The check then stays live everywhere else, so an actual
literal credential typed into shipped code fails the suite, which is the whole
reason to run `B105` at all. Seven markers is a list a reviewer can hold, and
each new one is a diff someone has to justify.

`B106` and `B112` fire only in `tests/`, which the shipped-code run does not
scan, so both come off the list for free.

## Sequencing

Independent of each other, roughly in order of what a compromise would cost:

1. Track A, the assert conversion, because `dpop_public_jwk()` under `-O`
   publishes a private key, and because every later claim about controls rests
   on this being true.
2. Track B, the HTTP client, because `download_certs()` decides which webhooks
   are genuine and currently trusts the system CA store with redirects on.
3. Track C, the co-signer SQL, because it is the rate limiter's counter.
4. Track E, the subprocess boundary, which is enforcement of a property that
   already holds, so it is cheap and it stops the property from quietly
   lapsing.
5. Tracks D and F, one line and seven lines.

Finish state: `SKIPS` contains `B101` with an accurate reason, plus
`B404`/`B603`/`B607` scoped to the operator-code run alone. Every other
exception is a `# nosec` on a line, and there are seven of them, all `B105`.
`B108`, `B310` and `B608` are absent because the code they described is gone.
