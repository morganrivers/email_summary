"""Letterlock web UI (Tracks U1, U2, U3, U4, U6, U7, U8, U9, U11).

Minimal stdlib HTTP server. Caddy terminates TLS and reverse-proxies.
Run as: python -m frontend.web_server

Routes
------
Public:
  GET  /                 home (landing)
  GET  /about            about + security model
  GET  /faq              FAQ
  GET  /pricing          pricing + comparison table
  GET  /contact          contact form
  POST /contact          handle contact form
  GET  /static/<name>    stylesheet + brand icons (see STATIC_TYPES)
  GET  /favicon.ico      brand icon at the conventional path

Auth:
  GET  /auth/login       mint PKCE state, redirect to Google
  GET  /auth/callback    exchange code, set session, redirect
  POST /auth/logout      clear session cookie

Authenticated:
  GET  /dashboard        account status + attestation check
  GET  /voice            voice profile, as editable plaintext
  POST /voice            save the edited profile
  POST /voice/generate   build a profile from the account's sent mail
  POST /voice/reset      drop the profile, back to the default
  GET  /settings         settings (telegram link, timezone, auto-scheduling)
  POST /settings         save timezone + auto-scheduling
  POST /settings/telegram/start    mint a one-time chat link code
  POST /settings/telegram/confirm  claim the chat that posted the code
  POST /settings/telegram/unlink   drop the linked chat
  GET  /billing          plan status + Polar portal link
  GET  /billing/return   where Polar returns a buyer; settles entitlement
  GET  /billing/portal   mint a Polar customer session, redirect to the portal
  GET  /account          account info + danger-zone delete
  POST /account/delete   delete account entry
"""

import http.cookies
import os
import secrets
import sys
import time
import urllib.parse
import zoneinfo
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from dotenv import load_dotenv

from backend import paths
from backend import site
from backend.accounts import account
from backend.billing import billing
from backend.drafting import voice_dna
from backend.integrations import telegram
from backend.onboarding import provisioning
from frontend import session as sess

load_dotenv(paths.ENV_FILE)

HOST = os.environ.get("WEB_HOST", "127.0.0.1")
PORT = int(os.environ.get("WEB_PORT", str(site.WEB_PORT)))
REDIRECT_URI = os.environ.get("WEB_OAUTH_REDIRECT_URI", site.oauth_callback_url())
STATE_COOKIE = "letterlock_oauth_state"
STATE_TTL = 600

# Every page is server-rendered from our own templates with no third-party
# assets, so the policy can be as tight as "nothing but us, and no framing".
SECURITY_HEADERS = [
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "same-origin"),
    # The pages carry inline style attributes and one inline script (the footer
    # clock), so the policy has to allow both. Tightening style-src/script-src
    # past this silently strips the layout: the browser drops every style="".
    ("Content-Security-Policy",
     "default-src 'none'; img-src 'self' data:; "
     "style-src 'self' 'unsafe-inline'; script-src 'unsafe-inline'; "
     "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"),
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
]

# A settings form post is a few hundred bytes; the voice profile textarea is the
# one large form, bounded by voice_dna.MAX_PROFILE_CHARS before url-encoding.
MAX_BODY = 128 * 1024

# How often the voice page re-checks a running generation, in seconds.
VOICE_POLL_SECONDS = 5

# Everything servable under /static/, by filename. The map is the allow-list:
# a request that is not a key here never touches the filesystem, so no path
# component from the URL is ever joined onto a directory.
STATIC_TYPES = {
    "app.css": "text/css; charset=utf-8",
    "favicon.ico": "image/x-icon",
    "favicon-32.png": "image/png",
    "icon-512.png": "image/png",
    "apple-touch-icon.png": "image/png",
    "mark.png": "image/png",
}
_STATIC_CACHE = {}

# account id -> (link code, expiry). In-process and short-lived on purpose: a
# code is only meaningful between rendering the page and the user pressing the
# confirm button, and a restart just means starting the link again.
_LINK_CODES = {}
LINK_TTL = 900


def _put_link_code(account_id):
    code = telegram.new_link_code()
    _LINK_CODES[account_id] = (code, time.time() + LINK_TTL)
    return code


def _get_link_code(account_id):
    entry = _LINK_CODES.get(account_id)
    if not entry:
        return None
    code, expiry = entry
    if expiry < time.time():
        del _LINK_CODES[account_id]
        return None
    return code


def log(msg):
    sys.stderr.write(f"web_server {msg}\n")
    sys.stderr.flush()


# The OAuth sequence (auth url, code exchange, creds custody, registration,
# watch) lives in backend.onboarding.provisioning, which is its only copy.


_BILLING = None


def _portal_url(acct):
    """Polar customer-portal link for the signed-in account, or None. Polar
    credentials are optional to the web UI: a box without them still serves
    every page, it just cannot mint a portal link."""
    global _BILLING
    if _BILLING is None:
        try:
            _BILLING = billing.PolarBilling()
        except AssertionError as err:
            log(f"polar portal unavailable: {err}")
            return None
    return _BILLING.portal_url(acct)


def _valid_timezone(name):
    try:
        zoneinfo.ZoneInfo(name)
    except Exception:
        return False
    return True


def _deliver_contact(name, email, message):
    """Put a contact message somewhere a person will see it. The form used to
    write one stderr line and tell the sender we would get back to them, which
    made it a form that quietly discarded mail."""
    log(f"contact form: name={name!r} email={email!r} msg={message[:80]!r}")
    text = (
        "✉️ <b>Contact form</b>\n"
        f"From: {_h(name or 'anonymous')} &lt;{_h(email or 'no address given')}&gt;\n\n"
        f"{_h(message[:3000])}"
    )
    if not telegram.send_telegram(text, telegram.operator_target()):
        log("contact form: no operator Telegram target; message is in the log only")


def _static(name):
    """Bytes and content type for an asset, or (None, None) if it is not one of
    ours. Read once and held: the files are small and only change on deploy,
    which restarts the service."""
    ctype = STATIC_TYPES.get(name)
    if ctype is None:
        return None, None
    if name not in _STATIC_CACHE:
        path = paths.STATIC_DIR / name
        assert path.is_file(), f"missing static asset: {path}"
        _STATIC_CACHE[name] = path.read_bytes()
    return _STATIC_CACHE[name], ctype


def _h(text):
    return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


def _layout(title, body, active=None, user_email=None, refresh=None):
    public_nav = [
        ("/", "Home"),
        ("/about", "About"),
        ("/faq", "FAQ"),
        ("/pricing", "Pricing"),
        ("/contact", "Contact"),
    ]
    auth_nav = [
        ("/dashboard", "Dashboard"),
        ("/voice", "Voice DNA"),
        ("/settings", "Settings"),
        ("/billing", "Billing"),
        ("/account", "Account"),
    ]
    nav_links = auth_nav if user_email else public_nav
    nav_html = ""
    for href, label in nav_links:
        cls = ' class="active"' if href == active else ""
        nav_html += f'<a href="{href}"{cls}>{label}</a>'
    if user_email:
        nav_html += (
            f'<span class="right">{_h(user_email)} &nbsp;'
            f'<form method="post" action="/auth/logout" style="display:inline">'
            f'<button type="submit" style="background:none;border:none;padding:0;'
            f'cursor:pointer;font-size:11px;font-weight:bold;color:#1a237e;'
            f'font-family:Verdana,sans-serif;">Logout</button></form></span>'
        )
    else:
        nav_html += (
            '<span class="right"><a href="/auth/login">Sign in</a></span>'
        )
    # Only ever set by a page waiting on background work, and only as an integer
    # of seconds, so the header cannot carry anything but a delay.
    refresh_html = ""
    if refresh is not None:
        refresh_html = f'<meta http-equiv="refresh" content="{int(refresh)}">\n'
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
{refresh_html}<title>{_h(title)} | Letterlock</title>
<link rel="stylesheet" href="/static/app.css">
<link rel="icon" href="/static/favicon.ico" sizes="any">
<link rel="icon" type="image/png" sizes="32x32" href="/static/favicon-32.png">
<link rel="apple-touch-icon" href="/static/apple-touch-icon.png">
<meta name="theme-color" content="#0f1730">
</head>
<body>
<div id="page">
  <div id="titlebar">
    <div class="brand">
      <a href="/"><img class="mark" src="/static/mark.png" alt="" width="23" height="14"> Letterlock</a>
      <span class="tagline">the most secure AI assistant for Gmail</span>
    </div>
  </div>
  <div id="navbar">{nav_html}</div>
  <div id="content">
{body}
  </div>
  <div id="footer">
    <span>&copy; 2026 Letterlock</span>
    <span class="footer-right">
      <span id="utc-clock"></span>
    </span>
  </div>
</div>
<script>
(function(){{
  function tick(){{
    var n=new Date();
    var pad=function(x){{return String(x).padStart(2,'0');}};
    document.getElementById('utc-clock').textContent=pad(n.getUTCHours())+':'+pad(n.getUTCMinutes())+':'+pad(n.getUTCSeconds())+' UTC';
  }}
  tick(); setInterval(tick,1000);
}})();
</script>
</body>
</html>""".encode()


def _page_home():
    body = """
<p>Responding to emails is a pain. Many tools are available, but when you choose an AI
assistant entrusted with your email, you are risking the privacy of you and everyone that
emails you. Letterlock solves both problems at once: Letterlock waits for emails and
securely searches your inbox and Google calendar for relevant information before drafting
a reply, saving hours a week in drafting replies to emails.</p>

<div style="text-align:center;padding:16px 0;">
  <a href="/auth/login" class="cta-btn">&#187; Connect your Gmail</a>
  &nbsp;&nbsp;
  <a href="/about" style="font-size:11px;">How it works &rarr;</a>
</div>

<h2>How secure is Letterlock?</h2>

<p>With ever more powerful AI agents, email security requires several layers of defense.
Letterlock uses the same security protocols as Signal messenger and Swiss Banks, to ensure
defense-in-depth. Email data is never saved on Letterlock servers. Compute is done in
secure enclaves, and Letterlock's security algorithms are constantly monitoring for
suspicious activity. Email access tokens requires simultaneous access to an encrypted
secure enclave as well as Letterlock's EU-based verifier server. As a separate layer of
defense, personally identifying information or private information is stripped before AI
inference is run on a separate, secure enclave inference provider, which verifiably cannot
store your email data.</p>

<h2>Why doesn't Letterlock send emails?</h2>

<p>The world doesn't need more AI slop. Letterlock provides useful information in a draft
form, but doesn't send. By default, letterlock matches the length of your emails, and is
configured to avoid overclaiming or hallucinating email content.</p>

<h2>Features</h2>

<ul style="font-size:11px;line-height:1.9;padding-left:18px;">
  <li>Automatic draft creation: Letterlock reads the thread, searches your email history for context, and writes a reply in your voice</li>
  <li>Google Calendar integration: checks your availability, and creates events from your sent mail when auto-scheduling is enabled</li>
  <li>Telegram notifications when a draft is ready</li>
  <li>Daily summary of your inbox and calendar when configured, skipping unimportant emails and highlighting urgent ones</li>
</ul>

<div class="tee-box">
<strong>What is a TEE?</strong> A Trusted Execution Environment is a locked compartment inside a
processor chip. Code running inside cannot be read or modified by the host operating system,
the cloud provider, or us. At boot, the enclave produces a signed attestation report containing
a hash of the code it is running. Anyone can verify that hash against the published source code.
</div>

<hr>

<div style="text-align:center;padding:10px 0;">
  <a href="/pricing" style="font-size:11px;font-weight:bold;">See pricing &rarr;</a>
  &nbsp;&nbsp;&nbsp;
  <a href="/faq" style="font-size:11px;font-weight:bold;">Read the FAQ &rarr;</a>
</div>
"""
    return _layout("Home", body, active="/")


def _page_about():
    body = """
<h2>What is Letterlock?</h2>

<p>Letterlock is a Gmail AI assistant that drafts replies, checks your calendar, and
summarises your inbox.</p>

<p>The assistant is open source, runs in a Trusted Execution Environment (TEE), and strips
personally identifying information from your email before any text reaches the AI model.</p>

<h2>How the security works</h2>

<div class="tee-box">
<strong>What is a TEE?</strong><br>
A Trusted Execution Environment is a hardware-enforced region of a processor. Code running
there cannot be read or modified by the operating system, the cloud provider, or the server
operator. At boot it produces an attestation report: a signed statement of which code is
running, chaining back to the chip manufacturer (Intel, for TDX). Compare that hash against
our published source and you know what the server is running. If it does not match, the Key
Management Service withholds the secrets and the server does not start.
</div>

<h2>The masking pipeline</h2>

<p>Before your email content leaves the enclave, a masking step replaces identifying
information (your name, email addresses, phone numbers, and contact names from your OAuth
profile) with placeholder tokens such as <code>[PERSON1]</code> or <code>[EMAIL2]</code>.
The model sees the masked text; the mapping stays inside the enclave and is restored before
the draft is written to Gmail.</p>

<p>The masking logic is open source, and the test corpus publishes its recall. Recall is not
100%, but your own name and email addresses are matched literally rather than only by the
NER model, so those are always caught.</p>

<h2>Your OAuth token</h2>

<p>Your Gmail refresh token grants read/write access to your mailbox. It lives inside the
enclave, in an encrypted volume whose key is released by the KMS only after the attestation
report passes verification. The key is never on the host filesystem.</p>

<p>You can revoke it at any time from your
<a href="https://myaccount.google.com/permissions">Google account permissions</a> page, and
deleting your Letterlock account removes all encrypted data.</p>

<h2>Open source</h2>

<p>All code is public: the masking logic, the draft pipeline, the attestation setup, the
billing integration, and this web server. A reproducible Nix build means anyone can rebuild
from source and derive the same image hash that the attestation report contains.</p>

<hr>

<div style="text-align:center;padding:10px 0;">
  <a href="/auth/login" class="cta-btn">&#187; Connect your Gmail</a>
</div>
"""
    return _layout("About", body, active="/about")


def _page_faq():
    body = """
<h2>Frequently asked questions</h2>

<details>
<summary>What is a TEE and why does it matter for email privacy?</summary>
<div class="answer">
<p>It is a locked compartment inside the processor that the operating system, the cloud
provider, and we ourselves cannot read into. Your Gmail token lives only in there.
<a href="/about">About</a> explains the attestation that makes this checkable rather than
a promise.</p>
</div>
</details>

<details>
<summary>Does Letterlock train on my emails?</summary>
<div class="answer">
<p>No. We have no training relationship with the model provider and no ability to train on
your data. The model never sees your raw email in the first place.</p>
</div>
</details>

<details>
<summary>Which AI models are available?</summary>
<div class="answer">
<p>Letterlock uses open-weight models served in the EU by Scaleway. Current options include
Llama 3.1 70B, Llama 3.1 405B, Mistral Large 2, DeepSeek R1, and Qwen 2.5 72B. All are
open-source models with published weights. Because the masking always runs, the choice of
model does not affect whether your raw PII is exposed.</p>
</div>
</details>

<details>
<summary>Can a malicious email manipulate the assistant?</summary>
<div class="answer">
<p>The drafter can search your mailbox for context, so an email written to look like
instructions is a possible attack: get the assistant to pull something out of your mail and
put it in a reply addressed back to the sender.</p>
<p>Email content and tool results are fenced and marked as untrusted data rather than
instructions. Letterlock also never sends: every draft waits in your Drafts folder until you
read it and press send.</p>
</div>
</details>

<details>
<summary>How do I get Telegram notifications?</summary>
<div class="answer">
<p>Open <a href="/settings">Settings</a> and follow the linking steps: we show you a
one-time code, you send it to the Letterlock bot, and we read the chat back from the bot. That is how
we know the chat is yours.</p>
</div>
</details>

<details>
<summary>Where is my data stored?</summary>
<div class="answer">
<p>Email bodies are not stored at all once a draft is written, and the masking mapping is
discarded with them. The only thing kept is your Gmail token, in an encrypted volume the
host cannot open (see <a href="/about">About</a>).</p>
</div>
</details>

<details>
<summary>How does the PII masking work?</summary>
<div class="answer">
<p>Identifying values are replaced with placeholders such as <code>[PERSON1]</code> before
anything leaves the enclave, and restored afterwards. A named-entity recogniser catches
what the known-values list misses. See <a href="/about">About</a> for the detail, including
what recall the open test corpus measures.</p>
</div>
</details>

<details>
<summary>What does it cost?</summary>
<div class="answer">
<p>&euro;20 a month, billed by Polar. There is no free tier: model calls cost money on every
email processed. <a href="/pricing">Pricing</a> compares this against the alternatives.</p>
</div>
</details>

<details>
<summary>Is the code open source?</summary>
<div class="answer">
<p>Yes, all of it. You can read it, run the test suite, and rebuild the enclave image
yourself.</p>
</div>
</details>

<details>
<summary>What is the jurisdiction?</summary>
<div class="answer">
<p>Inference runs on Scaleway (France). The TEE substrate is Phala Cloud (Intel TDX).
Both are EU or EU-aligned. This means no CLOUD Act exposure and no need for Standard
Contractual Clauses for the inference path.</p>
</div>
</details>

<hr>
<div style="text-align:center;padding:10px 0;">
  <a href="/auth/login" class="cta-btn">&#187; Connect your Gmail</a>
</div>
"""
    return _layout("FAQ", body, active="/faq")


def _page_pricing():
    body = """
<h2>Pricing</h2>

<div class="info-box" style="text-align:center;padding:16px;">
  <div style="font-size:22px;font-weight:bold;color:#1a237e;font-family:'Trebuchet MS',Verdana,sans-serif;">
    &euro;20 / month
  </div>
  <div style="font-size:11px;color:#444;margin-top:4px;">All features included. No usage caps.</div>
  <div style="margin-top:12px;">
    <a href="/auth/login" class="cta-btn">&#187; Connect your Gmail</a>
  </div>
</div>

<h2>How Letterlock compares</h2>

<p style="font-size:11px;color:#555;">
The table below compares tools that combine email with AI or strong privacy. Prices are
approximate and may change.
</p>

<table class="data-table">
<thead>
<tr>
  <th>Tool</th>
  <th>Price</th>
  <th>Encryption model</th>
  <th>Trains on data?</th>
  <th>Jurisdiction</th>
  <th>Best for</th>
</tr>
</thead>
<tbody>
<tr>
  <td>Proton Mail + Scribe</td>
  <td>from $6.99/mo</td>
  <td>Zero-access E2E</td>
  <td>No</td>
  <td>Switzerland</td>
  <td>Max privacy, very limited AI</td>
</tr>
<tr>
  <td>Tuta</td>
  <td>$3 to $8/mo</td>
  <td>Quantum-safe E2E</td>
  <td>No</td>
  <td>Germany</td>
  <td>Future-proof encryption, no AI</td>
</tr>
<tr>
  <td>Canary Mail</td>
  <td>$3 to $10/mo</td>
  <td>PGP + on-device AI</td>
  <td>No</td>
  <td>India / US</td>
  <td>Some AI features, on-device only</td>
</tr>
<tr>
  <td>alfred_</td>
  <td>$24.99/mo</td>
  <td>AES-256 + TLS 1.3</td>
  <td>No</td>
  <td>US</td>
  <td>Full AI features, server-side trust</td>
</tr>
<tr>
  <td>Superhuman</td>
  <td>$30 to $40/mo</td>
  <td>SOC 2 standard</td>
  <td>Not disclosed</td>
  <td>US</td>
  <td>Speed, enterprise</td>
</tr>
<tr>
  <td>Shortwave</td>
  <td>$30 to $120/seat/mo</td>
  <td>Standard encryption</td>
  <td>Not disclosed</td>
  <td>US</td>
  <td>Team email, privacy unclear</td>
</tr>
<tr>
  <td>Gmail + Gemini</td>
  <td>from $19.99/mo</td>
  <td>Google infrastructure</td>
  <td>Claims no (Workspace)</td>
  <td>US</td>
  <td>On-demand writing help inside Gmail itself</td>
</tr>
<tr class="highlight">
  <td><strong>Letterlock</strong></td>
  <td><strong>&euro;20/mo</strong></td>
  <td><strong>TEE enclave + PII masking</strong></td>
  <td><strong>No, open source</strong></td>
  <td><strong>EU</strong></td>
  <td><strong>Verifiably secure AI email (Gmail only)</strong></td>
</tr>
</tbody>
</table>

<p style="font-size:11px;color:#555;">
The key distinction: Letterlock's security is verifiable. The attestation report shows that
the server runs the published open-source code. Other tools require you to trust their word.
</p>

<h2>What is included</h2>

<ul style="font-size:11px;line-height:1.9;padding-left:18px;">
  <li>Automatic draft creation with email history search for context</li>
  <li>Google Calendar read, plus event creation from your sent mail when enabled</li>
  <li>Telegram notifications and a daily inbox summary</li>
  <li>A per-account voice profile, so drafts sound like you</li>
  <li>All open-source EU-hosted models (Llama 3, Mistral, DeepSeek R1, Qwen)</li>
  <li>On-demand attestation: verify the server is running the published code at any time</li>
</ul>

<hr>
<div style="text-align:center;padding:10px 0;">
  <a href="/auth/login" class="cta-btn">&#187; Sign up (&euro;20/mo)</a>
</div>
"""
    return _layout("Pricing", body, active="/pricing")


def _page_contact(msg=None, error=None):
    status_html = ""
    if msg:
        status_html = f'<div class="form-success" style="margin-bottom:10px;">{_h(msg)}</div>'
    if error:
        status_html = f'<div class="form-error" style="margin-bottom:10px;">{_h(error)}</div>'
    body = f"""
<h2>Contact</h2>

<div class="contact-form" style="max-width:520px;">
  <form method="post" action="/contact">
    <div class="form-row">
      <label for="name">Name</label>
      <input type="text" id="name" name="name" maxlength="100">
    </div>
    <div class="form-row">
      <label for="email">Email</label>
      <input type="email" id="email" name="email" maxlength="200">
    </div>
    <div class="form-row">
      <label for="message">Message *</label>
      <textarea id="message" name="message" required rows="6" maxlength="2000"></textarea>
    </div>
    <div class="hp"><input type="text" name="website" tabindex="-1" autocomplete="off"></div>
    <button type="submit" class="form-submit">Send Message</button>
  </form>
  {status_html}
</div>
"""
    return _layout("Contact", body, active="/contact")


def _page_dashboard(acct):
    plan_badge = (
        '<span class="status-ok">ACTIVE</span>'
        if acct.plan_status == "active"
        else '<span class="status-error">INACTIVE</span>'
    )
    body = f"""
<h2>Dashboard</h2>

<table class="data-table" style="width:auto;min-width:320px;">
<tbody>
<tr><td style="font-weight:bold;width:160px;">Account</td><td>{_h(acct.id)}</td></tr>
<tr><td style="font-weight:bold;">Plan</td><td>{plan_badge}</td></tr>
<tr><td style="font-weight:bold;">Gmail</td><td><span class="status-ok">CONNECTED</span></td></tr>
<tr><td style="font-weight:bold;">Attestation</td>
    <td><span class="status-warn">STUB (Hetzner)</span>
    <span style="font-size:10px;color:#666;margin-left:6px;">Live on Phala TEE</span></td></tr>
</tbody>
</table>

<p style="font-size:11px;margin-top:12px;">
The assistant monitors your inbox. When an email arrives that needs a reply,
it drafts a response and saves it to your Gmail Drafts folder. You review and send.
</p>

<p style="font-size:11px;color:#555;">
Drafts only. The assistant never sends email autonomously.
</p>

<h2>Quick links</h2>

<ul style="font-size:11px;line-height:1.9;padding-left:18px;">
  <li><a href="/voice">Voice DNA</a> (teach the assistant your writing style)</li>
  <li><a href="/settings">Settings</a> (Telegram target, inference model)</li>
  <li><a href="/billing">Billing</a> (plan status and Polar portal)</li>
  <li><a href="/account">Account</a> (details and delete)</li>
</ul>
"""
    return _layout("Dashboard", body, active="/dashboard", user_email=acct.id)


def _page_voice(acct, error=None, notice=None):
    """The voice profile, as editable plaintext.

    The textarea holds the profile document itself rather than a form of fields:
    it is what the drafter reads, so showing anything else would be showing a
    summary of the thing that actually matters. Generating overwrites it, which is
    why the page says so before the button rather than after.

    voice_dna.HARD_CONSTRAINTS is deliberately not in the box. Those rules are
    the product's, they are appended to every profile, and a user editing their
    voice must not be able to delete a rule the drafter enforces anyway."""
    own = voice_dna.load(acct)
    job = voice_dna.status(acct.id)
    running = bool(job and job["state"] == "running")
    if job and job["state"] == "failed" and not error:
        error = job["error"]
    if job and job["state"] == "done" and not notice:
        notice = "Profile generated from your sent mail. Read it over and edit anything that is off."
    if job and not running:
        voice_dna.clear_status(acct.id)

    status_badge = (
        '<span class="status-ok">SET</span>' if own
        else '<span class="status-warn">USING DEFAULT</span>'
    )
    error_html = (
        f'<div class="form-error" style="margin-bottom:10px;">{_h(error)}</div>'
        if error else ""
    )
    notice_html = (
        f'<div class="form-success" style="margin-bottom:10px;">{_h(notice)}</div>'
        if notice else ""
    )

    if running:
        # A meta refresh rather than a fetch loop: the page carries no scripts of
        # its own and the CSP has no reason to start allowing any.
        return _layout("Voice DNA", """
<h2>Voice DNA</h2>
<div class="info-box">
  <p><b>Reading your sent mail and writing your profile.</b></p>
  <p>
    This takes a minute or two: we sample recent emails you have written, then
    build the profile from them. The page refreshes itself.
  </p>
</div>
<hr>
<a href="/dashboard">&larr; Back to dashboard</a>
""", active="/voice", user_email=acct.id, refresh=VOICE_POLL_SECONDS)

    editable = own or voice_dna.default_text()
    reset_html = ""
    if own:
        reset_html = """
<form method="post" action="/voice/reset" style="display:inline;margin-left:8px;">
  <button type="submit" class="form-submit">Revert to default</button>
</form>
"""
    body = f"""
<h2>Voice DNA</h2>

{error_html}{notice_html}

<p>
Your voice profile tells the assistant how you write, so replies sound like you.
</p>

<table class="data-table" style="width:auto;min-width:280px;">
<tbody>
<tr><td style="font-weight:bold;width:160px;">Your profile</td><td>{status_badge}</td></tr>
</tbody>
</table>

<h3>Generate from your sent mail</h3>

<p>
We read recent emails you have sent, keep the ones long enough to show how you
write, and turn them into the profile below. Nothing is sent anywhere else, and
generating <b>replaces whatever is in the box</b>.
</p>

<form method="post" action="/voice/generate" style="display:inline">
  <button type="submit" class="form-submit">Generate from sent mail</button>
</form>
{reset_html}

<hr>

<h3>Edit the profile</h3>

<p>
This is the text the assistant reads before every draft. Edit it freely: plain
prose works better than a form. Letterlock always adds its own output rules
(plain text, no em-dashes, never invent facts), so you do not need to write those.
</p>

<div class="contact-form" style="max-width:100%;">
  <form method="post" action="/voice">
    <textarea name="profile" rows="26" style="width:100%;font-family:monospace;font-size:12px;"
              maxlength="{voice_dna.MAX_PROFILE_CHARS}">{_h(editable)}</textarea>
    <button type="submit" class="form-submit">Save profile</button>
  </form>
</div>

<hr>
<a href="/dashboard">&larr; Back to dashboard</a>
"""
    return _layout("Voice DNA", body, active="/voice", user_email=acct.id)


def _telegram_section(acct, link_code=None, error=None, notice=None):
    """The Telegram block of the settings page.

    Linking is a round trip through the bot rather than a chat-ID text field: the
    user posts a one-time code, and we read the chat id back off the bot. A typed
    chat id proves nothing about who owns it."""
    error_html = (
        f'<div class="form-error" style="margin-bottom:10px;">{_h(error)}</div>'
        if error else ""
    )
    notice_html = (
        f'<div class="form-success" style="margin-bottom:10px;">{_h(notice)}</div>'
        if notice else ""
    )

    if link_code:
        username = telegram.bot_username()
        open_link = (
            f'<a href="https://t.me/{_h(username)}" target="_blank" rel="noopener">'
            f'@{_h(username)}</a>'
            if username else "our Telegram bot"
        )
        return f"""
<h3>Telegram</h3>
{error_html}{notice_html}
<div class="info-box">
  <p>
    1. Open {open_link} in Telegram and press Start.<br>
    2. Send it this code:
  </p>
  <p style="text-align:center;font-size:18px;font-weight:bold;letter-spacing:2px;">
    {_h(link_code)}
  </p>
  <p>3. Come back here and press the button.</p>
  <form method="post" action="/settings/telegram/confirm" style="display:inline">
    <button type="submit" class="form-submit">I have sent the code</button>
  </form>
</div>
"""

    if acct.telegram:
        return f"""
<h3>Telegram</h3>
{error_html}{notice_html}
<p>
  Linked to chat <code>{_h(acct.telegram.chat_id)}</code>. You get a message when a draft
  is ready, plus the daily summary.
</p>
<form method="post" action="/settings/telegram/unlink" style="display:inline">
  <button type="submit" class="form-submit">Unlink</button>
</form>
"""

    return f"""
<h3>Telegram</h3>
{error_html}{notice_html}
<p>
  Link a chat to get a message when a draft is ready, plus your daily summary.
</p>
<form method="post" action="/settings/telegram/start" style="display:inline">
  <button type="submit" class="form-submit">Link Telegram</button>
</form>
"""


def _page_settings(acct, saved=False, link_code=None, error=None, notice=None,
                   settings_error=None):
    saved_html = ""
    if saved:
        saved_html = '<div class="form-success" style="margin-bottom:10px;">Settings saved.</div>'
    settings_error_html = (
        f'<div class="form-error" style="margin-bottom:10px;">{_h(settings_error)}</div>'
        if settings_error else ""
    )
    auto_checked = " checked" if acct.auto_schedule else ""
    body = f"""
<h2>Settings</h2>

{saved_html}

{_telegram_section(acct, link_code=link_code, error=error, notice=notice)}

<hr>

<h3>Preferences</h3>

{settings_error_html}

<div class="contact-form" style="max-width:520px;">
  <form method="post" action="/settings">
    <div class="form-row">
      <label for="timezone">Timezone</label>
      <input type="text" id="timezone" name="timezone" value="{_h(acct.timezone)}"
             maxlength="60">
      <span style="font-size:10px;color:#666;">
        IANA name, for example Europe/Berlin. Used for the times in calendar events.
      </span>
    </div>
    <div class="form-row">
      <label>
        <input type="checkbox" name="auto_schedule" value="1"{auto_checked}>
        Create calendar events from my sent mail
      </label>
      <span style="font-size:10px;color:#666;">
        When an email you send commits to a date and time, add it to your primary
        calendar. Off by default. No invitations are sent.
      </span>
    </div>
    <button type="submit" class="form-submit">Save</button>
  </form>
</div>

<hr>
<a href="/dashboard">&larr; Back to dashboard</a>
"""
    return _layout("Settings", body, active="/settings", user_email=acct.id)


def _confirm_checkout(acct, checkout_id):
    """Settle entitlement for a buyer returning from Polar. Never raises: they
    have paid, and an exception here would show them an error page over a
    successful payment."""
    global _BILLING
    if _BILLING is None:
        try:
            _BILLING = billing.PolarBilling()
        except AssertionError as err:
            return False, f"polar not configured: {err}"
    try:
        return _BILLING.confirm_checkout(checkout_id, acct)
    except Exception as err:
        return False, f"{type(err).__name__}: {err}"


def _page_checkout_return(acct, paid):
    """Landing page after Polar. Two outcomes, and the pending one must not claim
    the payment failed: the money may well have moved while the entitlement flip
    is still in flight behind a webhook."""
    if paid or acct.plan_status == "active":
        body = """
<h2>You're set up</h2>

<div class="form-success" style="margin-bottom:12px;">
  Payment received and your subscription is active.
</div>

<p>Letterlock is now watching your inbox. When an email arrives that warrants a
personal reply, a draft appears in Gmail.</p>

<p>Two things worth doing now:</p>

<ul>
  <li><a href="/voice">Voice DNA</a> — generate your writing profile from your sent
      mail, so drafts sound like you instead of like the neutral default.</li>
  <li><a href="/settings">Settings</a> — link Telegram to get a message when a
      draft is ready, and set your timezone.</li>
</ul>

<hr>
<a href="/dashboard">Go to your dashboard &rarr;</a>
"""
        return _layout("Welcome", body, active="/billing", user_email=acct.id)

    body = """
<h2>Payment received</h2>

<div class="notice" style="margin-bottom:12px;">
  Polar has your payment. We are waiting on the confirmation that switches your
  account on, which normally takes a few seconds.
</div>

<p>Reload this page in a moment. If it still says this after a few minutes, the
payment is safe and <a href="/contact">telling us</a> is the fastest way to get it
sorted.</p>

<hr>
<a href="/billing">Check billing status &rarr;</a>
"""
    return _layout("Payment received", body, active="/billing", user_email=acct.id)


def _page_billing(acct, error=None):
    plan_badge = (
        '<span class="status-ok">ACTIVE</span>'
        if acct.plan_status == "active"
        else '<span class="status-error">INACTIVE</span>'
    )
    error_html = ""
    if error:
        error_html = f'<div class="form-error" style="margin-bottom:10px;">{_h(error)}</div>'
    portal_html = ""
    if acct.polar_customer_id:
        portal_html = (
            '<p style="font-size:11px;margin-top:12px;">'
            '<a href="/billing/portal" class="cta-btn">Manage subscription &rarr;</a>'
            "</p>"
        )
    body = f"""
<h2>Billing</h2>

{error_html}

<table class="data-table" style="width:auto;min-width:280px;">
<tbody>
<tr><td style="font-weight:bold;width:140px;">Plan</td><td>&euro;20/mo</td></tr>
<tr><td style="font-weight:bold;">Status</td><td>{plan_badge}</td></tr>
</tbody>
</table>

{portal_html}

<p style="font-size:11px;color:#555;margin-top:12px;">
Billing is managed by Polar. Invoices, receipts, and cancellation are available
through the Polar customer portal.
</p>

<hr>
<a href="/dashboard">&larr; Back to dashboard</a>
"""
    return _layout("Billing", body, active="/billing", user_email=acct.id)


def _page_account(acct, error=None):
    error_html = ""
    if error:
        error_html = f'<div class="form-error" style="margin-bottom:10px;">{_h(error)}</div>'
    body = f"""
<h2>Account</h2>

{error_html}

<table class="data-table" style="width:auto;min-width:280px;margin-bottom:14px;">
<tbody>
<tr><td style="font-weight:bold;width:140px;">Email</td><td>{_h(acct.id)}</td></tr>
<tr><td style="font-weight:bold;">Name</td>
    <td>{_h(acct.identity.first)} {_h(acct.identity.last)}</td></tr>
<tr><td style="font-weight:bold;">Plan</td><td>{_h(acct.plan_status)}</td></tr>
</tbody>
</table>

<h2>Danger zone</h2>

<div class="notice">
  Deleting your account removes your credentials, masking identity, and all stored state.
  This cannot be undone. Your Gmail Drafts folder is not affected.
</div>

<div class="contact-form" style="max-width:400px;">
  <form method="post" action="/account/delete">
    <div class="form-row">
      <label>Type your email address to confirm</label>
      <input type="email" name="confirm_email" required maxlength="200"
             placeholder="{_h(acct.id)}">
    </div>
    <button type="submit" class="form-submit" style="background:#cc0000;border-color:#ff6666;">
      Delete my account
    </button>
  </form>
</div>

<hr>
<a href="/dashboard">&larr; Back to dashboard</a>
"""
    return _layout("Account", body, active="/account", user_email=acct.id)


def _page_deleted():
    body = """
<h2>Account deleted</h2>
<p>Your account and credentials have been removed. Thank you for using Letterlock.</p>
<p><a href="/">Return to home</a></p>
"""
    return _layout("Account deleted", body)


def _page_error(code, msg):
    body = f"""
<h2>Error {code}</h2>
<p>{_h(msg)}</p>
<p><a href="/">Return to home</a></p>
"""
    return _layout(f"Error {code}", body)


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body=b"", ctype="text/html; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in SECURITY_HEADERS:
            self.send_header(k, v)
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _redirect(self, location, extra=None):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()

    def _get_account(self):
        email = sess.get_email(self.headers)
        if not email:
            return None
        return account.account_for_email(email, include_inactive=True)

    def _require_auth(self):
        acct = self._get_account()
        if not acct:
            self._redirect("/auth/login")
            return None
        return acct

    def _oauth_state(self):
        raw = self.headers.get("Cookie", "")
        if not raw:
            return None
        jar = http.cookies.SimpleCookie()
        try:
            jar.load(raw)
        except http.cookies.CookieError:
            return None
        m = jar.get(STATE_COOKIE)
        return m.value if m else None

    def _read_body(self):
        """Form fields from the request body, or None when the request is
        malformed. A garbage Content-Length used to raise out of the handler,
        and an unbounded one let a client name any allocation it liked."""
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            return None
        if length < 0 or length > MAX_BODY:
            return None
        if not length:
            return {}
        raw = self.rfile.read(length).decode(errors="replace")
        return {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path.startswith("/static/"):
            body, ctype = _static(path[len("/static/"):])
            if body is None:
                return self._send(404, _page_error(404, "Page not found."))
            return self._send(200, body, ctype=ctype,
                              extra=[("Cache-Control", "public, max-age=86400")])
        if path == "/favicon.ico":
            body, ctype = _static("favicon.ico")
            return self._send(200, body, ctype=ctype,
                              extra=[("Cache-Control", "public, max-age=86400")])

        if path in ("/", ""):
            return self._send(200, _page_home())
        if path == "/about":
            return self._send(200, _page_about())
        if path == "/faq":
            return self._send(200, _page_faq())
        if path == "/pricing":
            return self._send(200, _page_pricing())
        if path == "/contact":
            return self._send(200, _page_contact())

        if path == "/auth/login":
            state = secrets.token_urlsafe(24)
            try:
                url = provisioning.build_auth_url(state, REDIRECT_URI)
            except provisioning.ProvisionError as e:
                log(f"auth/login failed: {e.msg}")
                return self._send(e.code, _page_error(e.code, "Sign-in unavailable. Please try again later."))
            cookie = (
                f"{STATE_COOKIE}={state}; HttpOnly; Path=/; "
                f"Max-Age={STATE_TTL}; SameSite=Lax; Secure"
            )
            return self._redirect(url, extra=[("Set-Cookie", cookie)])

        if path == "/auth/callback":
            query = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
            try:
                acct, location = provisioning.handle_callback(
                    query, self._oauth_state(), REDIRECT_URI
                )
            except provisioning.ProvisionError as e:
                log(f"auth/callback rejected: {e.msg}")
                return self._send(e.code, _page_error(
                    e.code, "Could not complete sign-in. Please try again."))
            except Exception as e:
                log(f"auth/callback error: {e}")
                return self._send(500, _page_error(500, "Sign-in failed. Please try again."))
            clear_state = f"{STATE_COOKIE}=; Path=/; Max-Age=0"
            session_cookie = sess.make_cookie(acct.id)
            return self._redirect(location, extra=[
                ("Set-Cookie", clear_state),
                ("Set-Cookie", session_cookie),
            ])

        if path == "/dashboard":
            acct = self._require_auth()
            if acct is None:
                return
            return self._send(200, _page_dashboard(acct))

        if path == "/voice":
            acct = self._require_auth()
            if acct is None:
                return
            return self._send(200, _page_voice(acct))

        if path == "/settings":
            acct = self._require_auth()
            if acct is None:
                return
            return self._send(200, _page_settings(acct))

        if path == "/billing":
            acct = self._require_auth()
            if acct is None:
                return
            return self._send(200, _page_billing(acct))

        if path == "/billing/return":
            acct = self._require_auth()
            if acct is None:
                return
            query = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
            paid, detail = _confirm_checkout(acct, query.get("checkout_id"))
            log(f"checkout return for {acct.id}: paid={paid} {detail}")
            # Reload either way: the webhook may have flipped the plan already.
            acct = account.account_for_email(acct.id, include_inactive=True) or acct
            return self._send(200, _page_checkout_return(acct, paid))

        if path == "/billing/portal":
            acct = self._require_auth()
            if acct is None:
                return
            try:
                url = _portal_url(acct)
            except Exception as e:
                log(f"billing portal error for {acct.id}: {e}")
                url = None
            if not url:
                return self._send(200, _page_billing(acct, error=(
                    "The billing portal is unavailable right now. "
                    "If you have an active subscription, try again shortly."
                )))
            return self._redirect(url)

        if path == "/account":
            acct = self._require_auth()
            if acct is None:
                return
            return self._send(200, _page_account(acct))

        return self._send(404, _page_error(404, "Page not found."))

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path == "/auth/logout":
            clear = sess.clear_cookie()
            return self._redirect("/", extra=[("Set-Cookie", clear)])

        if path == "/contact":
            form = self._read_body()
            if form is None:
                return self._send(400, _page_error(400, "Malformed request."))
            if form.get("website"):
                return self._redirect("/contact")
            message = form.get("message", "").strip()
            if not message:
                return self._send(200, _page_contact(error="Message is required."))
            name = form.get("name", "").strip()
            email = form.get("email", "").strip()
            _deliver_contact(name, email, message)
            return self._send(200, _page_contact(msg="Message received. We'll get back to you when we can."))

        if path == "/settings":
            acct = self._require_auth()
            if acct is None:
                return
            form = self._read_body()
            if form is None:
                return self._send(400, _page_error(400, "Malformed request."))
            tz = form.get("timezone", "").strip() or account.DEFAULT_TIMEZONE
            if not _valid_timezone(tz):
                return self._send(200, _page_settings(
                    acct, settings_error=f"{tz} is not a known timezone name."))
            acct = account.set_settings(
                acct.id, timezone=tz, auto_schedule=bool(form.get("auto_schedule")),
            )
            return self._send(200, _page_settings(acct, saved=True))

        if path == "/settings/telegram/start":
            acct = self._require_auth()
            if acct is None:
                return
            if not telegram.bot_token():
                return self._send(200, _page_settings(acct, error=(
                    "Telegram is not configured on this server yet.")))
            code = _put_link_code(acct.id)
            return self._send(200, _page_settings(acct, link_code=code))

        if path == "/settings/telegram/confirm":
            acct = self._require_auth()
            if acct is None:
                return
            code = _get_link_code(acct.id)
            if not code:
                return self._send(200, _page_settings(acct, error=(
                    "That link code expired. Start again.")))
            try:
                chat_id = telegram.claim_chat_id(code)
            except Exception as e:
                log(f"telegram claim failed for {acct.id}: {e}")
                chat_id = None
            if not chat_id:
                return self._send(200, _page_settings(acct, link_code=code, error=(
                    "We have not seen that code yet. Send it to the bot, "
                    "then press the button again.")))
            _LINK_CODES.pop(acct.id, None)
            acct = account.set_telegram(acct.id, chat_id=chat_id)
            telegram.send_telegram(
                "✅ <b>Letterlock is linked to this chat.</b>\n"
                "You will get a message when a draft is ready, plus your daily summary.",
                acct.telegram,
            )
            return self._send(200, _page_settings(
                acct, notice="Telegram linked. We sent a test message."))

        if path == "/settings/telegram/unlink":
            acct = self._require_auth()
            if acct is None:
                return
            _LINK_CODES.pop(acct.id, None)
            acct = account.set_telegram(acct.id, clear=True)
            return self._send(200, _page_settings(acct, notice="Telegram unlinked."))

        if path == "/voice":
            acct = self._require_auth()
            if acct is None:
                return
            form = self._read_body()
            if form is None:
                return self._send(400, _page_error(400, "Malformed request."))
            try:
                acct = voice_dna.save(acct, form.get("profile", ""))
            except voice_dna.VoiceError as e:
                return self._send(200, _page_voice(acct, error=str(e)))
            return self._send(200, _page_voice(acct, notice="Profile saved."))

        if path == "/voice/generate":
            acct = self._require_auth()
            if acct is None:
                return
            voice_dna.start(acct)
            # Straight to the waiting page rather than rendering it here, so a
            # refresh during generation is a GET and not a repeated POST.
            return self._redirect("/voice")

        if path == "/voice/reset":
            acct = self._require_auth()
            if acct is None:
                return
            acct = voice_dna.clear(acct)
            return self._send(200, _page_voice(
                acct, notice="Profile removed. Drafts use the default profile again."))

        if path == "/account/delete":
            acct = self._require_auth()
            if acct is None:
                return
            form = self._read_body()
            if form is None:
                return self._send(400, _page_error(400, "Malformed request."))
            confirm = form.get("confirm_email", "").strip().lower()
            if confirm != acct.id.lower():
                return self._send(200, _page_account(acct, error="Email address did not match. Account not deleted."))
            account.delete_account(acct.id)
            _LINK_CODES.pop(acct.id, None)
            voice_dna.clear_status(acct.id)
            clear = sess.clear_cookie()
            return self._send(200, _page_deleted(), extra=[("Set-Cookie", clear)])

        return self._send(404, _page_error(404, "Not found."))

    def log_message(self, *args):
        pass


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    log(f"listening on {HOST}:{PORT}, redirect_uri={REDIRECT_URI}")
    server.serve_forever()


if __name__ == "__main__":
    main()
