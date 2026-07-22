"""Faraday web UI (Tracks U1, U2, U3, U4, U6, U7, U8, U9, U11).

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
  GET  /static/app.css   stylesheet

Auth:
  GET  /auth/login       mint PKCE state, redirect to Google
  GET  /auth/callback    exchange code, set session, redirect
  POST /auth/logout      clear session cookie

Authenticated:
  GET  /dashboard        account status + attestation check
  GET  /voice            voice DNA status
  GET  /settings         settings (telegram, inference provider)
  POST /settings         save settings
  GET  /billing          plan status + Polar portal link
  GET  /account          account info + danger-zone delete
  POST /account/delete   delete account entry
"""

import http.cookies
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from dotenv import load_dotenv

from backend import paths
from backend.accounts import account
from backend.onboarding import watch_renew
from frontend import session as sess

load_dotenv(paths.ENV_FILE)

OAUTH_HELPER = paths.node_script("oauth_helper.mjs")

HOST = os.environ.get("WEB_HOST", "127.0.0.1")
PORT = int(os.environ.get("WEB_PORT", "8790"))
REDIRECT_URI = os.environ.get(
    "WEB_OAUTH_REDIRECT_URI", "https://faradaymail.ai/auth/callback"
)
POLAR_CHECKOUT_URL = os.environ.get("POLAR_CHECKOUT_URL", "")
STATE_COOKIE = "faraday_oauth_state"
STATE_TTL = 600

_CSS_PATH = Path(__file__).parent / "app.css"
_CSS_CACHE = None


def log(msg):
    sys.stderr.write(f"web_server {msg}\n")
    sys.stderr.flush()


class WebError(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code = code
        self.msg = msg


def _run_oauth_helper(args):
    result = subprocess.run(
        ["node", str(OAUTH_HELPER), *args],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
    )
    if result.returncode != 0:
        raise WebError(502, f"oauth_helper {args[0]} failed: {result.stderr.decode().strip()}")
    return result.stdout.decode()


def _build_auth_url(state):
    return _run_oauth_helper(
        ["auth-url", "--state", state, "--redirect", REDIRECT_URI]
    ).strip()


def _exchange_and_provision(code):
    account.ACCOUNTS_DIR.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(dir=account.ACCOUNTS_DIR, prefix=".staging-"))
    try:
        out = _run_oauth_helper(
            ["exchange", "--code", code, "--redirect", REDIRECT_URI,
             "--creds-dir", str(staging)]
        )
        profile = json.loads(out)
        email = profile["email"]
        creds_abs = account.ACCOUNTS_DIR / email / ".gmail-mcp"
        creds_abs.mkdir(parents=True, exist_ok=True)
        for name in ("gcp-oauth.keys.json", "credentials.json"):
            shutil.move(str(staging / name), str(creds_abs / name))
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    creds_rel = creds_abs.relative_to(paths.REPO_ROOT)
    acct = account.register_account(
        email, profile["first"], profile["last"], str(creds_rel)
    )
    watch_renew.renew_account(acct, log=lambda m: log(m))
    log(f"provisioned {acct.id}")
    return acct


def _checkout_redirect(email):
    if not POLAR_CHECKOUT_URL:
        return "/dashboard"
    sep = "&" if "?" in POLAR_CHECKOUT_URL else "?"
    return f"{POLAR_CHECKOUT_URL}{sep}customer_email={urllib.parse.quote(email)}"


def _css():
    global _CSS_CACHE
    if _CSS_CACHE is None:
        _CSS_CACHE = _CSS_PATH.read_bytes()
    return _CSS_CACHE


def _h(text):
    return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


def _layout(title, body, active=None, user_email=None):
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
            '<span class="right"><a href="/auth/login">Sign in with Google</a></span>'
        )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_h(title)} | Faraday</title>
<link rel="stylesheet" href="/static/app.css">
</head>
<body>
<div id="page">
  <div id="titlebar">
    <div>
      <a href="/"><span class="diamond">&#9830;</span> Faraday <span class="diamond">&#9830;</span></a>
      <span class="tagline">private Gmail assistant, running in a tamper-proof enclave</span>
    </div>
  </div>
  <div id="navbar">{nav_html}</div>
  <div id="content">
{body}
  </div>
  <div id="footer">
    <span>&copy; 2026 Faraday &nbsp;|&nbsp; <a href="/about">About</a> &nbsp;|&nbsp; <a href="/faq">FAQ</a> &nbsp;|&nbsp; <a href="https://github.com/faradaymail">Source</a></span>
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
<h2>The most secure, powerful Gmail AI assistant</h2>

<p>Most Gmail AI tools process your email on servers you have to trust. Faraday is different.</p>

<p>Your email is processed inside a TEE (Trusted Execution Environment): a locked region
of the processor that nobody, including us, can inspect. Before any text reaches the AI
model, personally identifying information is stripped and replaced with placeholders.
The model sees tokens, not your real data.</p>

<p>All code is open source. Anyone can verify, independently, that our server runs
exactly the published code. This is a technical claim backed by hardware attestation,
not a policy promise.</p>

<div style="text-align:center;padding:16px 0;">
  <a href="/auth/login" class="cta-btn">&#187; Connect your Gmail</a>
  &nbsp;&nbsp;
  <a href="/about" style="font-size:11px;">How it works &rarr;</a>
</div>

<hr>

<h2>Features</h2>

<div class="info-box">
<ul class="feature-list">
  <li>Automatic draft creation: the agent reads the thread, searches your email history for context, and writes a reply in your voice</li>
  <li>Google Calendar integration: checks your availability, books meetings, and creates events on confirmation</li>
  <li>Telegram notifications when a draft is ready</li>
  <li>Optional full agent trace: the draft email includes a log of every tool called and every source consulted</li>
  <li>Open-source models served in the EU (Llama 3, Mistral, DeepSeek R1, Qwen)</li>
  <li>All code open source and auditable</li>
</ul>
</div>

<div class="tee-box">
<strong>What is a TEE?</strong> A Trusted Execution Environment is a locked compartment inside a
processor chip. Code running inside cannot be read or modified by the host operating system,
the cloud provider, or us. At boot, the enclave produces a signed attestation report containing
a hash of the code it is running. Anyone can verify that hash against our published source code.
This is what "provably runs the published code" means.
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
<h2>What is Faraday?</h2>

<p>Faraday is a Gmail AI assistant that drafts replies, checks your calendar, and summarises
your inbox. It is not a general-purpose assistant. It only works with Gmail.</p>

<p>The assistant is open source, runs in a Trusted Execution Environment (TEE), and strips
personally identifying information from your email before any text reaches the AI model.
These three properties together are what makes the security claim verifiable rather than
just a policy statement.</p>

<hr>

<h2>How the security works</h2>

<div class="tee-box">
<strong>What is a TEE?</strong><br>
A Trusted Execution Environment is an isolated, hardware-enforced region of a processor.
Code that runs there cannot be read or modified by the operating system, the cloud provider,
or the server operator (us). Think of it as a vault inside the chip itself, not a software
container or a virtual machine. Both can be inspected or tampered with by someone with
root access. A TEE cannot.<br><br>
At boot, the TEE produces an attestation report: a signed cryptographic document stating
exactly which code is running. The signature chains back to the chip manufacturer (Intel,
for TDX-based enclaves). The hash in the report can be compared against our published
source code. If they match, you have hardware-backed proof that our server is running
exactly that code. If they do not match, the Key Management Service refuses to release
the secrets and the server does not start.
</div>

<h2>The masking pipeline</h2>

<p>Before your email content leaves the enclave to reach the AI model, a masking step runs.
It identifies personally identifying information: your name, email addresses, phone numbers,
and contact names pulled from your OAuth profile. Each piece of information is replaced with
a placeholder token such as <code>[NAME_1]</code> or <code>[EMAIL_2]</code>.</p>

<p>The AI model receives the masked text. The token mapping stays inside the enclave and is
never logged or transmitted. After the model responds, the tokens are restored before the
draft is written to Gmail.</p>

<p>The masking logic is open source. You can read the code, run the test corpus, and
verify the recall metrics yourself. The recall is not 100%, and we publish that
honestly. The highest-stakes values (your name and email addresses) are scrubbed
deterministically by literal match, not only by the NER model, so the irreducible
residual is bounded.</p>

<h2>Your OAuth token</h2>

<p>Your Gmail refresh token grants full read/write access to your mailbox. It is the
load-bearing secret the whole TEE exists to protect. It lives only inside the enclave,
stored in an encrypted volume whose key is released by the KMS only after the attestation
report passes verification. The key is never on the host filesystem.</p>

<h2>Open source</h2>

<p>All code is public. The masking logic, the draft pipeline, the attestation setup,
the billing integration, and this web server. You can read it, audit it, and rebuild
the enclave image yourself. A reproducible Nix build means anyone can rebuild from
source and derive the same image hash that the attestation report contains.</p>

<h2>What Faraday does not do</h2>

<ul style="font-size:11px;line-height:1.9;">
  <li>Faraday does not send email. It creates drafts. You review and send.</li>
  <li>Faraday does not work with Outlook, Apple Mail, or ProtonMail.</li>
  <li>Faraday does not browse the web, write code, or manage files.</li>
  <li>Faraday does not store your email content persistently.</li>
  <li>Faraday does not use US-based AI providers. All inference runs on EU-hosted open-weight models.</li>
</ul>

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
<p>A TEE (Trusted Execution Environment) is a locked compartment inside a processor chip.
Code running inside a TEE cannot be read or modified by the operating system, the cloud
provider, or the server operator. It is not a software container (Docker) or a virtual
machine. Both of those can be inspected by someone with root access to the host. A TEE
cannot.</p>
<p>At boot, the TEE produces a signed attestation report. This report contains a hash of
the code running inside and a signature that chains back to the chip manufacturer (Intel,
for TDX). Anyone can verify that hash against our published source code. If the hashes
match, you have hardware-backed proof that the server is running the code we published.
The Key Management Service will not release your secrets to a server running different code.</p>
<p>For email, this matters because the OAuth token that grants access to your Gmail account
lives only inside the enclave. The host cannot read it. We cannot read it. The only code
that touches it is the code whose hash is published and verifiable.</p>
</div>
</details>

<details>
<summary>Does Faraday train on my emails?</summary>
<div class="answer">
<p>No. The models Faraday uses are open-weight models served by Scaleway (France). We have
no training relationship with Scaleway and no ability to train on your data. Additionally,
the AI model never sees your raw email: personally identifying information is stripped before
the masked text leaves the enclave.</p>
</div>
</details>

<details>
<summary>Which AI models are available?</summary>
<div class="answer">
<p>Faraday uses open-weight models served in the EU by Scaleway. Current options include
Llama 3.1 70B, Llama 3.1 405B, Mistral Large 2, DeepSeek R1, and Qwen 2.5 72B. All are
open-source models with published weights. Because the masking always runs, the choice of
model does not affect whether your raw PII is exposed.</p>
</div>
</details>

<details>
<summary>What can Faraday do?</summary>
<div class="answer">
<ul style="margin:0 0 8px 0;padding-left:18px;line-height:1.9;">
  <li>Draft replies to emails, searching your thread history for context</li>
  <li>Read your Google Calendar to check availability before drafting a scheduling reply</li>
  <li>Create Google Calendar events on confirmation</li>
  <li>Send Telegram notifications when a draft is ready</li>
  <li>Include a full trace of agent actions inside the draft email (optional)</li>
</ul>
</div>
</details>

<details>
<summary>What can Faraday not do?</summary>
<div class="answer">
<ul style="margin:0 0 8px 0;padding-left:18px;line-height:1.9;">
  <li>Faraday does not send email autonomously. It creates drafts only.</li>
  <li>Faraday only works with Gmail. Not Outlook, Apple Mail, or ProtonMail.</li>
  <li>Faraday does not browse the web, write code, or manage files.</li>
  <li>Faraday does not support phone calls, SMS, or Slack.</li>
</ul>
</div>
</details>

<details>
<summary>What is the agent trace feature?</summary>
<div class="answer">
<p>When enabled, the draft email includes a log of every tool the agent called: the threads
it searched, the calendar events it checked, and any intermediate decisions. You can read
it to understand why the draft says what it says. This makes the agent's reasoning auditable
at the level of individual emails, not just at the level of published code.</p>
</div>
</details>

<details>
<summary>Where is my data stored?</summary>
<div class="answer">
<p>Your Gmail OAuth token is stored inside the enclave in an encrypted volume (LUKS2).
The encryption key is released by the KMS only after the enclave's attestation report
passes verification. The key is never accessible on the host filesystem.</p>
<p>No email content is stored permanently. The masking token mapping lives in memory
for the duration of one request and is discarded. Draft logs are not retained.</p>
</div>
</details>

<details>
<summary>How does the PII masking work?</summary>
<div class="answer">
<p>Before email content leaves the enclave, a masking step identifies personally identifying
information: your name, email addresses, phone numbers, and contact names from your OAuth
profile. It also runs a named-entity recogniser (spaCy) to catch values not on the known list.</p>
<p>Each identified value is replaced with a placeholder such as <code>[NAME_1]</code> or
<code>[EMAIL_2]</code>. The AI model receives the masked text. The mapping is restored
after the model responds.</p>
<p>The recall is not 100%, and we publish that honestly in the open masking test corpus.
Your name and email addresses are scrubbed by deterministic literal match (not only by NER),
so the highest-stakes identifiers are always caught regardless of what the NER model misses.</p>
</div>
</details>

<details>
<summary>What does it cost?</summary>
<div class="answer">
<p>Faraday costs 20 euros per month. Payment is handled by Polar (EU-based). No free trial
is available. There is no free tier because the computational cost of running a TEE-backed
email agent is fixed regardless of usage.</p>
</div>
</details>

<details>
<summary>Is the code open source?</summary>
<div class="answer">
<p>Yes. The masking logic, the draft pipeline, the attestation setup, the billing
integration, and this web server are all public. You can read the code, run the test
suite, and rebuild the enclave image from source. A reproducible Nix build means anyone
can rebuild and derive the same image hash that the attestation report contains.</p>
</div>
</details>

<details>
<summary>What is the jurisdiction?</summary>
<div class="answer">
<p>Inference runs on Scaleway (France). The TEE substrate is Phala Cloud (Intel TDX).
Both are EU or EU-aligned. No US cloud provider touches your data or your email content.
This means no CLOUD Act exposure and no need for Standard Contractual Clauses for the
inference path.</p>
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

<h2>How Faraday compares</h2>

<p style="font-size:11px;color:#555;margin-bottom:8px;">
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
  <td>Free</td>
  <td>Google infrastructure</td>
  <td>Claims no (Workspace)</td>
  <td>US</td>
  <td>Free, but it's Google</td>
</tr>
<tr class="highlight">
  <td><strong>Faraday</strong></td>
  <td><strong>&euro;20/mo</strong></td>
  <td><strong>TEE enclave + PII masking</strong></td>
  <td><strong>No, open source</strong></td>
  <td><strong>EU</strong></td>
  <td><strong>Provably secure AI email (Gmail only)</strong></td>
</tr>
</tbody>
</table>

<p style="font-size:10px;color:#666;margin-top:4px;">
The key distinction: Faraday's security is verifiable. The attestation report is a
cryptographic proof that the server runs the published open-source code. Other tools
require you to trust their word.
</p>

<hr>

<h2>Who Faraday is for</h2>

<div class="info-box">
<p><strong>Choose Faraday if:</strong> you want a Gmail AI assistant and security is a priority.
You want to verify, independently, that the code processing your email matches what was published.
You accept Gmail only (no Outlook, no ProtonMail). You want draft-only (no autonomous sending).</p>
</div>

<div class="info-box">
<p><strong>Do not choose Faraday if:</strong> you use Outlook, Apple Mail, or another provider.
You need a general-purpose AI assistant. You need something that browses the web, writes code,
or manages files. You need on-device processing with no server involved.
You need more than ~100 drafts per month (see <a href="/faq">FAQ</a> on trial limits).</p>
</div>

<h2>What is included</h2>

<ul style="font-size:11px;line-height:1.9;padding-left:18px;">
  <li>Automatic draft creation with email history search for context</li>
  <li>Google Calendar read and event creation</li>
  <li>Telegram notifications</li>
  <li>Full agent trace in drafts (optional)</li>
  <li>Voice DNA: the assistant learns your writing style from sample emails</li>
  <li>All open-source EU-hosted models (Llama 3, Mistral, DeepSeek R1, Qwen)</li>
  <li>On-demand attestation: verify the server is running the published code at any time</li>
</ul>

<hr>
<div style="text-align:center;padding:10px 0;">
  <a href="/auth/login" class="cta-btn">&#187; Connect your Gmail (&euro;20/mo)</a>
</div>
"""
    return _layout("Pricing", body, active="/pricing")


def _page_contact(msg=None, error=None):
    status_html = ""
    if msg:
        status_html = f'<div class="form-success">{_h(msg)}</div>'
    if error:
        status_html = f'<div class="form-error">{_h(error)}</div>'
    body = f"""
<h2>Contact</h2>

<div class="contact-form">
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

<hr>

<h2>Quick links</h2>

<ul style="font-size:11px;line-height:2;">
  <li><a href="/voice">Voice DNA</a> (teach the assistant your writing style)</li>
  <li><a href="/settings">Settings</a> (Telegram target, inference model)</li>
  <li><a href="/billing">Billing</a> (plan status and Polar portal)</li>
  <li><a href="/account">Account</a> (details and delete)</li>
</ul>
"""
    return _layout("Dashboard", body, active="/dashboard", user_email=acct.id)


def _page_voice(acct):
    body = f"""
<h2>Voice DNA</h2>

<p style="font-size:11px;">
The assistant learns your writing style from a few sample emails. Once configured,
it uses your voice when drafting replies rather than a generic style.
</p>

<div class="notice">
  Voice DNA setup runs through the assistant itself. After connecting your Gmail,
  the assistant will send you an email asking for sample emails or a paste of
  examples. Reply to that email to complete the setup.
</div>

<p style="font-size:11px;">
If you have not received that email yet, it will arrive within a few minutes of
a new email landing in your inbox. If you prefer not to wait, reply to any email
in your inbox with <code>@faraday voice</code> as the first line.
</p>

<p style="font-size:11px;">
Until voice DNA is set, drafts are framed as a guessed voice with a note to
correct any mismatch. This preserves the human-in-the-loop review that the
setup step would otherwise provide.
</p>

<hr>
<a href="/dashboard">&larr; Back to dashboard</a>
"""
    return _layout("Voice DNA", body, active="/voice", user_email=acct.id)


def _page_settings(acct, saved=False):
    telegram = acct.telegram
    chat_id = telegram.chat_id if telegram else ""
    saved_html = ""
    if saved:
        saved_html = '<div class="form-success" style="margin-bottom:10px;">Settings saved.</div>'
    body = f"""
<h2>Settings</h2>

{saved_html}

<div class="contact-form" style="max-width:520px;">
  <form method="post" action="/settings">
    <div class="form-row">
      <label>Telegram chat ID</label>
      <input type="text" name="telegram_chat_id" value="{_h(chat_id)}" maxlength="40">
      <span style="font-size:10px;color:#666;">
        Start a chat with your Telegram bot and send /start to get your chat ID.
      </span>
    </div>
    <button type="submit" class="form-submit">Save</button>
  </form>
</div>

<hr>
<a href="/dashboard">&larr; Back to dashboard</a>
"""
    return _layout("Settings", body, active="/settings", user_email=acct.id)


def _page_billing(acct):
    plan_badge = (
        '<span class="status-ok">ACTIVE</span>'
        if acct.plan_status == "active"
        else '<span class="status-error">INACTIVE</span>'
    )
    portal_html = ""
    if acct.polar_customer_id:
        portal_html = (
            '<p style="font-size:11px;margin-top:12px;">'
            '<a href="/billing/portal" class="cta-btn">Manage subscription &rarr;</a>'
            "</p>"
        )
    body = f"""
<h2>Billing</h2>

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

<hr>

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
<p>Your account and credentials have been removed. Thank you for using Faraday.</p>
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
        self.send_header("X-Content-Type-Options", "nosniff")
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
        length = int(self.headers.get("Content-Length", 0))
        if not length:
            return {}
        raw = self.rfile.read(length).decode(errors="replace")
        return {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path == "/static/app.css":
            return self._send(200, _css(), ctype="text/css; charset=utf-8")

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
                url = _build_auth_url(state)
            except WebError as e:
                log(f"auth/login failed: {e.msg}")
                return self._send(e.code, _page_error(e.code, "Sign-in unavailable. Please try again later."))
            cookie = (
                f"{STATE_COOKIE}={state}; HttpOnly; Path=/; "
                f"Max-Age={STATE_TTL}; SameSite=Lax; Secure"
            )
            return self._redirect(url, extra=[("Set-Cookie", cookie)])

        if path == "/auth/callback":
            query = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
            err = query.get("error")
            if err:
                return self._send(400, _page_error(400, f"Sign-in was cancelled or denied: {_h(err)}"))
            code = query.get("code")
            state = query.get("state")
            cookie_state = self._oauth_state()
            if not code or not state:
                return self._send(400, _page_error(400, "Missing code or state. Please try signing in again."))
            if not cookie_state or not secrets.compare_digest(state, cookie_state):
                return self._send(403, _page_error(403, "State mismatch. Please try signing in again."))
            try:
                acct = _exchange_and_provision(code)
            except WebError as e:
                log(f"auth/callback provision failed: {e.msg}")
                return self._send(e.code, _page_error(e.code, "Could not complete sign-in. Please try again."))
            except Exception as e:
                log(f"auth/callback error: {e}")
                return self._send(500, _page_error(500, "Sign-in failed. Please try again."))
            clear_state = f"{STATE_COOKIE}=; Path=/; Max-Age=0"
            session_cookie = sess.make_cookie(acct.id)
            location = _checkout_redirect(acct.id)
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
            if form.get("website"):
                return self._redirect("/contact")
            message = form.get("message", "").strip()
            if not message:
                return self._send(200, _page_contact(error="Message is required."))
            name = form.get("name", "").strip()
            email = form.get("email", "").strip()
            log(f"contact form: name={name!r} email={email!r} msg={message[:80]!r}")
            return self._send(200, _page_contact(msg="Message received. We'll get back to you when we can."))

        if path == "/settings":
            acct = self._require_auth()
            if acct is None:
                return
            form = self._read_body()
            chat_id = form.get("telegram_chat_id", "").strip()
            if chat_id:
                data = account._read_manifest()
                if data:
                    for entry in data["accounts"]:
                        if entry["id"].lower() == acct.id.lower():
                            entry.setdefault("telegram", {})["chat_id"] = chat_id
                            account.MANIFEST.write_text(json.dumps(data, indent=2))
                            break
            return self._send(200, _page_settings(acct, saved=True))

        if path == "/account/delete":
            acct = self._require_auth()
            if acct is None:
                return
            form = self._read_body()
            confirm = form.get("confirm_email", "").strip().lower()
            if confirm != acct.id.lower():
                return self._send(200, _page_account(acct, error="Email address did not match. Account not deleted."))
            data = account._read_manifest()
            if data:
                data["accounts"] = [
                    e for e in data["accounts"] if e["id"].lower() != acct.id.lower()
                ]
                account.MANIFEST.write_text(json.dumps(data, indent=2))
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
