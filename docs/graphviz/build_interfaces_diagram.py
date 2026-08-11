#!/usr/bin/env python3
"""Build interfaces.drawio: the containers, and what crosses their edges.

The other diagrams in this folder answer "what happens to an email". This one
answers "what is a container here, and what may go into and out of it" -- one
card per container, every card built from the same stripes so two cards can be
compared by eye:

    header      the role, its image, how many files that image carries
    identity    uid, supplementary groups, networks, volumes, entry point
    IN          one row per inbound interface; arrows land on the row
    OUT         one row per outbound interface; arrows leave from the row
    env         the secrets that container's process environment holds

A row is a real cell, so the arrow attaches to the interface rather than to the
box, and every row and every arrow carries a tooltip with the protocol: the
wire format, the port and mode, what authenticates it and what refuses it. The
picture stays legible and the detail is one hover away.

Two panels. The Phala CVM, where the partition is four containers and the
compose file that assigns them is measured into RTMR3; and the Hetzner box,
where the same partition is spelled in systemd accounts, groups and file modes.
The stripes are deliberately identical between the two, because the split is
the same statement in two mechanisms. One arrow crosses: the enclave's custody
traffic to the co-signer, which is a unit on the box.

Nothing here is typed twice from memory -- the uids, groups, networks, image
file counts, allowlist hosts, ports, unit accounts and env names are read from
docker-compose.yml, flake.nix, image_files.nix, egress_allowlist.json,
backend/site.py, cosigner/protocol.py and deploy/hetzner/*.

Usage:  python build_interfaces_diagram.py
        python drawio_to_png.py interfaces.drawio
"""
import json
import os
import re

from drawio_common import emit_box, emit_edge, tip_html, wrap_mxfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))


# ----------------------------------------------------------------- sources ---
def repo_text(rel):
    with open(os.path.join(ROOT, rel), encoding='utf-8') as fh:
        return fh.read()


def image_file_counts():
    """{role: number of files that role's measured image carries}."""
    src = repo_text('deploy/phala/image_files.nix')
    out = {}
    for role in ('mail', 'web', 'hook', 'egress'):
        block = re.search(role + r'\s*=\s*\[(.*?)\];', src, re.S)
        assert block, f'{role} missing from image_files.nix'
        out[role] = len(re.findall(r'"([^"]+)"', block.group(1)))
    return out


def allowlist_hosts():
    hosts = json.loads(repo_text('backend/egress_allowlist.json'))['hosts']
    assert hosts, 'egress allowlist is empty'
    return hosts


def compose_env(service):
    """The env names one compose service interpolates, in file order."""
    src = repo_text('deploy/phala/docker-compose.yml')
    body = re.search(rf'\n  {service}:\n(.*?)(?=\n  \w+:\n|\nvolumes:)', src, re.S)
    assert body, f'{service} missing from docker-compose.yml'
    block = re.search(r'\n    environment:\n(.*?)(?=\n    \w+:|\Z)', body.group(1), re.S)
    assert block, f'{service} declares no environment block'
    return [m.group(1) for m in re.finditer(r'\n      ([A-Za-z_][A-Za-z0-9_]*):', block.group(1))]


COMMON_ENV = ['TEE_REQUIRED', 'EXPECTED_COMPOSE_HASH', 'HTTP_PROXY', 'HTTPS_PROXY',
              'http_proxy', 'https_proxy', 'NO_PROXY', 'no_proxy']
FILES = image_file_counts()
HOSTS = allowlist_hosts()


def env_of(service, common=True):
    names = (COMMON_ENV if common else []) + compose_env(service)
    seen, out = set(), []
    for n in names:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


# ------------------------------------------------------------------ layout ---
CARD_W = 310
TITLE_H = 26
SUB_H = 16
META_LH = 13
ROW_H = 22
HDR_H = 15
ENV_LH = 12
PAD = 5

MONO = 'fontFamily=Courier New;'
CARD_BODY = 'rounded=0;whiteSpace=wrap;html=1;strokeWidth=2;fillColor=#ffffff;'
STRIPE = ('rounded=0;whiteSpace=wrap;html=1;align=left;verticalAlign=middle;'
          'spacingLeft=9;strokeWidth=1;')
TITLE_ST = ('rounded=0;whiteSpace=wrap;html=1;align=left;verticalAlign=middle;'
            'spacingLeft=9;fontSize=14;fontStyle=1;strokeWidth=1;')
SUB_ST = STRIPE + MONO + 'fontSize=8.5;'
META_ST = ('rounded=0;whiteSpace=wrap;html=1;align=left;verticalAlign=top;'
           'spacingLeft=9;spacingTop=4;strokeWidth=1;fontSize=8.5;' + MONO +
           'fillColor=#f5f7f9;strokeColor=#d8dfe6;fontColor=#42536a;')
ENV_ST = ('rounded=0;whiteSpace=wrap;html=1;align=left;verticalAlign=top;'
          'spacingLeft=9;spacingTop=4;strokeWidth=1;fontSize=8;' + MONO +
          'fillColor=#f0e9f8;strokeColor=#c8b0e0;fontColor=#4b3168;')
HDR_ST = ('rounded=0;whiteSpace=wrap;html=1;align=left;verticalAlign=middle;'
          'spacingLeft=9;fontSize=8;fontStyle=1;strokeWidth=1;')
IN_HDR = HDR_ST + 'fillColor=#c9dcef;strokeColor=#7ba0c4;fontColor=#1b3a56;'
OUT_HDR = HDR_ST + 'fillColor=#f6ddc2;strokeColor=#d3a271;fontColor=#5a3410;'
IN_ROW = STRIPE + 'fontSize=9;fillColor=#e7f0f9;strokeColor=#7ba0c4;fontColor=#12304a;'
OUT_ROW = STRIPE + 'fontSize=9;fillColor=#fdf0e3;strokeColor=#d3a271;fontColor=#4d2c08;'

LEAF = ('rounded=1;whiteSpace=wrap;html=1;arcSize=25;fontSize=9;strokeWidth=1.5;'
        'fillColor=#2f7dc4;strokeColor=#1c4f80;fontColor=#ffffff;')
LEAF_MUTED = ('rounded=1;whiteSpace=wrap;html=1;arcSize=25;fontSize=9;strokeWidth=1.5;'
              'fillColor=#dfe4e9;strokeColor=#8d9aa8;fontColor=#3d4854;')
STORE = ('shape=cylinder;whiteSpace=wrap;html=1;fontSize=8.5;' + MONO +
         'align=left;spacingLeft=10;verticalAlign=middle;strokeWidth=1.5;'
         'fillColor=#e9eef3;strokeColor=#7b8a9a;fontColor=#25313d;')
SOCK = ('rounded=1;whiteSpace=wrap;html=1;arcSize=20;fontSize=8.5;' + MONO +
        'align=left;spacingLeft=10;strokeWidth=1.5;'
        'fillColor=#ddefec;strokeColor=#4f8a80;fontColor=#153b35;')
NOTE = ('shape=note;whiteSpace=wrap;html=1;size=14;fontSize=9;align=left;'
        'verticalAlign=top;spacingLeft=12;spacingTop=6;strokeWidth=1.5;'
        'fillColor=#fdf5d4;strokeColor=#c9a227;fontColor=#5b4a00;')
FRAME = ('rounded=1;html=1;dashed=1;dashPattern=8 5;strokeWidth=2.5;fillColor=none;'
         'verticalAlign=top;align=left;spacingLeft=16;spacingTop=8;fontStyle=1;fontSize=15;')
BAND = 'rounded=1;html=1;strokeColor=none;opacity=45;verticalAlign=top;align=right;spacingRight=12;fontSize=10;'
BAND_LINE = ('rounded=1;html=1;fillColor=none;dashed=1;dashPattern=3 3;strokeWidth=1.5;'
             'verticalAlign=bottom;align=right;spacingRight=10;spacingBottom=2;fontSize=9;')

EBASE = 'edgeStyle=none;html=1;rounded=1;endArrow=block;endFill=1;fontSize=8;fontColor=#4a5866;'
EKIND = {
    'net':    'strokeColor=#2e7d4f;strokeWidth=2.2;',
    'netcfg': 'strokeColor=#2e7d4f;strokeWidth=1.6;dashed=1;dashPattern=6 4;',
    'https':  'strokeColor=#2f7dc4;strokeWidth=1.6;',
    'ipc':    'strokeColor=#3f8f85;strokeWidth=1.8;',
    'file':   'strokeColor=#7b8a9a;strokeWidth=1.4;dashed=1;dashPattern=4 3;',
    'cross':  'strokeColor=#8a5fb0;strokeWidth=2.6;',
}

ROLE_COLOURS = {
    'enclave': ('#cfe6cf', '#4f7f5a', '#1e3a24'),
    'egress':  ('#f6ddc2', '#b8823c', '#4d2c08'),
    'host':    ('#dfe7ef', '#62778f', '#1b2733'),
    'ctrl':    ('#e6d6f2', '#8a5fb0', '#3d2757'),
}

REG = {}
TIPS = {}
BG, MID, FG = [], [], []


def reg(nid, x, y, w, h, tip=None):
    assert nid not in REG, f'duplicate cell id {nid}'
    REG[nid] = (x, y, x + w, y + h)
    if tip:
        TIPS[nid] = tip
    return REG[nid]


def left(n):   return REG[n][0]
def top(n):    return REG[n][1]
def right(n):  return REG[n][2]
def bottom(n): return REG[n][3]
def cx(n):     return (REG[n][0] + REG[n][2]) / 2
def cy(n):     return (REG[n][1] + REG[n][3]) / 2


def wrap(names, width):
    """Pack short tokens into lines of at most `width` characters."""
    lines, cur = [], ''
    for n in names:
        cand = n if not cur else cur + ' ' + n
        if len(cand) > width and cur:
            lines.append(cur)
            cur = n
        else:
            cur = cand
    if cur:
        lines.append(cur)
    return lines


# ------------------------------------------------------------------- cards ---
def card(cid, x, y, title, sub, meta, ins, outs, env=None, palette='enclave',
         tip=None, row_h=ROW_H, w=CARD_W):
    """Emit one container card and register every row as its own cell, so an
    edge attaches to the interface and not to the box. Returns the card rect."""
    fill, stroke, fc = ROLE_COLOURS[palette]
    for label, _ in list(ins) + list(outs):
        assert len(label) <= 54, f'{cid}: row label too wide: {label!r}'
    envlines = wrap(env, 46) if env else []
    h = (TITLE_H + SUB_H + PAD + META_LH * len(meta) + 8
         + (HDR_H + row_h * len(ins) if ins else 0)
         + (HDR_H + row_h * len(outs) if outs else 0)
         + (6 + HDR_H + ENV_LH * len(envlines) if envlines else 0) + PAD)

    reg(cid, x, y, w, h)
    FG.append(emit_box(cid, x, y, w, h, '',
                       CARD_BODY + f'strokeColor={stroke};',
                       tip_html(tip) if tip else None))
    cur = y
    FG.append(emit_box(cid + '__t', x, cur, w, TITLE_H, title,
                       TITLE_ST + f'fillColor={fill};strokeColor={stroke};fontColor={fc};'))
    cur += TITLE_H
    FG.append(emit_box(cid + '__s', x, cur, w, SUB_H, sub,
                       SUB_ST + f'fillColor={fill};strokeColor={stroke};fontColor={fc};opacity=70;'))
    cur += SUB_H + PAD
    mh = META_LH * len(meta) + 8
    FG.append(emit_box(cid + '__m', x, cur, w, mh, '\n'.join(meta), META_ST))
    cur += mh

    for kind, rows, hdr_st, row_st, hdr in (('in', ins, IN_HDR, IN_ROW, 'IN'),
                                            ('out', outs, OUT_HDR, OUT_ROW, 'OUT')):
        if not rows:
            continue
        FG.append(emit_box(f'{cid}__{kind}h', x, cur, w, HDR_H, hdr, hdr_st))
        cur += HDR_H
        for i, (label, rtip) in enumerate(rows):
            rid = f'{cid}__{kind}{i}'
            reg(rid, x, cur, w, row_h, rtip)
            FG.append(emit_box(rid, x, cur, w, row_h, label, row_st,
                               tip_html(rtip) if rtip else None))
            cur += row_h

    if envlines:
        cur += 6
        FG.append(emit_box(cid + '__eh', x, cur, w, HDR_H,
                           'env  (compose interpolation, measured in compose-hash)'
                           if palette != 'host' else 'environment / credentials',
                           HDR_ST + 'fillColor=#e2d3f2;strokeColor=#c8b0e0;fontColor=#4b3168;'))
        cur += HDR_H
        FG.append(emit_box(cid + '__e', x, cur, w, ENV_LH * len(envlines) + 8,
                           '\n'.join(envlines), ENV_ST))
    return REG[cid]


def leaf(nid, x, y, w, h, label, tip, style=LEAF):
    reg(nid, x, y, w, h, tip)
    FG.append(emit_box(nid, x, y, w, h, label, style, tip_html(tip)))


def store(nid, x, y, w, h, label, tip, style=STORE):
    reg(nid, x, y, w, h, tip)
    FG.append(emit_box(nid, x, y, w, h, label, style, tip_html(tip)))


def note(nid, x, y, w, h, label):
    reg(nid, x, y, w, h)
    BG.append(emit_box(nid, x, y, w, h, label, NOTE))


# ------------------------------------------------------------------- edges ---
def edge(src, dst, kind, pts, label='', tip=None):
    """Connect two interfaces. An arrow with no tooltip of its own inherits the
    one on the interface it leaves, so hovering the line answers the same
    question as hovering the row."""
    assert src in REG and dst in REG, f'edge between unknown cells: {src} -> {dst}'
    eid = f'e{len(MID)}'
    MID.append(emit_edge(eid, {'from': src, 'to': dst, 'label': label,
                               'tip': tip or TIPS.get(src) or TIPS.get(dst)},
                         dedupe(pts), EBASE + EKIND[kind]))


def slots(x0, x1, n, inset=14):
    """Evenly spaced vertical routing channels inside the gap between two card
    columns. Every long edge picks its x from here, which is what keeps a
    dropping arrow out of the card it would otherwise cut through."""
    assert x1 - x0 > 2 * inset, f'gap {x0}..{x1} too narrow for a channel'
    step = (x1 - x0 - 2 * inset) / max(n - 1, 1)
    return [x0 + inset + i * step for i in range(n)]


def dedupe(pts):
    out = []
    for p in pts:
        if not out or (abs(p[0] - out[-1][0]) > 0.5 or abs(p[1] - out[-1][1]) > 0.5):
            out.append(p)
    return out


def jog(src, dst, x):
    """Leave src sideways, one vertical jog at x, arrive at dst sideways."""
    return [(x, cy(src)), (x, cy(dst))]


def over(src, dst, ox, chan, ix):
    """Leave src sideways, run along a horizontal channel, arrive sideways."""
    return [(ox, cy(src)), (ox, chan), (ix, chan), (ix, cy(dst))]


def into_top(src, dst, ox, chan, dx=0.0):
    """Leave src sideways, run along a channel, drop onto dst's top border."""
    return [(ox, cy(src)), (ox, chan), (cx(dst) + dx, chan)]


def out_top(src, dst, chan, ix, dx=0.0):
    """Leave src's top border, run along a channel, arrive at dst sideways."""
    return [(cx(src) + dx, chan), (ix, chan), (ix, cy(dst))]


# =============================================================== ENCLAVE =====
E_LEAF_X, E_LEAF_W = 60, 190
E_C1, E_C2, E_C3 = 340, 810, 1280
DEST_X, DEST_W = 1990, 310
DEST_ROW_H = 38

CARDS_TOP = 300
CH_PROXY = [206, 222, 238]
E_GAP1 = slots(E_C1 + CARD_W, E_C2, 9)
E_GAP2 = slots(E_C2 + CARD_W, E_C3, 4)

ENFORCED_TIP = (
    'Enforced, not merely configured\n'
    'This role is attached to `inner` alone, which docker creates with no route '
    'off the host, so it reaches the internet through the proxy or not at all. '
    'The proxy env vars point it there; the network is what leaves it no '
    'alternative.')
CONFIGURED_TIP = (
    'Configured, not enforced\n'
    'This role is on `edge` as well, because a published port on an '
    'internal-only network never receives forwarded ingress and it has to be '
    'reached from outside the CVM. So for this role the allowlist is the proxy '
    'env vars and nothing more, and saying otherwise in product copy is the '
    'thing to refuse. It still buys the dependency-phones-home case and the '
    'post-compromise case where the attacker uses our own HTTP clients. '
    'Closing it would need an ingress container in front holding no data, '
    'which is what Caddy is on the box.')
HOST_ENFORCED_TIP = (
    'Enforced by systemd\n'
    'hardening.conf gives every unit IPAddressDeny=any with '
    'IPAddressAllow=localhost, and egress-proxy.service is the one drop-in that '
    'reverses it. So on this machine the proxy is the only way out for all of '
    'them. deploy/check_egress.py proves the control is actually on, because '
    'without cgroup v2 BPF systemd logs a line and starts the unit anyway.')

PROXY_TIP = (
    'HTTP CONNECT to egress:8792\n'
    'HTTP_PROXY / HTTPS_PROXY (and both lowercase spellings) point every HTTP '
    'client in this role at the egress container; NO_PROXY keeps loopback '
    'direct. The proxy reads one CONNECT request line, exact-matches the host '
    'against backend/egress_allowlist.json and then moves opaque bytes, so TLS '
    'stays end to end between this role and the destination.')

DSTACK_TIP = (
    '/var/run/dstack.sock  (guest agent, host bind mount)\n'
    'GetKey derives the app sealing key, GetTlsKey mints this container\'s own '
    'RA-TLS key pair, GetQuote produces the TDX quote tee_boot checks at start '
    'and the co-signer client presents. The socket is unauthenticated and '
    'GetKey takes a caller-supplied derivation path, which is why it is mounted '
    'into a role rather than into the compose file as a whole.')

card('e_hook', E_C1, CARDS_TOP,
     'hook', f'tee-email-bot-hook   ·   {FILES["hook"]} files   ·   command: hook',
     ['user  10003:10003  (letterlock-hook)',
      'group_add  10011 letterlock-wake',
      'networks  inner, edge      ports  8787:8787',
      'volumes  state',
      'python -m backend.daemons.gmail_hook_server'],
     [(':8787   POST /   Pub/Sub push',
       'Inbound: Google Pub/Sub push, HTTP/1.1 POST\n'
       'Body is a Pub/Sub push envelope; message.attributes name the mailbox. '
       'Authorization: Bearer <OIDC identity JWT>, verified against Google\'s '
       'JWKS with aud = site.pubsub_audience() (WEBHOOK_AUD) and the signer '
       'required to be PUBSUB_SERVICE_ACCOUNT. Anything else raises HookError '
       'and is refused. Binds 0.0.0.0:8787 because a published port never '
       'reaches a loopback listener.')],
     [('wake spool + wake.fifo   →   state/',
       'Outbound: append one line, then poke the FIFO\n'
       'backend/spool.py appends a JSON line to state/wake_queue.jsonl under '
       'state/wake_queue.lock, then writes a byte to state/wake.fifo. The line '
       'carries the address Google named; this role does not resolve it, '
       'because resolving reads the account manifest and this role holds none. '
       'Files 0660 group letterlock-wake (10011); state/ is 2771 so traversal '
       'is open and each file\'s own mode is the grant.'),
      ('HTTPS CONNECT   →   egress:8792     (JWKS)',
       'Outbound: the only network call this role makes\n'
       'Fetching Google\'s OIDC signing certificates to verify the push token. '
       'Goes through the proxy like every other client.\n\n' + PROXY_TIP)],
     env_of('hook'),
     tip='hook — the Pub/Sub receiver\n'
         'The most exposed role and the cheapest to isolate: it is the process '
         'Google posts to, and it needs almost nothing. Its image is '
         f'{FILES["hook"]} files (the JWT verifier, the wake spool, '
         'paths/secrets/site and the co-signer wire contract), so the inference '
         'client, Telegram, billing and the custody stack are not in its '
         'address space to reach for. It mounts state and not database, and no '
         'guest-agent socket.')

card('e_web', E_C1, bottom('e_hook') + 46,
     'web', f'tee-email-bot-web   ·   {FILES["web"]} files   ·   command: web',
     ['user  10002:10002  (letterlock-web)',
      'group_add  10010 letterlock-data',
      'networks  inner, edge      ports  8790:8790',
      'volumes  database, state, tmpfs /app/attestation',
      'python -m backend.tee.tee_boot   (gate, fail-closed)',
      'python -m frontend.web_server'],
     [(':8790   product UI over HTTPS',
       'Inbound: the product web UI, reached through dstack ingress\n'
       'Sign-in, dashboard, /voice, /personal, /settings, /billing. Two signed '
       'cookies, each kid:value:iat:mac -- the session cookie and the OAuth '
       'state cookie -- verified against frontend/session.py\'s keyring, so '
       'SESSION_SECRET_PREVIOUS still verifies while only the current key '
       'mints. WEB_HOST=0.0.0.0 because a published port never reaches a '
       'loopback listener. X-Forwarded-For is believed only from '
       'site.TRUSTED_PROXIES, which is loopback plus LETTERLOCK_TRUSTED_PROXIES '
       'and ships empty.')],
     [('custody.sock   →   mail     (9 operations)',
       'Outbound: the handoff client, backend/custody/handoff.py\n'
       'AF_UNIX SOCK_STREAM at state/custody.sock, one newline-framed JSON '
       'request per connection, 64 KiB cap. Operations: auth-url, sign-in, '
       'voice-start, voice-status, voice-clear, chat-begin, chat-finish, '
       'chat-forget, providers. The first three need a Google token or the '
       'credential that obtains one; the chat-* three cross because the '
       'decision is not this tier\'s to make; providers crosses because the '
       'answer is a function of the inference keys. HandoffUnavailable renders '
       'a 503 and is never caught into doing the work locally.'),
      ('HTTPS CONNECT   →   egress:8792',
       'Outbound: co-signer /unwrap for a data key, and Polar\n'
       'dek_for() is the document path: one POST /unwrap over TLS with an '
       'RA-TLS client certificate, cached for DEK_TTL, which must stay under '
       'cosigner.policy.DISTINCT_WINDOW_SECONDS or a slow sweep hides behind '
       'the cache. Polar is checkout creation and confirm_checkout().\n\n'
       + PROXY_TIP),
      ('database/<id>/   dek.bin, *.enc    0660',
       'Outbound: the account\'s own documents\n'
       'Reads and writes voice-dna.enc and personal-context.enc through '
       'keyring.read_encrypted / write_encrypted, plus accounts.json for '
       'settings and plan. Group letterlock-data (10010), directories 2770. '
       'token.bin in the same directory is 0600 to the mail uid.'),
      ('state/audit.db    0600',
       'Outbound: the web tier\'s own record\n'
       'One SQLite row per sign-in, setting, document edit, plan flip and '
       'deletion, written by the account mutators rather than the route '
       'handlers. Request origin is ambient through audit.request_context(). '
       'Nothing in a row can carry content: detail is a short name token '
       'checked against audit.TOKEN.'),
      ('/var/run/dstack.sock   GetKey · GetTlsKey · quote', DSTACK_TIP)],
     env_of('web'),
     tip='web — the product UI\n'
         'Its own uid, so a parsing bug in the HTTP surface facing the open '
         'internet is not every mailbox in the enclave. It holds a data key for '
         'rendering an account\'s own documents and so runs the attestation '
         'gate, and it holds no inference key: which providers Settings offers '
         'is answered by the mail role over handoff providers, which sends '
         'catalog names and never a key.')

card('e_mail', E_C2, CARDS_TOP,
     'mail', f'tee-email-bot-mail   ·   {FILES["mail"]} files   ·   command: mail',
     ['user  10001:10001  (letterlock-mail)',
      'group_add  10010 letterlock-data, 10011 letterlock-wake',
      'networks  inner',
      'volumes  database, state, tmpfs /app/attestation',
      'python -m backend.tee.tee_boot   (gate, fail-closed)',
      'python -m backend.daemons.daemon_loop  +  supercronic',
      'cron  05:00 summary · Mon 04:00 watch · */3h billing'],
     [('wake spool + wake.fifo   ←   state/',
       'Inbound: a wake, from the receiver or from the box\n'
       'The FIFO listener drains state/wake_queue.jsonl under its lock and '
       'resolves the address against the manifest -- which is this role\'s job '
       'and not the receiver\'s. Each wake routes through '
       'manual_draft.is_bot_request() to a draft request or to '
       'draft_replies.process_emails(). Writing here starts a drafting pass '
       'against a named account and spends that account\'s co-signer budget, '
       'which is why letterlock-wake is a group of its own.'),
      ('custody.sock   (server, SO_PEERCRED)',
       'Inbound: the handoff listener, run on a thread by the daemon\n'
       'state/custody.sock at 0660 in a 2771 directory, so the mode is the '
       'grant; _may_connect() reads SO_PEERCRED and admits this uid and '
       'paths.web_uid() alone, refusing root and refusing a kernel that will '
       'not answer. It is a second check of the same fact because every way the '
       'mode can widen is silent. It does not authenticate the end user: the '
       'daemon takes account_id as an argument, which is why chat_link exists '
       'for the one field where trusting that was too much. It runs on a thread '
       'so a sign-in does not wait behind a drafting pass.')],
     [('HTTPS CONNECT   →   egress:8792',
       'Outbound: everything this role reaches, through the proxy\n'
       'Gmail and Calendar, Google\'s OAuth token endpoint, the co-signer '
       '(/wrap, /unwrap-and-sign, /sign-dpop, /dpop-jwk, /health), the '
       'inference provider, Telegram, Polar and the PCCS. This is the only role '
       'on the internal network alone, so for it the allowlist is enforced by '
       'docker rather than merely configured.\n\n' + PROXY_TIP),
      ('database/<id>/    token.bin 0600, *.enc 0660',
       'Outbound: the account store\n'
       'One random 32-byte data key per account in dek.bin; token.bin, '
       'voice-dna.enc and personal-context.enc all go through '
       'keyring.read_encrypted / write_encrypted. token.bin is 0600 to this '
       'uid, so the web tier cannot read the one file its data key would open. '
       'accounts.json is the manifest and the only plaintext left, because '
       'encrypting it would need the account list to find the account.'),
      ('state/    state.json · audit prune · restart.flag',
       'Outbound: daemon scratch, in the shared 2771 directory\n'
       'state.json is the runtime record; audit.maybe_prune() rides on the '
       'daemon\'s pass so RETENTION_DAYS is a period on a clock rather than on '
       'whoever last signed in; restart.flag is how a code change takes effect '
       'without a service restart.'),
      ('/var/run/dstack.sock   GetKey · GetTlsKey · quote', DSTACK_TIP)],
     env_of('mail'),
     tip='mail — the only role that opens a mailbox\n'
         'Holds the Google client credentials, the inference keys and the '
         'Telegram token, and is the only account that can read '
         'database/<id>/token.bin. Runs the scheduled work too, because the '
         'summary and the watch renewal read mailboxes and the billing '
         'reconcile writes plan_status into the manifest. No role in here is a '
         'Polar receiver, so that 3-hourly reconcile plus confirm_checkout() in '
         'web are the whole of entitlement inside the enclave.')

EGRESS_OUT = [
    ('Gmail + Calendar API      ← mail',
     'gmail.googleapis.com, www.googleapis.com\n'
     'googleapiclient over TLS. Credentials carry no refresh token at all, so '
     'every acquisition goes through tokens.refresh_handler_for() and therefore '
     'through a co-signer round trip. Drafts are created and updated here; '
     'calendar writes are pinned to calendar_api.WRITE_CALENDAR.'),
    ('Google OAuth              ← mail, hook',
     'oauth2.googleapis.com, accounts.google.com\n'
     'The code exchange and every refresh, DPoP-bound to the co-signer\'s '
     'signing key -- which is why the exchange is in Python at all. hook '
     'reaches accounts.google.com only for the OIDC JWKS.'),
    ('Google Calendar iCal feed ← mail',
     'calendar.google.com\n'
     'calendar_public.is_public() fetches the calendar\'s public iCal feed with '
     'no credentials, as a stranger would: 200 refuses the write, 404 proceeds. '
     'On the allowlist unconditionally, since the proxy cannot read the '
     'LETTERLOCK_CALENDAR_ACL_SCOPE switch that decides which check runs.'),
    ('DeepSeek                  ← mail',
     'api.deepseek.com\n'
     'The default provider. Every call is POST /v1/chat/completions, never '
     '/v1/responses, which is stateful and persists content server-side; '
     'tests/test_llm_boundary.py reads the tree as an AST and fails if anything '
     'reaches for it. Masking applies on every provider.'),
    ('NEAR AI confidential      ← mail',
     'glm-5-2.completions.near.ai, gpt-oss-120b.completions.near.ai\n'
     'Per-model endpoints rather than the cloud-api.near.ai gateway, because '
     'only a per-model endpoint\'s attestation can say which model it serves. '
     'confidential=True costs a check: inference_attestation.require() binds '
     'the response signing address, a fresh nonce and the stated model_name '
     'against inference_allowlist.json before make_client() returns.'),
    ('Telegram                  ← mail',
     'api.telegram.org\n'
     'Daily summaries to the account\'s linked chat, the linking codes '
     'chat_link reads back out of the bot\'s inbox, and operator alerts. '
     'send_telegram() always takes an explicit target; there is deliberately no '
     'env fallback on the per-account path.'),
    ('Polar                     ← mail, web',
     'api.polar.sh, sandbox-api.polar.sh\n'
     'web creates the checkout and settles the buyer synchronously on the '
     'return page; mail runs the 3-hourly reconcile that re-derives '
     'subscription status from Polar rather than from an event body.'),
    ('Phala PCCS                ← mail, web',
     'pccs.phala.network\n'
     'Quote verification collateral: the signature chain to the Intel root and '
     'the TCB status, for both directions of attestation -- the co-signer '
     'checking us and us checking an inference provider.'),
    ('co-signer                 ← mail, web',
     'cosigner.morganrivers.com\n'
     'The other half of split custody, on the Hetzner box below. Ours is the '
     'inner AES-GCM layer from the dstack KMS app_secret, theirs the outer '
     'wrapping -- reversed, their unwrap would yield a usable key and they '
     'would become the one box that can read every mailbox. A hard dependency '
     'with no bypass: while it is unreachable no mail is processed.'),
]

card('e_egress', E_C3, CARDS_TOP,
     'egress', f'tee-email-bot-egress   ·   {FILES["egress"]} files   ·   command: egress',
     ['user  10004:10004  (letterlock-egress)',
      'group_add  —',
      'networks  inner, edge',
      'volumes  —',
      'python -m backend.daemons.egress_proxy',
      'reads  backend/egress_allowlist.json'],
     [(':8792   HTTP CONNECT   from inner + edge',
       'Inbound: one CONNECT request line per tunnel\n'
       'Reads the request line, exact-matches the host against the rendered '
       'allowlist, port 443 only, then moves opaque bytes. Exact matches: a '
       'suffix rule for near.ai is what permits evil.near.ai. It does not '
       'authenticate its callers -- the boundary is over destinations, and the '
       'internal network is what stops a role going around it. AllowlistInvalid '
       'on a missing or malformed file, so it refuses to start rather than '
       'starting with an empty list and refusing every tunnel one at a time. '
       'Written in-repo rather than tinyproxy or squid because it faces an '
       'attacker with code execution and a memory-unsafe C parser is the wrong '
       'thing there.')],
     EGRESS_OUT,
     env_of('egress', common=False),
     palette='egress', row_h=DEST_ROW_H,
     tip='egress — the one container with a route off the host\n'
         f'The same module the box runs as egress-proxy.service, {FILES["egress"]} '
         'files, its own uid and no group at all. It was 39 files until the '
         'allowlist stopped being derived inside it: performing that walk at '
         'startup meant importing the modules that name each host, and through '
         'them the co-signer client, billing and the inference client -- the '
         'custody stack in the filesystem of the one container that can reach '
         'the internet, in order to compute thirteen strings. The walk moved to '
         'render time; this module now imports json, os and pathlib and nothing '
         'of ours. TLS is end to end, so it holds no plaintext and no key.')

# --- enclave: the substrate lane ----------------------------------------------
E_CARD_BOT = max(bottom('e_web'), bottom('e_mail'), bottom('e_egress'))
E_CH0 = E_CARD_BOT + 26
E_CHAN = [E_CH0 + 14 * i for i in range(10)]
E_LANE_Y = E_CHAN[-1] + 40
LANE_H = 96

store('e_vol_state', 340, E_LANE_Y, 300, LANE_H,
      'volume  state → /app/state\n'
      '2771 letterlock-data\n'
      'wake_queue.jsonl + .lock  0660 wake\n'
      'wake.fifo · state.json · audit.db 0600',
      'docker volume "state"\n'
      'Mounted by mail, web and hook. 2771 rather than 2770 because four uids '
      'open a file in it and are deliberately not all in one group: traversal '
      'is open and each file\'s own mode is the grant. Docker seeds a named '
      'volume from the first container to mount it, ownership and mode '
      'included, so every image that mounts it seeds it identically and '
      'whichever container starts first the result is the same.')

store('e_sock', 700, E_LANE_Y, 300, LANE_H,
      'state/custody.sock\n'
      'AF_UNIX SOCK_STREAM  0660\n'
      'group letterlock-data (10010)\n'
      'newline-framed JSON, 64 KiB cap',
      'The handoff socket\n'
      'A socket rather than the wake spool because the spool is one way: a '
      'synchronous sign-in would poll for a result file, and that file would '
      'hold a live authorization code at rest. The two uids in letterlock-data '
      'are the only ones that can open it, and the listener checks SO_PEERCRED '
      'on top of that.', style=SOCK)

store('e_vol_db', 1060, E_LANE_Y, 300, LANE_H,
      'volume  database → /app/database\n'
      '2770 letterlock-data (setgid)\n'
      'accounts.json  (manifest, plaintext)\n'
      '<id>/ dek.bin · token.bin 0600 · *.enc',
      'docker volume "database"\n'
      'Mounted by mail and web; hook mounts it not at all, which is what keeps '
      'the account list out of reach of the process Google posts to. Not '
      'traversable like state/, because who has an account is itself worth '
      'keeping. Everything under <id>/ is ciphertext and opening any of it '
      'costs a co-signer round trip that is rate limited and logged.')

store('e_dstack', 1420, E_LANE_Y, 300, LANE_H,
      '/var/run/dstack.sock\n'
      'host bind mount, guest agent\n'
      'GetKey · GetTlsKey · GetQuote\n'
      'mounted into mail and web only',
      DSTACK_TIP, style=SOCK)

# --- enclave: external parties -------------------------------------------------
leaf('e_pubsub', E_LEAF_X, cy('e_hook__in0') - 26, E_LEAF_W, 52,
     'Google Pub/Sub\nwatch push subscription',
     'Google Pub/Sub push\n'
     'A users.watch registration on each account\'s mailbox, renewed weekly, '
     'makes Google POST here on every change. The push carries an OIDC identity '
     'JWT signed by the configured service account.')

leaf('e_browser', E_LEAF_X, cy('e_web__in0') - 26, E_LEAF_W, 52,
     'End user\nbrowser over HTTPS',
     'The product UI\'s caller\n'
     'Reaches the published 8790 through dstack\'s ingress. Closing the '
     'allowlist for this role would need an ingress container in front of it '
     'holding no data, which is what Caddy is on the box and is not in this '
     'repository.')

for i, (label, tip) in enumerate(EGRESS_OUT):
    rid = f'e_egress__out{i}'
    name = label.split('  ')[0].strip()
    hosts = wrap(tip.split('\n')[0].split(', '), 40)
    base = LEAF_MUTED if i == len(EGRESS_OUT) - 1 else LEAF
    leaf(f'e_dest{i}', DEST_X, top(rid) + 1, DEST_W, DEST_ROW_H - 2,
         '\n'.join([name] + hosts), tip, style=base + 'fontSize=8;')

note('e_note', E_C1, 118, E_C3 + CARD_W - E_C1, 74,
     'Attested, not merely configured:  docker-compose.yml is embedded in app-compose.json, whose hash is the dstack\n'
     'compose-hash extended into RTMR3.  Which process runs as which account, which image it runs, and which secrets\n'
     'each is handed are measured — move SESSION_SECRET to the mail container and cosigner/attest.py stops accepting\n'
     'the client certificate.  Every name below must also be in allowed_envs;  EXPECTED_COMPOSE_HASH is refused empty.')

# --- enclave: the wiring -------------------------------------------------------
edge('e_pubsub', 'e_hook__in0', 'https', jog('e_pubsub', 'e_hook__in0', E_C1 - 40))
edge('e_browser', 'e_web__in0', 'https', jog('e_browser', 'e_web__in0', E_C1 - 55))

edge('e_hook__out0', 'e_vol_state', 'file',
     into_top('e_hook__out0', 'e_vol_state', E_GAP1[2], E_CHAN[0], -90), 'append')
edge('e_vol_state', 'e_mail__in0', 'file',
     out_top('e_vol_state', 'e_mail__in0', E_CHAN[8], E_GAP1[7], 90), 'drain')
edge('e_web__out0', 'e_sock', 'ipc',
     into_top('e_web__out0', 'e_sock', E_GAP1[3], E_CHAN[1], -80), 'connect')
edge('e_sock', 'e_mail__in1', 'ipc',
     out_top('e_sock', 'e_mail__in1', E_CHAN[9], E_GAP1[8], 80), 'accept')

edge('e_web__out2', 'e_vol_db', 'file',
     into_top('e_web__out2', 'e_vol_db', E_GAP1[4], E_CHAN[2], -100))
edge('e_web__out3', 'e_vol_state', 'file',
     into_top('e_web__out3', 'e_vol_state', E_GAP1[5], E_CHAN[3], 90))
edge('e_web__out4', 'e_dstack', 'ipc',
     into_top('e_web__out4', 'e_dstack', E_GAP1[6], E_CHAN[4], -100))
edge('e_mail__out1', 'e_vol_db', 'file',
     into_top('e_mail__out1', 'e_vol_db', E_GAP2[0], E_CHAN[5], 0))
edge('e_mail__out2', 'e_vol_state', 'file',
     into_top('e_mail__out2', 'e_vol_state', E_GAP2[1], E_CHAN[6], 0))
edge('e_mail__out3', 'e_dstack', 'ipc',
     into_top('e_mail__out3', 'e_dstack', E_GAP2[2], E_CHAN[7], 0))

edge('e_hook__out1', 'e_egress__in0', 'netcfg',
     over('e_hook__out1', 'e_egress__in0', E_GAP1[0], CH_PROXY[0], E_C3 - 34),
     'CONNECT', CONFIGURED_TIP)
edge('e_web__out1', 'e_egress__in0', 'netcfg',
     over('e_web__out1', 'e_egress__in0', E_GAP1[1], CH_PROXY[1], E_C3 - 52),
     'CONNECT', CONFIGURED_TIP)
edge('e_mail__out0', 'e_egress__in0', 'net',
     jog('e_mail__out0', 'e_egress__in0', E_GAP2[3]), 'CONNECT  (enforced)', ENFORCED_TIP)

for i in range(len(EGRESS_OUT)):
    edge(f'e_egress__out{i}', f'e_dest{i}', 'https', [])

# =============================================================== HETZNER =====
H_LEAF_X, H_LEAF_W = 40, 150
H_CADDY, H_C1, H_C2, H_C3 = 270, 680, 1150, 1620

E_LANE_BOT = E_LANE_Y + LANE_H
H_FRAME_TOP = E_LANE_BOT + 132
H_CARDS_TOP = H_FRAME_TOP + 116
H_CH_PROXY = [H_CARDS_TOP - 60, H_CARDS_TOP - 44, H_CARDS_TOP - 28]
H_GAP0 = slots(H_CADDY + CARD_W, H_C1, 5)
H_GAPL = slots(H_LEAF_X + H_LEAF_W, H_CADDY, 4, inset=10)
H_GAP1 = slots(H_C1 + CARD_W, H_C2, 13)
H_GAP2 = slots(H_C2 + CARD_W, H_C3, 6)

HOST_PROXY_TIP = (
    'HTTP CONNECT to 127.0.0.1:8792\n'
    'hardening.conf sets HTTP_PROXY / HTTPS_PROXY (both spellings) on every '
    'unit, together with IPAddressDeny=any and IPAddressAllow=localhost, so the '
    'machine\'s reachable set is exactly backend/egress_allowlist.json. '
    'deploy/check_egress.py proves the control is on: IPAddressDeny= needs '
    'cgroup v2 with BPF, and without it systemd logs a line and starts the unit '
    'anyway.')

card('h_caddy', H_CADDY, H_CARDS_TOP,
     'caddy', 'system package  ·  /etc/caddy/Caddyfile  ·  not in this repo',
     ['config  deploy/hetzner/Caddyfile  (generated)',
      'python -m deploy.render_caddyfile > Caddyfile',
      'from  backend/site.py  hosts + upstream ports',
      'the only process holding a public TLS certificate',
      'not synced by deploy.sh — installed by hand'],
     [(':443   letterlock.morganrivers.com',
       'Inbound: APP_HOST, the product site block\n'
       'site.APP_HOST, overridable with LETTERLOCK_HOST. Terminates TLS and '
       'reverse-proxies from 127.0.0.1, which is the one address '
       'web_server._source_ip() will read an X-Forwarded-For from.'),
      (':443   hezner.morganrivers.com',
       'Inbound: API_HOST, the machine-to-machine site block\n'
       'site.API_HOST. Carries the Gmail Pub/Sub push and the Polar webhook. '
       'The catch-all keeps POST / on the webhook: serving a landing page from '
       'this root would mean repointing the push subscription first.'),
      (':443   cosigner.morganrivers.com   client_auth',
       'Inbound: the one site block that demands a client certificate\n'
       'tls { client_auth { mode require } }, and acme with the TLS-ALPN '
       'challenge disabled because that challenge and required client auth '
       'cannot share a listener. The certificate is the enclave\'s RA-TLS cert, '
       'carrying its TDX quote; Caddy does not judge it, it forwards the DER '
       'and cosigner/attest.py decides.')],
     [('127.0.0.1:8790   letterlock-web',
       'Upstream: the product UI, site.WEB_PORT'),
      ('127.0.0.1:8787   email-webhook   (catch-all)',
       'Upstream: the Gmail push receiver, site.GMAIL_PUSH_PORT'),
      ('127.0.0.1:8789   billing-webhook',
       'Upstream: the Polar receiver, site.BILLING_WEBHOOK_PORT, routed on '
       'site.POLAR_WEBHOOK_PATH = /letterlock/polar/webhook under both hosts.'),
      ('127.0.0.1:8791   cosigner  + X-Client-Cert-Der',
       'Upstream: the co-signer, cosigner.protocol.PORT\n'
       'header_up X-Client-Cert-Der {http.request.tls.client.certificate_der_'
       'base64} is how the quote reaches the process that checks it; '
       'cosigner/protocol.py names the header so both ends agree.'),
      ('127.0.0.1:8788   ks_signer   (not Letterlock)',
       'Upstream: the Kitchen Search license signer, /opt/ks_signer\n'
       'Kept in the rendered file because this is the whole Caddy config, so '
       'dropping the route would take that service offline.')],
     palette='ctrl',
     tip='caddy — the ingress\n'
         'The Caddyfile is generated from backend/site.py so a host or a port '
         'is stated once. It is deliberately not rsynced by deploy.sh: it is '
         'validated and installed by hand, because a bad reload takes every '
         'site down at once.')

card('h_hook', H_C1, H_CARDS_TOP,
     'email-webhook.service', 'python -m backend.daemons.gmail_hook_server',
     ['User=letterlock-hook   Group=letterlock-hook',
      'SupplementaryGroups=letterlock letterlock-wake',
      'ReadWritePaths=/opt/letterlock/state',
      'IPAddressDeny=any  IPAddressAllow=localhost',
      'writes state/ — the daemon resolves the address'],
     [('127.0.0.1:8787   from caddy   (OIDC JWT)',
       'Inbound: the Pub/Sub push, already TLS-terminated\n'
       'Same verification as the enclave role: aud = site.pubsub_audience(), '
       'signer PUBSUB_SERVICE_ACCOUNT, JWKS checked. HookError refuses.')],
     [('wake spool + wake.fifo   →   state/',
       'Outbound: append then poke, group letterlock-wake\n'
       'The reason this uid is in letterlock-wake and not letterlock-data: '
       'writing here starts a drafting pass and spends an account\'s co-signer '
       'budget, so the capability is a group of its own.'),
      ('HTTPS CONNECT   →   127.0.0.1:8792   (JWKS)', HOST_PROXY_TIP)],
     palette='host',
     tip='email-webhook.service\n'
         'The fourth unit to get its own account, and one of the cheap ones: it '
         'parses HTTP from the open internet and needs no account data. The '
         'receiver spools the address Google names and the daemon resolves it.')

card('h_web', H_C1, bottom('h_hook') + 34,
     'letterlock-web.service', 'python -m frontend.web_server',
     ['User=letterlock-web   Group=letterlock-web',
      'SupplementaryGroups=letterlock letterlock-data',
      '                     letterlock-secrets',
      'ReadWritePaths=/opt/letterlock/database  …/state',
      'IPAddressDeny=any  IPAddressAllow=localhost'],
     [('127.0.0.1:8790   from caddy',
       'Inbound: the product UI\n'
       'Signed session and OAuth-state cookies, kid:value:iat:mac. '
       'site.upstream() asserts the address it renders into the Caddyfile is '
       'one web_server._source_ip() trusts, or every audit row would record the '
       'proxy instead of a browser.')],
     [('custody.sock   →   email-daemon',
       'Outbound: the handoff client\n'
       'Same nine operations as in the enclave. tests/test_web_boundary.py '
       'reads the tree for a frontend/ module importing keyring, tokens, '
       'wrapping or chat_link, or calling any of those directly.'),
      ('HTTPS CONNECT   →   127.0.0.1:8792', HOST_PROXY_TIP),
      ('database/<id>/   *.enc   0660 letterlock-data',
       'Outbound: the account\'s own documents, and accounts.json\n'
       'Still reachable and stated so nobody reads more into it: '
       'database/accounts.json is writable here, so a compromised web tier can '
       'edit its own settings and its plan. It can no longer move the telegram '
       'target, which was the one field that reached mail content.'),
      ('state/audit.db   0600',
       'Outbound: the web tier\'s record of what a person changed'),
      ('.env   (group letterlock-secrets)',
       'Reads: SESSION_SECRET and the Polar configuration\n'
       'secrets.load() is the only read of this file, idempotent, injected '
       'environment wins. The account store and .env are deliberately not in '
       'the letterlock group, which is what keeps cosigner and egress out of '
       'them.')],
     palette='host',
     tip='letterlock-web.service\n'
         'The third unit to name its own account and the newest of the three '
         'that matter most: while it ran as letterlock, a parsing bug in it '
         'read every account\'s database/<id>/ and could ask the co-signer to '
         'unwrap any of them. What makes that more than a change of file owner '
         'is what it cannot reach: token.bin is mail-uid-only at 0600, and the '
         'two operations needing a Google token happen in the daemon.')

card('h_billing', H_C1, bottom('h_web') + 34,
     'billing-webhook.service', 'python -m backend.billing.billing_webhook',
     ['User=letterlock-billing   Group=letterlock-billing',
      'SupplementaryGroups=letterlock letterlock-billing-queue',
      '                     letterlock-billing-secrets',
      'ReadWritePaths=/opt/letterlock/state',
      'reads .env.billing — the signing secret alone'],
     [('127.0.0.1:8789   Polar webhook   (HMAC)',
       'Inbound: a Polar event, signature-verified\n'
       'POLAR_WEBHOOK_SECRET (and its _SANDBOX twin) live in .env.billing '
       'alone, so the unit that verifies Polar signatures does not also hold '
       'SESSION_SECRET and cannot mint a login cookie.')],
     [('billing spool   →   state/billing_queue.jsonl',
       'Outbound: spool, do not apply\n'
       'This used to flip plan_status itself, which made a signature verifier a '
       'writer of the manifest. Two costs, both deliberate: Polar is acked on '
       'spool rather than on apply, and activation lands within '
       'WAKE_POLL_SECONDS. Acking early means nothing upstream resends, so a '
       'failed event is put back with its attempt count and the drop after '
       'MAX_ATTEMPTS alerts rather than logs.'),
      ('.env.billing   (letterlock-billing-secrets)',
       'Reads: the webhook signing secret, and nothing else\n'
       'secrets.secret_files() is the ordered list load() reads, each '
       'best-effort, so a process entitled to one file and not the other gets '
       'what it is entitled to.')],
     palette='host',
     tip='billing-webhook.service\n'
         'The fifth unit with its own account, and the other cheap one: it '
         'verifies the signature, spools the event for the daemon to apply, and '
         'so writes neither the manifest nor anything else under database/.')

leaf('h_ks', H_C1, bottom('h_billing') + 34, CARD_W, 40,
     'ks_signer   :8788\nKitchen Search license signer, /opt/ks_signer',
     'Not Letterlock\n'
     'A separate service on the same box behind the same Caddy. It is on this '
     'diagram because the generated Caddyfile carries its route, and dropping '
     'the route would take it offline.', style=LEAF_MUTED)

card('h_daemon', H_C2, H_CARDS_TOP,
     'email-daemon.service', 'python -m backend.daemons.daemon_loop',
     ['User=letterlock   Group=letterlock   (hardening.conf)',
      'ReadWritePaths=/opt/letterlock/state  …/database',
      'IPAddressDeny=any  IPAddressAllow=localhost',
      'Restart=always;  also honors state/restart.flag',
      'runs handoff_server.start() on a thread'],
     [('wake spool + wake.fifo   ←   state/',
       'Inbound: a wake, then resolve the address against the manifest'),
      ('custody.sock   (server, SO_PEERCRED)',
       'Inbound: the handoff listener\n'
       'On a thread because this loop is serial by design, so the work the web '
       'tier hands over cannot wait behind a drafting pass. Admits this uid and '
       'paths.web_uid() alone.'),
      ('billing spool   ←   state/billing_queue.jsonl',
       'Inbound: process_billing() on each pass\n'
       'Where a spooled Polar event is actually applied. Under it sits the '
       '3-hourly reconcile, which re-derives subscription status from Polar '
       'rather than from an event body, so a lost subscription.* event heals '
       'within one sweep.')],
     [('HTTPS CONNECT   →   127.0.0.1:8792', HOST_PROXY_TIP),
      ('database/<id>/   token.bin 0600 to this uid',
       'Outbound: the account store, including the one file only this uid opens'),
      ('state/   state.json · audit prune · restart.flag',
       'Outbound: daemon scratch'),
      ('.env  +  .gmail-mcp/gcp-oauth.keys.json',
       'Reads: the inference keys, and the OAuth app\'s client id and secret\n'
       'One OAuth app serves every user; no per-user token lives in that '
       'directory. oauth_app.py prefers the injected '
       'GOOGLE_OAUTH_CLIENT_ID/SECRET and refuses the file entirely under '
       'TEE_REQUIRED, so this is the box\'s fallback and not the enclave\'s.')],
     palette='host',
     tip='email-daemon.service\n'
         'The FIFO listener, and the unit that still runs as the base '
         'letterlock account: everything that has been split off has been split '
         'off from here.')

card('h_timers', H_C2, bottom('h_daemon') + 34,
     'systemd timers', 'User=letterlock  ·  same unit hardening',
     ['email-summary.timer    05:00 UTC daily',
      'gmail-watch.timer      Mon 04:00 weekly',
      'billing-poller.timer   */3 h',
      'in the enclave these three are a supercronic crontab',
      'the reconcile there is the only path a renewal travels'],
     [],
     [('HTTPS CONNECT   →   127.0.0.1:8792', HOST_PROXY_TIP),
      ('database/  +  state/',
       'Outbound: the same store the daemon writes\n'
       'email_summary sweeps every active account and delivers to '
       'account.telegram, skipping accounts with no linked chat; watch_renew '
       're-registers users.watch per account; billing_poller reconciles '
       'entitlement and visits only customers Polar names, so the seeded owner '
       'is never touched by it.')],
     palette='host',
     tip='The scheduled work\n'
         'A systemd timer and a crontab are two deployment formats and neither '
         'can read the other, so flake.nix restates these cadences and the '
         'comment there says to keep them in step.')

card('h_cosigner', H_C2, bottom('h_timers') + 34,
     'cosigner.service', 'python -m cosigner.server',
     ['User=cosigner   Group=cosigner',
      'SupplementaryGroups=letterlock',
      'ReadWritePaths=   (emptied)',
      'StateDirectory=cosigner  StateDirectoryMode=0700',
      'LoadCredentialEncrypted=  cosigner-master, cosigner-dpop',
      'EnvironmentFile=-/opt/letterlock/.env.alerts',
      '/wrap /unwrap /unwrap-and-sign /rewrap',
      '/sign-dpop /dpop-jwk /health'],
     [('127.0.0.1:8791  from caddy  + X-Client-Cert-Der',
       'Inbound: the enclave, over mutual TLS\n'
       'Every request but /health carries the client certificate Caddy '
       'forwarded as DER. cosigner/attest.py runs quote_policy\'s five checks '
       'against this box\'s measurement allowlist -- the point of the second '
       'machine, since the enclave cannot edit it. policy.py is the only place '
       'a request is decided and the same call writes its audit row, so the '
       'limit enforced and the log cannot disagree, including _sweep_refusal, '
       'which meters how many different accounts were unwrapped in a window. An '
       'account is named by an opaque handle the enclave minted, never an '
       'address; nothing here parses it.')],
     [('/var/lib/private/cosigner/audit.db   0700',
       'Outbound: grants and requests, kept apart\n'
       'grants is wrap-once state and is never deleted; requests is the log and '
       'every reader is windowed, which is what lets retention.py prune. That '
       'module is the only code in the package that deletes a row, runs on a '
       'thread inside this process (a second process would VACUUM under the one '
       'answering requests) and derives its floor from policy.longest_window().'),
      ('HTTPS CONNECT   →   127.0.0.1:8792   (alerts)',
       'Outbound: Telegram, for a refused unwrap\n'
       'The alert channel arrives as EnvironmentFile=-/opt/letterlock/.env.'
       'alerts, which systemd reads as root before dropping to this account, so '
       'the co-signer gets an alert channel without getting .env or the group '
       'that opens it. Before that this unit was in letterlock alone, so '
       'TELEGRAM_BOT_TOKEN was unset and every refused unwrap alerted nobody. '
       'The - prefix means a box without the file still boots, since a '
       'co-signer that refuses to start stops all mail.'),
      ('systemd credstore   (TPM-sealed, host)',
       'Reads: the outer wrapping key and the DPoP signing key\n'
       'LoadCredentialEncrypted= from /etc/credstore.encrypted, sealed to the '
       'host TPM and provisioned by hand once. keys.py is the only place the '
       'outer key is derived or a DPoP proof signed, and the only written-down '
       'rotation procedure: a master key per version, known_versions() derived '
       'from which credentials actually load so retiring one fails closed, and '
       '/rewrap moving a record between versions without opening it.')],
     palette='ctrl',
     tip='cosigner.service — the other half of split custody\n'
         'Holds the outer wrapping key and no ciphertext, so compromising it '
         'alone reads no mail; the enclave holds the ciphertext and cannot '
         'strip the outer layer alone. It imports nothing from backend/ except '
         'the Telegram call in alerts.py, so it can move to its own box under '
         'its own operator -- until then this is separation of privilege on one '
         'box, not separation of operator, and no product copy may say '
         'otherwise.')

card('h_egress', H_C3, H_CARDS_TOP,
     'egress-proxy.service', 'python -m backend.daemons.egress_proxy',
     ['User=egress   Group=egress',
      'SupplementaryGroups=letterlock',
      'ReadWritePaths=   (emptied)',
      'IPAddressDeny=      IPAddressAllow=any',
      'the only unit allowed off the machine',
      'reads backend/egress_allowlist.json  (rendered)'],
     [('127.0.0.1:8792   HTTP CONNECT   every other unit',
       'Inbound: one CONNECT request line per tunnel\n'
       'Not behind Caddy. A hard dependency with no bypass: a fallback to '
       'direct connections would silently turn the control off.')],
     [(f'443 to {len(HOSTS)} exact names   (same allowlist file)',
       'Outbound: the machine\'s whole reachable set\n'
       + ', '.join(HOSTS) +
       '.\nNames only and no addresses, so no bare IP is reachable. This does '
       'not defend against prompt injection -- the drafter\'s tools fetch no '
       'URLs. It is for the post-compromise case and for a dependency that '
       'phones home.')],
     palette='egress',
     tip='egress-proxy.service\n'
         'Its own account, because the process holding the network must not be '
         'the one holding the API keys -- which is also why it reads the '
         'allowlist rather than deriving it.')

# --- hetzner: substrate lane ---------------------------------------------------
H_CARD_BOT = max(bottom('h_ks'), bottom('h_cosigner'), bottom('h_egress'))
H_CH0 = H_CARD_BOT + 26
H_CHAN = [H_CH0 + 14 * i for i in range(13)]
H_LANE_Y = H_CHAN[-1] + 40

store('h_state', 270, H_LANE_Y, 300, LANE_H,
      '/opt/letterlock/state   2771\n'
      'wake_queue.jsonl  0660 letterlock-wake\n'
      'billing_queue.jsonl  0660 -billing-queue\n'
      'wake.fifo · state.json · audit.db 0600',
      '/opt/letterlock/state\n'
      'Four uids open a file in here and are deliberately not all in one group, '
      'so the directory is traversable and each file\'s own mode is the grant. '
      'backend/spool.py is the one append-and-drain protocol under both spools; '
      'each names its own group, since waking the daemon and settling a '
      'subscription are different capabilities.')

store('h_sock', 630, H_LANE_Y, 300, LANE_H,
      'state/custody.sock\n'
      'AF_UNIX SOCK_STREAM  0660\n'
      'group letterlock-data\n'
      'SO_PEERCRED: daemon uid + web uid',
      'The handoff socket, same contract as in the enclave\n'
      'The mode is the grant and _may_connect() is a second check of the same '
      'fact, not a replacement: every way that mode can widen is silent.',
      style=SOCK)

store('h_db', 990, H_LANE_Y, 300, LANE_H,
      '/opt/letterlock/database   2770\n'
      'group letterlock-data (setgid)\n'
      'accounts.json  (manifest, plaintext)\n'
      '<id>/ dek.bin · token.bin 0600 · *.enc',
      '/opt/letterlock/database\n'
      'letterlock-data holds exactly the mail uid and the web uid, so cosigner '
      'and egress -- in letterlock only -- reach none of it. Not traversable '
      'like state/, since who has an account is itself worth keeping. '
      'Git-ignored; seed the owner once with '
      'python -m backend.accounts.seed_owner.')

store('h_secrets', 1350, H_LANE_Y, 320, LANE_H,
      'server-only files   (never synced)\n'
      '.env  0600 letterlock-secrets\n'
      '.env.billing  ·  .env.alerts\n'
      '.gmail-mcp/gcp-oauth.keys.json',
      'The secrets, split by who is entitled to which\n'
      'Each has a matching --exclude in deploy/deploy.sh, because the rsync is '
      'authoritative: --delete-after removes remote files the repo no longer '
      'has, so EXCLUDES is the protected set. .env.alerts is read by no Python '
      'at all -- systemd reads it as root and hands it to the co-signer alone.')

store('h_cred', 1730, H_LANE_Y, 300, LANE_H,
      '/etc/credstore.encrypted   (host)\n'
      'cosigner-master · cosigner-dpop\n'
      'sealed to the host TPM\n'
      '/var/lib/private/cosigner  0700',
      'The co-signer\'s own state, outside the app directory\n'
      'LoadCredentialEncrypted= decrypts these at unit start, so the keys are '
      'never on disk in the clear and never in the app directory the deploy '
      'rsyncs over. StateDirectory= is why ReadWritePaths= can be emptied '
      'entirely.', style=SOCK)

# --- hetzner: external parties -------------------------------------------------
H_LEAF_Y = top('h_caddy__in0') - 24
leaf('h_browser', H_LEAF_X, H_LEAF_Y, H_LEAF_W, 48,
     'End user\nbrowser over HTTPS', 'The product UI\'s caller')
leaf('h_pubsub', H_LEAF_X, H_LEAF_Y + 58, H_LEAF_W, 48,
     'Google Pub/Sub\nwatch push',
     'Pub/Sub push to API_HOST\n'
     'The catch-all route on that site block keeps POST / on the receiver.')
leaf('h_polar', H_LEAF_X, H_LEAF_Y + 116, H_LEAF_W, 48,
     'Polar\nsubscription webhook',
     'Polar webhook\n'
     'POST to site.POLAR_WEBHOOK_PATH, routed on both site blocks. Verified '
     'against POLAR_WEBHOOK_SECRET and spooled, never applied in the receiver.')

leaf('h_dest', DEST_X, cy('h_egress__out0') - 34, DEST_W, 68,
     f'egress allowlist\nthe same {len(HOSTS)} names as above\n'
     'backend/egress_allowlist.json',
     'One allowlist, two deployments\n'
     + ', '.join(HOSTS) +
     '.\nDerived at render time by deploy/render_egress_allowlist.py from the '
     'modules that already name each host, so adding a provider cannot leave '
     'the allowlist behind. tests/test_egress.py compares the committed file '
     'against the live constants, so a stale render fails there rather than as '
     'an outage that reads like the provider being down.')

# --- hetzner: the wiring -------------------------------------------------------
edge('h_browser', 'h_caddy__in0', 'https', jog('h_browser', 'h_caddy__in0', H_GAPL[1]))
edge('h_pubsub', 'h_caddy__in1', 'https', jog('h_pubsub', 'h_caddy__in1', H_GAPL[2]))
edge('h_polar', 'h_caddy__in1', 'https', jog('h_polar', 'h_caddy__in1', H_GAPL[3]))

edge('h_caddy__out0', 'h_web__in0', 'https', jog('h_caddy__out0', 'h_web__in0', H_GAP0[1]))
edge('h_caddy__out1', 'h_hook__in0', 'https', jog('h_caddy__out1', 'h_hook__in0', H_GAP0[2]))
edge('h_caddy__out2', 'h_billing__in0', 'https', jog('h_caddy__out2', 'h_billing__in0', H_GAP0[3]))
edge('h_caddy__out4', 'h_ks', 'https', jog('h_caddy__out4', 'h_ks', H_GAP0[4]))
edge('h_caddy__out3', 'h_cosigner__in0', 'https',
     over('h_caddy__out3', 'h_cosigner__in0', H_GAP0[0], H_CH_PROXY[0], H_GAP1[12]),
     'mTLS + quote')

edge('h_hook__out1', 'h_egress__in0', 'net',
     over('h_hook__out1', 'h_egress__in0', H_GAP1[0], H_CH_PROXY[1], H_C3 - 34), 'CONNECT',
     HOST_ENFORCED_TIP)
edge('h_web__out1', 'h_egress__in0', 'net',
     over('h_web__out1', 'h_egress__in0', H_GAP1[1], H_CH_PROXY[2], H_C3 - 52), 'CONNECT',
     HOST_ENFORCED_TIP)
edge('h_daemon__out0', 'h_egress__in0', 'net',
     jog('h_daemon__out0', 'h_egress__in0', H_GAP2[0]), 'CONNECT', HOST_ENFORCED_TIP)
edge('h_timers__out0', 'h_egress__in0', 'net',
     jog('h_timers__out0', 'h_egress__in0', H_GAP2[1]))
edge('h_cosigner__out1', 'h_egress__in0', 'net',
     jog('h_cosigner__out1', 'h_egress__in0', H_GAP2[2]))
edge('h_egress__out0', 'h_dest', 'https', [])

edge('h_hook__out0', 'h_state', 'file',
     into_top('h_hook__out0', 'h_state', H_GAP1[2], H_CHAN[0], -100), 'append')
edge('h_web__out0', 'h_sock', 'ipc',
     into_top('h_web__out0', 'h_sock', H_GAP1[3], H_CHAN[1], -90), 'connect')
edge('h_web__out2', 'h_db', 'file',
     into_top('h_web__out2', 'h_db', H_GAP1[4], H_CHAN[2], -100))
edge('h_web__out3', 'h_state', 'file',
     into_top('h_web__out3', 'h_state', H_GAP1[5], H_CHAN[3], 90))
edge('h_web__out4', 'h_secrets', 'file',
     into_top('h_web__out4', 'h_secrets', H_GAP1[6], H_CHAN[4], -110))
edge('h_billing__out0', 'h_state', 'file',
     into_top('h_billing__out0', 'h_state', H_GAP1[7], H_CHAN[5], 0))
edge('h_billing__out1', 'h_secrets', 'file',
     into_top('h_billing__out1', 'h_secrets', H_GAP1[8], H_CHAN[6], 0))
edge('h_daemon__out1', 'h_db', 'file',
     into_top('h_daemon__out1', 'h_db', H_GAP2[3], H_CHAN[7], 100))
edge('h_daemon__out2', 'h_state', 'file',
     into_top('h_daemon__out2', 'h_state', H_GAP2[4], H_CHAN[8], 0))
edge('h_daemon__out3', 'h_secrets', 'file',
     into_top('h_daemon__out3', 'h_secrets', H_GAP2[5], H_CHAN[9], 110))
edge('h_timers__out1', 'h_db', 'file',
     into_top('h_timers__out1', 'h_db', H_GAP2[0], H_CHAN[10], -100))
edge('h_cosigner__out0', 'h_cred', 'file',
     into_top('h_cosigner__out0', 'h_cred', H_GAP2[1], H_CHAN[11], -100))
edge('h_cosigner__out2', 'h_cred', 'file',
     into_top('h_cosigner__out2', 'h_cred', H_GAP2[2], H_CHAN[12], 100))

edge('h_state', 'h_daemon__in0', 'file',
     out_top('h_state', 'h_daemon__in0', H_CHAN[11], H_GAP1[9], -100), 'drain')
edge('h_state', 'h_daemon__in2', 'file',
     out_top('h_state', 'h_daemon__in2', H_CHAN[12], H_GAP1[10], 100), 'drain')
edge('h_sock', 'h_daemon__in1', 'ipc',
     out_top('h_sock', 'h_daemon__in1', H_CHAN[10], H_GAP1[11], 90), 'accept')

# --- the one arrow that crosses -----------------------------------------------
CROSS_Y = E_LANE_BOT + 66
edge('e_dest8', 'h_caddy__in2', 'cross',
     [(DEST_X + DEST_W + 40, cy('e_dest8')),
      (DEST_X + DEST_W + 40, CROSS_Y),
      (H_GAPL[0], CROSS_Y),
      (H_GAPL[0], cy('h_caddy__in2'))],
     'split custody:  RA-TLS client certificate carrying the enclave\'s TDX quote',
     'The one interface that leaves the machine it is drawn on\n'
     'Mutual TLS to cosigner.morganrivers.com. The client certificate is derived '
     'from the guest agent GetTlsKey and carries this enclave\'s TDX quote; Caddy '
     'requires it, forwards the DER as X-Client-Cert-Der and judges nothing, and '
     'cosigner/attest.py runs the five quote_policy checks against an allowlist '
     'the enclave cannot edit -- which is the whole point of the second machine. '
     'Layer order is the guarantee: our AES-GCM layer inside, theirs outside. '
     'Reversed, their unwrap would yield a usable key and they would become the '
     'one box that can read every mailbox. No bypass, ever: while this is '
     'unreachable no mail is processed, which is the availability cost accepted '
     'for the confidentiality gain.')

# ------------------------------------------------------------------ frames ---


def frame(fid, x0, y0, x1, y1, label, col):
    BG.insert(0, emit_box(fid, x0, y0, x1 - x0, y1 - y0, label,
                          FRAME + f'strokeColor={col};fontColor={col};'))


E_BOT = E_LANE_Y + LANE_H + 34
frame('f_enclave', 30, 84, DEST_X + DEST_W + 70, E_BOT,
      'Phala dstack CVM  (Intel TDX)  —  four containers, four images, one uid each;  '
      'the partition is measured into RTMR3', '#4f7f5a')

H_BOT = H_LANE_Y + LANE_H + 34
frame('f_host', 30, H_FRAME_TOP, DEST_X + DEST_W + 70, H_BOT,
      'Hetzner box  hezner.morganrivers.com  —  the same partition in systemd accounts, '
      'groups and file modes;  one machine, six units, three timers, one ingress', '#62778f')

BG.append(emit_box('b_inner', E_C1 - 26, CARDS_TOP - 42,
                   E_C3 + CARD_W + 26 - (E_C1 - 26), E_CARD_BOT + 40 - (CARDS_TOP - 42),
                   'network  inner   (internal: true — docker installs no route off the host)',
                   BAND + 'fillColor=#dff0e0;align=left;spacingLeft=14;'))
for i, (bx0, bx1) in enumerate(((E_C1 - 13, E_C1 + CARD_W + 13), (E_C3 - 13, E_C3 + CARD_W + 13))):
    BG.append(emit_box(f'b_edge{i}', bx0, CARDS_TOP - 14, bx1 - bx0, E_CARD_BOT + 26 - (CARDS_TOP - 14),
                       'network  edge   (ordinary bridge: these roles must be reached from outside the CVM)'
                       if i == 0 else 'network  edge',
                       BAND_LINE + 'strokeColor=#b8823c;fontColor=#8a5f21;'
                       + ('align=left;spacingLeft=10;' if i == 0 else '')))

# ------------------------------------------------------------------ legend ---
LEG_Y = H_BOT + 26
LEG_W = DEST_X + DEST_W + 40 - 30
BG.append(emit_box('legend', 30, LEG_Y, LEG_W, 100,
                   'Reading this diagram', FRAME + 'strokeColor=#8d9aa8;fontColor=#46566a;dashed=0;'))
LEG = [
    ('IN row', IN_ROW, None, 'one inbound interface;  arrows land on the row, not on the box'),
    ('OUT row', OUT_ROW, None, 'one outbound interface;  hover any row or any arrow for the protocol'),
    ('volume / socket', STORE + 'align=center;spacingLeft=0;', None,
     'what the interfaces on either side of it actually share'),
    ('CONNECT  (enforced)', None, 'net', 'the caller has no route off the host except the proxy'),
    ('CONNECT  (configured)', None, 'netcfg', 'the caller is on edge too, so this is env vars and not a boundary'),
    ('unix socket', None, 'ipc', 'AF_UNIX;  the file mode and SO_PEERCRED are the grant'),
    ('filesystem', None, 'file', 'a volume or a file;  the mode and the group are the grant'),
    ('split custody', None, 'cross', 'the one interface that leaves the machine it is drawn on'),
]
for i, (name, boxst, ekind, why) in enumerate(LEG):
    col, row = i // 4, i % 4
    lx, ly = 52 + col * int(LEG_W / 2), LEG_Y + 30 + row * 17
    if boxst:
        BG.append(emit_box(f'legk{i}', lx, ly, 118, 15, name, boxst + 'fontSize=8;'))
    else:
        BG.append(emit_box(f'lega{i}', lx + 4, ly + 7, 1, 1, '',
                           'fillColor=none;strokeColor=none;'))
        BG.append(emit_box(f'legb{i}', lx + 112, ly + 7, 1, 1, '',
                           'fillColor=none;strokeColor=none;'))
        MID.append(emit_edge(f'lege{i}', {'from': f'lega{i}', 'to': f'legb{i}'}, [],
                             EBASE + EKIND[ekind]))
        BG.append(emit_box(f'legk{i}', lx + 122, ly, 130, 15, name,
                           'rounded=0;html=1;fillColor=none;strokeColor=none;align=left;'
                           'spacingLeft=0;fontSize=8;fontColor=#46566a;'))
    BG.append(emit_box(f'legv{i}', lx + 262, ly, 560, 15, why,
                       'rounded=0;html=1;fillColor=none;strokeColor=none;align=left;'
                       'spacingLeft=0;fontSize=8;fontColor=#5b6675;'))

BG.insert(0, emit_box('title', 30, 26, 1200, 46,
                      'Letterlock — containers and their interfaces',
                      'rounded=0;html=1;fillColor=none;strokeColor=none;align=left;spacingLeft=6;'
                      'verticalAlign=middle;fontSize=24;fontStyle=1;fontColor=#25313d;'))
BG.insert(1, emit_box('subtitle', 30, 62, 1400, 20,
                      'What goes into each container and what comes out of it.  '
                      'Every row and every arrow carries the protocol in its tooltip.',
                      'rounded=0;html=1;fillColor=none;strokeColor=none;align=left;spacingLeft=6;'
                      'verticalAlign=middle;fontSize=11;fontColor=#5b6675;'))

OUT = os.path.join(HERE, 'interfaces.drawio')
with open(OUT, 'w', encoding='utf-8') as fh:
    fh.write(wrap_mxfile(BG + MID + FG, 'interfaces', 'letterlock-interfaces',
                         page_w=DEST_X + DEST_W + 110, page_h=int(LEG_Y + 140)))
print(f'wrote {OUT}: {len(REG)} cells, {len(MID)} edges, '
      f'{DEST_X + DEST_W + 110} x {int(LEG_Y + 140)}')
