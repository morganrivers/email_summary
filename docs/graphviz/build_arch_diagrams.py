#!/usr/bin/env python3
"""Build two architecture diagrams for the email_summary project as editable
draw.io files, using the shared drawio_common primitives (Graphviz layout +
draw.io emit). Renders:

  arch_current.drawio  - what exists today (single-tenant Hetzner box)
  arch_target.drawio   - everything that must exist for a monetized,
                         provably-secure, multi-tenant product

Usage:  python build_arch_diagrams.py
Requires Graphviz 'dot' on PATH.
"""
import os
from drawio_common import (run_dot, transforms, decl, emit_node, emit_edges,
                           wrap_mxfile, group_box)

HERE = os.path.dirname(__file__)

SVC_BASE = 'rounded=1;whiteSpace=wrap;html=1;fontSize=11;'
SVC_BY_GRP = {
    'host': 'fillColor=#dfe7ef;strokeColor=#6b7f96;fontColor=#1b2733;',
    'tee':  'fillColor=#cfe6cf;strokeColor=#5a9367;fontColor=#1e3a24;',
    'ctrl': 'fillColor=#e6d6f2;strokeColor=#8a5fb0;fontColor=#3d2757;',
}
STYLE = {
    'store':  'shape=cylinder;whiteSpace=wrap;html=1;fillColor=#e6ecf3;strokeColor=#8493a4;fontColor=#1b2733;fontSize=11;',
    'ext':    'rounded=1;whiteSpace=wrap;html=1;arcSize=45;fillColor=#2f7dc4;strokeColor=#1c4f80;fontColor=#ffffff;fontSize=11;',
    'danger': 'rounded=1;whiteSpace=wrap;html=1;fillColor=#f6c9c0;strokeColor=#c0392b;fontColor=#5a1a12;fontSize=11;fontStyle=1;',
    'note':   'shape=note;whiteSpace=wrap;html=1;size=14;fillColor=#fdf3cf;strokeColor=#c9a227;fontColor=#5b4a00;fontSize=11;dashed=1;',
}

EBASE = 'edgeStyle=none;curved=1;html=1;endArrow=block;endFill=1;strokeColor=#9aa6b3;fontSize=9;fontColor=#5b6675;'
EK = {
    'flow':   'strokeColor=#2e8b57;',
    'mask':   'strokeColor=#1e7a3a;strokeWidth=2;',
    'danger': 'strokeColor=#c0392b;dashed=1;',
    'loader': 'strokeColor=#3d72b4;dashed=1;',
    'boot':   'strokeColor=#c17a3a;dashed=1;',
}


def style_for(n):
    if n['type'] == 'svc':
        return SVC_BASE + SVC_BY_GRP.get(n.get('grp'), SVC_BY_GRP['host'])
    return STYLE[n['type']]


def size(n):
    lines = n['lbl'].split('\n')
    maxc = max(len(x) for x in lines)
    w = max(150, int(maxc * 6.6) + 28)
    h = len(lines) * 16 + 20
    return w, h


def build(nodes, edges, clusters, name, out):
    for n in nodes:
        n['w'], n['h'] = size(n)
    dot = ['digraph P{', 'rankdir=TB;', 'splines=polyline;', 'nodesep=0.5;',
           'ranksep=0.9;', 'node[shape=box,fixedsize=true];']
    for n in nodes:
        dot.append(decl(n))
    # keep cluster members spatially together so the group boxes do not overlap
    for cid, spec in clusters.items():
        dot.append(f'subgraph cluster_{cid} {{')
        for nid in spec['ids']:
            dot.append(f'"{nid}";')
        dot.append('}')
    for e in edges:
        dot.append(f'"{e["from"]}"->"{e["to"]}";')
    dot.append('}')
    pos, H, edgepts = run_dot(dot)
    X, Y = transforms(H)

    bg, fg = [], []
    for cid, spec in clusters.items():
        group_box(nodes, spec['ids'], pos, X, Y, f'grp_{cid}',
                  spec['label'], spec['col'], bg, pad=30, ptop=42)
    for n in nodes:
        if n['id'] in pos:
            fg.append(emit_node(n, style_for(n), pos, X, Y))
    mid = emit_edges(edges, edgepts, X, Y, EBASE, EK)
    xml = wrap_mxfile(bg + mid + fg, name, name)
    open(out, 'w').write(xml)
    print(f'wrote {out}: nodes={len(pos)} edges={len(edges)}')


# ---------------------------------------------------------------- CURRENT ----
cur_nodes = [
    {'id': 'gmail',   'type': 'ext', 'lbl': 'Gmail\n(user mailbox)'},
    {'id': 'pubsub',  'type': 'ext', 'lbl': 'Google Pub/Sub\nwatch push'},
    {'id': 'deepseek','type': 'danger', 'lbl': 'DeepSeek LLM\n(UNTRUSTED)'},
    {'id': 'telegram','type': 'ext', 'lbl': 'Telegram'},

    {'id': 'webhook', 'type': 'svc', 'grp': 'host', 'lbl': 'gmail_hook_server.py\nverify OIDC JWT, wake daemon'},
    {'id': 'daemon',  'type': 'svc', 'grp': 'host', 'lbl': 'daemon_loop.py\nFIFO listener, fetch email'},
    {'id': 'router',  'type': 'svc', 'grp': 'host', 'lbl': 'manual_draft / draft_replies\nis_bot_request routing'},
    {'id': 'llm',     'type': 'svc', 'grp': 'host', 'lbl': 'llm_client.complete()\nmask -> call -> restore'},
    {'id': 'mask',    'type': 'svc', 'grp': 'host', 'lbl': 'pseudonymizer.py\nPresidio PII masking (single user)'},
    {'id': 'draft',   'type': 'svc', 'grp': 'host', 'lbl': 'create_draft.mjs\ndrafts.create / update'},
    {'id': 'summary', 'type': 'svc', 'grp': 'host', 'lbl': 'email_summary.py\ndaily 05:00 timer'},

    {'id': 'state',   'type': 'store', 'lbl': 'state.json\nruntime state'},
    {'id': 'secrets', 'type': 'danger', 'lbl': '.env + .gmail-mcp/\nOAuth token + API keys\n(PLAINTEXT on disk)'},
]
cur_edges = [
    {'from': 'gmail',   'to': 'pubsub',  'label': 'users.watch', 'kind': 'flow'},
    {'from': 'pubsub',  'to': 'webhook', 'label': 'OIDC push',  'kind': 'flow'},
    {'from': 'webhook', 'to': 'daemon',  'label': 'wake (FIFO)', 'kind': 'flow'},
    {'from': 'daemon',  'to': 'gmail',   'label': 'fetch RAW email (OAuth)', 'kind': 'danger'},
    {'from': 'daemon',  'to': 'router',  'label': 'fetched email', 'kind': 'flow'},
    {'from': 'router',  'to': 'llm',     'label': 'draft request', 'kind': 'flow'},
    {'from': 'llm',     'to': 'mask',    'label': 'pseudonymize()', 'kind': 'mask'},
    {'from': 'mask',    'to': 'deepseek','label': 'MASKED text only', 'kind': 'mask'},
    {'from': 'deepseek','to': 'llm',     'label': 'masked reply -> restore', 'kind': 'flow'},
    {'from': 'llm',     'to': 'draft',   'label': 'restored payload', 'kind': 'flow'},
    {'from': 'draft',   'to': 'gmail',   'label': 'write draft', 'kind': 'flow'},
    {'from': 'summary', 'to': 'telegram','label': 'daily summary', 'kind': 'flow'},
    {'from': 'secrets', 'to': 'daemon',  'label': 'OAuth token', 'kind': 'danger'},
    {'from': 'secrets', 'to': 'llm',     'label': 'API key', 'kind': 'loader'},
    {'from': 'state',   'to': 'daemon',  'label': 'load/save', 'kind': 'loader'},
]
cur_clusters = {
    'host': {
        'ids': ['webhook', 'daemon', 'router', 'llm', 'mask', 'draft', 'summary', 'state', 'secrets'],
        'label': 'Hetzner host  -  single tenant, operator fully trusted, secrets in plaintext',
        'col': '#6b7f96',
    },
}

# ----------------------------------------------------------------- TARGET ----
tgt_nodes = [
    # untrusted external
    {'id': 'user',    'type': 'ext', 'lbl': 'End user\n(browser)'},
    {'id': 'gmail',   'type': 'ext', 'lbl': 'Gmail + Calendar\n(user mailbox)'},
    {'id': 'pubsub',  'type': 'ext', 'lbl': 'Google Pub/Sub\nwatch push'},
    {'id': 'deepseek','type': 'danger', 'lbl': 'Frontier LLM\n(UNTRUSTED)'},
    {'id': 'telegram','type': 'ext', 'lbl': 'Telegram / notify'},
    {'id': 'billing', 'type': 'ext', 'lbl': 'Polar.sh / Stripe\nsubscription billing'},
    {'id': 'ghash',   'type': 'note', 'lbl': 'Open-source repo\nreproducible build ->\npublished image hash'},

    # control plane (your infra, untrusted for PII)
    {'id': 'site',    'type': 'svc', 'grp': 'ctrl', 'lbl': 'Landing site + dashboard\nshows attestation proof'},
    {'id': 'signin',  'type': 'svc', 'grp': 'ctrl', 'lbl': 'Sign in with Google\nOAuth consent (login + Gmail scope)'},
    {'id': 'accts',   'type': 'store', 'lbl': 'Account store\nidentity + plan + sealed refresh tokens'},
    {'id': 'watchreg','type': 'svc', 'grp': 'ctrl', 'lbl': 'watch_register (per user)\nweekly users.watch renewal'},
    {'id': 'kms',     'type': 'svc', 'grp': 'ctrl', 'lbl': 'KMS / release service\nunseal secrets IFF attested'},

    # attested TEE
    {'id': 'attest',  'type': 'svc', 'grp': 'tee', 'lbl': 'Attestation agent\nhw-signed measurement -> quote'},
    {'id': 'webhook', 'type': 'svc', 'grp': 'tee', 'lbl': 'webhook receiver\nverify OIDC, route by user'},
    {'id': 'daemon',  'type': 'svc', 'grp': 'tee', 'lbl': 'daemon (multi-tenant)\nper-user FIFO / queue'},
    {'id': 'custody', 'type': 'svc', 'grp': 'tee', 'lbl': 'OAuth token custody\nfetch RAW mail in-enclave'},
    {'id': 'cfg',     'type': 'store', 'lbl': 'per-user config\nUSER_FIRST/LAST, aliases, prefs'},
    {'id': 'mask',    'type': 'svc', 'grp': 'tee', 'lbl': 'pseudonymizer (per user)\nPresidio PII masking'},
    {'id': 'llm',     'type': 'svc', 'grp': 'tee', 'lbl': 'llm_client.complete()\nmask -> call -> restore'},
    {'id': 'draft',   'type': 'svc', 'grp': 'tee', 'lbl': 'draft + calendar writer\ncreate_draft / create_event'},
]
tgt_edges = [
    {'from': 'user',    'to': 'site',    'label': 'visit / subscribe', 'kind': 'flow'},
    {'from': 'site',    'to': 'signin',  'label': 'onboard', 'kind': 'flow'},
    {'from': 'site',    'to': 'billing', 'label': 'checkout', 'kind': 'flow'},
    {'from': 'signin',  'to': 'accts',   'label': 'store SEALED refresh token', 'kind': 'loader'},
    {'from': 'signin',  'to': 'watchreg','label': 'register watch', 'kind': 'flow'},
    {'from': 'watchreg','to': 'gmail',   'label': 'users.watch', 'kind': 'flow'},

    {'from': 'ghash',   'to': 'kms',     'label': 'expected measurement', 'kind': 'boot'},
    {'from': 'attest',  'to': 'kms',     'label': 'hw-signed quote + nonce', 'kind': 'boot'},
    {'from': 'kms',     'to': 'custody', 'label': 'unseal secrets iff hash matches', 'kind': 'boot'},
    {'from': 'accts',   'to': 'custody', 'label': 'sealed token (unseal in TEE)', 'kind': 'loader'},
    {'from': 'site',    'to': 'attest',  'label': 'client verifies proof', 'kind': 'boot'},

    {'from': 'gmail',   'to': 'pubsub',  'label': 'push', 'kind': 'flow'},
    {'from': 'pubsub',  'to': 'webhook', 'label': 'OIDC push', 'kind': 'flow'},
    {'from': 'webhook', 'to': 'daemon',  'label': 'wake (user)', 'kind': 'flow'},
    {'from': 'daemon',  'to': 'custody', 'label': 'fetch mail', 'kind': 'flow'},
    {'from': 'custody', 'to': 'gmail',   'label': 'RAW email (OAuth, in-enclave)', 'kind': 'flow'},
    {'from': 'custody', 'to': 'mask',    'label': 'raw text', 'kind': 'flow'},
    {'from': 'cfg',     'to': 'mask',    'label': 'user identity rules', 'kind': 'loader'},
    {'from': 'mask',    'to': 'llm',     'label': 'masked', 'kind': 'mask'},
    {'from': 'llm',     'to': 'deepseek','label': 'MASKED text only', 'kind': 'mask'},
    {'from': 'deepseek','to': 'llm',     'label': 'masked reply -> restore', 'kind': 'flow'},
    {'from': 'llm',     'to': 'draft',   'label': 'restored payload', 'kind': 'flow'},
    {'from': 'draft',   'to': 'gmail',   'label': 'write draft / event', 'kind': 'flow'},
    {'from': 'draft',   'to': 'telegram','label': 'notify', 'kind': 'flow'},
]
tgt_clusters = {
    'tee': {
        'ids': ['attest', 'webhook', 'daemon', 'custody', 'cfg', 'mask', 'llm', 'draft'],
        'label': 'Attested TEE  -  Confidential VM (Intel TDX / AMD SEV-SNP): measured image, secrets unsealed only post-attestation',
        'col': '#5a9367',
    },
    'ctrl': {
        'ids': ['site', 'signin', 'accts', 'watchreg', 'kms'],
        'label': 'Control plane  -  your infra, untrusted for PII: identity, billing, sealed token store',
        'col': '#8a5fb0',
    },
}


# ------------------------------------------------------- ATTESTATION FLOW ----
att_nodes = [
    {'id': 'verifier', 'type': 'svc', 'grp': 'ctrl', 'lbl': 'Verifier / KMS\nchecks quote, releases secrets'},
    {'id': 'intel',    'type': 'ext', 'lbl': 'Intel / AMD\nroot certificate (public key)'},
    {'id': 'pubhash',  'type': 'note', 'lbl': 'Published open-source\nreproducible build =\nexpected measurement'},
    {'id': 'tokenstore','type': 'store', 'lbl': 'Sealed OAuth token\nencrypted at rest'},

    {'id': 'host',     'type': 'danger', 'lbl': 'Untrusted host / operator\ncontrols network: can replay or\nreroute, but cannot forge a quote'},

    {'id': 'chip',     'type': 'svc', 'grp': 'tee', 'lbl': 'CPU root of trust\nmeasures + signs the quote'},
    {'id': 'code',     'type': 'svc', 'grp': 'tee', 'lbl': 'Loaded code (measured)\nlaunch-time hash chain'},
    {'id': 'ekey',     'type': 'svc', 'grp': 'tee', 'lbl': 'Enclave keypair\nprivate key never leaves'},
    {'id': 'app',      'type': 'svc', 'grp': 'tee', 'lbl': 'app: fetch -> mask -> draft'},

    {'id': 'gmail',    'type': 'ext', 'lbl': 'Gmail\n(mail only via token, TLS)'},
    {'id': 'llm',      'type': 'danger', 'lbl': 'Untrusted LLM\n(masked text only)'},
]
att_edges = [
    {'from': 'verifier', 'to': 'host', 'label': '1. nonce (fresh random)', 'kind': 'boot'},
    {'from': 'host',     'to': 'chip', 'label': 'relay nonce', 'kind': 'boot'},
    {'from': 'code',     'to': 'chip', 'label': 'measurement (launch hash)', 'kind': 'loader'},
    {'from': 'ekey',     'to': 'chip', 'label': '2. enclave public key', 'kind': 'loader'},
    {'from': 'chip',     'to': 'verifier', 'label': '3. QUOTE {measure, nonce, pubkey} signed by chip', 'kind': 'boot'},
    {'from': 'intel',    'to': 'verifier', 'label': '4a. signature valid vs cert?', 'kind': 'loader'},
    {'from': 'pubhash',  'to': 'verifier', 'label': '4b. measurement == published hash?', 'kind': 'loader'},
    {'from': 'verifier', 'to': 'tokenstore', 'label': '5. all checks pass -> unseal', 'kind': 'boot'},
    {'from': 'tokenstore','to': 'ekey', 'label': '6. token encrypted to enclave pubkey', 'kind': 'loader'},
    {'from': 'ekey',     'to': 'app', 'label': 'token usable only in-enclave', 'kind': 'flow'},
    {'from': 'app',      'to': 'gmail', 'label': '7. fetch RAW email', 'kind': 'flow'},
    {'from': 'app',      'to': 'llm', 'label': '8. MASKED only', 'kind': 'mask'},
]
att_clusters = {
    'tee': {
        'ids': ['chip', 'code', 'ekey', 'app'],
        'label': 'Attested enclave  -  measured code, private key sealed, operator cannot see inside',
        'col': '#5a9367',
    },
    'ver': {
        'ids': ['verifier', 'intel', 'pubhash', 'tokenstore'],
        'label': 'Verifier side  -  trusts Intel + the published hash, NOT the operator',
        'col': '#8a5fb0',
    },
}


if __name__ == '__main__':
    build(cur_nodes, cur_edges, cur_clusters, 'email-summary-current',
          os.path.join(HERE, 'arch_current.drawio'))
    build(tgt_nodes, tgt_edges, tgt_clusters, 'email-summary-target',
          os.path.join(HERE, 'arch_target.drawio'))
    build(att_nodes, att_edges, att_clusters, 'email-summary-attestation',
          os.path.join(HERE, 'arch_attestation.drawio'))
