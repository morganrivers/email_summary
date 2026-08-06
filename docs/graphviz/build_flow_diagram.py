#!/usr/bin/env python3
"""
Build an editable draw.io diagram of the letterlock runtime data flow from
letterlock_flow_diagram.json, using Graphviz for a layered layout with routed
edges. Shares all layout/emit machinery with build_arch_diagrams.py via
drawio_common.py; this script only defines this diagram's stage bands, colours
and repo link base.

Stages (bottom → top, the order one email travels):
  B  boot     – attest before anything runs; where a secret comes from
  W  sign-up  – web UI, Google consent, Polar subscription, the tenant manifest
  C  custody  – this box's inner encryption layer, and the only wire to K
  K  cosigner – the second account: outer key, DPoP key, rate limit, audit
  G  ingest   – Pub/Sub push → wake spool → daemon → per-account pipeline
  F  google   – the one seam for Gmail + Calendar
  R  draft    – what to say, in this account's voice
  M  inference– masking boundary + provider attestation
  O  notify   – Telegram, and the daily summary
External services (grp "ext") float alongside via dashed loaders.

Usage:  python build_flow_diagram.py [graph.json] [out.drawio]
Requires Graphviz 'dot' on PATH.
"""
import json, subprocess, sys, os
from drawio_common import (run_dot, transforms, decl, emit_node, emit_edges,
                           wrap_mxfile, esc)

SRC = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), 'letterlock_flow_diagram.json')
OUT = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(__file__), 'letterlock_flow_diagram.drawio')

G = json.load(open(SRC))
edges = G['edges']

GITHUB_BASE = 'https://github.com/morganrivers/email_summary'
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
TRACKED = set(subprocess.run(['git', '-C', REPO_ROOT, 'ls-files'],
                             capture_output=True, text=True).stdout.split())

def gh_link(path):
    """Return a GitHub URL for a checked-in repo path, or '' otherwise. Git is
    the authority rather than the filesystem: database/, state/ and config/ hold
    user data and are git-ignored, so a path that exists on this machine is not
    a path that exists on GitHub. Per-user templates (database/<id>/token.bin)
    and box-only paths (/var/lib/cosigner/audit.db) get no link either."""
    trimmed = (path or '').rstrip('/')
    if not trimmed or trimmed not in TRACKED:
        return ''
    kind = 'tree' if path.endswith('/') or '.' not in os.path.basename(trimmed) else 'blob'
    return f'{GITHUB_BASE}/{kind}/main/{trimmed}'

for n in G['nodes']:
    if n.get('link'):                       # explicit JSON override wins
        continue
    link = gh_link(n.get('file', ''))
    if link:
        n['link'] = link

# ---------- node sizing (label-driven, so Graphviz reserves real footprint) --
def size(n):
    lines = n['lbl'].split('\n')
    maxc = max(len(x) for x in lines)
    w = max(90, int(maxc * 6.6) + 24) + (20 if n.get('robot') else 0)
    h = len(lines) * 15 + (26 if n['type'] == 'data' else 20)
    return w, h
# Show each node's full path (its real location) under the short name, not just
# the name. Nodes without a backing file (proxies, ✳ chips, pure data) keep lbl.
for n in G['nodes']:
    if n.get('file'):
        n['lbl'] = n['lbl'] + '\n' + n['file']
for n in G['nodes']:
    if 'w' not in n:            # honour any explicit size (e.g. small ✳ chips)
        n['w'], n['h'] = size(n)

# ---------- styles ----------------------------------------------------------
SCRIPT_BASE = 'rounded=1;whiteSpace=wrap;html=1;fontSize=11;'
SCRIPT_BY_GRP = {
    'B': 'fillColor=#dfe7ef;strokeColor=#6b7f96;fontColor=#1b2733;',   # boot     – slate
    'W': 'fillColor=#cfe8e6;strokeColor=#4f9b95;fontColor=#163a37;',   # sign-up  – teal
    'C': 'fillColor=#cfe6cf;strokeColor=#5a9367;fontColor=#1e3a24;',   # custody  – green
    'K': 'fillColor=#f6d9c0;strokeColor=#c17a3a;fontColor=#5a3410;',   # cosigner – peach
    'G': 'fillColor=#dfe7ef;strokeColor=#6b7f96;fontColor=#1b2733;',   # ingest   – slate
    'F': 'fillColor=#e3e8ef;strokeColor=#5b6675;fontColor=#1b2733;',   # google   – grey
    'R': 'fillColor=#e6d6f2;strokeColor=#8a5fb0;fontColor=#3d2757;',   # draft    – lavender
    'M': 'fillColor=#cfe6cf;strokeColor=#5a9367;fontColor=#1e3a24;',   # inference– green
    'O': 'fillColor=#cfe8e6;strokeColor=#4f9b95;fontColor=#163a37;',   # notify   – teal
}
STYLE = {
    'ext':    'rounded=1;whiteSpace=wrap;html=1;arcSize=45;fillColor=#2f7dc4;strokeColor=#1c4f80;fontColor=#ffffff;fontSize=11;',
    'danger': 'rounded=1;whiteSpace=wrap;html=1;arcSize=45;fillColor=#c0392b;strokeColor=#7d2318;fontColor=#ffffff;fontSize=11;',
    'data':   'shape=cylinder;whiteSpace=wrap;html=1;fillColor=#e6ecf3;strokeColor=#8493a4;fontColor=#1b2733;fontSize=11;',
    'note':   'shape=note;whiteSpace=wrap;html=1;size=14;fillColor=#fdf3cf;strokeColor=#c9a227;fontColor=#5b4a00;fontSize=12;dashed=1;',
    'proxy':  'rounded=1;whiteSpace=wrap;html=1;fillColor=#eef2f7;strokeColor=#8493a4;fontColor=#5b6675;fontSize=9;dashed=1;',
}
def node_style(n):
    if n['type'] == 'script':
        return SCRIPT_BASE + SCRIPT_BY_GRP.get(n['grp'], SCRIPT_BY_GRP['B'])
    return STYLE[n['type']]

EBASE = 'edgeStyle=none;curved=1;html=1;endArrow=block;endFill=1;strokeColor=#9aa6b3;fontSize=9;fontColor=#5b6675;'
EK = {'flow': 'strokeColor=#2e8b57;', 'loader': 'strokeColor=#3d72b4;dashed=1;',
      'mask': 'strokeColor=#1e7a3a;strokeWidth=2;', 'boot': 'strokeColor=#c17a3a;dashed=1;',
      'store': 'strokeColor=#b98a1e;dashed=1;', 'nav': 'strokeColor=#8493a4;dashed=1;',
      'danger': 'strokeColor=#c0392b;dashed=1;', 'proxy': 'strokeColor=#8493a4;dashed=1;'}

# stage banding (label + tag colour), ordered bottom → top
BANDS = ['B', 'W', 'C', 'K', 'G', 'F', 'R', 'M', 'O']
STLAB = {
    'B': 'BOOT · attest before anything runs',
    'W': 'SIGN-UP · web UI, Google consent, subscription',
    'C': 'CUSTODY · the enclave\'s half (inner layer)',
    'K': 'CO-SIGNER · second account, second key, no ciphertext',
    'G': 'INGEST · push → wake → per-account run',
    'F': 'GOOGLE · one seam for mail + calendar',
    'R': 'DRAFT · what to say, in this account\'s voice',
    'M': 'INFERENCE · masked text, verified enclave',
    'O': 'NOTIFY · Telegram + daily summary',
}
STCOL = {'B': '#6b7f96', 'W': '#4f9b95', 'C': '#5a9367', 'K': '#c17a3a',
         'G': '#6b7f96', 'F': '#5b6675', 'R': '#8a5fb0', 'M': '#5a9367',
         'O': '#4f9b95'}

# ---------- layout via Graphviz --------------------------------------------
dot = ['digraph P{', 'rankdir=BT;', 'splines=polyline;', 'nodesep=0.45;', 'ranksep=0.85;',
       'node[shape=box,fixedsize=true];']
for n in G['nodes']:
    dot.append(decl(n))
grp = {n['id']: n['grp'] for n in G['nodes']}
# real (routed) edges. Two classes of edge must not set layer rank:
#
#   * an external service that fans out to *multiple* bands, else its multi-band
#     pull distorts the clean stage bands (a single-consumer service keeps normal
#     ranking so it lands right next to that consumer instead of floating away);
#   * any edge that runs *against* the band order. This flow is not a pipeline
#     the way the webapp's is: the Google seam is called from four bands, the
#     custody layer is entered from above by gmail_api and from below by
#     provisioning, and the co-signer answers back down the same wire it was
#     called up. Left constrained, those edges contradict the funnel below and
#     dot resolves the contradiction by reversing whichever it likes, which is
#     what threw mailbox to the top of the page. The bands are declared by
#     BANDS; a return arrow is drawn, not obeyed.
from collections import Counter
outdeg = Counter(e['from'] for e in edges)
rank_of = {g: i for i, g in enumerate(BANDS)}
def constrains(e):
    if grp.get(e['from']) == 'ext' and outdeg[e['from']] > 1:
        return False
    a, b = rank_of.get(grp.get(e['from'])), rank_of.get(grp.get(e['to']))
    return a is None or b is None or b >= a
for e in edges:
    attr = '' if constrains(e) else '[constraint=false]'
    dot.append(f'"{e["from"]}"->"{e["to"]}"{attr};')
# Force clean stage bands via one invisible funnel node per gap (same trick as
# build_drawio): every node of band k ranks above every node of band k+1.
band_ids = {g: [n['id'] for n in G['nodes'] if n['grp'] == g] for g in BANDS}
for i in range(len(BANDS) - 1):
    z = f'__z{i}'
    dot.append(f'"{z}"[style=invis,width=0.01,height=0.01,label=""];')
    for nid in band_ids[BANDS[i]]:
        dot.append(f'"{nid}"->"{z}"[style=invis];')
    for nid in band_ids[BANDS[i + 1]]:
        dot.append(f'"{z}"->"{nid}"[style=invis];')
dot.append('}')
pos, H, edgepts = run_dot(dot)
X, Y = transforms(H)

bg = []   # stage tags (behind)
mid = []  # edges
fg = []   # nodes (front)

# stage tags centred above each band's nodes
for g in BANDS:
    ns = [n for n in G['nodes'] if n['grp'] == g and n['id'] in pos]
    if not ns:
        continue
    xs = [X(pos[n['id']][0]) for n in ns]
    ytop = min(Y(pos[n['id']][1]) - n['h'] / 2 for n in ns)
    cx = (min(xs) + max(xs)) / 2
    w = max(150, 9 * len(STLAB[g]))
    st = f'rounded=1;whiteSpace=wrap;html=1;fillColor={STCOL[g]};strokeColor=none;fontColor=#ffffff;fontSize=12;fontStyle=1;opacity=90;'
    bg.append(f'<mxCell id="lab_{g}" value="{esc(STLAB[g])}" style="{st}" vertex="1" parent="1">'
              f'<mxGeometry x="{cx-w/2:.0f}" y="{ytop-40:.0f}" width="{w:.0f}" height="24" as="geometry"/></mxCell>')

# nodes + edges
for n in G['nodes']:
    if n['id'] in pos:
        fg.append(emit_node(n, node_style(n), pos, X, Y))
mid = emit_edges(edges, edgepts, X, Y, EBASE, EK)

xml = wrap_mxfile(bg + mid + fg, 'letterlock flow', 'letterlock-flow')
open(OUT, 'w').write(xml)
print('wrote %s: nodes=%d edges=%d bytes=%d' % (OUT, len(pos), len(edges), len(xml)))
