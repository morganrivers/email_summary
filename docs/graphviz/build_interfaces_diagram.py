#!/usr/bin/env python3
"""Build interfaces.drawio: the containers, and what crosses their edges.

The other diagrams in this folder answer "what happens to an email". This one
answers "what is a container here, what does it hold, and what may go into and
out of it" -- one card per container, every card built from the same stripes so
two cards can be compared by eye:

    header      the role, its image, how many files that image carries
    identity    uid, supplementary groups, networks, volumes, entry point
    code        which repository files this container carries, by directory
    pypi        which third-party packages this container's own code imports
    mail text   what this container can see of a message body
    IN          one row per inbound interface; arrows land on the row
    OUT         one row per outbound interface; arrows leave from the row
    env         the secrets that container's process environment holds

A row is a real cell, so the arrow attaches to the interface rather than to the
box, and every row and every arrow carries a tooltip saying what the thing is:
the wire format, the port and mode, what authenticates it and what refuses it.
Jargon is defined rather than assumed -- every tooltip ends with a plain
definition of each term of art it uses, and the same definitions are listed in
the glossary panel at the bottom. The picture stays legible and the detail is
one hover away.

Two panels. The Phala CVM, where the partition is five containers and the
compose file that assigns them is measured into RTMR3; and the Hetzner box,
where the same partition is spelled in systemd accounts, groups and file modes.
The stripes are deliberately identical between the two, because the split is
the same statement in two mechanisms. One arrow crosses: the enclave's custody
traffic to the co-signer, which is a unit on the box.

The pink stripe and the pink arrows are one question followed end to end: where
a message body can be. It enters one role, lives in memory for one pass, and
leaves as a Gmail draft; no volume on either machine holds one.

Nothing here is typed twice from memory -- the uids, groups, networks, image
file lists, package lists, allowlist hosts, ports, unit accounts and env names
are read from docker-compose.yml, flake.nix, image_files.nix, uv.lock,
requirements.txt, egress_allowlist.json, backend/roles.py, backend/site.py,
cosigner/protocol.py and deploy/hetzner/*. What each box on the Hetzner panel
carries is walked from that unit's own ExecStart with tools/reachability.py,
which is the same walk that generates image_files.nix.

Usage:  python build_interfaces_diagram.py
        python drawio_to_png.py interfaces.drawio
"""
import ast
import json
import os
import re
import sys
from collections import Counter

from drawio_common import emit_box, emit_edge, tip_html, wrap_mxfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, ROOT)

from backend import roles                      # noqa: E402
from tools import reachability                 # noqa: E402


# ----------------------------------------------------------------- sources ---
def repo_text(rel):
    with open(os.path.join(ROOT, rel), encoding='utf-8') as fh:
        return fh.read()


def role_files():
    """{role: every file that role's measured image carries}.

    image_files.nix is generated from the modules each role's entry points
    import, so this is the image contents rather than a description of them."""
    src = repo_text('deploy/phala/image_files.nix')
    out = {}
    for match in re.finditer(r'\n  (\w+) = \[(.*?)\];', src, re.S):
        out[match.group(1)] = sorted(re.findall(r'"([^"]+)"', match.group(2)))
    assert set(out) == set(roles.ROLES), (
        f'image_files.nix is keyed {sorted(out)}, backend/roles.py says '
        f'{sorted(roles.ROLES)}')
    return out


def allowlist_hosts():
    hosts = json.loads(repo_text('backend/egress_allowlist.json'))['hosts']
    assert hosts, 'egress allowlist is empty'
    return hosts


# The import name each pinned distribution installs. Not derivable from a name
# -- `python-dotenv` imports as `dotenv` -- so it is written once here and
# checked both ways against requirements.txt below.
DISTRIBUTIONS = {
    'certifi': 'certifi',
    'cryptography': 'cryptography',
    'dcap_qvl': 'dcap-qvl',
    'dotenv': 'python-dotenv',
    'google.auth': 'google-auth',
    'google.oauth2': 'google-auth',
    'googleapiclient': 'google-api-python-client',
    'openai': 'openai',
    'presidio_analyzer': 'presidio-analyzer',
    'presidio_anonymizer': 'presidio-anonymizer',
    'requests': 'requests',
    'requests_oauth2client': 'requests-oauth2client',
    'standardwebhooks': 'standardwebhooks',
    'spacy': 'spacy',
}

FIRST_PARTY = {'backend', 'frontend', 'cosigner', 'runtime_guard',
               'tools', 'deploy', 'tests'}


def requirement_pins():
    """{distribution: pin}, and None as the pin for a commented-out line.

    A commented line is a dependency this tree deliberately does not install
    (the Presidio analyzer), and it has to be readable here or a package the
    code imports on a feature flag looks like an unpinned import."""
    out = {}
    for line in repo_text('requirements.txt').splitlines():
        text = line.lstrip('#').strip()
        match = re.fullmatch(r'([A-Za-z0-9_.-]+)==([0-9][\w.]*)', text)
        if match:
            out[match.group(1)] = None if line.startswith('#') else match.group(2)
    assert out, 'no pins found in requirements.txt'
    return out


PINS = requirement_pins()
assert set(DISTRIBUTIONS.values()) <= set(PINS), (
    'DISTRIBUTIONS names a distribution requirements.txt does not pin: '
    f'{sorted(set(DISTRIBUTIONS.values()) - set(PINS))}')
assert set(PINS) <= set(DISTRIBUTIONS.values()), (
    'requirements.txt pins a distribution with no import name here: '
    f'{sorted(set(PINS) - set(DISTRIBUTIONS.values()))}')


def locked_packages():
    """Every package the built virtualenv installs, from the resolved lock.

    The direct pins are ten; the lock is what actually lands in every image,
    because a pin brings its own dependency tree with it."""
    names = re.findall(r'\nname = "([^"]+)"', repo_text('deploy/phala/uv.lock'))
    found = sorted(set(names) - {'tee-email-bot'})
    assert found, 'no packages in uv.lock'
    return found


def third_party(paths):
    """The distributions the code in `paths` imports, pinned ones and the
    feature-flagged ones alike."""
    used = set()
    for rel in paths:
        if not rel.endswith('.py'):
            continue
        tree = ast.parse(repo_text(rel), filename=rel)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
                names = [node.module]
            else:
                continue
            for dotted in names:
                head = dotted.split('.')[0]
                if head in FIRST_PARTY or head in sys.stdlib_module_names:
                    continue
                dist = (DISTRIBUTIONS.get('.'.join(dotted.split('.')[:2]))
                        or DISTRIBUTIONS.get(head))
                assert dist, (
                    f'{rel} imports {dotted!r}, which no entry in '
                    f'DISTRIBUTIONS maps to a pinned distribution')
                used.add(dist)
    return sorted(used)


GRAPH = reachability.Graph()


def unshipped_files():
    """First-party files no enclave image carries.

    The other half of "which files are in which container": what is in the
    repository, ships to the box, and is in no image at all -- the co-signer
    (a unit on the box), the deploy and tooling code, and the modules a person
    runs by hand."""
    in_image = set().union(*ROLE_FILES.values())
    every = {str(GRAPH.modules[name].path.relative_to(reachability.REPO_ROOT))
             for name in GRAPH.shipped}
    out = sorted(p for p in every if p not in in_image)
    assert out, 'every first-party module is in an image, which cannot be right'
    return out


def unit_files(entry_module):
    """Every first-party file the process started by `entry_module` imports.

    The same walk that generates image_files.nix, pointed at a systemd unit's
    ExecStart instead of at a role: on the box no image splits the tree, so
    this is what a unit's process actually reaches rather than what its uid can
    open, and those two are different numbers on purpose."""
    reached = GRAPH.reachable_modules([entry_module])
    found = sorted(
        str(GRAPH.modules[name].path.relative_to(reachability.REPO_ROOT))
        for name in reached if name in GRAPH.modules)
    assert found, f'{entry_module} reaches no module of its own'
    return found


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
ROLE_FILES = role_files()
FILES = {role: len(paths) for role, paths in ROLE_FILES.items()}
HOSTS = allowlist_hosts()
LOCKED = locked_packages()


def env_of(service, common=True):
    names = (COMMON_ENV if common else []) + compose_env(service)
    seen, out = set(), []
    for n in names:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


# ---------------------------------------------------------------- glossary ---
# Every term of art this diagram uses, defined in one line. A tooltip that uses
# one gets the definition appended to it, and the panel at the bottom lists them
# all, so no box on this page depends on the reader already knowing the word.
GLOSSARY = {
    'TDX': 'Intel Trust Domain Extensions: CPU memory encryption, so the machine\'s owner cannot read the VM\'s memory.',
    'CVM': 'Confidential virtual machine: a VM whose memory is encrypted by the CPU (here, a TDX one).',
    'dstack': 'Phala\'s runtime for confidential VMs: it launches the compose file, measures it, and runs the guest agent.',
    'guest agent': 'The dstack process inside the VM that hands out sealing keys, RA-TLS keys and quotes, over a unix socket.',
    'RTMR3': 'A runtime measurement register: an append-only hash inside the CPU that the compose file is extended into at launch.',
    'compose-hash': 'The hash of the compose file as launched; extended into RTMR3, so it is part of what a quote proves.',
    'quote': 'A CPU-signed statement of what is running: the measurements, plus 64 bytes the caller chose (report_data).',
    'report_data': 'The 64 caller-chosen bytes inside a quote, used to bind the quote to a key, a nonce or a model name.',
    'attestation': 'Checking a quote before trusting the thing that produced it.',
    'RA-TLS': 'TLS where the certificate carries a quote, so the peer proves what code it is while the connection is made.',
    'mTLS': 'Mutual TLS: both ends present a certificate, not just the server.',
    'PCCS': 'The caching service that serves the Intel signature chain and TCB status a quote is checked against.',
    'KMS': 'Key management service: here, dstack\'s, which releases the app sealing key only to a measurement it accepts.',
    'sealing key': 'A key derived inside the CVM from the platform and the app\'s measurement; nothing outside can re-derive it.',
    'DPoP': 'A signed proof sent with an OAuth token that binds it to a key, so a stolen token is useless without the key.',
    'AES-GCM': 'Authenticated symmetric encryption: it both hides the bytes and detects any change to them.',
    'HKDF': 'A key derivation function: one secret plus a label in, one purpose-specific key out.',
    'data key': 'One random 32-byte key per account, the only thing that opens that account\'s files.',
    'DEK': 'Data encryption key: the per-account key, the term the custody code uses for it.',
    'wrapping': 'Encrypting a key with another key. Here twice over: our layer inside, the co-signer\'s outside.',
    'ciphertext': 'Encrypted bytes; unreadable without the key.',
    'manifest': 'database/accounts.json: the list of accounts and their settings, the one file left in plaintext.',
    'OIDC': 'OpenID Connect: an identity layer on OAuth. Google signs a JWT with it to prove which service account is calling.',
    'JWT': 'A signed JSON token; the signature is what makes its claims worth reading.',
    'JWKS': 'The published set of public keys a JWT signature is checked against.',
    'Pub/Sub': 'Google\'s message bus. A watch registration makes it POST to our receiver whenever a mailbox changes.',
    'historyId': 'Gmail\'s per-mailbox cursor: a number naming a point in the change log, and the only mail state stored.',
    'HMAC': 'A keyed hash proving a message came from someone holding the shared secret and was not altered.',
    'webhook': 'An HTTP request another service sends us when something happened on their side.',
    'FIFO': 'A named pipe: a file that carries a byte from one process to another and stores nothing.',
    'spool': 'An append-only file of pending work, drained under a lock by the process that acts on it.',
    'CONNECT': 'The HTTP verb that asks a proxy for a raw tunnel to a host and port; the TLS inside it stays end to end.',
    'allowlist': 'The closed list of hostnames anything here may connect to; anything not named is refused.',
    'AF_UNIX': 'A socket that is a file on disk rather than a network address, so file permissions decide who may connect.',
    'SO_PEERCRED': 'A socket option that asks the kernel which uid is on the other end, rather than believing what it says.',
    'setgid': 'A directory bit (the 2 in 2770) making new files inherit the directory\'s group instead of the writer\'s.',
    'tmpfs': 'A filesystem in RAM: it never reaches disk and does not survive a restart.',
    'uid': 'The numeric account a process runs as; the kernel checks it on every file it opens.',
    'supplementary group': 'An extra group a process carries beyond its own, which is how one uid gets at another\'s files.',
    'systemd': 'The service manager on the Hetzner box: it starts each unit, as which account, with which restrictions.',
    'unit': 'One systemd service, timer or socket, described by a file in deploy/hetzner/.',
    'credstore': 'systemd\'s encrypted credential store: secrets sealed to the host TPM and handed to one unit at start.',
    'TPM': 'A chip that holds keys the host cannot export, used here to seal the co-signer\'s credentials to this machine.',
    'ReadWritePaths': 'The systemd setting naming the only paths a unit may write; everything else is mounted read-only.',
    'IPAddressDeny': 'The systemd setting that blocks a unit\'s network at the kernel, not in its configuration.',
    'cgroup': 'The kernel grouping systemd puts a unit in; the network and resource limits are enforced there.',
    'X-Forwarded-For': 'A header a proxy adds naming the original client. Worth reading only from a proxy you trust.',
    'reverse-proxy': 'A server that terminates the connection from outside and forwards it to a local process.',
    'masking': 'Replacing names, addresses and keys with stable tags before text leaves for a model, and restoring them after.',
    'NER': 'Named-entity recognition: a model finding people and places in text, used to mask names no rule knows.',
    'PII': 'Personally identifiable information: the names, addresses and numbers masking exists to remove.',
    'pseudonymize': 'Replace a value with a stable tag, so the same person reads as the same token in every message.',
    'fence': 'The delimiters wrapped around text an outsider wrote, with a per-conversation nonce so it cannot be forged.',
    'nonce': 'A value used once, so a reply cannot be replayed and a delimiter cannot be guessed.',
    'supercronic': 'A cron daemon for containers: it runs the crontab in the foreground as the container\'s own process.',
    'idempotent': 'Safe to run twice: the second run changes nothing.',
    'fail closed': 'On any doubt, refuse rather than continue. The opposite is a fallback that quietly does less.',
}

TERM_RE = {
    term: re.compile(r'(?<![\w-])' + re.escape(term) + r'(?![\w-])',
                     0 if term[0].isupper() or term.isupper() else re.IGNORECASE)
    for term in GLOSSARY
}


def gloss(tip, limit=5):
    """A tooltip, plus a plain definition of each term of art it uses.

    A diagram may not assume its reader already speaks its jargon, and a
    glossary nobody scrolls to is the same as none, so the definitions travel
    with the box that used the word. Capped, because a tooltip long enough to
    need scrolling is a tooltip nobody reads either."""
    if not tip:
        return tip
    hits = [(term, GLOSSARY[term]) for term, rx in TERM_RE.items() if rx.search(tip)]
    if not hits:
        return tip
    return tip + '\n\n' + '\n'.join(f'{t}:  {m}' for t, m in hits[:limit])


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
CARRY_ST = ('rounded=0;whiteSpace=wrap;html=1;align=left;verticalAlign=top;'
            'spacingLeft=9;spacingTop=4;strokeWidth=1;fontSize=8;' + MONO)
CARRY_KIND = {
    'code':    'fillColor=#eef3ec;strokeColor=#b9cdb6;fontColor=#2f4a2c;',
    'pypi':    'fillColor=#f4f1e6;strokeColor=#ccc3a3;fontColor=#4d4526;',
    'content': 'fillColor=#fbeaf0;strokeColor=#d9a3b8;fontColor=#6d1738;',
}
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
    'https':  'strokeColor=#2f7dc4;strokeWidth=1.6;',
    'ipc':    'strokeColor=#3f8f85;strokeWidth=1.8;',
    'file':   'strokeColor=#7b8a9a;strokeWidth=1.4;dashed=1;dashPattern=4 3;',
    'cross':  'strokeColor=#8a5fb0;strokeWidth=2.6;',
    'text':   'strokeColor=#c2185b;strokeWidth=2.4;',
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
def carry_lines(kind, paths, packages, content):
    """The three "what is in here" stripes, as (kind, lines, tooltip).

    Every card gets the same three whatever the mechanism, because the question
    "which files, which packages, and can it see a message body" has an answer
    for a systemd unit as much as for an image."""
    out = []
    if paths is not None:
        counts = Counter(os.path.dirname(p) or '(repo root)' for p in paths)
        tokens = [f'{d} {n}' for d, n in
                  sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))]
        head = f'{kind}  {len(paths)} files'
        out.append(('code', [head] + wrap(tokens, 44), file_tip(kind, paths)))
    if packages is not None:
        # A package imported behind a feature flag is commented out in
        # requirements.txt and installed nowhere, so it is shown but not
        # counted: the number is what this container actually has.
        installed = [d for d in packages if PINS.get(d)]
        optional = [d for d in packages if not PINS.get(d)]
        out.append(('pypi',
                    [f'pypi  {len(installed)} of {len(LOCKED)} in the venv']
                    + wrap(installed + [d + ' (not installed)' for d in optional], 44),
                    package_tip(installed, optional)))
    if content is not None:
        out.append(('content', ['mail text  ' + content[0]] + wrap_words(content[1], 46),
                    content[2]))
    return out


def wrap_words(sentence, width):
    return wrap(sentence.split(' '), width)


HOST_FILE_NOTE = (
    'On the Hetzner box the code is not split. deploy.sh rsyncs the repository '
    'to /opt/letterlock minus the server-only list, every unit can read all of '
    'it, and the venv is one directory too. So this stripe is what this unit\'s '
    'process actually imports, walked from its own ExecStart by '
    'tools/reachability.py -- the same walk that generates the enclave\'s '
    'per-image file lists. What keeps one unit out of another\'s data here is '
    'the uid, the group and the file mode, not the file list.')

IMAGE_FILE_NOTE = (
    'The measured image carries exactly these files and nothing else. deploy/, '
    'tests/, tools/ and docs/ are in no image at all, and a module another role '
    'needs is absent rather than merely unused. The list is generated by '
    'walking this role\'s entry points, so cutting a role\'s reach means moving '
    'code rather than deferring an import.')


def file_tip(kind, paths):
    """The complete file list, one line per directory."""
    by_dir = {}
    for p in paths:
        by_dir.setdefault(os.path.dirname(p) or '(repo root)', []).append(
            os.path.basename(p))
    lines = [f'{len(paths)} files, in {len(by_dir)} directories']
    for d in sorted(by_dir):
        names = sorted(by_dir[d])
        for i, chunk in enumerate(wrap(names, 64)):
            lines.append(f'  {d}/  {chunk}' if i == 0 else f'      {chunk}')
    return ('Which of this repository is in here\n'
            + (IMAGE_FILE_NOTE if kind == 'image' else HOST_FILE_NOTE)
            + '\n\n' + '\n'.join(lines))


def package_tip(installed, optional):
    return ('Third-party packages this container\'s own code imports\n'
            + (', '.join(installed) if installed else 'none') + '.\n\n'
            f'Every enclave image installs the same virtualenv: {len(LOCKED)} '
            'packages, built by uv2nix from deploy/phala/uv.lock, which is the '
            f'{len([p for p in PINS.values() if p])} pins in requirements.txt '
            'plus everything they depend on. The box pip-installs the same '
            'requirements.txt into one venv every unit shares. So packages are '
            'not what separates one container from another -- the files are. '
            'What this row names is the smaller set: the ones this role\'s own '
            'modules import, and therefore the ones whose next advisory '
            'actually reaches it.'
            + ('\n\nNot installed: ' + ', '.join(optional) + '. Commented out '
               'in requirements.txt and imported only behind a feature flag, so '
               'the import exists in the code and the package exists in neither '
               'deployment. The Presidio analyzer is the one case: with it the '
               'masking layer does NER, without it the regex rules still run.'
               if optional else ''))


def card(cid, x, y, title, sub, meta, ins, outs, env=None, palette='enclave',
         tip=None, row_h=ROW_H, w=CARD_W, carries=()):
    """Emit one container card and register every row as its own cell, so an
    edge attaches to the interface and not to the box. Returns the card rect."""
    fill, stroke, fc = ROLE_COLOURS[palette]
    for label, _ in list(ins) + list(outs):
        assert len(label) <= 54, f'{cid}: row label too wide: {label!r}'
    envlines = wrap(env, 46) if env else []
    h = (TITLE_H + SUB_H + PAD + META_LH * len(meta) + 8
         + sum(ENV_LH * len(lines) + 8 for _k, lines, _t in carries)
         + (HDR_H + row_h * len(ins) if ins else 0)
         + (HDR_H + row_h * len(outs) if outs else 0)
         + (6 + HDR_H + ENV_LH * len(envlines) if envlines else 0) + PAD)

    reg(cid, x, y, w, h)
    FG.append(emit_box(cid, x, y, w, h, '',
                       CARD_BODY + f'strokeColor={stroke};',
                       tip_html(gloss(tip)) if tip else None))
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

    for j, (kind, lines, ctip) in enumerate(carries):
        ch = ENV_LH * len(lines) + 8
        FG.append(emit_box(f'{cid}__c{j}', x, cur, w, ch, '\n'.join(lines),
                           CARRY_ST + CARRY_KIND[kind],
                           tip_html(gloss(ctip)) if ctip else None))
        cur += ch

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
                               tip_html(gloss(rtip)) if rtip else None))
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
    FG.append(emit_box(nid, x, y, w, h, label, style, tip_html(gloss(tip))))


def store(nid, x, y, w, h, label, tip, style=STORE):
    reg(nid, x, y, w, h, tip)
    FG.append(emit_box(nid, x, y, w, h, label, style, tip_html(gloss(tip))))


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
                               'tip': gloss(tip or TIPS.get(src) or TIPS.get(dst))},
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
E_LEAF_X, E_LEAF_W = 40, 160
E_C0, E_C1, E_C2, E_C3 = 240, 620, 1090, 1560
DEST_X, DEST_W = 2270, 310
DEST_ROW_H = 38

CARDS_TOP = 372
CH_PROXY = [278, 294, 310]
E_GAP0 = slots(E_C0 + CARD_W, E_C1, 4, inset=12)
E_GAP1 = slots(E_C1 + CARD_W, E_C2, 9)
E_GAP2 = slots(E_C2 + CARD_W, E_C3, 4)

ENFORCED_TIP = (
    'Enforced by the network, not by the caller\n'
    'This role is attached to `inner` alone, which docker creates with no route '
    'off the host, so it reaches the internet through the proxy or not at all. '
    'The proxy env vars point it there; the network is what leaves it no '
    'alternative. Every role holding data is in that position, which is what '
    'the ingress container bought: while web and hook held the published ports '
    'they had to sit on the ordinary bridge, and there the allowlist was two '
    'environment variables their own HTTP clients chose to honour.')
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

MAIL_TEXT_TIP = (
    'Where a message body can be, end to end\n'
    'It enters exactly one process. mailbox.fetch_since_history asks Gmail for '
    'what changed since the stored historyId, gmail_api.fetch_message returns '
    'the messages, and they live in Python memory for that one pass. '
    'draft_replies masks them, posts to the model, restores the reply, and '
    'submit_draft creates a Gmail draft in the account\'s own mailbox. The pass '
    'ends and the objects go.\n\n'
    'Nothing writes one down. state/ holds a spool, a FIFO, a socket and audit '
    'rows; database/<id>/ holds the data key, the OAuth token and two encrypted '
    'documents. The only mail state kept anywhere is the historyId, which is a '
    'cursor number. There is no cache of message text on either machine, which '
    'is why no volume on this page has a mail-text stripe.\n\n'
    'What is derived from mail and kept: voice-dna.enc, a voice profile '
    'distilled from the account\'s own sent mail, encrypted under that '
    'account\'s data key like everything else under <id>/.\n\n'
    'What leaves carrying content: the model call (masked, and to an attested '
    'endpoint if the account chose confidential inference), the Gmail draft '
    'itself, and Telegram -- one sender-and-subject line per draft, plus the '
    'daily summary, which is written from the day\'s mail.')

TEXT_MAIL = ('in memory, for one pass',
             'fetched from Gmail, masked, drafted, released. Never written to a volume.',
             MAIL_TEXT_TIP)
TEXT_WEB = ('never',
            'renders the two documents under <id>/. It opens no mailbox.',
            'This process never holds a message body\n'
            'It has no Google token -- token.bin is 0600 to the mail uid -- and '
            'the two operations that would need one cross to the mail role over '
            'the handoff socket. What it does read of an account is '
            'voice-dna.enc and personal-context.enc, which are a profile and a '
            'user-written note rather than mail.\n\n' + MAIL_TEXT_TIP)
TEXT_HOOK = ('never',
             'reads one field of the push, emailAddress. The rest is dropped.',
             'This process never holds a message body\n'
             'A Pub/Sub push says a mailbox changed; it does not carry the '
             'change. route_push() reads emailAddress and discards the rest of '
             'the envelope, so the line it appends to the wake spool is an '
             'address and nothing else -- and it does not even resolve that to '
             'an account, because resolving reads the manifest and this '
             'process cannot read the account manifest.\n\n' + MAIL_TEXT_TIP)
TEXT_TLS = ('encrypted only',
            'TLS is end to end between the role and the destination; this moves opaque bytes.',
            'This process sees ciphertext, never text\n'
            'A CONNECT tunnel is joined before any TLS handshake happens '
            'inside it, so the session key is between the calling role and the '
            'destination and this process holds neither it nor a certificate '
            'that would let it interpose. What it can see is the hostname on '
            'the request line, which is the whole point of it.\n\n'
            + MAIL_TEXT_TIP)
TEXT_FWD = ('opaque bytes',
            'joins two TCP connections. It parses nothing and terminates no TLS.',
            'This process reads nothing it forwards\n'
            'A TCP forwarder: a connection arriving on a published port is '
            'joined to a connection to the service that port belongs to, and '
            'after that it moves bytes. It reads no request line and no header, '
            'which is the entire design -- the process the open internet '
            'reaches first should have the smallest possible answer to "what '
            'can I make it misinterpret".\n\n' + MAIL_TEXT_TIP)

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
      'networks  inner            ports  none',
      'volumes  state',
      'python -m backend.daemons.gmail_hook_server'],
     [(':8787   POST /   Pub/Sub push',
       'Inbound: Google Pub/Sub push, HTTP/1.1 POST, forwarded by ingress\n'
       'Body is a Pub/Sub push envelope; message.attributes name the mailbox. '
       'Authorization: Bearer <OIDC identity JWT>, verified against Google\'s '
       'JWKS with aud = site.pubsub_audience() (WEBHOOK_AUD) and the signer '
       'required to be PUBSUB_SERVICE_ACCOUNT. Anything else raises HookError '
       'and is refused. Binds 0.0.0.0:8787 because the caller is the ingress '
       'container, which a loopback listener would not answer.')],
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
     carries=carry_lines('image', ROLE_FILES['hook'],
                         third_party(ROLE_FILES['hook']), TEXT_HOOK),
     tip='hook — the Pub/Sub receiver\n'
         'What it is: the HTTP server Google posts to when a mailbox changes. '
         'It checks the push is really Google\'s, writes the address down, and '
         'wakes the mail role. That is the whole job.\n\n'
         'The most exposed role and the cheapest to isolate. Its image is '
         f'{FILES["hook"]} files (the JWT verifier, the wake spool, '
         'paths/secrets/site and the co-signer wire contract), so the inference '
         'client, Telegram, billing and the custody stack are not in its '
         'address space to reach for. It mounts state and not database, and no '
         'guest-agent socket.')

card('e_web', E_C1, bottom('e_hook') + 46,
     'web', f'tee-email-bot-web   ·   {FILES["web"]} files   ·   command: web',
     ['user  10002:10002  (letterlock-web)',
      'group_add  10010 letterlock-data',
      'networks  inner            ports  none',
      'volumes  database, state, tmpfs /app/attestation',
      'python -m backend.tee.tee_boot   (gate, fail-closed)',
      'python -m frontend.web_server'],
     [(':8790   product UI   from ingress',
       'Inbound: the product web UI, forwarded in by the ingress container\n'
       'Sign-in, dashboard, /voice, /personal, /settings, /billing. Two signed '
       'cookies, each kid:value:iat:mac -- the session cookie and the OAuth '
       'state cookie -- verified against frontend/session.py\'s keyring, so '
       'SESSION_SECRET_PREVIOUS still verifies while only the current key '
       'mints. WEB_HOST=0.0.0.0 because the caller is another container, which '
       'a loopback listener would not answer. X-Forwarded-For is believed only '
       'from site.TRUSTED_PROXIES, which is loopback plus '
       'LETTERLOCK_TRUSTED_PROXIES and ships empty -- so in the CVM the peer '
       'this records is the ingress container, since a TCP forwarder cannot '
       'name the browser without becoming an HTTP parser.')],
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
     carries=carry_lines('image', ROLE_FILES['web'],
                         third_party(ROLE_FILES['web']), TEXT_WEB),
     tip='web — the product UI\n'
         'What it is: the site a person signs in to, to set their voice '
         'profile, their personal context, their notification target and their '
         'plan. It renders that account\'s own documents and nothing else.\n\n'
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
       'inference provider, Telegram, Polar and the PCCS. Message bodies both '
       'arrive and leave over this one interface: fetched from Gmail, sent '
       'masked to the model, and posted back as a draft.\n\n' + PROXY_TIP),
      ('database/<id>/    token.bin 0600, *.enc 0660',
       'Outbound: the account store\n'
       'One random 32-byte data key per account in dek.bin; token.bin, '
       'voice-dna.enc and personal-context.enc all go through '
       'keyring.read_encrypted / write_encrypted. token.bin is 0600 to this '
       'uid, so the web tier cannot read the one file its data key would open. '
       'accounts.json is the manifest and the only plaintext left, because '
       'encrypting it would need the account list to find the account. '
       'state.json lives here too and holds one number, the Gmail historyId '
       'this account was last read up to.'),
      ('state/    audit prune · restart.flag',
       'Outbound: daemon scratch, in the shared 2771 directory\n'
       'audit.maybe_prune() rides on the daemon\'s pass so RETENTION_DAYS is a '
       'period on a clock rather than on whoever last signed in; restart.flag '
       'is how a code change takes effect without a service restart. The '
       'per-account cursor is not here -- that is database/<id>/state.json, '
       'beside the account\'s own data.'),
      ('/var/run/dstack.sock   GetKey · GetTlsKey · quote', DSTACK_TIP)],
     env_of('mail'),
     carries=carry_lines('image', ROLE_FILES['mail'],
                         third_party(ROLE_FILES['mail']), TEXT_MAIL),
     tip='mail — the only role that opens a mailbox\n'
         'What it is: the drafting daemon. It waits for a wake, reads what '
         'arrived in that account\'s mailbox since the last cursor, decides '
         'which messages want a reply, writes one for each into Gmail as a '
         'draft, and tells the user over Telegram. The scheduled work runs '
         'here too.\n\n'
         'Holds the Google client credentials, the inference keys and the '
         'Telegram token, and is the only account that can read '
         'database/<id>/token.bin. It runs the scheduled work because the '
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
     carries=carry_lines('image', ROLE_FILES['egress'],
                         third_party(ROLE_FILES['egress']), TEXT_TLS),
     tip='egress — the one container with a route off the host\n'
         'What it is: a proxy. Every other container is asked to send its HTTP '
         'through here, and has no other way out; this process checks the '
         'hostname against a fixed list and then joins the two sockets '
         'together.\n\n'
         f'The same module the box runs as egress-proxy.service, {FILES["egress"]} '
         'files, its own uid and no group at all. It was 39 files until the '
         'allowlist stopped being derived inside it: performing that walk at '
         'startup meant importing the modules that name each host, and through '
         'them the co-signer client, billing and the inference client -- the '
         'custody stack in the filesystem of the one container that can reach '
         'the internet, in order to compute thirteen strings. The walk moved to '
         'render time; this module now imports json, os and pathlib and nothing '
         'of ours. TLS is end to end, so it holds no plaintext and no key.')

INGRESS_ROWS = sorted(roles.INGRESS_ROUTES.items())

card('e_ingress', E_C0, CARDS_TOP,
     'ingress',
     f'tee-email-bot-ingress   ·   {FILES["ingress"]} files   ·   command: ingress',
     ['user  10005:10005  (letterlock-ingress)',
      'group_add  —',
      'networks  inner, edge',
      'ports  ' + '  '.join(f'{p}:{p}' for p, _r in INGRESS_ROWS),
      'volumes  —',
      'python -m backend.daemons.ingress_proxy',
      'routes  backend/roles.INGRESS_ROUTES'],
     [(f':{port}   TCP   from outside the CVM',
       f'Inbound: a connection on published port {port}\n'
       'Whatever dstack forwards in from outside arrives here. This process '
       'reads no request line and no header: it looks the port up in a table '
       'fixed before it accepted anything, opens a connection to the role that '
       'port belongs to, and moves bytes between the two. It terminates no TLS '
       'and adds no header, so the role behind it sees this container as its '
       'peer rather than the browser.')
      for port, (_role, _up) in INGRESS_ROWS],
     [(f'TCP   →   {role}:{up}   over inner',
       f'Outbound: the forwarded half of the connection, to {role}\n'
       'Over the internal network, by the compose service name, which docker\'s '
       'embedded DNS resolves. This is what lets the role behind it publish no '
       'port and sit on the internal network alone, which is what turned the '
       'egress allowlist from a request into a control for every container '
       'holding data.')
      for _port, (role, up) in INGRESS_ROWS],
     env_of('ingress', common=False),
     palette='egress',
     carries=carry_lines('image', ROLE_FILES['ingress'],
                         third_party(ROLE_FILES['ingress']), TEXT_FWD),
     tip='ingress — the only container the outside world connects to\n'
         'What it is: a TCP forwarder holding the published ports. A '
         'connection arriving on 8790 is joined to one to web:8790, and 8787 '
         'to hook:8787; nothing in between parses anything.\n\n'
         'Why it exists at all: a published port on an internal-only network '
         'never receives forwarded ingress, so before this container web and '
         'hook had to sit on the ordinary bridge to be reachable -- and that '
         'is a route off the host, which made the egress allowlist two '
         'environment variables their own HTTP clients chose to honour. The '
         'two roles the control failed to cover were the two facing the '
         'internet. It holds no volume, no secret, no guest-agent socket and '
         'no group, and runs no attestation gate because it has nothing to '
         'unseal.')

# --- enclave: the substrate lane ----------------------------------------------
E_CARD_BOT = max(bottom('e_web'), bottom('e_mail'), bottom('e_egress'),
                 bottom('e_ingress'))
E_CH0 = E_CARD_BOT + 26
E_CHAN = [E_CH0 + 14 * i for i in range(10)]
E_LANE_Y = E_CHAN[-1] + 40
LANE_H = 96

store('e_vol_state', 300, E_LANE_Y, 300, LANE_H,
      'volume  state → /app/state\n'
      '2771 letterlock-data\n'
      'wake_queue.jsonl + .lock  0660 wake\n'
      'wake.fifo · custody.sock · audit.db 0600',
      'docker volume "state" — the shared scratch directory\n'
      'What is in it: the wake spool and its lock, the FIFO the daemon waits '
      'on, the handoff socket, the audit database and restart.flag. No message '
      'text and no account data: a spool line is an address, an audit row is a '
      'short token, and both are gone or pruned on a schedule.\n\n'
      'Mounted by mail, web and hook. 2771 rather than 2770 because four uids '
      'open a file in it and are deliberately not all in one group: traversal '
      'is open and each file\'s own mode is the grant. Docker seeds a named '
      'volume from the first container to mount it, ownership and mode '
      'included, so every image that mounts it seeds it identically and '
      'whichever container starts first the result is the same.')

store('e_sock', 660, E_LANE_Y, 300, LANE_H,
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

store('e_vol_db', 1020, E_LANE_Y, 300, LANE_H,
      'volume  database → /app/database\n'
      '2770 letterlock-data (setgid)\n'
      'accounts.json  (manifest, plaintext)\n'
      '<id>/ dek.bin · token.bin · *.enc · state.json',
      'docker volume "database" — the account store\n'
      'What is in it, per account: dek.bin (that account\'s data key, itself '
      'wrapped twice), token.bin (the Google refresh grant), voice-dna.enc (a '
      'voice profile distilled from their own sent mail), personal-context.enc '
      '(a note they wrote) and state.json (one number, the Gmail historyId '
      'read up to). No message body: nothing in this tree writes one.\n\n'
      'Mounted by mail and web; hook mounts it not at all, which is what keeps '
      'the account list out of reach of the process Google posts to. Not '
      'traversable like state/, because who has an account is itself worth '
      'keeping. Everything under <id>/ is ciphertext and opening any of it '
      'costs a co-signer round trip that is rate limited and logged.')

store('e_dstack', 1380, E_LANE_Y, 300, LANE_H,
      '/var/run/dstack.sock\n'
      'host bind mount, guest agent\n'
      'GetKey · GetTlsKey · GetQuote\n'
      'mounted into mail and web only',
      DSTACK_TIP, style=SOCK)

UNSHIPPED = unshipped_files()
UNSHIPPED_DIRS = Counter(os.path.dirname(p) or '(repo root)' for p in UNSHIPPED)

leaf('e_unshipped', 1740, E_LANE_Y, 340, LANE_H,
     f'in no image at all   ({len(UNSHIPPED)} files)\n'
     + '\n'.join(wrap([f'{d} {n}' for d, n in
                       sorted(UNSHIPPED_DIRS.items(), key=lambda kv: (-kv[1], kv[0]))], 46)),
     'What the repository holds that no container here does\n'
     + file_tip('image', UNSHIPPED).split('\n', 1)[1].split('\n\n', 1)[1] +
     '\n\ncosigner/ is the largest part and is the point: it runs as a unit on '
     'the Hetzner box, and putting it in an enclave image would put the outer '
     'wrapping key in the same measurement as the ciphertext it protects. '
     'billing_webhook is box-only because no role in the enclave is a Polar '
     'receiver. deploy/ and tools/ are refused by tests/test_image_manifest.py '
     'outright, and seed_owner and unlink_telegram are run by hand.',
     style='rounded=1;arcSize=8;whiteSpace=wrap;html=1;fontSize=8.5;' + MONO +
           'align=left;spacingLeft=12;verticalAlign=middle;strokeWidth=1.5;'
           'dashed=1;dashPattern=6 4;'
           'fillColor=#f7f5f0;strokeColor=#a8a294;fontColor=#3f3a30;')

# --- enclave: external parties -------------------------------------------------
E_IN_MID = (cy('e_ingress__in0') + cy('e_ingress__in1')) / 2

leaf('e_pubsub', E_LEAF_X, E_IN_MID - 64, E_LEAF_W, 52,
     'Google Pub/Sub\nwatch push subscription',
     'Google Pub/Sub push\n'
     'A users.watch registration on each account\'s mailbox, renewed weekly, '
     'makes Google POST here on every change. The push says which mailbox '
     'changed and carries no part of the change: one field, emailAddress, is '
     'all the receiver reads. It is authenticated by an OIDC identity JWT '
     'signed by the configured service account.')

leaf('e_browser', E_LEAF_X, E_IN_MID + 12, E_LEAF_W, 52,
     'End user\nbrowser over HTTPS',
     'The product UI\'s caller\n'
     'A person signing in to set their voice profile, their personal context, '
     'their notification target or their plan. They reach the published 8790, '
     'which belongs to the ingress container, and are forwarded to web over '
     'the internal network.')

for i, (label, tip) in enumerate(EGRESS_OUT):
    rid = f'e_egress__out{i}'
    name = label.split('  ')[0].strip()
    hosts = wrap(tip.split('\n')[0].split(', '), 40)
    base = LEAF_MUTED if i == len(EGRESS_OUT) - 1 else LEAF
    leaf(f'e_dest{i}', DEST_X, top(rid) + 1, DEST_W, DEST_ROW_H - 2,
         '\n'.join([name] + hosts), tip, style=base + 'fontSize=8;')

NOTE_W = (E_C3 + CARD_W - E_C0 - 30) / 2

note('e_note', E_C0, 112, NOTE_W, 118,
     'What "attested" means here.  docker-compose.yml is embedded in app-compose.json, whose hash\n'
     'is the dstack compose-hash extended into RTMR3, a register inside the CPU that a quote is\n'
     'signed over.  So which process runs as which account, which image it runs, and which secrets\n'
     'each is handed are not just configured but provable to someone else — move SESSION_SECRET to\n'
     'the mail container and cosigner/attest.py stops accepting the client certificate.  Every name\n'
     'in an env stripe below must also be in allowed_envs;  EXPECTED_COMPOSE_HASH is refused empty.')

note('e_text_note', E_C0 + NOTE_W + 30, 112, NOTE_W, 118,
     'Where a message body can be.  It enters one container: mail fetches what changed since the stored\n'
     'historyId, keeps it in memory for that pass, masks it for the model, writes the reply back as a Gmail\n'
     'draft, and drops it.  No volume on this page holds one — the wake spool holds an address, the account\n'
     'store holds keys and two encrypted documents, and the only mail state kept is a cursor number.  The\n'
     'pink stripe on each card says what that container can see of a body;  the pink arrows are the four\n'
     'destinations content reaches:  Gmail, the model (masked), and Telegram (subject lines, daily summary).')

# --- enclave: the wiring -------------------------------------------------------
edge('e_pubsub', 'e_ingress__in0', 'https',
     jog('e_pubsub', 'e_ingress__in0', E_C0 - 32))
edge('e_browser', 'e_ingress__in1', 'https',
     jog('e_browser', 'e_ingress__in1', E_C0 - 16))
edge('e_ingress__out0', 'e_hook__in0', 'net',
     jog('e_ingress__out0', 'e_hook__in0', E_GAP0[1]), 'TCP')
edge('e_ingress__out1', 'e_web__in0', 'net',
     jog('e_ingress__out1', 'e_web__in0', E_GAP0[2]), 'TCP')

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

edge('e_hook__out1', 'e_egress__in0', 'net',
     over('e_hook__out1', 'e_egress__in0', E_GAP1[0], CH_PROXY[0], E_C3 - 34),
     'CONNECT', ENFORCED_TIP)
edge('e_web__out1', 'e_egress__in0', 'net',
     over('e_web__out1', 'e_egress__in0', E_GAP1[1], CH_PROXY[1], E_C3 - 52),
     'CONNECT', ENFORCED_TIP)
edge('e_mail__out0', 'e_egress__in0', 'text',
     jog('e_mail__out0', 'e_egress__in0', E_GAP2[3]), 'CONNECT  (message text)',
     'The one interface a message body crosses\n'
     'Everything this role reaches goes down this tunnel, message bodies '
     'included: fetched from Gmail, sent masked to the model, posted back as a '
     'draft. The proxy sees none of it -- the TLS inside a CONNECT tunnel is '
     'between mail and the destination.\n\n' + ENFORCED_TIP)

# Which destinations a message body, or something written from one, actually
# reaches. Derived from the row labels rather than by index, so reordering
# EGRESS_OUT cannot silently move the marking to the wrong line.
CONTENT_DESTS = ('Gmail + Calendar API', 'DeepSeek', 'NEAR AI confidential', 'Telegram')
for i, (label, _tip) in enumerate(EGRESS_OUT):
    name = label.split('  ')[0].strip()
    kind = 'text' if name in CONTENT_DESTS else 'https'
    edge(f'e_egress__out{i}', f'e_dest{i}', kind, [])
assert sum(1 for label, _ in EGRESS_OUT
           if label.split('  ')[0].strip() in CONTENT_DESTS) == len(CONTENT_DESTS), (
    'a destination named in CONTENT_DESTS is not a row of EGRESS_OUT')

# =============================================================== HETZNER =====
H_LEAF_X, H_LEAF_W = 40, 150
H_CADDY, H_C1, H_C2, H_C3 = 300, 760, 1300, 1840

E_LANE_BOT = E_LANE_Y + LANE_H
H_FRAME_TOP = E_LANE_BOT + 132
H_CARDS_TOP = H_FRAME_TOP + 194
H_CH_PROXY = [H_CARDS_TOP - 60, H_CARDS_TOP - 44, H_CARDS_TOP - 28]
H_GAP0 = slots(H_CADDY + CARD_W, H_C1, 5)
H_GAPL = slots(H_LEAF_X + H_LEAF_W, H_CADDY, 4, inset=10)
H_GAP1 = slots(H_C1 + CARD_W, H_C2, 13)
H_GAP2 = slots(H_C2 + CARD_W, H_C3, 6)


def host_carries(entry, content):
    """The three stripes for one systemd unit, walked from its ExecStart."""
    files = unit_files(entry)
    return carry_lines('imports', files, third_party(files), content)


TEXT_HOST_MAIL = (TEXT_MAIL[0], TEXT_MAIL[1], TEXT_MAIL[2])
TEXT_BILLING = ('never',
                'a Polar event names a subscription and a customer, nothing more.',
                'This process never holds a message body\n'
                'It verifies a webhook signature and appends the event to a '
                'spool for the daemon to apply. It has no Google token, no '
                'mailbox and no reason to read one.\n\n' + MAIL_TEXT_TIP)
TEXT_COSIGNER = ('never',
                 'unwraps a key it is handed. It holds no ciphertext of ours and no mail.',
                 'This process never holds a message body\n'
                 'The co-signer is given an already-wrapped key and asked to '
                 'strip its own outer layer. It never sees the account\'s '
                 'files, let alone a message: it holds the outer wrapping key '
                 'and no ciphertext, which is the half of split custody that '
                 'makes compromising it alone read nothing.\n\n'
                 + MAIL_TEXT_TIP)
TEXT_CADDY = ('never',
              'terminates TLS for three sites. No mailbox traffic passes through it.',
              'This process never holds a message body\n'
              'Mail is fetched by the daemon, outbound, through the egress '
              'proxy; it does not arrive through the front door. What crosses '
              'Caddy is the product UI, a Pub/Sub push naming a mailbox, a '
              'Polar event and the co-signer\'s custody traffic.\n\n'
              + MAIL_TEXT_TIP)
TEXT_TIMERS = ('in memory, for one pass',
               'the daily summary reads the day\'s mail, writes a summary, sends it, and exits.',
               'A message body lives here for the length of one run\n'
               'email_summary fetches the last day of unread mail and the next '
               'day of calendar, has the model write a summary, and delivers it '
               'to the account\'s linked Telegram chat. Nothing is written to '
               'disk in between; the process exits when the run ends.\n\n'
               + MAIL_TEXT_TIP)

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
     carries=[('code', ['config  1 file', 'deploy/hetzner/Caddyfile (generated, installed by hand)'],
               'Caddy is a system package, not this repository\n'
               'The only file of ours it reads is the Caddyfile, rendered from '
               'backend/site.py by python -m deploy.render_caddyfile. It is '
               'deliberately not rsynced: a bad reload takes every site on the '
               'box down at once, so it is validated and installed by hand.\n\n'
               + HOST_FILE_NOTE),
              ('pypi', ['pypi  none  (a Go binary, not a python process)'],
               'Caddy ships as one static Go binary from the distribution\'s '
               'package repository. None of the pins in requirements.txt reach '
               'it, and it runs under no virtualenv of ours.'),
              ('content', ['mail text  ' + TEXT_CADDY[0]] + wrap_words(TEXT_CADDY[1], 46),
               TEXT_CADDY[2])],
     tip='caddy — the front door\n'
         'What it is: the web server every connection from outside the box '
         'lands on. It holds the public TLS certificates, decides which of the '
         'three hostnames was asked for, and forwards to a local port. Nothing '
         'else on the box listens on a public address.\n\n'
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
     carries=host_carries('backend.daemons.gmail_hook_server', TEXT_HOOK),
     tip='email-webhook.service\n'
         'What it is: the box\'s copy of the Pub/Sub receiver, the same module '
         'the enclave runs as the hook role.\n\n'
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
     carries=host_carries('frontend.web_server', TEXT_WEB),
     tip='letterlock-web.service\n'
         'What it is: the box\'s copy of the product UI, the same module the '
         'enclave runs as the web role.\n\n'
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
     carries=host_carries('backend.billing.billing_webhook', TEXT_BILLING),
     tip='billing-webhook.service\n'
         'What it is: the receiver Polar posts a subscription event to. It '
         'checks the signature, writes the event to a spool, and answers. The '
         'daemon is what acts on it. There is no equivalent role in the '
         'enclave, where entitlement is read back from Polar\'s API '
         'instead.\n\n'
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
      ('state/   audit prune · restart.flag',
       'Outbound: daemon scratch\n'
       'The per-account cursor is not here: database/<id>/state.json holds the '
       'Gmail historyId, beside that account\'s own data.'),
      ('.env  +  .gmail-mcp/gcp-oauth.keys.json',
       'Reads: the inference keys, and the OAuth app\'s client id and secret\n'
       'One OAuth app serves every user; no per-user token lives in that '
       'directory. oauth_app.py prefers the injected '
       'GOOGLE_OAUTH_CLIENT_ID/SECRET and refuses the file entirely under '
       'TEE_REQUIRED, so this is the box\'s fallback and not the enclave\'s.')],
     palette='host',
     carries=host_carries('backend.daemons.daemon_loop', TEXT_MAIL),
     tip='email-daemon.service\n'
         'What it is: the box\'s drafting daemon, the same work the enclave\'s '
         'mail role does. It waits on the FIFO, reads what arrived, drafts '
         'replies into Gmail, and serves the handoff socket on a thread.\n\n'
         'The FIFO listener, and the unit that still runs as the base '
         'letterlock account: everything that has been split off has been split '
         'off from here.')

TIMER_FILES = sorted(set(unit_files('backend.drafting.email_summary'))
                     | set(unit_files('backend.onboarding.watch_renew'))
                     | set(unit_files('backend.billing.billing_poller')))

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
     carries=carry_lines('imports', TIMER_FILES, third_party(TIMER_FILES),
                         TEXT_TIMERS),
     tip='The scheduled work\n'
         'What it is: three short-lived processes systemd starts on a clock. '
         'The daily summary, the weekly re-registration of the Gmail watch, and '
         'the 3-hourly billing reconcile. Each runs, does its sweep and '
         'exits.\n\n'
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
     carries=host_carries('cosigner.server', TEXT_COSIGNER),
     tip='cosigner.service — the other half of split custody\n'
         'What it is: a small HTTP service that holds one key and answers one '
         'question -- may this caller have this account\'s key unwrapped, and '
         'is the caller the code it claims to be. It is a separate account on '
         'this box today and is written to be movable to a separate '
         'machine.\n\n'
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
     carries=host_carries('backend.daemons.egress_proxy', TEXT_TLS),
     tip='egress-proxy.service\n'
         'What it is: the same CONNECT proxy the enclave runs, as a systemd '
         'unit. Every other unit on the box is denied the network at the kernel '
         'and pointed here, so this list of hostnames is the machine\'s whole '
         'reachable set.\n\n'
         'Its own account, because the process holding the network must not be '
         'the one holding the API keys -- which is also why it reads the '
         'allowlist rather than deriving it.')

# --- hetzner: substrate lane ---------------------------------------------------
H_CARD_BOT = max(bottom('h_ks'), bottom('h_cosigner'), bottom('h_egress'))
H_CH0 = H_CARD_BOT + 26
H_CHAN = [H_CH0 + 14 * i for i in range(13)]
H_LANE_Y = H_CHAN[-1] + 40

store('h_state', 300, H_LANE_Y, 300, LANE_H,
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

store('h_sock', 700, H_LANE_Y, 300, LANE_H,
      'state/custody.sock\n'
      'AF_UNIX SOCK_STREAM  0660\n'
      'group letterlock-data\n'
      'SO_PEERCRED: daemon uid + web uid',
      'The handoff socket, same contract as in the enclave\n'
      'The mode is the grant and _may_connect() is a second check of the same '
      'fact, not a replacement: every way that mode can widen is silent.',
      style=SOCK)

store('h_db', 1100, H_LANE_Y, 300, LANE_H,
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

store('h_secrets', 1500, H_LANE_Y, 320, LANE_H,
      'server-only files   (never synced)\n'
      '.env  0600 letterlock-secrets\n'
      '.env.billing  ·  .env.alerts\n'
      '.gmail-mcp/gcp-oauth.keys.json',
      'The secrets, split by who is entitled to which\n'
      'Each has a matching --exclude in deploy/deploy.sh, because the rsync is '
      'authoritative: --delete-after removes remote files the repo no longer '
      'has, so EXCLUDES is the protected set. .env.alerts is read by no Python '
      'at all -- systemd reads it as root and hands it to the co-signer alone.')

store('h_cred', 1900, H_LANE_Y, 300, LANE_H,
      '/etc/credstore.encrypted   (host)\n'
      'cosigner-master · cosigner-dpop\n'
      'sealed to the host TPM\n'
      '/var/lib/private/cosigner  0700',
      'The co-signer\'s own state, outside the app directory\n'
      'LoadCredentialEncrypted= decrypts these at unit start, so the keys are '
      'never on disk in the clear and never in the app directory the deploy '
      'rsyncs over. StateDirectory= is why ReadWritePaths= can be emptied '
      'entirely.', style=SOCK)

H_NOTE_W = (H_C3 + CARD_W - H_CADDY - 30) / 2
note('h_note', H_CADDY, H_FRAME_TOP + 34, H_NOTE_W, 84,
     'Same split, different mechanism.  Here nothing is measured and nothing is proved to anyone: what keeps one\n'
     'process out of another\'s files is the uid it runs as, the groups it is in, and the mode on the file — all of it\n'
     'checkable by nobody but this box.  There is one code tree at /opt/letterlock and one venv, readable by every\n'
     'unit, so the code stripes below say what a unit imports, not what it could open.  Separation of privilege on\n'
     'one machine, not of operator:  the co-signer is a second account here, not a second party.')

note('h_text_note', H_CADDY + H_NOTE_W + 30, H_FRAME_TOP + 34, H_NOTE_W, 84,
     'Where a message body can be, on this machine.  The same answer as above and for the same reason: the daemon\n'
     'fetches from Gmail through the proxy, holds the messages in memory for one pass, and writes the reply back as\n'
     'a draft.  Mail does not arrive through Caddy at all — what comes in the front door is the product UI, a push\n'
     'saying which mailbox changed, a Polar event, and the enclave\'s custody traffic.  /opt/letterlock/state holds a\n'
     'spool, a socket and audit rows;  /opt/letterlock/database holds keys, two encrypted documents and a cursor.')

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
      f'Phala dstack CVM  (Intel TDX)  —  {len(roles.ROLES)} containers, '
      f'{len(roles.ROLES)} images, one uid each;  '
      'the partition is measured into RTMR3', '#4f7f5a')

H_BOT = H_LANE_Y + LANE_H + 34
frame('f_host', 30, H_FRAME_TOP, DEST_X + DEST_W + 70, H_BOT,
      'Hetzner box  hezner.morganrivers.com  —  the same partition in systemd accounts, '
      'groups and file modes;  one machine, six units, three timers, one ingress', '#62778f')

BG.append(emit_box('b_inner', E_C0 - 26, CARDS_TOP - 42,
                   E_C3 + CARD_W + 26 - (E_C0 - 26), E_CARD_BOT + 40 - (CARDS_TOP - 42),
                   'network  inner   (internal: true — docker installs no route off the host, '
                   'so every container holding data reaches the internet only through egress '
                   'and is reached only through ingress)',
                   BAND + 'fillColor=#dff0e0;align=left;spacingLeft=14;'))
for i, (bx0, bx1) in enumerate(((E_C0 - 13, E_C0 + CARD_W + 13), (E_C3 - 13, E_C3 + CARD_W + 13))):
    BG.append(emit_box(f'b_edge{i}', bx0, CARDS_TOP - 14, bx1 - bx0, E_CARD_BOT + 26 - (CARDS_TOP - 14),
                       'network  edge   (an ordinary bridge with a route off the host: '
                       'the two containers that hold nothing)'
                       if i == 0 else 'network  edge',
                       BAND_LINE + 'strokeColor=#b8823c;fontColor=#8a5f21;'
                       + ('align=left;spacingLeft=10;' if i == 0 else '')))

# ------------------------------------------------------------------ legend ---
LEG_Y = H_BOT + 26
LEG_W = DEST_X + DEST_W + 40 - 30
BG.append(emit_box('legend', 30, LEG_Y, LEG_W, 138,
                   'Reading this diagram', FRAME + 'strokeColor=#8d9aa8;fontColor=#46566a;dashed=0;'))
LEG = [
    ('IN row', IN_ROW, None, 'one inbound interface;  arrows land on the row, not on the box'),
    ('OUT row', OUT_ROW, None, 'one outbound interface;  hover any row or any arrow for what it is'),
    ('code stripe', CARRY_ST + CARRY_KIND['code'], None,
     'which repository files this container carries;  hover for the whole list'),
    ('pypi stripe', CARRY_ST + CARRY_KIND['pypi'], None,
     'which third-party packages its own code imports, out of the shared venv'),
    ('mail text stripe', CARRY_ST + CARRY_KIND['content'], None,
     'what this container can see of a message body'),
    ('volume / socket', STORE + 'align=center;spacingLeft=0;', None,
     'what the interfaces on either side of it actually share'),
    ('carries message text', None, 'text', 'a connection a message body, or something written from one, crosses'),
    ('CONNECT  (enforced)', None, 'net', 'the caller has no route off the host except the proxy'),
    ('unix socket', None, 'ipc', 'AF_UNIX;  the file mode and SO_PEERCRED are the grant'),
    ('filesystem', None, 'file', 'a volume or a file;  the mode and the group are the grant'),
    ('split custody', None, 'cross', 'the one interface that leaves the machine it is drawn on'),
]
for i, (name, boxst, ekind, why) in enumerate(LEG):
    col, row = i // 6, i % 6
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

# ---------------------------------------------------------------- glossary ---
# The same definitions the tooltips append, in one place, for a reader who wants
# them without hovering. Every term of art on this page is here; if a box uses a
# word that is not, the word is the bug.
GLOS_Y = LEG_Y + 158
GLOS_COLS = 3
GLOS_ROWS = -(-len(GLOSSARY) // GLOS_COLS)
GLOS_H = 34 + GLOS_ROWS * 13
BG.append(emit_box('glossary', 30, GLOS_Y, LEG_W, GLOS_H,
                   'Every term of art on this page',
                   FRAME + 'strokeColor=#8d9aa8;fontColor=#46566a;dashed=0;'))
GLOS_CW = int((LEG_W - 40) / GLOS_COLS)
for i, (term, meaning) in enumerate(sorted(GLOSSARY.items(), key=lambda kv: kv[0].lower())):
    col, row = i // GLOS_ROWS, i % GLOS_ROWS
    BG.append(emit_box(f'glost{i}', 50 + col * GLOS_CW, GLOS_Y + 28 + row * 13,
                       104, 12, term,
                       'rounded=0;html=1;fillColor=none;strokeColor=none;align=left;'
                       'spacingLeft=0;fontSize=8;fontStyle=1;fontColor=#25313d;' + MONO))
    BG.append(emit_box(f'glosd{i}', 156 + col * GLOS_CW, GLOS_Y + 28 + row * 13,
                       GLOS_CW - 118, 12, meaning,
                       'rounded=0;html=1;fillColor=none;strokeColor=none;align=left;'
                       'spacingLeft=0;fontSize=8;fontColor=#5b6675;'))

BG.insert(0, emit_box('title', 30, 26, 1200, 46,
                      'Letterlock — containers and their interfaces',
                      'rounded=0;html=1;fillColor=none;strokeColor=none;align=left;spacingLeft=6;'
                      'verticalAlign=middle;fontSize=24;fontStyle=1;fontColor=#25313d;'))
BG.insert(1, emit_box('subtitle', 30, 62, 1800, 20,
                      'What each container holds, what goes into it and what comes out of it.  '
                      'Every row and every arrow says what it is in its tooltip, and defines '
                      'the terms it uses.',
                      'rounded=0;html=1;fillColor=none;strokeColor=none;align=left;spacingLeft=6;'
                      'verticalAlign=middle;fontSize=11;fontColor=#5b6675;'))

PAGE_W = DEST_X + DEST_W + 110
PAGE_H = int(GLOS_Y + GLOS_H + 40)
OUT = os.path.join(HERE, 'interfaces.drawio')
with open(OUT, 'w', encoding='utf-8') as fh:
    fh.write(wrap_mxfile(BG + MID + FG, 'interfaces', 'letterlock-interfaces',
                         page_w=PAGE_W, page_h=PAGE_H))
print(f'wrote {OUT}: {len(REG)} cells, {len(MID)} edges, {PAGE_W} x {PAGE_H}')
