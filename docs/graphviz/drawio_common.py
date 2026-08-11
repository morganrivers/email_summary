"""
drawio_common.py — shared primitives for the draw.io diagram generators in this
folder (build_arch_diagrams.py, build_flow_diagram.py, build_interfaces_diagram.py).

The first two lay a node/edge graph out with Graphviz `dot`, then bake the
resulting node positions and routed edge waypoints into an editable .drawio.
The third places every rectangle itself, because a diagram of docked ports has
no graph for `dot` to lay out. What is identical across all three (the pixel
emission of a vertex, of an edge with waypoints, the tooltip encoding and the
mxfile wrapper) lives here so there is a single source of truth; `run_dot` and
`transforms` are used by the two that want a layout engine.

Node dicts use the schema: id, lbl, type, grp, file, desc, robot, w, h.
Edge dicts use: from, to, label, kind, tip.
"""
import subprocess, collections, html

S = 72.0  # Graphviz points-per-inch → draw.io pixel scale


def esc(s):
    return html.escape(str(s), quote=True)


def text(s):
    """Literal text for a cell label or tooltip.

    Two layers escape here, and one is easy to miss. The value lands in an XML
    attribute, and draw.io then renders that value as HTML because every style
    in these diagrams sets html=1. So a `<` needs to survive both: escaped once
    it arrives as a tag draw.io drops silently, which is how `database/<id>/`
    rendered as `database//`."""
    return esc(esc(s))


def lblh(s):
    """Cell label with newlines turned into draw.io <br>."""
    return '&lt;br&gt;'.join(text(x) for x in str(s).split('\n'))


def run_dot(dot_lines):
    """Run Graphviz `dot -Tplain` on the assembled DOT source; return
    (pos, H, edgepts): node centre positions, graph height, per-edge polylines."""
    plain = subprocess.run(['dot', '-Tplain'], input='\n'.join(dot_lines),
                           capture_output=True, text=True).stdout
    pos = {}
    H = 0.0
    edgepts = collections.defaultdict(list)
    for line in plain.splitlines():
        t = line.split()
        if not t:
            continue
        if t[0] == 'graph':
            H = float(t[3])
        elif t[0] == 'node':
            pos[t[1]] = (float(t[2]), float(t[3]))
        elif t[0] == 'edge':
            n = int(t[3]); c = t[4:4 + 2 * n]
            edgepts[(t[1], t[2])].append([(float(c[2 * i]), float(c[2 * i + 1])) for i in range(n)])
    return pos, H, edgepts


def transforms(H):
    """Return (X, Y) functions mapping Graphviz coords → draw.io pixel coords."""
    return (lambda x: x * S), (lambda y: (H - y) * S)


def decl(n):
    """Fixed-size Graphviz node declaration (label drawn later by draw.io)."""
    return f'"{n["id"]}"[width={max(n["w"],70)/72.0:.3f},height={max(n["h"],30)/72.0:.3f},label=""];'


def node_rect(n, pos, X, Y):
    cx, cy = X(pos[n['id']][0]), Y(pos[n['id']][1])
    return (cx - n['w'] / 2, cy - n['h'] / 2, cx + n['w'] / 2, cy + n['h'] / 2)


def overlap(a, b):
    return bool(a) and bool(b) and not (a[2] <= b[0] or b[2] <= a[0] or a[3] <= b[1] or b[3] <= a[1])


GROUP_BOX = ('rounded=1;html=1;dashed=1;dashPattern=6 4;strokeWidth=2;fillColor=none;'
             'verticalAlign=top;align=left;spacingLeft=12;spacingTop=6;fontStyle=1;fontSize=13;')


def group_box(nodes, ids, pos, X, Y, idkey, label, col, cells, pad=22, ptop=30):
    """Append a dotted container box (behind the nodes) enclosing `ids`; return
    its (x0,y0,x1,y1) rect, or None if none of the ids were laid out."""
    ns = [n for n in nodes if n['id'] in ids and n['id'] in pos]
    if not ns:
        return None
    rs = [node_rect(n, pos, X, Y) for n in ns]
    x0 = min(r[0] for r in rs) - pad; y0 = min(r[1] for r in rs) - ptop
    x1 = max(r[2] for r in rs) + pad; y1 = max(r[3] for r in rs) + pad
    st = GROUP_BOX + f'strokeColor={col};fontColor={col};'
    cells.append(f'<mxCell id="{idkey}" value="{esc(label)}" style="{st}" vertex="1" parent="1">'
                 f'<mxGeometry x="{x0:.0f}" y="{y0:.0f}" width="{x1-x0:.0f}" height="{y1-y0:.0f}" as="geometry"/></mxCell>')
    return (x0, y0, x1, y1)


def tip_html(tip):
    """Tooltip markup from plain text: first line bold, newlines as breaks.

    The result is an *attribute value*, so its `<b>`/`<br>` arrive as the
    escaped forms that XML parsing turns back into tags for draw.io to render,
    while any `<` in `tip` stays literal."""
    lines = str(tip).split('\n')
    head = f'&lt;b&gt;{text(lines[0])}&lt;/b&gt;'
    return head + ''.join('&lt;br&gt;' + text(x) for x in lines[1:])


def emit_box(nid, x, y, w, h, label, style, tip_markup=None, link=None):
    """Emit one vertex at an absolute rect. `tip_markup` is already-encoded
    tooltip markup (see tip_html); `link` makes the cell clickable, which
    drawio_to_png promotes to an <a xlink:href> wrapper in the SVG."""
    attrs = f' tooltip="{tip_markup}"' if tip_markup else ''
    if link:
        attrs += f' link="{esc(link)}"'
    return (f'<object label="{lblh(label)}" id="{esc(nid)}"{attrs}>'
            f'<mxCell style="{style}" vertex="1" parent="1">'
            f'<mxGeometry x="{x:.0f}" y="{y:.0f}" width="{w:.0f}" height="{h:.0f}" as="geometry"/>'
            f'</mxCell></object>')


def emit_node(n, style, pos, X, Y):
    """Emit one laid-out node as a labelled draw.io <object> with hover tooltip."""
    x = X(pos[n['id']][0]) - n['w'] / 2
    y = Y(pos[n['id']][1]) - n['h'] / 2
    rb = '🤖 ' if n.get('robot') else ''
    tip = (f'&lt;b&gt;{text(n["file"])}&lt;/b&gt;&lt;br&gt;&lt;br&gt;' if n.get('file') else '') + text(n.get('desc', ''))
    return emit_box(n['id'], x, y, max(n['w'], 70), max(n['h'], 30),
                    rb + n['lbl'], style, tip, n.get('link'))


def emit_edge(eid, e, pts, style):
    """Emit one edge between two cell ids, through explicit pixel waypoints.
    `e` may carry label, tip (plain text) and link."""
    wp = ''
    if pts:
        wp = '<Array as="points">' + ''.join(f'<mxPoint x="{px:.0f}" y="{py:.0f}"/>' for px, py in pts) + '</Array>'
    geom = f'<mxGeometry relative="1" as="geometry">{wp}</mxGeometry>'
    body = (f'<mxCell style="{style}" edge="1" parent="1" '
            f'source="{esc(e["from"])}" target="{esc(e["to"])}">{geom}</mxCell>')
    if e.get('link') or e.get('tip'):
        attrs = f' label="{text(e["label"])}"' if e.get('label') else ''
        if e.get('tip'):
            attrs += f' tooltip="{tip_html(e["tip"])}"'
        if e.get('link'):
            attrs += f' link="{esc(e["link"])}"'
        return f'<object id="{esc(eid)}"{attrs}>{body}</object>'
    val = f' value="{text(e["label"])}"' if e.get('label') else ''
    return (f'<mxCell id="{esc(eid)}"{val} style="{style}" edge="1" parent="1" '
            f'source="{esc(e["from"])}" target="{esc(e["to"])}">{geom}</mxCell>')


def emit_edges(edges, edgepts, X, Y, ebase, ek):
    """Emit every edge with Graphviz routing waypoints; `ek` maps edge kind →
    extra style. Returns a list of mxCell strings."""
    out = []
    used = collections.defaultdict(int)
    for i, e in enumerate(edges):
        key = (e['from'], e['to']); pts = []
        if edgepts[key]:
            idx = min(used[key], len(edgepts[key]) - 1); used[key] += 1
            raw = edgepts[key][idx]
            pts = [(X(px), Y(py)) for px, py in (raw[1:-1] if len(raw) > 2 else [])]
        out.append(emit_edge(f'e{i}', e, pts, ebase + ek.get(e.get('kind'), '')))
    return out


def wrap_mxfile(cells, name, dia_id, page_w=1600, page_h=2400):
    """Wrap emitted cells (already ordered back→front) in the mxfile envelope."""
    return (f'<mxfile host="app.diagrams.net" type="device"><diagram name="{name}" id="{dia_id}">'
            '<mxGraphModel dx="1400" dy="900" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" '
            f'fold="1" page="1" pageScale="1" pageWidth="{page_w}" pageHeight="{page_h}" math="0" shadow="0"><root>'
            '<mxCell id="0"/><mxCell id="1" parent="0"/>' + ''.join(cells) + '</root></mxGraphModel></diagram></mxfile>')
