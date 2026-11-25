#!/usr/bin/env python3
"""Generate the README architecture diagram, one SVG per colour scheme.

Two files rather than one self-switching file: GitHub strips <style> blocks
from inline SVG, so a `prefers-color-scheme` media query inside the document is
silently dropped. The README pairs them with <picture>, which GitHub honours.

A README diagram is studied, not narrated, so it is COMPLETE rather than
minimal: the operator and PoC, the SSM plane that is the only way in, all three
lab nodes (each carrying all three affected JDK trains) with the verdict each is
built to produce, the NAT gateway the nodes reach out through, and the Corretto
archive the pinned JDKs come from.
Run:  python3 make_diagram.py
"""

import os

HERE = os.path.dirname(os.path.abspath(__file__))

# ------------------------------------------------------------------------------
# Geometry and style (shared with the other projects' diagrams)
# ------------------------------------------------------------------------------
NW, NH = 384, 104                          # node width, height
GUTTER = 80                                # between the three node columns
MARGIN = 44
NCOL = 3
COL = [MARGIN + i * (NW + GUTTER) for i in range(NCOL)]
ROW = [40 + i * 200 for i in range(4)]
W = MARGIN * 2 + NW * NCOL + GUTTER * (NCOL - 1)
H = ROW[-1] + NH + 40
TITLE_PX, SUB_PX, EDGE_PX = 26, 17, 16

THEMES = {
    "dark": {
        "bg": "#0d1117", "panel": "#161b22", "text": "#e6edf3",
        "muted": "#8b949e", "line": "#58a6ff", "local": "#39c5bb",
        "purple": "#c39be8", "navy": "#c8d6e8", "blue": "#58a6ff",
        "amber": "#f2c163", "store": "#7ee787", "danger": "#ff6b66",
    },
    "light": {
        "bg": "#ffffff", "panel": "#f6f8fa", "text": "#1f2328",
        "muted": "#59636e", "line": "#0969da", "local": "#137e77",
        "purple": "#8250df", "navy": "#475467", "blue": "#0969da",
        "amber": "#9a6700", "store": "#1a7f37", "danger": "#cf222e",
    },
}

# Lucide icon paths, on a 24-unit grid.
ICONS = {
    "globe": ['<circle cx="12" cy="12" r="10"/>',
              '<path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/>',
              '<path d="M2 12h20"/>'],
    "network": ['<rect x="16" y="16" width="6" height="6" rx="1"/>',
                '<rect x="2" y="16" width="6" height="6" rx="1"/>',
                '<rect x="9" y="2" width="6" height="6" rx="1"/>',
                '<path d="M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3"/>',
                '<path d="M12 12V8"/>'],
    "database": ['<ellipse cx="12" cy="5" rx="9" ry="3"/>',
                 '<path d="M3 5V19A9 3 0 0 0 21 19V5"/>',
                 '<path d="M3 12A9 3 0 0 0 21 12"/>'],
    "key": ['<path d="M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 '
            '1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 '
            '1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z"/>',
            '<circle cx="16.5" cy="7.5" r=".5"/>'],
    "monitor": ['<rect width="20" height="14" x="2" y="3" rx="2"/>',
                '<line x1="8" x2="16" y1="21" y2="21"/>',
                '<line x1="12" x2="12" y1="17" y2="21"/>'],
    "terminal": ['<polyline points="4 17 10 11 4 5"/>',
                 '<line x1="12" x2="20" y1="19" y2="19"/>'],
    "cpu": ['<rect x="4" y="4" width="16" height="16" rx="2"/>',
            '<rect x="9" y="9" width="6" height="6"/>',
            '<path d="M15 2v2"/>', '<path d="M15 20v2"/>', '<path d="M2 15h2"/>',
            '<path d="M2 9h2"/>', '<path d="M20 15h2"/>', '<path d="M20 9h2"/>',
            '<path d="M9 2v2"/>', '<path d="M9 20v2"/>'],
    "shield": ['<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 '
               '13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 '
               '3.81 17 5 19 5a1 1 0 0 1 1 1z"/>'],
}

NODES = {}


def _r(nid):
    x, y = NODES[nid][0], NODES[nid][1]
    return x, y, x + NW, y + NH, x + NW / 2, y + NH / 2


def gutter_y(r):
    return ROW[r] + NH + (ROW[1] - ROW[0] - NH) / 2


# ------------------------------------------------------------------------------
# Layout
# Operator at top, the SSM plane below it (the only way in), the three nodes
# across the middle, and the egress path to the Corretto archive at the bottom.
#
# id: (x, y, colour key, icon, title, subtitle[, "dashed"])
# ------------------------------------------------------------------------------
NODES.update({
    "op":    (COL[1], ROW[0], "navy", "terminal", "Operator + PoC",
              "AWS CLI, and your calif.io PoC"),
    "ssm":   (COL[1], ROW[1], "purple", "key", "AWS SSM",
              "Session Manager / Run Command"),
    # One node per CPU class; each carries all three affected trains (17/21/25).
    # The EXPOSED node has the AVX-512 VBMI instruction the intrinsic needs.
    "vuln":  (COL[1], ROW[2], "danger", "cpu", "vuln-x86",
              "c7i x86 . VBMI . JDK 17+21+25 . EXPOSED"),
    # Two immune nodes — same three vulnerable JDKs, but no VBMI path to fire it.
    "arm":   (COL[0], ROW[2], "store", "shield", "safe-arm",
              "t4g ARM64 . no VBMI . JDK 17+21+25 . safe"),
    "intel": (COL[2], ROW[2], "store", "cpu", "safe-intel",
              "t3 x86 . no VBMI . JDK 17+21+25 . safe"),
    "nat":   (COL[1], ROW[3], "navy", "network", "NAT gateway",
              "egress only - no inbound path exists"),
    "corretto": (COL[2], ROW[3], "local", "database", "Corretto archive",
                 "pinned JDK tarballs, 3 trains (verify)", "dashed"),
})

op, ssm = _r("op"), _r("ssm")
vuln = _r("vuln")
arm, intel = _r("arm"), _r("intel")
nat, cor = _r("nat"), _r("corretto")

# id: (path, colour key, label, label_x, label_y, anchor[, "dashed"])
EDGES = {
    "e_in":   (f"M{op[4]},{op[3]} V{ssm[1] - 5}", "purple",
               "SSM only", op[4] + 14, gutter_y(0) + 6, "start"),
    # SSM fans out to all three nodes; the centre edge carries the label.
    "e_vuln": (f"M{ssm[4]},{ssm[3]} V{vuln[1] - 5}", "purple",
               "exec . verdict", ssm[4] + 14, gutter_y(1) + 6, "start"),
    "e_arm":  (f"M{ssm[4]},{ssm[3]} L{arm[4]},{arm[1] - 5}", "purple",
               "", 0, 0, "middle"),
    "e_intel": (f"M{ssm[4]},{ssm[3]} L{intel[4]},{intel[1] - 5}", "purple",
                "", 0, 0, "middle"),
    "e_eg":   (f"M{vuln[4]},{vuln[3]} V{nat[1] - 5}", "line",
               "egress", vuln[4] + 14, gutter_y(2) + 6, "start"),
    "e_dl":   (f"M{nat[2]},{nat[5]} H{cor[0] - 5}", "local",
               "JDK pull", (nat[2] + cor[0]) / 2, nat[5] - 12, "middle", "dashed"),
}

ALT = ("The operator, running the AWS CLI and the public calif.io proof of "
       "concept, reaches the lab only through AWS SSM - Session Manager and Run "
       "Command - because the nodes have no inbound network path. "
       "SSM drives three nodes in private subnets, and every node installs all "
       "three affected Java trains at once (Corretto 17.0.13, 21.0.13 and 25.0.5), "
       "so the detector must judge every installed JDK. One node is EXPOSED: "
       "vuln-x86, a c7i x86 instance with the AVX-512 VBMI instruction the "
       "vulnerable intrinsic needs, so all three of its JDKs are exposed. The "
       "other two run the same three vulnerable JDKs but are immune because "
       "neither has AVX-512 VBMI: safe-arm, a t4g Graviton ARM64 instance, and "
       "safe-intel, a t3 x86 instance. There is no pre-patched node; patch.sh "
       "upgrades all three trains on a node live to flip it from EXPOSED to not "
       "exposed. The nodes egress through a NAT gateway to pull pinned JDK "
       "tarballs from the Amazon Corretto archive.")

# ------------------------------------------------------------------------------
# Rendering
# ------------------------------------------------------------------------------
from html import escape

FONT = "-apple-system, BlinkMacSystemFont, Segoe UI, Helvetica, Arial, sans-serif"


def node_svg(nid, t):
    x, y, key, icon, title, sub, *opt = NODES[nid]
    title, sub = escape(title), escape(sub)
    colour = t[key]
    dash = ' stroke-dasharray="10 7"' if opt and opt[0] == "dashed" else ""
    scale = 1.25
    isz = 24 * scale
    ix, iy = x + 20, y + (NH - isz) / 2
    tx = x + 20 + isz + 14
    return "".join([
        f'<rect x="{x}" y="{y}" width="{NW}" height="{NH}" rx="10" ry="10" '
        f'fill="{t["panel"]}" stroke="{colour}" stroke-width="2"{dash}/>',
        f'<g transform="translate({ix},{iy}) scale({scale})" fill="none" '
        f'stroke="{colour}" stroke-width="2" stroke-linecap="round" '
        f'stroke-linejoin="round">' + "".join(ICONS[icon]) + "</g>",
        f'<text x="{tx}" y="{y + NH/2 - 4}" font-family="{FONT}" '
        f'font-size="{TITLE_PX}" font-weight="600" fill="{t["text"]}">{title}</text>',
        f'<text x="{tx}" y="{y + NH/2 + 22}" font-family="{FONT}" '
        f'font-size="{SUB_PX}" fill="{t["muted"]}">{sub}</text>',
    ])


def edge_svg(eid, t):
    d, key, label, lx, ly, anchor, *opt = EDGES[eid]
    label = escape(label)
    colour = t[key]
    dash = ' stroke-dasharray="8 6"' if opt and opt[0] == "dashed" else ""
    out = (f'<path d="{d}" fill="none" stroke="{colour}" stroke-width="2"{dash} '
           f'marker-end="url(#a_{eid})"/>')
    if label:
        out += (f'<text x="{lx}" y="{ly}" text-anchor="{anchor}" '
                f'font-family="{FONT}" font-size="{EDGE_PX}" font-weight="600" '
                f'fill="{colour}" stroke="{t["bg"]}" stroke-width="6" '
                f'paint-order="stroke">{label}</text>')
    return out


def build(t):
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
           f'viewBox="0 0 {W} {H}" role="img" aria-label="{ALT}">', "<defs>"]
    for eid, spec in EDGES.items():
        out.append(
            f'<marker id="a_{eid}" viewBox="0 0 10 10" refX="9" refY="5" '
            f'markerWidth="5" markerHeight="5" orient="auto-start-reverse">'
            f'<path d="M0,0 L10,5 L0,10 z" fill="{t[spec[1]]}"/></marker>')
    out.append("</defs>")
    out.append(f'<rect width="{W}" height="{H}" fill="{t["bg"]}"/>')
    for eid in EDGES:
        out.append(edge_svg(eid, t))
    for nid in NODES:
        out.append(node_svg(nid, t))
    out.append("</svg>")
    return "".join(out)


def main():
    for name, theme in THEMES.items():
        path = os.path.join(HERE, f"architecture-{name}.svg")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(build(theme))
        print(f"  architecture-{name}.svg")


if __name__ == "__main__":
    main()
