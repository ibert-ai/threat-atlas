#!/usr/bin/env python3
"""Render docs/CLOUDFLARE-RADAR-TOKEN-GUIDE.md as a self-contained, read-only HTML page.

The macOS build ships the result inside the app so "How to get a token..." opens it in the
customer's browser (read-only, same on every Mac). No third-party packages, no network, no
scripts in the output. Supports the Markdown the guide uses: headings, paragraphs, block
quotes, bullet and numbered lists (with indented continuation, including tables), pipe
tables, **bold**, *italic*, `code`, [text](url) and <url> links.

Usage: python3 -I scripts/render-token-guide.py SOURCE.md OUTPUT.html
"""
import html
import re
import sys

CSS = """
:root { color-scheme: light dark; --bg:#fff; --fg:#1d1d1f; --muted:#5f6368; --line:#d9dce1;
  --accent:#0a7c8c; --note:#eef7f8; --code:#f2f3f5; }
@media (prefers-color-scheme: dark) { :root { --bg:#0b0f14; --fg:#e8eaed; --muted:#9aa0a6;
  --line:#2c333b; --accent:#40d6e6; --note:#10232a; --code:#1a2028; } }
body { background:var(--bg); color:var(--fg); margin:0;
  font:16px/1.55 -apple-system, BlinkMacSystemFont, "Helvetica Neue", sans-serif; }
main { max-width:760px; margin:0 auto; padding:32px 20px 64px; }
h1 { font-size:1.9rem; line-height:1.2; margin:0 0 16px; }
h2 { font-size:1.3rem; margin:36px 0 10px; padding-top:12px; border-top:1px solid var(--line); }
a { color:var(--accent); }
code { background:var(--code); padding:1px 5px; border-radius:4px; font-size:.92em; }
blockquote { margin:16px 0; padding:10px 16px; background:var(--note);
  border-left:4px solid var(--accent); border-radius:4px; }
blockquote p { margin:4px 0; }
li { margin:6px 0; }
table { border-collapse:collapse; margin:10px 0; }
th, td { border:1px solid var(--line); padding:6px 10px; text-align:left; vertical-align:top; }
th { background:var(--code); }
footer { margin-top:40px; color:var(--muted); font-size:.85rem; }
"""


def inline(text):
    out, pos = [], 0
    pattern = re.compile(r"`([^`]+)`|<(https?://[^>\s]+)>|\[([^\]]+)\]\((https?://[^)\s]+)\)")
    for m in pattern.finditer(text):
        out.append(emphasis(html.escape(text[pos:m.start()], quote=False)))
        if m.group(1) is not None:
            out.append("<code>" + html.escape(m.group(1), quote=False) + "</code>")
        elif m.group(2) is not None:
            url = html.escape(m.group(2))
            out.append(f'<a href="{url}">{url}</a>')
        else:
            out.append(f'<a href="{html.escape(m.group(4))}">{emphasis(html.escape(m.group(3), quote=False))}</a>')
        pos = m.end()
    out.append(emphasis(html.escape(text[pos:], quote=False)))
    return "".join(out)


def emphasis(text):
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    return re.sub(r"(?<![\w*])\*(?!\s)(.+?)(?<!\s)\*(?![\w*])", r"<em>\1</em>", text)


def table(rows):
    cells = [[c.strip() for c in r.strip().strip("|").split("|")] for r in rows]
    head, body = cells[0], cells[2:]
    out = ["<table><thead><tr>"] + [f"<th>{inline(c)}</th>" for c in head] + ["</tr></thead><tbody>"]
    for r in body:
        out += ["<tr>"] + [f"<td>{inline(c)}</td>" for c in r] + ["</tr>"]
    return "".join(out + ["</tbody></table>"])


LIST_ITEM = re.compile(r"^(\s*)(?:([-*])|(\d+)\.)\s+(.*)$")


def blocks(lines):
    out, i = [], 0
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            i += 1
            continue
        if line.startswith("#"):
            level = len(line) - len(line.lstrip("#"))
            out.append(f"<h{level}>{inline(line[level:].strip())}</h{level}>")
            i += 1
        elif line.startswith(">"):
            quote = []
            while i < len(lines) and lines[i].startswith(">"):
                quote.append(lines[i][1:].removeprefix(" "))
                i += 1
            out.append("<blockquote>" + blocks(quote) + "</blockquote>")
        elif line.lstrip().startswith("|"):
            rows = []
            while i < len(lines) and lines[i].lstrip().startswith("|"):
                rows.append(lines[i])
                i += 1
            out.append(table(rows))
        elif LIST_ITEM.match(line) and not LIST_ITEM.match(line).group(1):
            ordered = LIST_ITEM.match(line).group(3) is not None
            items = []
            while i < len(lines):
                m = LIST_ITEM.match(lines[i])
                if m and not m.group(1) and (m.group(3) is not None) == ordered:
                    items.append([m.group(4)])
                    i += 1
                elif lines[i].startswith((" ", "\t")) and items:
                    items[-1].append(lines[i].strip())
                    i += 1
                elif not lines[i].strip() and items:
                    nxt = next((l for l in lines[i + 1:] if l.strip()), "")
                    nm = LIST_ITEM.match(nxt)
                    if nxt.startswith((" ", "\t")) or (nm and not nm.group(1) and (nm.group(3) is not None) == ordered):
                        items[-1].append("")
                        i += 1
                    else:
                        break
                else:
                    break
            tag = "ol" if ordered else "ul"
            rendered = []
            for item in items:
                inner = blocks(item)
                if inner.count("<p>") == 1 and inner.startswith("<p>") and inner.endswith("</p>"):
                    inner = inner[3:-4]
                rendered.append(f"<li>{inner}</li>")
            out.append(f"<{tag}>" + "".join(rendered) + f"</{tag}>")
        else:
            para = []
            while i < len(lines) and lines[i].strip() and not lines[i].startswith(("#", ">", "|")) \
                    and not LIST_ITEM.match(lines[i]):
                para.append(lines[i].strip())
                i += 1
            out.append("<p>" + inline(" ".join(para)) + "</p>")
    return "".join(out)


def main(src, dst):
    lines = open(src, encoding="utf-8").read().splitlines()
    title = next((l.lstrip("#").strip() for l in lines if l.startswith("# ")), "Threat Atlas SOC")
    body = blocks(lines)
    page = (
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        f"<title>{html.escape(title)}</title><style>{CSS}</style></head>\n"
        f"<body><main>{body}<footer>Threat Atlas SOC · Ibert Consulting · "
        "included with the app</footer></main></body></html>\n"
    )
    open(dst, "w", encoding="utf-8").write(page)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__.strip().splitlines()[-1])
    main(sys.argv[1], sys.argv[2])
