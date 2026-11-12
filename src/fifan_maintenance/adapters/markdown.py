"""Parse only with public markdown-it APIs; token lines are diagnostic hints."""
from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
import re
import unicodedata

from markdown_it import MarkdownIt


@dataclass
class Link:
    target: str
    line: int | None = None
    kind: str = "link"


@dataclass
class Document:
    links: list[Link] = field(default_factory=list)
    anchors: set[str] = field(default_factory=set)
    paragraphs: list[tuple[int, str]] = field(default_factory=list)
    unsupported: list[str] = field(default_factory=list)


class _HTML(HTMLParser):
    def __init__(self, result: Document, line: int):
        super().__init__(convert_charrefs=True)
        self.result, self.line = result, line

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        for key in ("href", "src"):
            if attrs.get(key):
                self.result.links.append(Link(attrs[key], self.line + self.getpos()[0] - 1, "html"))
        for key in ("id", "name" if tag == "a" else "id"):
            if attrs.get(key):
                self.result.anchors.add(attrs[key])
        if "srcset" in attrs or "style" in attrs:
            self.result.unsupported.append("HTML srcset/style URL references are not parsed")

    handle_startendtag = handle_starttag


def github_slug(text: str) -> str:
    # GitHub keeps Unicode letters and punctuation such as underscore/hyphen.
    lowered = "".join(c.lower() for c in text)
    return "".join(c for c in lowered if c in "-_ \u200c\u200d" or unicodedata.category(c)[0] in "LM" or unicodedata.category(c) in {"Nd", "Nl", "Pc"}).replace(" ", "-")


def parse(text: str) -> Document:
    result = Document()
    parser = MarkdownIt("commonmark", {"html": True})
    env = {}
    tokens = parser.parse(text, env)
    for reference in [*env.get("references", {}).values(), *env.get("duplicate_refs", [])]:
        lines = reference.get("map", [0])
        result.links.append(Link(reference["href"], lines[0] + 1, "definition"))
    counts: dict[str, int] = {}
    used: set[str] = set()
    for i, token in enumerate(tokens):
        line = token.map[0] + 1 if token.map else 1
        if token.type == "heading_open" and i + 1 < len(tokens):
            inline = tokens[i + 1]
            title = "".join(c.content for c in (inline.children or []) if c.type in {"text", "code_inline", "image"})
            base = github_slug(title)
            number = counts.get(base, 0)
            slug = base if not number else f"{base}-{number}"
            while slug in used:
                number += 1
                slug = f"{base}-{number}"
            counts[base] = number + 1
            used.add(slug)
            result.anchors.add(slug)
        if token.type == "inline":
            if i and tokens[i - 1].type == "paragraph_open":
                result.paragraphs.append((line, "".join(c.content for c in token.children or [] if c.type not in {"code_inline", "html_inline"})))
            for child in token.children or []:
                if child.type == "link_open":
                    result.links.append(Link(child.attrGet("href") or "", line))
                elif child.type == "image":
                    result.links.append(Link(child.attrGet("src") or "", line, "image"))
                elif child.type == "html_inline":
                    _HTML(result, line).feed(child.content)
            # Never interpret code_inline as a reference or unsupported construct.
            visible = " ".join(c.content for c in token.children or [] if c.type == "text")
            if re.search(r"\[[^\]]*\]\([^)]*\)", visible):
                result.unsupported.append("unparsed inline link syntax or blocked URL")
            if re.search(r"\[\[[^\]]+\]\]", visible):
                result.unsupported.append("wiki links have an unknown host-specific syntax")
            if re.search(r"\[[^\]]+\]\s*\[[^\]]*\]", visible):
                result.unsupported.append("unresolved or unsupported reference-style link")
            if re.search(r"^\s*\[[^\]]+\]:\s", visible):
                result.unsupported.append("unparsed reference definition or blocked URL")
        elif token.type == "html_block":
            _HTML(result, line).feed(token.content)
    return result
