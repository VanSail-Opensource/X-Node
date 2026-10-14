#!/usr/bin/env python3
"""Build X-Node's dependency-free static API reference for Cloudflare Pages."""

from __future__ import annotations

import argparse
import html
import json
import re
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "docs-site"
REPO_URL = "https://github.com/VanSail-Opensource/X-Node"


def inline(text: str) -> str:
    """Escape source text before rendering the small supported Markdown subset."""
    text = html.escape(text)
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)

    def link(match: re.Match[str]) -> str:
        label, href = match.groups()
        # Source documents are trusted, but never render executable URL schemes.
        if re.match(r"^(?:javascript|data|vbscript):", href, re.I):
            return label
        if href.startswith(("schemas/", "./schemas/")):
            href = "downloads/" + href.removeprefix("./")
        if href.endswith(".md") and not href.startswith("http"):
            href = "downloads/docs/" + href.split("/")[-1]
        return f'<a href="{href}">{label}</a>'

    return re.sub(r"\[([^]]+)\]\(([^)]+)\)", link, text)


def code_block(code: str, language: str = "json") -> str:
    return (
        '<div class="code-block"><div class="code-toolbar">'
        f'<span>{html.escape(language or "text")}</span>'
        '<button class="copy-button" type="button" aria-label="Copy code">Copy</button>'
        f'</div><pre><code>{html.escape(code.rstrip())}</code></pre></div>'
    )


def markdown(source: str) -> str:
    lines = source.splitlines()
    rendered: list[str] = []
    index = 0
    heading_counts: dict[str, int] = {}
    while index < len(lines):
        line = lines[index].strip()
        if not line:
            index += 1
            continue
        if line.startswith("```"):
            language = line[3:]
            content = []
            index += 1
            while index < len(lines) and not lines[index].strip().startswith("```"):
                content.append(lines[index])
                index += 1
            rendered.append(code_block("\n".join(content), language))
            index += 1
            continue
        heading = re.match(r"^(#{1,6})\s+(.+)$", line)
        if heading:
            level, title = len(heading[1]), heading[2]
            # Page titles are rendered by the shell; source H1s become H2s.
            level = max(2, min(level, 4))
            slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-") or "section"
            count = heading_counts.get(slug, 0)
            heading_counts[slug] = count + 1
            if count:
                slug += f"-{count + 1}"
            rendered.append(f'<h{level} id="{slug}">{inline(title)}</h{level}>')
            index += 1
            continue
        if line.startswith("|") and index + 1 < len(lines) and re.match(r"^\s*\|[\s:|\-]+\|\s*$", lines[index + 1]):
            headers = [v.strip() for v in line.strip("|").split("|")]
            rows = []
            index += 2
            while index < len(lines) and lines[index].strip().startswith("|"):
                cells = [v.strip() for v in lines[index].strip().strip("|").split("|")]
                rows.append("<tr>" + "".join(f"<td>{inline(v)}</td>" for v in cells) + "</tr>")
                index += 1
            rendered.append('<div class="table-wrap"><table><thead><tr>' + "".join(f"<th>{inline(v)}</th>" for v in headers) + "</tr></thead><tbody>" + "".join(rows) + "</tbody></table></div>")
            continue
        bullet = re.match(r"^(?:[-*]|\d+\.)\s+(.+)$", line)
        if bullet:
            ordered = bool(re.match(r"^\d+\.", line))
            tag = "ol" if ordered else "ul"
            items = []
            while index < len(lines):
                item = re.match(r"^(?:[-*]|\d+\.)\s+(.+)$", lines[index].strip())
                if not item:
                    break
                items.append(f"<li>{inline(item[1])}</li>")
                index += 1
            rendered.append(f"<{tag}>" + "".join(items) + f"</{tag}>")
            continue
        paragraph = [line]
        index += 1
        while index < len(lines) and lines[index].strip() and not re.match(r"^(?:#|```|\||[-*]\s|\d+\.\s)", lines[index].strip()):
            paragraph.append(lines[index].strip())
            index += 1
        rendered.append("<p>" + inline(" ".join(paragraph)) + "</p>")
    return "\n".join(rendered)


def schema_type(schema: dict) -> str:
    if "const" in schema:
        return json.dumps(schema["const"])
    value = schema.get("type", "value")
    if value == "array":
        return schema_type(schema.get("items", {})) + "[]"
    if value == "object" and isinstance(schema.get("additionalProperties"), dict):
        return "map<string, " + schema_type(schema["additionalProperties"]) + ">"
    return str(value)


def schema_fields(schema: dict, descriptions: dict[str, str], prefix: str = "") -> str:
    rows = []
    required = set(schema.get("required", []))
    for name, value in schema.get("properties", {}).items():
        key = f"{prefix}{name}"
        description = descriptions.get(key, value.get("description", ""))
        bounds = []
        for field in ("minimum", "maximum", "minItems", "maxItems"):
            if field in value:
                bounds.append(f"{field}: {value[field]}")
        if "enum" in value:
            bounds.append("Allowed: " + ", ".join(str(v) for v in value["enum"]))
        if bounds:
            description += " " + "; ".join(bounds) + "."
        rows.append("<tr>" + f'<td><code>{html.escape(name)}</code></td><td><code>{html.escape(schema_type(value))}</code></td><td>{"Required" if name in required else "Optional"}</td><td>{inline(description.strip())}</td>' + "</tr>")
    return '<div class="table-wrap"><table class="field-table"><thead><tr><th>Field</th><th>Type</th><th>Presence</th><th>Description</th></tr></thead><tbody>' + "".join(rows) + "</tbody></table></div>"


def build(output: Path) -> dict:
    reference = json.loads((SOURCE / "reference.json").read_text(encoding="utf-8"))
    master = json.loads((ROOT / "docs/schemas/master-message.schema.json").read_text(encoding="utf-8"))
    configuration = json.loads((ROOT / "docs/schemas/config.schema.json").read_text(encoding="utf-8"))
    openapi = json.loads((ROOT / "docs/openapi.json").read_text(encoding="utf-8"))
    asyncapi = json.loads((ROOT / "docs/asyncapi.json").read_text(encoding="utf-8"))
    branches = {branch["properties"]["type"]["const"]: branch for branch in master["oneOf"]}
    described = {entry["name"] for entry in reference["messages"]}
    missing = set(branches) - described
    agent_messages = openapi["paths"]["/v1/agents/connect"]["get"]["x-websocket-messages"]["agentToMaster"]
    missing |= set(agent_messages) - described
    commands = branches["command"]["properties"]["data"]["properties"]["name"]["enum"]
    missing_commands = set(commands) - {entry["name"] for entry in reference["commands"]}
    if missing or missing_commands:
        raise ValueError(f"Missing reference descriptions: messages={sorted(missing)}, commands={sorted(missing_commands)}")
    keys = [entry["key"] for entry in reference["guides"]]
    names = [entry["name"] for entry in reference["messages"]]
    command_names = [entry["name"] for entry in reference["commands"]]
    if any(len(values) != len(set(values)) for values in (keys, names, command_names)):
        raise ValueError("Reference contains duplicate guide, message or command names")
    examples_checked = 0
    try:
        from jsonschema import Draft202012Validator
    except ImportError:
        Draft202012Validator = None
    if Draft202012Validator is not None:
        validator = Draft202012Validator(master)
        for entry in reference["messages"]:
            if entry["direction"] == "Master → agent" and "example" in entry:
                validator.validate(entry["example"])
                examples_checked += 1
    if output.resolve() in {ROOT.resolve(), SOURCE.resolve()}:
        raise ValueError("Build output must not replace the repository or source directory")
    output.mkdir(parents=True, exist_ok=True)
    pages: list[dict] = []

    def add(key: str, title: str, group: str, description: str, body: str, **metadata: str) -> None:
        plain = re.sub(r"<[^>]+>", " ", body)
        plain = re.sub(r"\s+", " ", html.unescape(plain))
        pages.append({"key": key, "title": title, "group": group, "description": description, "body": body, "search": plain, **metadata})

    for guide in reference["guides"]:
        add(guide["key"], guide["title"], "Start here", guide["description"], markdown(guide["body"]))

    body = markdown(reference["configuration_intro"])
    body += schema_fields(configuration, reference["fields"])
    for name, field in configuration["properties"].items():
        nested = field
        if field.get("type") == "array":
            nested = field.get("items", {})
        elif "properties" not in field:
            nested = field.get("additionalProperties", {})
        if isinstance(nested, dict) and nested.get("properties"):
            body += f'<h2 id="config-{html.escape(name)}">{html.escape(name)}</h2>'
            body += schema_fields(nested, reference["fields"], name + ".")
            if name == "certificates":
                body += '<h3 id="certificate-config">Certificate profile config</h3>' + schema_fields(nested["properties"]["config"], reference["fields"], "certificates.config.")
    add("configuration", "Remote configuration", "Start here", "Native Xray configuration, managed users, limits and operational policies.", body)

    for entry in reference["messages"]:
        body = markdown(entry["body"])
        if entry["name"] in branches:
            payload = branches[entry["name"]]["properties"]["data"]
            if payload.get("properties") and entry["name"] not in ("state.sync", "config.apply"):
                body += '<h2 id="payload">Payload fields</h2>' + schema_fields(payload, entry.get("fields", {}))
        example = entry.get("example")
        if example is not None:
            body += '<h2 id="example">Example frame</h2>' + code_block(json.dumps(example, indent=2))
        add("messages/" + entry["name"], entry["name"], "Messages", entry["description"], body, direction=entry["direction"], kind="message")

    for entry in reference["commands"]:
        body = markdown(entry["body"])
        if entry.get("fields"):
            rows = "".join(f'<tr><td><code>{html.escape(row[0])}</code></td><td><code>{html.escape(row[1])}</code></td><td>{html.escape(row[2])}</td><td>{inline(row[3])}</td></tr>' for row in entry["fields"])
            body += '<h2 id="arguments">Arguments</h2><div class="table-wrap"><table class="field-table"><thead><tr><th>Field</th><th>Type</th><th>Presence</th><th>Description</th></tr></thead><tbody>' + rows + '</tbody></table></div>'
        frame = {"v": 1, "type": "command", "id": "op-" + entry["name"].replace(".", "-"), "data": {"name": entry["name"], "args": entry.get("args", {})}}
        if Draft202012Validator is not None:
            validator.validate(frame)
            examples_checked += 1
        body += '<h2 id="example">Example request</h2>' + code_block(json.dumps(frame, indent=2))
        add("commands/" + entry["name"], entry["name"], "Commands", entry["description"], body, direction="Master → agent", kind="command")

    for filename, title, description in [
        ("protocol.md", "Protocol guide", "Synchronization, reporting, command lifecycle and operational defaults."),
        ("features.md", "Xray & host capabilities", "Native core settings, transport support and Debian metric collectors."),
        ("migration.md", "Migration", "Move from legacy panel integrations to the WebSocket agent."),
        ("release-notes.md", "Release notes", "Changes and compatibility notes for the current release."),
    ]:
        add("guides/" + filename.removesuffix(".md"), title, "Guides", description, markdown((ROOT / "docs" / filename).read_text(encoding="utf-8")))

    downloads = output / "downloads"
    for directory in ("docs", "schemas", "examples"):
        (downloads / directory).mkdir(parents=True, exist_ok=True)
    for source in sorted((ROOT / "docs").glob("*.md")):
        shutil.copyfile(source, downloads / "docs" / source.name)
    for source in sorted((ROOT / "docs/schemas").glob("*.json")):
        json.loads(source.read_text(encoding="utf-8"))
        shutil.copyfile(source, downloads / "schemas" / source.name)
    for name in ("openapi.json", "asyncapi.json"):
        # Preserve relative JSON Schema references in the downloaded specs.
        shutil.copyfile(ROOT / "docs" / name, downloads / name)
    example_html = ""
    for source in sorted((ROOT / "examples").rglob("*")):
        if not source.is_file():
            continue
        relative = source.relative_to(ROOT / "examples")
        target = downloads / "examples" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        example_html += f'<h2 id="example-{html.escape(source.stem)}">{html.escape(relative.as_posix())}</h2><p><a href="downloads/examples/{html.escape(relative.as_posix())}" download>Download example ↗</a></p>'
        if source.suffix == ".json":
            example_html += code_block(json.dumps(json.loads(source.read_text(encoding="utf-8")), indent=2))
        elif source.suffix in (".py", ".sh", ".md"):
            example_html += code_block(source.read_text(encoding="utf-8"), source.suffix[1:])
    add("examples", "Working examples", "Resources", "Download native remote configurations for master-side snapshot tests.", example_html)
    add("schemas", "Schemas & downloads", "Resources", "Machine-readable contracts for your master implementation.", markdown(reference["downloads_intro"]) + '<h2 id="openapi">OpenAPI</h2>' + code_block(json.dumps(openapi, indent=2)) + '<h2 id="asyncapi">AsyncAPI</h2>' + code_block(json.dumps(asyncapi, indent=2)))
    add("deployment", "Deploy these docs", "Resources", "Publish the static reference with Cloudflare Pages.", markdown((SOURCE / "README.md").read_text(encoding="utf-8")))

    grouped: dict[str, list[dict]] = {}
    for page in pages:
        grouped.setdefault(page["group"], []).append(page)
    navigation = "".join('<div class="nav-group"><h2>' + html.escape(group) + '</h2>' + "".join(f'<a class="nav-link" href="#/{page["key"]}" data-page="{page["key"]}">{html.escape(page["title"])}</a>' for page in items) + '</div>' for group, items in grouped.items())
    shell = (SOURCE / "index.html").read_text(encoding="utf-8")
    shell = shell.replace("<!-- NAVIGATION -->", navigation)
    (output / "index.html").write_text(shell, encoding="utf-8", newline="\n")
    for name in ("style.css", "app.js", "favicon.svg", "_headers"):
        shutil.copyfile(SOURCE / name, output / name)
    payload = json.dumps({"pages": pages, "repo": REPO_URL}, ensure_ascii=False, separators=(",", ":")).replace("<", "\\u003c").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    (output / "data.js").write_text("window.XNODE_DOCS=" + payload + ";\n", encoding="utf-8", newline="\n")
    return {"pages": len(pages), "messages": len(reference["messages"]), "commands": len(reference["commands"]), "schema_validated_examples": examples_checked, "output": str(output)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=SOURCE / "dist", help="Output directory (default: docs-site/dist)")
    args = parser.parse_args()
    print(json.dumps(build(args.output), indent=2))
