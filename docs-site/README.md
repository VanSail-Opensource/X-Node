# Static API documentation

Build the complete documentation site from the repository root:

```sh
python3 scripts/build_docs.py
```

The output is `docs-site/dist/`. It contains plain HTML, CSS and JavaScript, documentation downloads, JSON schemas and configuration examples. No package installation, CDN, server application, account credentials or environment variables are required. The builder uses only the Python standard library and fails when a required source is missing.

For a local preview:

```sh
python3 -m http.server 8080 --directory docs-site/dist
```

Open `http://localhost:8080`. Hash-based navigation also works when hosted below a path. Search, page links, code copying and keyboard navigation run entirely in the browser. The site does not connect to a master or collect visitor data.

## Cloudflare Pages

Create a Pages project connected to `VanSail-Opensource/X-Node`, select the `main` production branch and use these settings:

| Setting | Value |
| --- | --- |
| Framework preset | None |
| Root directory | Repository root (leave empty) |
| Build command | `python3 scripts/build_docs.py` |
| Build output directory | `docs-site/dist` |

Python is the only build requirement. Pages serves the generated `_headers` file, including a restrictive content security policy. No Pages Functions, Workers, bindings or secrets are needed. This change prepares the site; it does not create a Cloudflare deployment.

Cloudflare documents these settings in its [build configuration guide](https://developers.cloudflare.com/pages/configuration/build-configuration/) and includes Python in its [Pages build image](https://developers.cloudflare.com/pages/configuration/build-image/).

## Source of truth

The builder consumes `docs/protocol.md`, `docs/features.md`, `docs/migration.md`, `docs/release-notes.md`, OpenAPI, AsyncAPI, every schema under `docs/schemas/` and every file under `examples/`. Configuration field tables are generated from the schema. `reference.json` adds explanations and examples for individual messages and commands; update it whenever the wire contract changes. The builder checks that master message and command documentation covers the published contract, and validates example JSON against the master schema when the repository schema-check dependencies are available.

`index.html`, `style.css` and `app.js` are the site shell and browser behavior. Build output is ignored; deploy the output directory after building it.
