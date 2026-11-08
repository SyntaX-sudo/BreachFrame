# Architecture

BreachFrame is a Rust workspace with a React front end, packaged by Tauri 2.
Users install a single native application: there is no Python, Node.js or
server to install, and nothing listens on the network.

```
┌──────────────────────────── Desktop app (src-tauri) ────────────────────────────┐
│                                                                                  │
│  React + TypeScript UI (src/)                                                    │
│   views ─ components ─ lib/api.ts ──invoke()──┐                                  │
│                                               │  Tauri IPC (typed commands)      │
│  commands.rs  ── thin adapters, Mutex<Connection> ◄┘                             │
│      │                                                                           │
│  service.rs   ── projects, artifacts, analyses, finding lifecycle, reports       │
│      │                         │                                                 │
│  db.rs (SQLite, migrations)    │        discovery.rs (lists known MCP config     │
│                                │        paths that exist; never reads others)    │
└────────────────────────────────┼─────────────────────────────────────────────────┘
                                 ▼
             breachframe-engine (crates/engine): pure library, no I/O
   input ─► detect ─► environment | rbac | iam | mcp ─► Graph + Findings
                                   policy (BFS paths) ─► analyze (merge, score)
                     simulate · compare · report (HTML/JSON) · labs
                                 ▲
             breachframe CLI (crates/cli): same engine, for CI pipelines
```

## Layers

| Layer | Path | Responsibility |
|-------|------|----------------|
| Engine | `crates/engine` | Parsing, validation, graph building, rules, policy evaluation, risk score, simulation, comparison, report rendering, built-in labs. It never touches the filesystem or network and never executes anything, so it is fully unit-testable. |
| CLI | `crates/cli` | `breachframe analyze` for scripts and CI (`--fail-on high` exits with code 2). |
| Storage + services | `src-tauri/src/service.rs`, `db.rs` | SQLite schema (`PRAGMA user_version` migrations), import with size/type checks and SHA-256 de-duplication, transactional analysis runs, finding reconciliation, report export. |
| OS integration | `src-tauri/src/lib.rs`, `commands.rs`, `discovery.rs` | Window, dialogs, app-data directory, IPC commands. |
| UI | `src/` | Views, interactive graphs (React Flow + dagre layout), charts, command palette, shortcuts. All data comes from IPC; when the backend is missing (e.g. the page opened in a browser) the UI says so and shows no fake data. |

## Data model

- **Graph**: nodes (`kind`, `label`, `attributes`) and directed edges
  (`relation`, `permissions`). An edge `a → b` means *a can reach, act as, or
  access b*. Each artifact produces a partial graph, and the partials are merged
  per analysis.
- **Finding**: `ruleId`, severity, category, title, description, impact,
  recommendation, evidence list, involved nodes, optional path. Its `id` is a
  stable fingerprint.
- **Risk score**: `100 × (1 − Π(1 − wᵢ))` over all findings, with weights
  critical 0.35, high 0.20, medium 0.08, low 0.03, info 0. One critical finding
  gives 35. The score approaches 100 as findings accumulate and is 0 only when
  nothing above *info* remains.

## Finding lifecycle (per project)

Findings are stored by fingerprint (`UNIQUE(project_id, fingerprint)`):

| Event | Effect |
|-------|--------|
| First seen | inserted as `open`, `present = 1` |
| Seen again | evidence refreshed. Analyst status and notes are kept. |
| Missing from the latest analysis | `present = 0`. `open`/`in_progress` become `resolved`. |
| Reappears after `resolved` | reopened as `open` |
| Analyst sets `accepted_risk` / `false_positive` | kept across re-runs |

## Simulation

The *blast-radius* simulation is a breadth-first expansion over the model from a
chosen start node, replayed hop by hop in the UI. It is labelled
"Model-based simulation" everywhere it appears. It only reads the graph built
from your files. No real system, credential or network is touched.

The training labs are bundled YAML scenarios (vulnerable and fixed variants)
analyzed by the same engine.

## Security measures

- **Content Security Policy**: `script-src 'self'`, `object-src 'none'`. The
  only network target is the Tauri IPC endpoint.
- **Report preview**: shown in a sandboxed `iframe` with no script permission.
  Exported HTML contains no JavaScript and has its own CSP meta tag, and every
  value in it is HTML-escaped.
- **Input**: limits as described in [environment-format.md](environment-format.md#validation-and-limits).
  Imports from disk accept only regular files ≤ 5 MiB, and files are read once
  and stored in SQLite.
- **Secrets**: credential values are redacted before they reach findings,
  graphs, the database or reports.
- **No execution**: commands in MCP configs are parsed as text only.
- **Remote debugging**: the WebView2 DevTools port used by the E2E tests is
  compiled only into debug builds (`cfg(debug_assertions)`) and requires an
  explicit environment variable.

## Data location

| OS | Database |
|----|----------|
| Windows | `%APPDATA%\dev.breachframe.app\breachframe.db` |
| macOS | `~/Library/Application Support/dev.breachframe.app/breachframe.db` |
| Linux | `~/.local/share/dev.breachframe.app/breachframe.db` |

Set `BREACHFRAME_DATA_DIR` to use another directory (portable mode, tests).
Uninstalling the app does not delete this directory.
