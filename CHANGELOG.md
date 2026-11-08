# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Analysis engine: environment graphs with deny-path policies, Kubernetes RBAC
  (RBAC-001…023), AWS IAM (IAM-001…006), MCP configurations (MCP-001…010),
  secret detection with redaction, risk score, blast-radius simulation,
  before/after comparison.
- Desktop app (Tauri 2): dashboard, projects with artifact import and MCP config
  discovery, attack-path visualizer, permission auditor, MCP analyzer, four
  training labs, before & after view, findings manager with workflow status and
  notes, HTML/JSON report export, command palette and keyboard shortcuts.
- `breachframe` CLI with `--fail-on` for CI pipelines.
- CI workflow (lint, typecheck, unit tests, Rust tests on three OSes, Windows
  E2E, installer bundles) and a manually approved, draft-only release workflow
  with SHA-256 checksums.
