//! # BreachFrame engine
//!
//! Offline security analysis of configuration artifacts:
//!
//! * [`environment`] — declarative graphs of identities, services, APIs, agents and resources with access policies.
//! * [`rbac`] — Kubernetes RBAC auditing.
//! * [`iam`] — AWS IAM policy auditing.
//! * [`mcp`] — MCP server configuration auditing (static; nothing is executed).
//! * [`policy`] — path-based policy evaluation over the merged graph.
//! * [`simulate`] — blast-radius simulation over the graph (model only).
//! * [`compare`] — before/after comparison.
//! * [`report`] — self-contained HTML and JSON reports.
//! * [`labs`] — built-in vulnerable/fixed training scenarios.
//!
//! The engine performs no network I/O and never executes content from artifacts.

pub mod analyze;
pub mod compare;
pub mod environment;
pub mod iam;
pub mod input;
pub mod labs;
pub mod mcp;
pub mod model;
pub mod policy;
pub mod rbac;
pub mod report;
pub mod secrets;
pub mod simulate;
pub mod util;

pub use analyze::{analyze, analyze_artifact, ArtifactInput, ENGINE_VERSION};
pub use model::*;
