# Environment file format (v1)

An *environment file* describes a system as a directed graph of principals,
services, APIs, MCP agents, tools and protected resources, plus **policies** that
state which access paths must not exist. BreachFrame finds every policy
violation as a concrete shortest path through the graph.

Environment files are YAML or JSON. They are recognised by the top-level key
`breachframe: 1`. A complete example lives in
[`examples/environment/support-agent-platform.yaml`](../examples/environment/support-agent-platform.yaml).

```yaml
breachframe: 1
name: Orders platform            # optional, informational
description: ...                 # optional
nodes:   [ ... ]
edges:   [ ... ]
policies: [ ... ]
```

## Nodes

| Field        | Type   | Required | Notes |
|--------------|--------|----------|-------|
| `id`         | string | yes      | Unique, max 512 chars. Convention: `kind:name` (e.g. `svc:orders`). |
| `kind`       | enum   | yes      | `user`, `group`, `role`, `service_account`, `service`, `api`, `agent`, `mcp_server`, `tool`, `resource`, `secret`, `external`. Unknown values become `other`. |
| `label`      | string | no       | Display name. Defaults to the id. |
| `attributes` | map    | no       | Free-form key/values used by policy selectors. |

A node counts as **sensitive** (highlighted in the graph and used as a target by
the blast-radius simulation) when its kind is `secret`, or it has
`sensitivity: high | critical`, or `crown_jewel: true`.

## Edges

An edge `from → to` means *"`from` can reach, act as, or access `to`"*.

| Field         | Type     | Required | Notes |
|---------------|----------|----------|-------|
| `from`, `to`  | string   | yes      | Must reference existing node ids. |
| `relation`    | string   | yes      | Free text (`calls`, `uses`, `reads`, `bound_to`, ...). Can be filtered with `via`. |
| `permissions` | string[] | no       | Shown as evidence, e.g. `["SELECT", "UPDATE"]`. |
| `attributes`  | map      | no       | Informational. |

## Policies

```yaml
policies:
  - id: P-TENANT-01                  # unique; findings get rule id POLICY:P-TENANT-01
    name: Tenants must never reach another tenant's data
    severity: critical               # info | low | medium | high (default) | critical
    description: ...                 # optional
    recommendation: ...              # optional, shown in the finding
    deny:
      from: { attributes: { tenant: a } }
      to:   { attributes: { tenant: b } }
      via:  [calls, forwards, queries]   # optional: only traverse these relations
      maxDepth: 6                         # optional, 1-16 (default 16)
```

A **selector** (`from` / `to`) matches a node when **all** given criteria match:

- `ids` (alias `id`): one id or a list. Exact match.
- `kinds` (alias `kind`): one kind or a list.
- `attributes`: every listed key must be present with an equal value.

An empty selector is rejected. For each matching source node, BreachFrame runs a
breadth-first search and reports the shortest path to each matching target. That
gives one finding per (source, target) pair, capped at 50 per policy. Policies are
evaluated over the **merged graph of every artifact in the project**. A policy in
an environment file can therefore match nodes produced from Kubernetes RBAC,
AWS IAM or MCP configurations in the same project. Their node ids are listed in
[rules.md](rules.md#graph-node-ids).

## Validation and limits

Files are rejected (with an error shown on the artifact, never a crash) when they:

- exceed 5 MiB, are empty or binary, or are not valid UTF-8;
- nest deeper than 64 levels, or contain more than 5000 YAML documents;
- use YAML anchors/aliases (alias-expansion bombs are refused);
- declare duplicate node ids, edges to unknown nodes, empty selectors or a
  `maxDepth` outside 1–16.

Graph-wide limits: 20 000 nodes and 100 000 edges per analysis, and 200 artifacts
per project.
