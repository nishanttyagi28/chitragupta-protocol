# Causal Effect Graphs

KarmaSakshi schema 1.x can bind several sealed effects into a portable,
signed causal directed acyclic graph (DAG). This makes relationships such as
“verify the ledger after refunding the invoice” independently inspectable
instead of relying on the unsigned `parent_manifest_id` hint.

Each `CausalLink` signs the exact parent manifest hash, child manifest hash,
relationship, link identifier and creation time. A `CausalEffectGraph`
canonicalizes node and link ordering, calculates a deterministic graph hash,
and rejects missing endpoints, self-links, duplicate identifiers, cycles,
graphs above 256 nodes, and dependency paths deeper than 32 nodes.

The Action Passport records the graph ID and hash, all causal ancestors of the
passport's manifest, and whether every link signature verified against the
supplied keyring. The HTTP API supports `POST /causal-graphs` and
`GET /causal-graphs/{graph_id}`.

## Security boundary

This first version is proof metadata. It does **not** automatically propagate
authorization, revocation, policy, or failure state across causal links. Every
node remains an independently sealed and authorized consequential effect.
Applications must not treat graph membership as permission to execute a child.
Execution-order and parent-state enforcement belong to a later, explicitly
versioned graph-policy layer.

The API's default graph repository is process-local and therefore suitable for
the reference service only. Durable cross-process graph storage is deferred to
the durable lifecycle-storage phase.
