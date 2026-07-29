"""Canonical directed acyclic graph of signed causal effect links."""

from __future__ import annotations

import uuid
from collections import defaultdict, deque

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from karmasakshi.canonical.serialize import canonical_hash
from karmasakshi.causal.link import CausalLink, verify_causal_link
from karmasakshi.crypto.keyring import Keyring
from karmasakshi.errors import CausalGraphError

MAX_GRAPH_NODES = 256
MAX_GRAPH_DEPTH = 32


class CausalEffectGraph(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    graph_id: str
    node_manifest_hashes: tuple[str, ...]
    links: tuple[CausalLink, ...]

    @field_validator("node_manifest_hashes")
    @classmethod
    def _nodes(cls, nodes: tuple[str, ...]) -> tuple[str, ...]:
        if not nodes:
            raise ValueError("causal graph requires at least one node")
        if len(nodes) > MAX_GRAPH_NODES:
            raise ValueError(f"causal graph exceeds {MAX_GRAPH_NODES} nodes")
        if len(set(nodes)) != len(nodes):
            raise ValueError("causal graph node hashes must be unique")
        return tuple(sorted(nodes))

    @field_validator("links")
    @classmethod
    def _links(cls, links: tuple[CausalLink, ...]) -> tuple[CausalLink, ...]:
        if len({link.link_id for link in links}) != len(links):
            raise ValueError("causal graph link IDs must be unique")
        return tuple(sorted(links, key=lambda link: link.link_id))

    @model_validator(mode="after")
    def _validate_dag(self) -> CausalEffectGraph:
        nodes = set(self.node_manifest_hashes)
        adjacency: dict[str, list[str]] = defaultdict(list)
        indegree = dict.fromkeys(nodes, 0)
        for link in self.links:
            parent = link.parent_manifest_hash
            child = link.child_manifest_hash
            if parent not in nodes or child not in nodes:
                raise ValueError("every causal link endpoint must exist in graph nodes")
            if parent == child:
                raise ValueError("a manifest cannot causally depend on itself")
            adjacency[parent].append(child)
            indegree[child] += 1

        queue = deque(node for node, degree in indegree.items() if degree == 0)
        depths = dict.fromkeys(nodes, 1)
        visited = 0
        max_depth = 0
        while queue:
            node = queue.popleft()
            depth = depths[node]
            visited += 1
            max_depth = max(max_depth, depth)
            for child in adjacency[node]:
                depths[child] = max(depths[child], depth + 1)
                indegree[child] -= 1
                if indegree[child] == 0:
                    queue.append(child)
        if visited != len(nodes):
            raise ValueError("causal graph must be acyclic")
        if max_depth > MAX_GRAPH_DEPTH:
            raise ValueError(f"causal graph exceeds maximum depth {MAX_GRAPH_DEPTH}")
        return self

    def canonical_hash(self) -> str:
        return canonical_hash(self)

    def roots(self) -> tuple[str, ...]:
        children = {link.child_manifest_hash for link in self.links}
        return tuple(node for node in self.node_manifest_hashes if node not in children)

    def ancestors_of(self, manifest_hash: str) -> tuple[str, ...]:
        if manifest_hash not in self.node_manifest_hashes:
            raise CausalGraphError("manifest hash is not a node in this causal graph")
        parents: dict[str, list[str]] = defaultdict(list)
        for link in self.links:
            parents[link.child_manifest_hash].append(link.parent_manifest_hash)
        seen: set[str] = set()
        queue = deque(parents[manifest_hash])
        while queue:
            node = queue.popleft()
            if node in seen:
                continue
            seen.add(node)
            queue.extend(parents[node])
        return tuple(sorted(seen))

    def verify(self, keyring: Keyring) -> None:
        for link in self.links:
            verify_causal_link(link, keyring)


def build_causal_graph(
    *,
    node_manifest_hashes: tuple[str, ...],
    links: tuple[CausalLink, ...],
    graph_id: str | None = None,
) -> CausalEffectGraph:
    return CausalEffectGraph(
        graph_id=graph_id or str(uuid.uuid4()),
        node_manifest_hashes=node_manifest_hashes,
        links=links,
    )


__all__ = [
    "MAX_GRAPH_DEPTH",
    "MAX_GRAPH_NODES",
    "CausalEffectGraph",
    "build_causal_graph",
]
