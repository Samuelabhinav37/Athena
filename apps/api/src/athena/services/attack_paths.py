import uuid
from dataclasses import dataclass
from typing import Any

from neo4j import GraphDatabase
from neo4j.exceptions import Neo4jError
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from athena.config import Settings
from athena.models import EffectiveEntitlement


class AttackPathError(RuntimeError):
    pass


@dataclass(frozen=True)
class GraphNode:
    id: str
    kind: str
    label: str


@dataclass(frozen=True)
class GraphEdge:
    source_id: str
    target_id: str
    relationship: str
    entitlement_id: str
    privileged: bool


@dataclass(frozen=True)
class GraphProjection:
    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]


@dataclass(frozen=True)
class AttackPath:
    nodes: tuple[GraphNode, ...]
    relationships: tuple[str, ...]


def build_projection(session: Session) -> GraphProjection:
    entitlements = session.scalars(
        select(EffectiveEntitlement)
        .options(selectinload(EffectiveEntitlement.provenance_edges))
        .where(EffectiveEntitlement.active.is_(True))
    ).all()
    nodes: dict[str, GraphNode] = {}
    edges: dict[tuple[str, str, str, str], GraphEdge] = {}
    for entitlement in entitlements:
        for edge in entitlement.provenance_edges:
            source_id, target_id = str(edge.from_id), str(edge.to_id)
            nodes[source_id] = GraphNode(source_id, edge.from_type, edge.from_label)
            nodes[target_id] = GraphNode(target_id, edge.to_type, edge.to_label)
            graph_edge = GraphEdge(
                source_id=source_id,
                target_id=target_id,
                relationship=edge.relationship_type,
                entitlement_id=str(entitlement.id),
                privileged=entitlement.permission.privileged,
            )
            edges[(source_id, target_id, edge.relationship_type, str(entitlement.id))] = graph_edge
    return GraphProjection(tuple(nodes.values()), tuple(edges.values()))


class Neo4jAttackPathAdapter:
    def __init__(self, settings: Settings) -> None:
        if not settings.neo4j_enabled or not settings.neo4j_password.get_secret_value():
            raise AttackPathError("Neo4j attack-path analysis is not configured")
        self.database = settings.neo4j_database
        self.driver = GraphDatabase.driver(
            settings.neo4j_url,
            auth=(settings.neo4j_user, settings.neo4j_password.get_secret_value()),
        )

    def __enter__(self) -> "Neo4jAttackPathAdapter":
        self.driver.verify_connectivity()
        return self

    def __exit__(self, *_: object) -> None:
        self.driver.close()

    def project(self, projection: GraphProjection) -> dict[str, int]:
        try:
            with self.driver.session(database=self.database) as graph:
                graph.execute_write(self._write_projection, projection)
        except Neo4jError as error:
            raise AttackPathError("Neo4j projection failed") from error
        return {"nodes": len(projection.nodes), "edges": len(projection.edges)}

    @staticmethod
    def _write_projection(transaction: Any, projection: GraphProjection) -> None:
        transaction.run(
            "UNWIND $nodes AS node MERGE (n:AthenaNode {id: node.id}) "
            "SET n.kind = node.kind, n.label = node.label",
            nodes=[node.__dict__ for node in projection.nodes],
        ).consume()
        transaction.run(
            "UNWIND $edges AS edge MATCH (a:AthenaNode {id: edge.source_id}) "
            "MATCH (b:AthenaNode {id: edge.target_id}) "
            "MERGE (a)-[r:ATHENA_EDGE {entitlement_id: edge.entitlement_id, "
            "relationship: edge.relationship}]->(b) "
            "SET r.privileged = edge.privileged",
            edges=[edge.__dict__ for edge in projection.edges],
        ).consume()

    def find_privileged_paths(
        self, identity_id: uuid.UUID, *, max_depth: int = 6, limit: int = 25
    ) -> list[AttackPath]:
        if not 1 <= max_depth <= 8 or not 1 <= limit <= 100:
            raise ValueError("Attack-path bounds are invalid")
        query = (
            f"MATCH p=(start:AthenaNode {{id: $identity_id}})-[:ATHENA_EDGE*1..{max_depth}]"
            "->(target:AthenaNode {kind: 'resource'}) "
            "WHERE any(edge IN relationships(p) WHERE edge.privileged = true) "
            "RETURN [node IN nodes(p) | "
            "{id: node.id, kind: node.kind, label: node.label}] AS nodes, "
            "[edge IN relationships(p) | edge.relationship] AS relationships "
            "ORDER BY length(p), target.label LIMIT $limit"
        )
        try:
            records, _, _ = self.driver.execute_query(
                query,
                identity_id=str(identity_id),
                limit=limit,
                database_=self.database,
                routing_="r",
            )
        except Neo4jError as error:
            raise AttackPathError("Neo4j attack-path query failed") from error
        return [
            AttackPath(
                nodes=tuple(GraphNode(**node) for node in record["nodes"]),
                relationships=tuple(record["relationships"]),
            )
            for record in records
        ]
