# ASTM F3532 Standard Adapter - Phase 1

## Scope

Phase 1 establishes two foundations:

1. Standard knowledge layer: import the `f3532_model/csv` clause database into Neo4j.
2. F3532 01/02 input layer: preview and commit Excel-derived rows into ASTRA graph facts.

The implementation follows:

- `ASTRA_F3532条款数据库集成实施方案.md`
- `F3532_model_与老师MD校核表.xlsx`

## Standard Knowledge Model

Neo4j labels:

- `StandardKnowledgeBase`
- `StandardClause`
- `StandardArtifactType`
- `StandardArtifactField`
- `StandardPipelineStage`
- `StandardMapping`

Core relationships:

- `(:StandardClause)-[:PARENT_OF]->(:StandardClause)`
- `(:StandardClause)-[:REFERENCES|TRIGGERS|ITERATES_WITH|DEPENDS_ON|TAILORS|DEFINES|CHECKS|PRODUCES]->(:StandardClause)`
- `(:StandardArtifactType)-[:DERIVED_FROM]->(:StandardClause)`
- `(:StandardArtifactField)-[:BELONGS_TO]->(:StandardArtifactType)`
- `(:StandardArtifactField)-[:TRACE_TO]->(:StandardClause)`
- `(:StandardMapping)-[:MAPS_CLAUSE]->(:StandardClause)`
- `(:StandardMapping)-[:MAPS_TO]->(business node)`

## Backend Endpoints

- `POST /standard/f3532/import`
- `GET /standard/f3532/summary`
- `GET /standard/f3532/clauses?section=6.2`
- `GET /standard/f3532/artifacts`
- `GET /standard/f3532/mappings`
- `POST /standard/f3532/mappings`
- `POST /imports/f3532-input/preview`
- `POST /imports/f3532-input/commit`

## Local Import Command

```bash
npm run standard:f3532:import
```

Optional custom CSV directory:

```bash
npm run standard:f3532:import -w @attackgraph/backend -- E:\document\airness\standardClause\f3532_model\csv
```

## 01/02 Input Mapping

| F3532 input | ASTRA target | Notes |
|---|---|---|
| 01/边界接口 | `BoundaryInterface` | BI ids normalize to `BI1`, `BI2`, ... |
| 01/边界数据流 | `AssetNode` with `business_id=BDFx` | Creates `BoundaryInterface -[:CARRIES_FLOW]-> BDF asset` through existing commit logic. |
| 01/系统间接口 | `AssetEdge` between generated `SYS-*` endpoints | Producer/Consumer system endpoints are created as internal terminal assets. |
| 01/系统间数据流 | `SystemDataFlow` | Validates `对应系统间接口编号`; stores SI reference in description for phase 2. |
| 02/威胁主体 | `ThreatActor` | Supports external/internal/third-party mapping. |
| 02/安保边界 | `TrustBoundary` | Extracts `BIx` and `TA-*` references from free text. |

The first downstream query target is:

```text
TrustBoundary -> HAS_INTERFACE -> BoundaryInterface -> CARRIES_FLOW -> BDF AssetNode
```

This is the data path needed for the phase 2/3 `03 边界数据流-安保边界对照表` generation.
