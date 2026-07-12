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
- `POST /analysis/f3532/generate-03`
- `GET /reports/f3532/03`

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
| 01/边界数据流 | `AssetNode` with `business_id=BDFx` | Creates `BoundaryInterface -[:CARRIES]-> BDF asset`; `CARRIES_FLOW` is also kept for legacy report compatibility. |
| 01/系统间接口 | `AssetEdge` between generated `SYS-*` endpoints | Producer/Consumer system endpoints are created as internal terminal assets. |
| 01/系统间数据流 | `SystemDataFlow` | Validates `对应系统间接口编号`; stores SI reference in description for phase 2. |
| 02/威胁主体 | `ThreatActor` | Supports external/internal/third-party mapping. |
| 02/安保边界 | `TrustBoundary` | Extracts `BIx` and `TA-*` references from free text. |

The first downstream query target is:

```text
TrustBoundary -> HAS_INTERFACE -> BoundaryInterface -> CARRIES -> BDF AssetNode
```

This is the data path needed for the phase 2/3 `03 边界数据流-安保边界对照表` generation.

## 03 Generation

`POST /analysis/f3532/generate-03` does three things:

1. Reads BDF start points and SDF directed edges from Neo4j.
2. Runs the existing `FpAnalysisService` with type-channel traversal.
3. Persists `FunctionPropagationPath` rows and returns the two F3532 03 tables:
   - `boundary_data_flows.rows`: 边界数据流-安保边界对照表
   - `function_propagation.rows`: 关键数据流传播路径表

The frontend also exposes:

- `生成 F3532 03`: run FP generation and refresh both tables.
- `加载 F3532 03`: read current stored 03 rows without regenerating.
- `导出 03 Excel`: export a two-sheet workbook.

## Verification Checklist

1. Start Neo4j and the backend.
2. Import F3532 01/02 through the frontend panel or call `/imports/f3532-input/commit`.
3. Confirm graph basics:
   - `GET /graph` includes `SB01/SB02/SB03` in `trust_boundaries`.
   - `boundary_interfaces`, BDF-like `asset_nodes`, `system_data_flows`, and `threat_actors` are non-empty.
4. Generate 03:
   - Frontend: click `生成 F3532 03`.
   - API: `POST /analysis/f3532/generate-03` with `{ "group_by": "boundary", "max_hops": 5 }`.
5. Confirm output:
   - `boundary_data_flows.count > 0`
   - `function_propagation.count > 0`
   - rows contain BI/BDF/SDF/function ids.
6. Export 03 Excel from the frontend and inspect the two generated sheets.

## FHA And 04 Generation

FHA is imported before finalizing 04 because the 01 workbook only carries failure-condition references. The authoritative severity and the complete FC inventory come from FHA, including FC rows not currently reached by a data flow.

Neo4j additions:

- `(:FailureCondition)` stores FC id, description, flight phase, original hazard class, mapped severity and probability objective.
- `(:SystemDataFlow)-[:TRACES_TO]->(:FailureCondition)` links the 01 reference column to FHA.
- `(:ThreatCondition)-[:DERIVED_FROM]->(:FailureCondition)` preserves TC-to-FHA traceability.
- `(:ThreatCondition)-[:AFFECTS_FUNCTION]->(:FunctionNode)` records the impacted function when available.
- `(:ThreatScenario)-[:TRIGGERS]->(:ThreatCondition)` records TS-to-TC traceability.

Default hazard-class mapping for the attached AFHA table:

| AFHA class | Default severity |
|---|---|
| I | Catastrophic |
| II | Hazardous |
| III | Major |
| IV | Minor |
| V | NoSafetyEffect |

04 generation rules:

- `single`: generate C, I and A as separate TC candidates.
- `all_non_empty`: generate all seven non-empty CIA combinations.
- Threat-condition descriptions and existing security measures are blank by default.
- Aircraft/system/crew/occupant effects expose common options but remain free-text editable.
- The default attack-path text is `ThreatActor -> FunctionPropagationPath`.
- FHA rows without SDF/function/path coverage remain in the result with `coverage_status=unlinked`.

Endpoints:

- `POST /imports/fha/preview`
- `POST /imports/fha/commit`
- `GET /fha/failure-conditions`
- `GET /analysis/f3532/04/defaults`
- `POST /analysis/f3532/generate-04`
- `POST /analysis/f3532/commit-04`
- `GET /reports/f3532/04`
