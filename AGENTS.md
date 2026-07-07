# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## Project Overview

ASTRA (Aviation Semantic Threat Reasoning & Analysis System) — an aviation threat modeling platform based on DO-356A / DO-326A standards. It maintains a Neo4j graph of assets, edges, threat points, and compliance links, runs attack path analysis (DPS scoring), and provides a React review workbench.

## Commands

```bash
# Start Neo4j (Docker)
docker compose up -d

# Install dependencies
npm install

# Start backend (Express + tsx watch mode)
npm run dev

# Start frontend (Vite dev server, separate terminal)
npm run dev:frontend

# Build both
npm run build

# Seed sample DO-356A dataset
npm run seed:sample

# Seed generic example dataset
npm run seed:generic

# Run baseline experiment
npm run exp:do356a:baseline
```

## Architecture

Monorepo with npm workspaces (`apps/*`):

### Backend (`apps/backend/`) — Express + TypeScript (ESM)
- **`src/config/env.ts`** — Env vars (port, Neo4j credentials)
- **`src/db/neo4j.ts`** — Lazy Neo4j driver singleton
- **`src/types/domain.ts`** — Domain types: AssetNode, AssetEdge, ThreatPoint, AttackPath, DO326ALink, GraphChangeSet, GraphSnapshot
- **`src/types/api.ts`** — Zod schemas for request validation (Zod superRefine for cross-field rules)
- **`src/repositories/graphRepository.ts`** — All Neo4j operations: CRUD, constraints, ChangeSet commit (atomic with version conflict detection), seed data, audit log
- **`src/services/analysisService.ts`** — DPS (Dynamic Path Scoring) attack path engine: DFS-based traversal with heuristic scoring, hop decay, edge factor computation
- **`src/services/importService.ts`** — Single-sheet Excel import: row_type-based parser, Zod validation per entity type
- **`src/services/cxfImportService.ts`** — Multi-sheet CXF workbook import: generates assets, edges, auto-threats from functional/interface/support/data/domain worksheets
- **`src/routes/index.ts`** — All API routes (Express Router)

Key API endpoints:
- `GET /graph` — Full graph snapshot
- `POST /graph/changeset/validate` — Validate a ChangeSet
- `POST /graph/changeset/commit` — Atomic commit with version check
- `POST /analysis/attack-paths/run` — Run DPS analysis
- `POST /admin/seed/sample` / `POST /admin/seed/generic` — Seed demo data
- `POST /imports/excel/single-sheet/commit` — Single-sheet Excel import
- `POST /imports/cxf-asset-inventory/commit` — Multi-sheet CXF workbook import
- `GET /exports/modeling-result` — Export full modeling bundle as JSON

### Frontend (`apps/frontend/`) — React 18 + Vite + ReactFlow
- **`src/App.tsx`** — Main application: topology canvas (ReactFlow), Review Panel (path ranking, export), ChangeSet Studio (form/JSON entity editor, queue, validate, commit). Single-file SPA (~1240 lines)
- **`src/CxfImportPanel.tsx`** — Multi-sheet Excel upload panel: parse > preview > commit workflow
- **`src/api.ts`** — Typed fetch wrappers for all backend endpoints
- **`src/types.ts`** — Frontend-side type definitions (mirrors backend domain types)
- **`src/cxfWorkbook.ts`** — Client-side xlsx workbook parser

### Data Flow

1. **Graph Editing**: Editor (form/JSON) -> Draft ChangeSet (in-memory queue) -> Validate -> Commit to Neo4j (atomic via `commitChangeSet`, version conflict detection)
2. **Attack Path Analysis**: Snapshot graph from Neo4j -> DFS from each ThreatPoint -> score paths (heuristic * dps * hop_decay) -> rank by normalized score
3. **Excel Import**: Parse .xlsx client-side -> POST parsed JSON -> backend generates ChangeSet (assets, edges, auto-threats) -> commit atomically

### Key Concepts

- **ChangeSet**: `{ graph_version, asset_nodes: { add, update, delete }, asset_edges, threat_points, do326a_links }` — atomic unit of mutation
- **GraphVersion**: Stored as a Neo4j node, incremented on every commit via timestamp; conflicts reject stale ChangeSets
- **DPS Scoring**: Entry likelihood * attack complexity * source weight * expert modifier (heuristic) * edge factor product * hop decay (structural)
- **DO-326A Links**: Map semantic model elements (assets, threats, paths) to standard clauses with review workflow
- **Security Domains**: Internal/Shared/DMZ/External — drive lane-based topology layout and trust level inference