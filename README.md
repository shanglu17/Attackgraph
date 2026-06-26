# ASTRA — 航空语义威胁推理与分析系统

**A**viation **S**emantic **T**hreat **R**easoning & **A**nalysis System

基于 **DO-356A / DO-326A / ASTM F3532** 的航空网络安保威胁建模平台。以 Neo4j 图谱维护资产、数据流、信任边界与威胁点，运行攻击路径推演与功能传播分析，并提供 React 审查工作台与 vol3 第四章报表导出。

> 当前以 **ZG-ONE 无人机系统** 为真实建模对象。

---

## 核心能力

- **多层语义模型**：功能资产(F) → 支持资产(子系统) → 边界接口(BI) → 边界数据流(BDF) → 系统内部数据流(SDF) → 功能传播路径(FP)，并叠加信任边界(SB)、威胁主体(TA)、DO-326A 合规链接。
- **Excel 导入**：单表导入与 **CXF 多 sheet 工作簿导入**（资产/接口/数据流/边界/威胁主体一次性导入，自动生成边、自动威胁点）。
- **真实数据转换器**：`scripts/convert_source_to_v4.py` 把 ZG-ONE 原始清单转换成可导入的 v4 模板。
- **攻击路径推演（DPS）**：从威胁点出发的 DFS 路径搜索 + 启发式/结构化评分。
- **功能传播分析（FP）**：从边界数据流出发，沿**同类型**系统数据流做类型通道传播，按边界/类型/功能归并成传播路径。
- **内部数据流分析**：识别"不从任何边界进入的纯内部流"，以 IMS 为核心归类。
- **vol3 第四章报表**：4.2 信任边界汇总 / 4.3 边界数据流分析 / 4.4 内部数据流分析 / 4.5 功能传播路径，可一键导出 Excel。
- **审查工作台**：ReactFlow 拓扑、路径排名、ChangeSet 编辑器（表单/JSON）、原子提交与版本冲突检测。

---

## 架构

npm workspaces 单仓（`apps/*`）+ Neo4j：

### 后端 `apps/backend/` — Express + TypeScript (ESM)
- `src/config/env.ts` — 环境变量（端口、Neo4j 凭据）
- `src/db/neo4j.ts` — Neo4j 驱动单例
- `src/types/domain.ts` — 领域类型（AssetNode / AssetEdge / BoundaryInterface / SystemDataFlow / TrustBoundary / FunctionPropagationPath / 各报表行类型 …）
- `src/types/api.ts` — Zod 请求校验
- `src/repositories/graphRepository.ts` — 所有 Neo4j 操作：CRUD、约束、ChangeSet 原子提交、四张第四章报表、审计
- `src/services/analysisService.ts` — DPS 攻击路径引擎
- `src/services/fpAnalysisService.ts` — 功能传播（FP）引擎 + 边界可达性计算
- `src/services/importService.ts` — 单表 Excel 导入
- `src/services/cxfImportService.ts` — CXF 多 sheet 工作簿导入
- `src/routes/index.ts` — 所有 API 路由

### 前端 `apps/frontend/` — React 18 + Vite + ReactFlow
- `src/App.tsx` — 主应用：拓扑画布、审查面板、ChangeSet Studio、第四章报表加载/导出
- `src/CxfImportPanel.tsx` — 多 sheet 上传：解析 → 预览 → 提交
- `src/cxfWorkbook.ts` — 客户端 xlsx 解析
- `src/api.ts` / `src/types.ts` — 类型化 fetch 封装与前端类型

### 数据转换 `scripts/`
- `convert_source_to_v4.py` — ZG-ONE 真实源表 → `docs/资产清单_v4_真实数据.xlsx`

---

## 关键概念

| 概念 | 说明 |
|---|---|
| **BI（边界接口）** | 飞机↔外部的安保边界穿越点，携带 外部实体 / 接入对象 / 所属信任边界(SB) |
| **BDF（边界数据流）** | 跨边界的数据流，挂在 BI 上，是 FP 传播的**起点** |
| **SDF（系统数据流）** | 机载子系统之间的有向内部流，是 FP 传播的**内部图** |
| **FP（功能传播路径）** | 从 BDF 沿同类型 SDF 传播归并出的路径（vol3 §4.5）|
| **类型通道传播** | 传播只沿**同一数据流类型**的边（CMD 沿 CMD、STATE 沿 STATE…），避免 IMS 枢纽让一切互达 |
| **是否进入内部传播** | 每条 BDF 的标志：入站注入=是，出站读出=否。**否**的流不作为 FP 传播种子 |
| **DPS 评分** | 入口可能性 × 攻击复杂度 × 来源权重 × 专家修正（启发式）× 边因子 × 跳数衰减（结构）|
| **ChangeSet** | 资产/边/威胁/边界等的原子变更单元，提交时做版本冲突检测 |

---

## 快速启动

```bash
# 1. 启动 Neo4j
docker compose up -d

# 2. 安装依赖
npm install

# 3. 启动后端（tsx watch）
npm run dev

# 4. 启动前端（另开终端）
npm run dev:frontend

# 5. 写入示例数据（另开终端，可选）
npm run seed:sample      # DO-356A 示例
npm run seed:generic     # 通用示例
```

打开前端 `http://localhost:5173`，点"刷新图数据"即可。

---

## 真实数据建模流程（ZG-ONE）

```
原始清单(网络安保资产_边界及系统_接口和数据流清单_xxxx.xlsx)
   │  python scripts/convert_source_to_v4.py "<源表路径>"
   ▼
docs/资产清单_v4_真实数据.xlsx        ← 可导入的 v4 模板
   │  前端 CXF 多 sheet 导入（解析→预览→提交）
   ▼
Neo4j 图谱
   │  POST /analysis/function-propagation/run
   ▼
功能传播路径 (FP)
   │  前端"加载第四章报告" → 导出
   ▼
vol3-chapter4-report-*.xlsx  (4.2 / 4.3 / 4.4 / 4.5 四张 sheet)
```

转换器输出沿用标准 sheet 名/表头；跑完看打印的 **未匹配 BI 数** 与各表条数即可自检。源表格式不变时，换版本通常只需改源路径（详见脚本头部说明）。

---

## 常用命令

```bash
npm run build              # 构建前后端（tsc + vite）
npm run clear              # 清空 Neo4j 图谱
npm run seed:sample        # 写入 DO-356A 示例数据
npm run seed:generic       # 写入通用示例数据
npm run exp:do356a:baseline# 运行 DO-356A 基线实验
```

---

## 主要 API

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/health` | 健康检查 |
| GET | `/graph` | 全量图快照 |
| POST | `/graph/changeset/validate` | 校验 ChangeSet |
| POST | `/graph/changeset/commit` | 原子提交（版本冲突检测）|
| POST | `/imports/excel/single-sheet/{preview,commit}` | 单表 Excel 导入 |
| POST | `/imports/cxf-asset-inventory/{preview,commit}` | CXF 多 sheet 导入 |
| POST | `/analysis/attack-paths/run` | 运行 DPS 攻击路径分析 |
| GET/POST | `/analysis/attack-paths`、`/persist` | 查询 / 持久化攻击路径 |
| POST | `/analysis/function-propagation/run` | 运行 FP 分析（`group_by`、`max_hops`）|
| GET | `/reports/chapter4/trust-boundaries` | 4.2 信任边界汇总 |
| GET | `/reports/chapter4/boundary-data-flows` | 4.3 边界数据流分析 |
| GET | `/reports/chapter4/internal-data-flows` | 4.4 内部数据流分析 |
| GET | `/reports/chapter4/function-propagation` | 4.5 功能传播路径 |
| GET | `/exports/modeling-result` | 导出完整建模结果(JSON) |
| GET/POST | `/compliance/do326a-links` | DO-326A 合规链接 |
| POST | `/admin/seed/{sample,generic}` | 写入示例数据 |
| GET | `/audit/commits` | 审计记录 |

---

## 默认配置

| 项 | 值 |
|---|---|
| Neo4j URI | `bolt://localhost:7687` |
| Neo4j User | `neo4j` |
| Neo4j Password | `YB52013140402hh`（可用 `NEO4J_PASSWORD` 覆盖）|
| Backend | `http://localhost:4000`（可用 `PORT` 覆盖）|
| Frontend | `http://localhost:5173` |

---

## 文档

- `docs/requirements-spec.md` — 需求规格
- `docs/system-operation-flow.md` — 系统运行流程
- `docs/cxf-asset-inventory-api-contract.md` — CXF 导入 API 契约
- `docs/asset-inventory-v2-design.md` — 资产清单设计
- `docs/do356a-baseline-experiment.md` — DO-356A 基线实验
