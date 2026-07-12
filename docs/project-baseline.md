# ASTRA 项目长期开发基线

本文档是当前项目的交接基线。之后做功能扩展、论文实验复现、界面调整或数据模板调整时，默认遵循这里定义的模型、数据流和生成规则；如果确实需要改动，必须同步更新本文档、类型定义、API 契约和前端导出逻辑。

## 1. 项目定位

ASTRA（Aviation Semantic Threat Reasoning & Analysis System）是面向航空网络安保建模的图谱化分析平台。当前系统同时承载三条主线：

- DO-326A / DO-356A 语义威胁建模：资产、接口、威胁点、攻击路径、合规链接。
- ASTM F3532 建模流程：01/02 输入导入，03 边界数据流与功能传播路径生成，04 威胁状况与威胁场景生成。
- ZG-ONE 无人机真实数据建模：通过 Excel 模板导入，沉淀为 Neo4j 图谱，再生成论文与报告所需表格。

代码组织是 npm workspaces：

- `apps/backend`：Express + TypeScript + Neo4j，负责导入、校验、图谱存储、分析生成和报表 API。
- `apps/frontend`：React + Vite + ReactFlow，负责图谱审查、Excel 导入、03/04 生成预览与导出。
- `docs`：需求、接口、实验和交接文档。
- `scripts`：真实数据转换脚本与辅助生成脚本。

## 2. 基线原则

后续开发必须遵守以下约束：

- Neo4j 是事实源。前端只做解析、预览、展示和导出，不在本地保存权威业务状态。
- 所有图谱变更必须走 `GraphChangeSet` 和 `GraphRepository.commitChangeSet`，不能绕过版本检查直接散写业务节点。
- TypeScript 类型以 `apps/backend/src/types/domain.ts` 为准；API 入参以 `apps/backend/src/types/api.ts` 的 Zod schema 为准。
- 业务编号必须稳定。BI、BDF、SDF、SB、TA、F、FC、FP、TC、TS 等编号一旦进入报告链路，不允许随意改格式。
- 03 和 04 是可再生成的派生结果。03 的 `FunctionPropagationPath` 可由 01/02 输入重新计算；04 的默认 TC/TS 可由 FHA + FP + TA 重新生成，人工评审后的版本再通过 commit 接口覆盖保存。
- 任何新增节点或关系，都要明确它是“源数据事实”“派生分析结果”还是“人工评审结果”，并写入本文档。

## 3. Neo4j 图数据库如何存

### 3.1 约束与版本

启动后端时会创建唯一约束，核心约束如下：

| 标签/关系 | 唯一键 |
|---|---|
| `AssetNode` | `asset_id` |
| `ASSET_EDGE` | `edge_id` |
| `ThreatPoint` | `threatpoint_id` |
| `DO326A_Link` | `link_id` |
| `GraphVersion` | `id` |
| `FunctionNode` | `function_id` |
| `TrustBoundary` | `boundary_id` |
| `BoundaryInterface` | `interface_id` |
| `ThreatActor` | `actor_id` |
| `SystemDataFlow` | `sdf_id` |
| `FunctionPropagationPath` | `fp_id` |
| `FailureCondition` | `failure_condition_id` |
| `ThreatCondition` | `tc_id` |
| `ThreatScenario` | `ts_id` |
| `AttackPath` | `(analysis_batch_id, path_id)` |

图谱版本存在固定节点：

```cypher
(:GraphVersion {id: "GRAPH_VERSION", value: "v_..."})
```

每次 `commitChangeSet` 成功后都会生成新的 `v_${Date.now()}`，并写入 `AuditCommit` 审计记录。提交时如果请求携带的 `graph_version` 不是当前版本，会被拒绝。

### 3.2 核心业务节点

| 节点 | 含义 | 主要字段 |
|---|---|---|
| `AssetNode` | 通用资产节点，也用于承载 BDF 边界数据流资产 | `asset_id`, `asset_name`, `asset_type`, `criticality`, `security_domain`, `business_id`, `data_flow_type`, `boundary_interface_id`, `failure_condition_ids` |
| `AssetEdge` / `ASSET_EDGE` | 系统资产之间的普通拓扑边 | `edge_id`, `link_type`, `direction`, `protocol_or_medium`, `trust_level` |
| `ThreatPoint` | 威胁入口点，叠加在资产上 | `threatpoint_id`, `stride_category`, `attack_vector`, `entry_likelihood_level`, `attack_complexity_level` |
| `FunctionNode` | 功能节点，编号为 `F...` | `function_id`, `name`, `description` |
| `BoundaryInterface` | 边界接口，编号为 `BIxx` | `interface_id`, `external_entity`, `access_object`, `physical_interconnect`, `logical_protocol`, `direction`, `boundary_id` |
| `TrustBoundary` | 信任边界，编号为 `SBxx` | `boundary_id`, `name`, `description`, `enters_internal_propagation` |
| `ThreatActor` | 威胁主体，编号如 `TA-E-xx` | `actor_id`, `name`, `actor_type`, `boundary_ids` |
| `SystemDataFlow` | 系统内部有向数据流，编号为 `SDF...` | `sdf_id`, `producer`, `consumer`, `data_flow_type`, `function_ids`, `failure_condition_ids`, `system_interface_id` |
| `FunctionPropagationPath` | 03 生成的功能传播路径，编号为 `FPxx` | `fp_id`, `data_type_label`, `system_path_text`, `bdf_ids`, `sdf_ids`, `sdf_note` |
| `FailureCondition` | FHA/AFHA 失效状态 | `failure_condition_id`, `name`, `flight_phases`, `hazard_class`, `severity` |
| `ThreatCondition` | 04 生成/提交的威胁状况 | `tc_id`, `function_id`, `failure_condition_ids`, `cia_attributes`, `severity`, `path_ids`, `coverage_status` |
| `ThreatScenario` | 04 生成/提交的威胁场景 | `ts_id`, `threat_actor_id`, `tc_ids`, `attack_vector`, `attack_path` |

### 3.3 核心关系

| 关系 | 方向 | 含义 |
|---|---|---|
| `ASSET_EDGE` | `AssetNode -> AssetNode` | 普通资产连接或系统间接口边 |
| `OVERLAY_ON` | `ThreatPoint -> AssetNode` | 威胁点挂载到资产 |
| `HAS_INTERFACE` | `TrustBoundary -> BoundaryInterface` | 信任边界包含边界接口 |
| `COVERS_DOMAIN` | `TrustBoundary -> AssetNode` | 信任边界覆盖域资产 |
| `CARRIES` / `CARRIES_FLOW` | `BoundaryInterface -> AssetNode(BDF)` | BI 承载 BDF；`CARRIES_FLOW` 保留兼容旧查询 |
| `THREATENS` | `ThreatActor -> TrustBoundary` | 威胁主体威胁某信任边界 |
| `SUPPORTS_FUNCTION` | `AssetNode/SystemDataFlow -> FunctionNode` | BDF 或 SDF 支撑功能 |
| `TRACES_TO` | `AssetNode(BDF)/SystemDataFlow -> FailureCondition` | 数据流追踪到 FHA 失效状态 |
| `INCLUDES_BDF` | `FunctionPropagationPath -> AssetNode(BDF)` | FP 包含 BDF |
| `INCLUDES_SDF` | `FunctionPropagationPath -> SystemDataFlow` | FP 包含 SDF |
| `DERIVED_FROM` | `ThreatCondition -> FailureCondition` | TC 来源于 FHA |
| `AFFECTS_FUNCTION` | `ThreatCondition -> FunctionNode` | TC 影响功能 |
| `REACHABLE_BY` | `ThreatCondition -> FunctionPropagationPath` | TC 可由 FP 触达 |
| `TRIGGERS` | `ThreatScenario -> ThreatCondition` | TS 触发 TC |
| `ORIGINATES_FROM` | `ThreatScenario -> ThreatActor` | TS 来源威胁主体 |
| `MAPS_TO` | `DO326A_Link -> AssetNode/ThreatPoint/AttackPath` | 标准条款到语义元素映射 |

### 3.4 写库顺序

`commitChangeSet` 的写库顺序是基线：

1. 删除旧的链接、威胁点、边、资产、功能、边界、主体、接口、SDF、FP。
2. 写 `AssetNode`，同步 `TRACES_TO` 到已有 `FailureCondition`。
3. 写 `FunctionNode`。
4. 写 `TrustBoundary`，重建 `COVERS_DOMAIN`。
5. 写 `BoundaryInterface`，重建 `HAS_INTERFACE`。
6. 根据资产上的 `boundary_interface_id(s)` 重建 `BI -> CARRIES/CARRIES_FLOW -> BDF`。
7. 写 `ThreatActor`，重建 `THREATENS`。
8. 写 `SystemDataFlow`，重建 `SUPPORTS_FUNCTION` 与 `TRACES_TO`。
9. 写 `FunctionPropagationPath`，重建 `INCLUDES_BDF` 与 `INCLUDES_SDF`。
10. 写显式 `function_links`，重建 BDF/资产到功能的 `SUPPORTS_FUNCTION`。
11. 写普通 `ASSET_EDGE`。
12. 写 `ThreatPoint` 和 `OVERLAY_ON`。
13. 写 `DO326A_Link` 和 `MAPS_TO`。
14. 更新 `GraphVersion` 并写审计。

因此，新增导入服务应只负责把外部表格转换为 `GraphChangeSet`，不要自己写 Cypher。

## 4. 01/02 输入如何进入图谱

F3532 输入接口使用模板版本：

```json
{
  "template_version": "f3532_input_01_02_v1"
}
```

工作簿包含六类 sheet 数据：

- `boundary_interfaces`：01 边界接口。
- `boundary_data_flows`：01 边界数据流。
- `system_interfaces`：01 系统间接口。
- `system_data_flows`：01 系统间数据流。
- `threat_actors`：02 威胁主体。
- `trust_boundaries`：02 安保/信任边界。

导入流程：

1. 前端读取 Excel，转成上述 JSON。
2. `POST /imports/f3532-input/preview` 做字段与引用预检。
3. `POST /imports/f3532-input/commit` 读取当前图版本，生成 `GraphChangeSet` 并提交。

关键映射规则：

| 输入 | 图谱目标 | 规则 |
|---|---|---|
| BI | `BoundaryInterface` | ID 规范化为 `BI01`, `BI02` 等 |
| BDF | `AssetNode` | `asset_type=Interface`, `business_id=BDFx`, `boundary_interface_id=BIxx`, `data_flow_type=CMD/STATE/...` |
| SI | `ASSET_EDGE` | 生产者/消费者自动生成 `SYS-*` 资产，并创建有向或双向系统接口边 |
| SDF | `SystemDataFlow` | 保留 `producer`, `consumer`, `data_flow_type`, `system_interface_id` |
| target_function | `FunctionNode` + `SUPPORTS_FUNCTION` | 从文本中抽取 `F...` |
| failure_condition | `failure_condition_ids` | 从文本中抽取 `FC...`，后续与 FHA 导入结果建立 `TRACES_TO` |
| TA | `ThreatActor` | 类型归一为 `external/internal/third-party` |
| SB | `TrustBoundary` | 从覆盖范围抽取 BI，从威胁主体引用抽取 TA |

BDF 在图里不是单独标签，而是带 `business_id=BDFx`、`boundary_interface_id` 和 `data_flow_type` 的 `AssetNode`。这是当前 03 查询和 FP 生成依赖的基线，不能随意改成新标签，除非同步兼容所有查询。

## 5. 03 如何得到

03 目前包含两张表：

- `boundary_data_flows`：边界数据流-安保边界对照表。
- `function_propagation`：功能传播路径表。

相关接口：

| 接口 | 作用 |
|---|---|
| `POST /analysis/f3532/generate-03` | 重新运行 FP 分析，覆盖保存 `FunctionPropagationPath`，返回两张 03 表 |
| `GET /reports/f3532/03` | 读取当前已保存的 03 结果，不重新生成 |
| `POST /analysis/function-propagation/run` | 通用 FP 分析接口，同时返回第四章功能传播报表 |
| `GET /reports/chapter4/boundary-data-flows` | 只读边界数据流报表 |
| `GET /reports/chapter4/function-propagation` | 只读功能传播路径报表 |

### 5.1 边界数据流表

`getBoundaryDataFlowReport()` 使用以下图谱路径：

```text
TrustBoundary -> HAS_INTERFACE -> BoundaryInterface -> CARRIES/CARRIES_FLOW -> AssetNode(BDF)
```

然后按 `(boundary_id, data_flow_type, enters_internal_propagation)` 聚合，输出：

- `boundary_id`
- `boundary_name`
- `data_flow_type`
- `interfaces`
- `bdf_ids`
- `function_ids`
- `enters_internal_propagation`

这个表只反映边界与 BDF 的事实关系，不做 DFS。

### 5.2 功能传播路径表

`generate-03` 先调用 `getFunctionPropagationInputs()` 取两类输入：

- BDF 起点：来自 `AssetNode`，要求 `boundary_interface_id IS NOT NULL`，且 `enters_internal_propagation !== false`。
- SDF 有向边：来自 `SystemDataFlow` 的 `producer -> consumer`。

然后由 `FpAnalysisService.run()` 计算 FP：

1. 用全部 SDF 构建有向邻接表。
2. 每条 BDF 确定入口子系统：
   - 优先使用 `BoundaryInterface.access_object` 中能匹配 SDF 图的系统名。
   - 如果没有匹配，取 `access_object` 的第一个候选。
   - 再不行才使用 `external_entity`。
3. 只沿相同 `data_flow_type` 的 SDF 传播。例如 CMD 只走 CMD，STATE 只走 STATE。
4. 深度默认 `max_hops=5`，接口允许 `1..12`。
5. 收集可达的 SDF、关联功能和最长代表链路。
6. 按 `group_by` 聚合：
   - `boundary`：默认，按数据类型 + 入口信任边界聚合。
   - `function`：按数据类型 + 影响功能集合聚合。
   - `type`：只按数据类型聚合。
7. 稳定排序后编号为 `FP01`, `FP02`, ...
8. 用 `replaceFunctionPropagationPaths()` 清空旧 FP，再写入新 FP 及 `INCLUDES_BDF/INCLUDES_SDF`。

功能传播表最终从图中读取：

```text
FunctionPropagationPath -> INCLUDES_BDF -> AssetNode(BDF)
FunctionPropagationPath -> INCLUDES_SDF -> SystemDataFlow
BI -> CARRIES/CARRIES_FLOW -> BDF
BDF/SDF -> SUPPORTS_FUNCTION -> FunctionNode
```

输出字段：

- `fp_id`
- `data_type`
- `entry_bis`
- `bdf_ids`
- `sdf_ids`
- `sdf_note`
- `system_path`
- `function_ids`

注意：03 不是攻击路径评分，也不使用 `ThreatPoint`。它是边界输入到内部功能传播的结构化可达性分析。

## 6. 04 如何得到

04 目前包含：

- `threat_conditions`：威胁状况 TC。
- `threat_scenarios`：威胁场景 TS。

相关接口：

| 接口 | 作用 |
|---|---|
| `POST /imports/fha/preview` | 预检 FHA/AFHA 失效状态 |
| `POST /imports/fha/commit` | 写入 `FailureCondition`，并把 BDF/SDF 的 `failure_condition_ids` 连接到 FC |
| `GET /fha/failure-conditions` | 查看带 BDF/SDF/FP 上下文的 FC |
| `GET /analysis/f3532/04/defaults` | 获取 04 前端可用默认选项 |
| `POST /analysis/f3532/generate-04` | 重新刷新 FP，然后根据 FHA + FP + TA 生成默认 TC/TS |
| `POST /analysis/f3532/commit-04` | 保存人工确认或修改后的 TC/TS，覆盖旧 04 |
| `GET /reports/f3532/04` | 读取当前已保存的 04 |

### 6.1 FHA 导入

FHA 导入写入：

```text
(:FailureCondition)
```

随后根据 BDF/SDF 上已有 `failure_condition_ids` 建立：

```text
AssetNode(BDF) -> TRACES_TO -> FailureCondition
SystemDataFlow -> TRACES_TO -> FailureCondition
```

FHA 是 04 严重度和失效状态全集的权威来源。01 表里的 failure condition 引用只用于连接，不作为完整 FC 清单。

### 6.2 04 生成输入

`generate-04` 会先重新运行一次 FP：

```text
getFunctionPropagationInputs()
FpAnalysisService.run({ group_by: "function" })
replaceFunctionPropagationPaths()
```

然后读取两类上下文：

- FailureConditionContext：FC 及其关联的 BDF、SDF、功能、FP、受影响资产。
- ThreatPathContext：FP 及其功能、边界、威胁主体。

ThreatPathContext 的关键图路径是：

```text
FP -> INCLUDES_BDF/SDF -> flow -> SUPPORTS_FUNCTION -> FunctionNode
FP -> INCLUDES_BDF -> BDF <- CARRIES/CARRIES_FLOW <- BI <- HAS_INTERFACE <- SB <- THREATENS <- TA
```

### 6.3 TC 生成规则

每个符合条件的 FC 生成一个或多个 TC：

1. 如果 `include_unlinked_failure_conditions=true`，所有 FHA FC 都进入生成；否则只生成已有功能或路径覆盖的 FC。
2. 通过 FC 编号推断功能族。例如 `FC1.2.3` 会优先匹配 `F1.2.3`，再退到 `F1.2`、`F1` 或同族功能。
3. 如果 FC 已直接关联 FP，则优先使用直接路径；否则按功能族匹配可支持该功能的 FP。
4. CIA 模式：
   - `single`：生成 `C`、`I`、`A` 三个单属性 TC。
   - `all_non_empty`：生成 7 个非空组合。
5. 默认严重度继承 FHA：`severity_source="FHA"`。
6. 如果同时有功能和路径，则 `coverage_status="linked"`；否则为 `unlinked`。
7. 默认人工填写字段为空，例如描述、飞机影响、系统影响、机组影响、乘员影响。

TC 编号按生成顺序稳定为：

```text
TC-001, TC-002, ...
```

### 6.4 TS 生成规则

TS 根据 TC 的 `path_ids`、FP 关联的威胁主体和推断攻击向量聚合：

1. 遍历每个 TC 的路径。
2. 对每条 FP 找到相关信任边界及威胁主体。
3. 聚合键为 `path_id + actor_id + attack_vector`。
4. 如果 TC 找不到路径或威胁主体，生成未关联 TS。
5. 默认攻击路径文本为：

```text
威胁主体 -> 功能传播路径
```

攻击向量推断：

- third-party、供应链、vendor、`TA-T`：`SupplyChain`
- 维护、maintenance、`SB03`、`SB-03`：`Maintenance`
- GNSS、射频、无线、wireless：`Wireless`
- 物理、physical：`Physical`
- 其他默认：`Network`

TS 编号按聚合键排序后稳定为：

```text
TS-001, TS-002, ...
```

### 6.5 04 保存方式

`commit-04` 不走 `GraphChangeSet`，它保存的是 04 人工评审结果，使用 `replaceF353204()`：

1. 删除旧的 `ThreatCondition` 和 `ThreatScenario`。
2. 创建新的 TC 节点。
3. 建立 `TC -> DERIVED_FROM -> FC`。
4. 建立 `TC -> AFFECTS_FUNCTION -> FunctionNode`。
5. 建立 `TC -> REACHABLE_BY -> FP`。
6. 创建新的 TS 节点。
7. 建立 `TS -> TRIGGERS -> TC`。
8. 建立 `TS -> ORIGINATES_FROM -> ThreatActor`。

这是当前唯一允许绕过 `GraphChangeSet` 的业务写入路径，因为它保存的是独立的 04 评审结果集合，不改变基础图谱事实。

## 7. 攻击路径 DPS 与 03/04 的区别

系统里有两种“路径”，不能混淆：

| 类型 | 节点 | 输入 | 算法 | 用途 |
|---|---|---|---|---|
| 攻击路径 | `AttackPath` | `ThreatPoint + AssetNode + ASSET_EDGE` | DFS + DPS 评分 | 威胁路径排序、DO-356A 示例实验 |
| 功能传播路径 | `FunctionPropagationPath` | `BDF + SDF + FunctionNode` | 同类型有向 DFS + 聚合 | F3532 03/04 |

DPS 攻击路径从 `ThreatPoint` 出发，沿资产边搜索，并计算 `raw_score/dps_score/normalized_score`。F3532 03/04 使用的是 FP，不依赖 DPS 评分。

## 8. 主要 API 基线

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/graph` | 全量图快照 |
| `POST` | `/graph/changeset/validate` | 校验 ChangeSet |
| `POST` | `/graph/changeset/commit` | 原子提交基础图谱 |
| `POST` | `/imports/f3532-input/preview` | F3532 01/02 输入预览 |
| `POST` | `/imports/f3532-input/commit` | F3532 01/02 输入提交 |
| `POST` | `/imports/fha/preview` | FHA 预览 |
| `POST` | `/imports/fha/commit` | FHA 提交 |
| `POST` | `/analysis/f3532/generate-03` | 生成并保存 03 FP |
| `GET` | `/reports/f3532/03` | 读取 03 |
| `GET` | `/analysis/f3532/04/defaults` | 04 默认选项 |
| `POST` | `/analysis/f3532/generate-04` | 生成 04 默认 TC/TS |
| `POST` | `/analysis/f3532/commit-04` | 保存 04 TC/TS |
| `GET` | `/reports/f3532/04` | 读取 04 |
| `POST` | `/analysis/attack-paths/run` | 运行 DPS 攻击路径 |
| `POST` | `/analysis/attack-paths/persist` | 保存 DPS 攻击路径 |
| `GET` | `/exports/modeling-result` | 导出完整建模结果 |

## 9. 开发命令

```bash
docker compose up -d
npm install
npm run dev
npm run dev:frontend
npm run build
npm run seed:sample
npm run seed:generic
npm run standard:f3532:import
npm run exp:do356a:baseline
```

后端默认端口 `4000`，前端默认端口 `5173`，Neo4j 默认 `bolt://localhost:7687`。

## 10. 后续开发检查清单

提交任何影响模型或报表的改动前，至少检查：

- `npm run build` 通过。
- 新字段已同步到 `domain.ts`、`api.ts`、后端 repository、前端 `types.ts` 和导出逻辑。
- 新 Neo4j 标签或关系已在本文档补充说明。
- 03 相关改动不会破坏 `TrustBoundary -> BI -> BDF` 和 `FP -> BDF/SDF -> FunctionNode` 两条查询链。
- 04 相关改动不会破坏 `FailureCondition -> TC -> TS` 的追踪链。
- 如果编号规则改变，必须说明迁移策略；默认不允许改变既有编号格式。
- 如果新增人工评审字段，必须保证 `generate-04` 生成默认值、`commit-04` 保存值、`GET /reports/f3532/04` 可读回。

## 11. 当前不可随意改变的基线

- BDF 继续用 `AssetNode` 表示，通过 `business_id=BDFx` 和 `boundary_interface_id` 识别。
- `BoundaryInterface -> CARRIES/CARRIES_FLOW -> BDF` 两个关系名都保留，避免旧报表失效。
- FP 生成必须坚持“同数据类型通道传播”，不能让 CMD/STATE/DATA 等跨类型互通。
- `enters_internal_propagation=false` 的 BDF 不作为 FP 起点。
- `generate-03` 可以覆盖 FP，因为 FP 是派生结果。
- `generate-04` 只生成默认 TC/TS；最终以 `commit-04` 保存的人工评审结果为准。
- FHA 严重度是 04 默认严重度来源，人工修改后必须把 `severity_source` 改为 `manual`。
- 基础图谱事实变更走 `GraphChangeSet`；04 评审结果走 `replaceF353204()`。

