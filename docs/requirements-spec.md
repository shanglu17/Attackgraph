# Attackgraph Platform 需求规格说明书（整理版）

## 1. 文档信息
- 文档名称: Attackgraph Platform 需求规格说明书
- 文档版本: v0.1（基于当前代码实现整理）
- 整理日期: 2026-03-11
- 适用范围: `apps/backend`、`apps/frontend`、`docker-compose.yml`
- 说明: 本文档以当前仓库实现为准，属于“现状需求基线（As-Is）”。

## 2. 项目目标与背景
Attackgraph 平台用于构建航空系统资产图（Asset Graph）及威胁覆盖（Threat Overlay），并支持:
- 图谱变更草案（ChangeSet）校验与提交
- 静态攻击路径推演与评分（DPS + Heuristic）
- 攻击路径持久化与查询
- DO-326A/DO-356A 语义映射与审查
- 审计追踪（commit 记录）

目标是形成可运行的安全分析与审查工作台，为后续标准流程映射和工程化扩展提供基础。

## 3. 系统范围

### 3.1 In Scope（当前已覆盖）
- 后端 REST API（Express + Zod + Neo4j）
- 前端审查工作台（React + ReactFlow）
- 示例数据一键初始化
- 图谱读取、变更校验与提交
- 攻击路径计算、持久化、查询
- DO326A 链接创建/更新/评审
- 提交审计记录查询

### 3.2 Out of Scope（当前未覆盖）
- Excel 原始文件上传与二进制解析（当前接口仍以 `headers + rows` JSON 载荷为主）
- 认证授权（当前仅通过 `x-user-id` 透传）
- 多租户隔离
- 细粒度 RBAC
- 自动化测试与质量门禁（仓库未体现）

## 4. 角色与使用者
- 安全分析工程师: 运行攻击路径分析、查看路径优先级
- 图谱建模工程师: 管理资产/边/威胁变更草案并提交
- 合规工程师: 维护 DO326A 关联，执行评审状态流转
- 审计/管理角色: 查看 commit 审计记录与图谱版本演进

## 5. 业务能力分解

### 5.1 能力域 A: 图谱建模与版本管理
- 资产节点、资产边、威胁点、DO326A 链接的增删改
- 变更集语义校验
- 图谱版本冲突检测
- 提交后版本号更新与审计记录写入

### 5.2 能力域 B: 攻击路径分析
- 从 ThreatPoint 相关资产出发进行 DFS/DPS 路径扩展
- 支持最大跳数、可选 scope 资产范围
- 评分计算: 边因子、hop 衰减、启发式因子
- 路径归一化后分级（High/Medium/Low）

### 5.3 能力域 C: 结果管理
- 攻击路径持久化到 Neo4j
- 按 `analysis_batch_id` 查询路径结果

### 5.4 能力域 D: 合规映射与评审
- DO326A_Link upsert
- 语义元素映射到 AssetNode / ThreatPoint / AttackPath
- 评审状态更新（Draft/Reviewed/Approved）

### 5.5 能力域 E: 审查工作台
- 图谱可视化与域分层展示
- 路径排名及高亮
- 草案校验/提交操作
- DO326A 映射与复核操作

## 6. 功能需求（Functional Requirements）

## 6.1 FR-A: 平台基础与健康检查
- FR-A-001: 系统应提供健康检查接口 `GET /health`，返回 `{ ok: true }`。
- FR-A-002: 系统启动时应确保 Neo4j 约束存在（唯一键与版本节点）。
- FR-A-003: 系统应支持通过环境变量配置端口与数据库连接。

## 6.2 FR-B: 示例数据与导入预览
- FR-B-001: 系统应提供 `POST /admin/seed/sample` 重置并写入演示数据。
- FR-B-002: 种子数据应包含 AssetNode、AssetEdge、ThreatPoint、DO326A_Link。
- FR-B-003: 系统应提供 Excel 单表导入预览 `POST /imports/excel/single-sheet/preview`。
- FR-B-004: 导入预览应返回 accepted/rejected/errors/summary。
- FR-B-005: 导入写入接口 `POST /imports/excel/single-sheet/commit` 应执行模板校验、字段校验、绑定校验与原子提交。

## 6.3 FR-C: 图谱读取与变更集
- FR-C-001: 系统应提供 `GET /graph` 返回完整图谱快照:
  - `graph_version`
  - `asset_nodes`
  - `asset_edges`
  - `threat_points`
  - `do326a_links`
- FR-C-002: 系统应提供 `POST /graph/changeset/validate` 校验 changeSet。
- FR-C-003: 系统应提供 `POST /graph/changeset/commit` 提交 changeSet。
- FR-C-004: 提交前必须执行 validate；校验失败时返回冲突/错误信息。
- FR-C-005: 提交成功后应返回 `commit_id` 和 `new_version`。
- FR-C-006: 提交应写入 `CommitAudit` 记录（用户、时间、摘要、版本）。

## 6.4 FR-D: 攻击路径分析
- FR-D-001: 系统应提供 `POST /analysis/attack-paths/run`。
- FR-D-002: 参数需包含 `analysis_batch_id`、`max_hops`、`generated_by`。
- FR-D-003: 系统应支持可选 `scope_asset_ids` 与 `dps_hop_decay`。
- FR-D-004: 系统应基于 ThreatPoint 覆盖资产启动路径搜索。
- FR-D-005: 系统应避免环路（visited 集合）。
- FR-D-006: 系统应计算并返回:
  - `dps_score`
  - `heuristic_score`
  - `raw_score`
  - `normalized_score`
  - `priority_label`
  - `is_low_priority`
- FR-D-007: 系统应输出路径解释说明 `explanations`。

## 6.5 FR-E: 攻击路径结果持久化与查询
- FR-E-001: 系统应提供 `POST /analysis/attack-paths/persist`。
- FR-E-002: 系统应将路径写入 AttackPath 节点及关联关系（STARTS_FROM / TARGETS / TRAVERSES）。
- FR-E-003: 系统应提供 `GET /analysis/attack-paths`，可按 `analysis_batch_id` 过滤。

## 6.6 FR-F: DO326A 合规映射
- FR-F-001: 系统应提供 `GET /compliance/do326a-links`。
- FR-F-002: 系统应提供 `POST /compliance/do326a-links` 执行创建或更新。
- FR-F-003: 系统应提供 `PATCH /compliance/do326a-links/:link_id/review` 更新评审状态。
- FR-F-004: 映射关系应基于 `semantic_element_id` 自动连接到 AssetNode/ThreatPoint/AttackPath。

## 6.7 FR-G: 审计能力
- FR-G-001: 系统应提供 `GET /audit/commits`，按时间倒序返回最近提交记录。

## 6.8 FR-H: 前端审查台
- FR-H-001: 前端应提供图谱刷新与样例初始化按钮。
- FR-H-002: 前端应展示资产/威胁/路径/链接 KPI。
- FR-H-003: 前端应按安全域分组展示资产，并渲染拓扑关系。
- FR-H-004: 前端应可触发 DPS 分析并展示路径排名。
- FR-H-005: 选中路径后应高亮相关边。
- FR-H-006: 前端应支持 Persist Paths 操作。
- FR-H-007: 前端应支持 ChangeSet validate/commit 操作。
- FR-H-008: 前端应支持 DO326A link 新增/更新与评审更新。

## 7. 数据模型需求

### 7.1 核心实体
- AssetNode
- AssetEdge
- ThreatPoint
- AttackPath
- DO326A_Link
- GraphVersion
- CommitAudit

### 7.2 标识与约束（Neo4j）
系统应保证如下唯一性约束:
- `AssetNode.asset_id`
- `ASSET_EDGE.edge_id`
- `ThreatPoint.threatpoint_id`
- `AttackPath.path_id`
- `DO326A_Link.link_id`
- `GraphVersion.id`

### 7.3 关键关系
- `(ThreatPoint)-[:OVERLAY_ON]->(AssetNode)`
- `(AttackPath)-[:STARTS_FROM]->(ThreatPoint)`
- `(AttackPath)-[:TARGETS]->(AssetNode)`
- `(AttackPath)-[:TRAVERSES {hop, edge_id, edge_factor}]->(AssetNode)`
- `(DO326A_Link)-[:MAPS_TO {semantic_element_id}]->(AssetNode|ThreatPoint|AttackPath)`

## 8. 输入校验与业务规则

### 8.1 API 结构校验（Zod）
- 资产 ID、边 ID、威胁 ID、路径 ID、链接 ID 均有格式约束。
- `max_hops` 范围: 1-8。
- `dps_hop_decay` 范围: 0.8-1.0。
- `review_status` 为 Reviewed/Approved 时必须填写 reviewer。
- `asset_type=Data` 时必须提供 `data_classification`。
- `Logical/DataFlow` 边必须提供 `protocol_or_medium`。

### 8.2 语义校验（Repository）
- graph version 冲突检测（提交版本 vs 当前版本）。
- 边和威胁引用的资产必须存在于现图或本次草案。
- 跨安全域边若未提供 `trust_level` 则报错。
- DO326A `semantic_element_id` 必须能解析到已知语义实体。

## 9. 攻击路径评分需求

### 9.1 启发式因子
- `entry_likelihood_value`:
  - High=0.7, Medium=0.5, Low=0.3
- `attack_success_factor`:
  - Low=1.0, Medium=0.7, High=0.4
- `source_weight`:
  - internal=0.9, external=0.7, third-party=0.5
- `expert_modifier`: 默认 1.0，限制区间 [0.5, 1.5]

### 9.2 结构因子
- 边信任因子:
  - Trusted=1.0
  - Semi-Trusted=0.85
  - Untrusted=0.7
  - 缺省=0.9
- 安全机制修正因子（示例规则）:
  - `tls|ssl|ipsec|vpn|wpa2|wpa3|macsec|802.1x` -> 0.8
  - `certificate|token|mfa|signature` -> 0.85
  - 缺省=0.9
- 最终边因子下限: 0.3

### 9.3 计算公式
- `dps_score = edge_factor_product * hop_decay`
- `hop_decay = (dps_hop_decay)^(hop-1)`
- `raw_score = heuristic_score * dps_score`
- `normalized_score = raw_score / max(raw_score_all_paths)`

### 9.4 分级规则
- High: `normalized_score >= 0.5`
- Medium: `0.15 <= normalized_score < 0.5`
- Low: `normalized_score < 0.15`

### 9.5 算法工程实现细节（路径分析内核）

#### 9.5.1 图构建过程
- 实现入口: `AnalysisService.run(input)`。
- 输入数据: `asset_nodes`、`asset_edges`、`threat_points`。
- 工程步骤:
  1. 调用 `buildAdjacency(asset_edges)` 构建邻接表 `Map<string, AssetEdge[]>`，以 `source_asset_id` 为 key。
  2. 对 `direction = Bidirectional` 的边，运行时动态生成反向边（`edge_id#rev`），写入邻接表，仅用于搜索阶段，不回写图谱主数据。
  3. 构建 `asset_ids` 集合用于 O(1) 节点存在性判断。
  4. 若请求携带 `scope_asset_ids`，构建 `scope_set` 用于范围约束过滤。
- 该实现的工程优势是“搜索时图展开、存储时图简化”，减少持久层冗余边写入。

#### 9.5.2 起点和终点设定
- 起点设定:
  - 以每个 `ThreatPoint.related_asset_id` 作为搜索起点资产。
  - 路径条目中的 `entry_point_id` 取自 `ThreatPoint.threatpoint_id`。
- 终点设定:
  - 当前实现不预设固定终点资产。
  - 每次扩展到一个合法下一跳资产时，都会产出一条“从起点到该资产”的候选路径，因此终点是“所有可达资产”。
- 工程说明:
  - 这种设计支持全图风险扩散分析，不受单终点假设限制。
  - 前端可按 `target_asset_id` 与优先级筛选目标资产。

#### 9.5.3 搜索策略
- 策略类型: 深度优先递归搜索（DFS），实现函数为 `dps(context, state)`。
- 状态结构 `DfsState` 包含:
  - `current_asset_id`: 当前节点
  - `traverses`: 当前路径跳序列（含 hop、edge_id、asset_id、edge_factor）
  - `structural_score`: 当前路径结构累计分（边因子连乘）
  - `visited`: 当前分支访问集
- 扩展逻辑:
  1. 从邻接表取 `current_asset_id` 的所有出边。
  2. 逐边执行过滤（scope、资产存在性、去环）。
  3. 计算下一跳 `nextHop` 与边因子 `edgeFactor`。
  4. 增量计算 `nextStructuralScore = structural_score * edgeFactor`。
  5. 计算启发式分、hop 衰减、`dps_score` 和 `raw_score`。
  6. 立即落入候选集，再递归进入下一层。
- 该策略属于“边扩展边评分”的在线计算方式，避免二次遍历路径重算成本。

#### 9.5.4 剪枝方法
- 剪枝 1: 最大跳数剪枝
  - 条件: `state.traverses.length >= input.max_hops` 时立即返回。
  - 作用: 控制指数级扩展，稳定计算时长。
- 剪枝 2: 范围剪枝（scope）
  - 条件: 目标资产不在 `scope_set` 则跳过。
  - 作用: 支持局部子图分析，降低无关路径干扰。
- 剪枝 3: 非法资产剪枝
  - 条件: `target_asset_id` 不在 `asset_ids` 集合则跳过。
  - 作用: 避免脏边导致无效路径与异常评分。
- 剪枝 4: 循环剪枝
  - 条件: 目标资产已存在于 `visited` 集合则跳过。
  - 作用: 防止无限递归与环路路径污染。

#### 9.5.5 去环逻辑
- 实现方式:
  - 每个递归分支维护独立 `visited: Set<string>`。
  - 进入下一跳前复制当前集合：`nextVisited = new Set(state.visited)`。
  - 将下一跳资产 `add` 到 `nextVisited` 后递归。
- 工程含义:
  - 去环粒度是“路径分支级”，而非全局级。
  - 同一资产可出现在不同分支中（允许多路径比较），但不能在同一路径内重复出现。
- 效果:
  - 保证输出路径是简单路径（simple path），避免闭环放大分数。

#### 9.5.6 路径输出格式
- 运行时候选对象 `CandidatePath` 字段:
  - 标识类: `analysis_batch_id`、`entry_point_id`、`target_asset_id`
  - 路径类: `hop_sequence`、`hop_count`、`traverses[]`
  - 评分类: `path_probability`、`raw_score`、`dps_score`、`heuristic_score`
  - 上下文类: `entry_likelihood_level`、`attack_complexity_level`、`threat_source`、`expert_modifier`
- 最终输出 `AttackPath` 增强字段:
  - `path_id`（`AP-0001` 递增）
  - `normalized_score`
  - `priority_label`（High/Medium/Low）
  - `is_low_priority`
  - `score_config_version`
  - `explanations[]`（解释性证据）
- 输出与持久化衔接:
  - `POST /analysis/attack-paths/run` 返回计算结果。
  - `POST /analysis/attack-paths/persist` 将结果写入 `AttackPath` 节点并重建 `STARTS_FROM`、`TARGETS`、`TRAVERSES` 关系。

## 10. 接口需求总览（REST）
- `GET /health`
- `POST /admin/seed/sample`
- `POST /imports/excel/single-sheet/preview`
- `POST /imports/excel/single-sheet/commit`
- `GET /graph`
- `POST /graph/changeset/validate`
- `POST /graph/changeset/commit`
- `POST /analysis/attack-paths/run`
- `POST /analysis/attack-paths/persist`
- `GET /analysis/attack-paths`
- `GET /exports/modeling-result`
- `GET /compliance/do326a-links`
- `POST /compliance/do326a-links`
- `PATCH /compliance/do326a-links/:link_id/review`
- `GET /audit/commits`

## 11. 非功能需求（NFR）

### 11.1 可用性
- 本地部署应可在 3 个进程内启动:
  - Neo4j (`docker compose up -d`)
  - Backend (`npm run dev`)
  - Frontend (`npm run dev:frontend`)

### 11.2 性能（建议基线）
- 图谱读取接口在中小规模数据下应在 2s 内返回。
- 单次分析接口应在可接受时间内完成（受 `max_hops` 与图规模影响）。

### 11.3 可靠性
- API 异常应返回结构化错误信息。
- 提交操作应在事务中执行，保证一致性。

### 11.4 可维护性
- 类型定义前后端对齐（TypeScript）。
- 路由参数通过 Zod 统一校验。
- 仓储层集中管理 Cypher 与持久化行为。

### 11.5 安全性（当前状态）
- 当前仅具备基础输入校验与模型约束。
- 尚未实现鉴权、审计签名、防重放、速率限制、机密管理策略。

## 12. 部署与运行需求
- Node.js + npm workspace
- Neo4j 5.x
- 环境变量:
  - `PORT`（默认 4000）
  - `NEO4J_URI`（默认 `bolt://localhost:7687`）
  - `NEO4J_USERNAME`（默认 `neo4j`）
  - `NEO4J_PASSWORD`（默认仓库默认值）

## 13. 验收标准（建议）

### 13.1 基础验收
- 可成功启动前后端与 Neo4j。
- `GET /health` 返回 `ok: true`。
- 一键 seed 后可读取到非空图谱。

### 13.2 业务验收
- ChangeSet validate 能识别版本冲突和语义错误。
- ChangeSet commit 成功后版本号变化并写入审计记录。
- run analysis 返回路径列表且包含评分、解释、优先级。
- persist paths 后可通过查询接口读回。
- DO326A link 可创建/更新/评审，且映射关系可重建。

### 13.3 前端验收
- 前端可完成“加载图谱 -> 运行分析 -> 高亮路径 -> 持久化 -> 合规映射更新”闭环流程。

## 14. 风险与待办（Gap List）
- Excel 导入 commit 尚未实现。
- 无用户身份体系与权限模型。
- 未看到自动化测试、压测、监控告警配置。
- 默认明文数据库凭据存在安全风险，需环境化并脱敏。
- 前后端 baseUrl 固定为 localhost，不适配多环境部署。

## 15. 需求追踪建议（面向后续 DO-356A 映射）
- 为每条 FR 增加唯一追踪号（已提供基础编号）。
- 增加“FR -> API -> 数据实体 -> 验收用例”的矩阵表。
- 将 AttackPath explanation 字段结构化（当前为字符串数组），便于审计与证据提取。
- 将场景（Threat Scenario）提升为一等实体，连接 ThreatPoint/AttackPath/Control。

---

## 附录 A: 主要代码锚点
- Backend 入口: `apps/backend/src/index.ts`
- 路由: `apps/backend/src/routes/index.ts`
- 评分引擎: `apps/backend/src/services/analysisService.ts`
- 导入预览: `apps/backend/src/services/importService.ts`
- 仓储: `apps/backend/src/repositories/graphRepository.ts`
- API Schema: `apps/backend/src/types/api.ts`
- Domain 模型: `apps/backend/src/types/domain.ts`
- Frontend 主界面: `apps/frontend/src/App.tsx`
- Frontend API: `apps/frontend/src/api.ts`
- Docker: `docker-compose.yml`
- 参考文档: `docs/do356a_appendix_d_example.md`

## 16. 2026-03-19 增量更新

### 16.1 Excel 单表导入
- `POST /imports/excel/single-sheet/preview` 与 `POST /imports/excel/single-sheet/commit` 均已启用模板列头强校验。
- 请求体格式为 `{ headers?: string[]; rows: Array<Record<string, unknown>> }`。
- 模板列头要求“全集存在、顺序可变、非法列拒绝”。
- 允许的额外列仅有 `template_version`，当前不参与业务校验。
- 当 Excel 解析器会丢失全空列时，调用方应显式传入 `headers` 以保留模板列头信息。
- 导入提交会先将单表数据映射为 `GraphChangeSet`，再复用仓储层校验与事务提交逻辑。
- `AssetEdge.source_asset_id`、`AssetEdge.target_asset_id` 以及 `ThreatPoint.related_asset_id` 必须能绑定到当前图谱或同批导入的 `AssetNode`；任一引用缺失时整批拒绝，数据库不允许部分写入。
- 导入错误统一返回 `error_details`，错误类别分为 `template`、`field`、`binding`。

模板列头集合：

```text
row_type, id, asset_name, asset_type, criticality, security_domain, description, data_classification, tags,
source_asset_id, target_asset_id, link_type, protocol_or_medium, direction, trust_level, security_mechanism,
related_asset_id, name, stride_category, attack_vector, entry_likelihood_level, attack_complexity_level,
threat_source, preconditions, detection_status, cve_reference, expert_modifier, expert_adjustment_note,
mitigation_reference, standard_id, clause_title, semantic_element_id, linkage_type, evidence_reference,
review_status, reviewer, mapping_version
```

### 16.2 建模结果导出
- 新增只读导出接口 `GET /exports/modeling-result`。
- 支持可选查询参数 `analysis_batch_id`，用于过滤 `Analysis Paths` 导出范围。
- 导出响应结构为 `metadata + payload`：
  - `metadata` 包含 `exported_at`、过滤条件、`graph_version` 与数据条数统计。
  - `payload` 包含 `graph`、`analysis_paths`、`do326a_links` 三部分。

### 16.3 前端审查台
- 攻击路径列表取消 `slice(0, 8)` 限制，改为完整展示。
- 页面新增“导出建模结果(JSON)”入口，并支持填写可选的 `analysis_batch_id` 过滤条件。
