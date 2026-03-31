# 轻量级安全建模与静态攻击路径分析平台：系统架构设计

## 1. 设计目标与约束

本系统定位为**工程化分析与评审平台**，交互范式对标 Jama Software 的“可审查、可追踪、高信息密度”风格，而非炫技式可视化。

### 1.1 核心目标

- 支持轻量语义建模：`AssetNode`、`AssetEdge`、`ThreatPoint`、`AttackPath`。
- 聚焦静态分析：拓扑结构、路径可达性、多跳攻击链表达。
- 支持审查闭环：建模 → 推演 → 评分 → 评审 → 审计。
- 保证数据一致性：Neo4j 为单一权威数据源（SSOT）。

### 1.2 明确不做

- 不做动态攻击阶段仿真。
- 不引入 ATT&CK/STRIDE 全流程复杂语义。
- 不把前端本地状态当作长期真值存储。

---

## 2. 整体架构与职责划分

```text
┌────────────────────────────────────────────────────────────────────┐
│                            Frontend Web                           │
│  A. 资产图建模层：AssetNode / AssetEdge 编辑                      │
│  B. Threat Overlay 层：ThreatPoint 悬浮挂载显示                   │
│  C. AttackPath Overlay 层：路径高亮、评分解释、评审操作            │
│  D. 导入与审查工作台：单表 Excel 导入、差异对比、显式保存          │
└───────────────────────▲───────────────────────────────┬────────────┘
                        │ REST API                      │
                        │ (Draft Validate / Commit)     │
┌───────────────────────┴───────────────────────────────▼────────────┐
│                           Backend Service                           │
│  1) 模板与字段校验（单表 Excel 严格校验）                           │
│  2) 语义映射与约束检查（Asset/Edge/Threat）                         │
│  3) Draft ChangeSet 校验与事务提交                                  │
│  4) 静态路径推演（多跳遍历 + 去重）                                  │
│  5) 启发式评分与可解释化输出                                         │
│  6) 分析工件落库（AttackPath 作为一等节点）                          │
│  7) 审计日志与版本快照                                                │
└───────────────────────▲───────────────────────────────┬────────────┘
                        │ Cypher/Bolt                   │
┌───────────────────────┴───────────────────────────────▼────────────┐
│                               Neo4j                                 │
│  权威语义图：AssetNode / ThreatPoint / AttackPath + 关系边           │
│  约束索引、图查询、路径工件存储、版本化追踪                           │
└────────────────────────────────────────────────────────────────────┘
```

### 2.1 前端职责（工程审查导向）

1. **图建模层**：资产节点、资产关系的新增/删除/修改。
2. **Threat Overlay 层**：ThreatPoint 以悬浮标记附着在资产节点上，不破坏主拓扑可读性。
3. **AttackPath Overlay 层**：在资产图上叠加高亮路径，同时支持路径工件详情审查。
4. **显式保存机制**：所有操作先进入 Draft，用户点击保存后统一提交。
5. **差异审查面板**：提交前展示新增/更新/删除清单，确保可复核。

### 2.2 后端职责（语义守门 + 分析引擎）

1. **导入守门**：单表模板结构、列名、字段类型、枚举值、引用关系严格校验；失败即拒绝落库。
2. **语义守门**：保障 `ThreatPoint` 必须挂载于 `AssetNode`，`AttackPath` 必须可追溯到路径序列。
3. **事务提交**：将前端 ChangeSet 原子化写入 Neo4j，避免部分成功。
4. **攻击路径推演**：基于 ThreatPoint 起点进行多跳遍历，输出候选路径并去重。
5. **评分解释**：输出总分、优先级和因子解释，服务工程评审，不声称真实概率。
6. **审计追踪**：记录谁在何时提交了哪些变更与分析结果。

### 2.3 Neo4j 职责（唯一真源）

1. 持久化全部核心语义对象及关系。
2. 提供路径查询、邻接查询、子图过滤能力。
3. 对关键 ID 建立唯一约束与索引。
4. 保存 AttackPath 分析结果节点及其与资产/威胁点的关联，支持复审与回溯。

---

## 3. 语义模型（最小闭环）

## 3.1 节点实体

- `AssetNode`
  - `assetId` (unique)
  - `name`
  - `assetType`
  - `criticality`
  - `owner`
  - `tags[]`

- `ThreatPoint`（悬浮挂载对象）
  - `threatId` (unique)
  - `name`
  - `category`
  - `severityBase`
  - `preconditionText`

- `AttackPath`（一等语义节点）
  - `pathId` (unique)
  - `analysisBatchId`
  - `hopCount`
  - `score`
  - `priority` (P1/P2/P3)
  - `explanations[]`
  - `generatedBy`
  - `generatedAt`

## 3.2 关系语义

- `(:AssetNode)-[:ASSET_EDGE {edgeId, relationType, trustBoundary, directionality}]->(:AssetNode)`
- `(:ThreatPoint)-[:OVERLAY_ON]->(:AssetNode)`
- `(:AttackPath)-[:STARTS_FROM]->(:ThreatPoint)`
- `(:AttackPath)-[:HITS {hop}]->(:AssetNode)`
- `(:AttackPath)-[:TRAVERSES {hop, edgeId}]->(:AssetNode)`（或改用路径片段节点表达）

> 说明：`ThreatPoint` 在前端表现为 overlay（悬浮层），在 Neo4j 中仍为独立节点 + 挂载关系，兼顾可视简洁与可审计语义。

---

## 4. 核心数据流

## 4.1 单表 Excel 导入流（严格校验）

1. 用户上传**单表模板** Excel。
2. 后端校验模板版本与表头签名（列集合、顺序、必填列）。
3. 行级校验：
   - 主键格式/唯一性
   - 字段类型与枚举合法性
   - AssetEdge 端点资产是否存在
   - ThreatPoint 挂载资产是否存在
4. 生成导入预览：新增/更新/拒绝记录及原因。
5. 用户确认后执行提交。
6. 后端开启单事务写入 Neo4j；若任一校验失败则整体回滚，不写入任何数据。

## 4.2 图建模与显式保存流

1. 前端编辑仅更新 Draft Graph（本地工作区）。
2. 前端形成 `changeSet`（add/update/delete + 对象版本号）。
3. 点击保存时调用 `validate`。
4. 后端执行语义与并发冲突检查。
5. 校验通过后 `commit` 原子落库并返回新版本。

## 4.3 攻击路径推演与持久化流

1. 用户选择范围（全图/子图）与 `maxHops`。
2. 后端以 `ThreatPoint -> AssetNode` 为起点集执行静态遍历。
3. 生成候选路径并基于路径签名去重。
4. 计算启发式评分并生成解释因子。
5. 将路径结果写为 `AttackPath` 节点并关联涉及的 ThreatPoint/AssetNode。
6. 前端以 overlay 层展示路径高亮与评审标签。

---

## 5. 前端图建模与叠加层交互设计

## 5.1 界面结构（Jama 风格：信息密度优先）

- **左栏：对象导航与过滤**
  - 资产分组树（域/系统/标签）
  - ThreatPoint 清单（可筛选严重度）
  - AttackPath 列表（按优先级、批次）
- **中栏：主图画布（资产拓扑）**
  - 默认只展示 AssetNode + AssetEdge
  - 可开关 Threat Overlay 与 AttackPath Overlay
- **右栏：审查详情面板**
  - 对象属性
  - 变更历史
  - 路径评分拆解与解释
- **底栏：变更与提交面板**
  - Draft ChangeSet
  - 校验错误
  - 显式保存/回滚

## 5.2 Threat Overlay 交互

1. ThreatPoint 不作为“主拓扑节点”占位，而是附着于资产节点角标/浮层。
2. 鼠标悬停显示 ThreatPoint 摘要（类别、基线严重度、前提条件）。
3. 点击可进入右侧详情并查看关联 AttackPath。
4. 支持在资产详情中“挂载/解除挂载”，变更进入 Draft。

## 5.3 AttackPath Overlay 交互

1. 运行分析后，路径按优先级分组显示（P1/P2/P3）。
2. 选择某条路径时：
   - 中栏高亮 hop 序列
   - 非路径元素降噪显示
   - 右栏展示评分因子与解释句
3. 路径作为独立对象可被标注状态（待评审/已评审/驳回）。
4. 可切换“路径视角”和“资产视角”，保证工程评审可读性。

## 5.4 可解释评分展示

建议评分分解：

- ThreatPoint 基线严重度
- 路径 hop 数（过长路径折减）
- 信任边界穿越次数
- 目标资产关键性
- 关系类型权重（管理面/控制面/业务面）

展示输出：
- 总分 + 优先级标签
- 因子贡献条
- 自动生成解释句（可复制进评审记录）

---

## 6. API 分层建议

- `POST /imports/excel/single-sheet/preview`：模板与字段校验 + 预览
- `POST /imports/excel/single-sheet/commit`：事务导入
- `GET /graph`：获取资产主图 + 版本
- `POST /graph/changeset/validate`：草稿校验
- `POST /graph/changeset/commit`：草稿提交
- `POST /analysis/attack-paths/run`：路径推演 + 评分
- `POST /analysis/attack-paths/persist`：AttackPath 节点落库
- `GET /analysis/attack-paths`：按批次查询历史路径
- `GET /audit/commits`：变更审计记录

---

## 7. 分阶段落地建议

1. **Phase 1：建模与导入闭环**
   - 单表 Excel 严格导入 + 资产图编辑 + 显式保存。
2. **Phase 2：分析闭环**
   - Threat Overlay + 多跳路径推演 + AttackPath 节点持久化。
3. **Phase 3：评审闭环**
   - 评分解释模板、评审状态流转、审计与版本对比。

该分层方案可在保持语义克制的前提下，支持高可维护、高可审查的工程化静态攻击路径分析流程。
