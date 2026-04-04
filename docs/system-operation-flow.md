# Attackgraph 系统运行与建模说明

## 1. 这套系统在做什么

这个系统本质上是在做 4 件事：

1. 维护一张可编辑的安全建模图
   - 资产节点 `AssetNode`
   - 资产连接 `AssetEdge`
   - 威胁点 `ThreatPoint`
   - 合规映射 `DO326A_Link`
2. 基于威胁点跑攻击路径分析
3. 把分析结果保存成 `AttackPath`
4. 在前端把图、路径、审查状态展示出来

核心数据模型定义在 [domain.ts](/e:/document/airness/project/Attackgraph/apps/backend/src/types/domain.ts#L1)。

## 2. 系统是怎么一步步跑起来的

### 2.1 启动阶段

后端启动时会先建立 Neo4j 约束，再启动 HTTP 服务，这一步在 [index.ts](/e:/document/airness/project/Attackgraph/apps/backend/src/index.ts#L21)。

通常运行顺序是：

1. 启动 Neo4j
2. 启动后端
3. 启动前端
4. 装载一套示例数据，或者导入你自己的建模数据

你现在仓库里有两套示例入口：

- `POST /admin/seed/sample`
  对应 DO-356A 示例，路由在 [index.ts](/e:/document/airness/project/Attackgraph/apps/backend/src/routes/index.ts#L39)
- `POST /admin/seed/generic`
  对应通用简单示例，路由在 [index.ts](/e:/document/airness/project/Attackgraph/apps/backend/src/routes/index.ts#L48)

前端对应按钮在 [App.tsx](/e:/document/airness/project/Attackgraph/apps/frontend/src/App.tsx#L814) 和 [App.tsx](/e:/document/airness/project/Attackgraph/apps/frontend/src/App.tsx#L817)。

### 2.2 图模型加载阶段

前端点 `Refresh Graph` 或初始化示例后，会调用 `GET /graph` 读取当前完整图快照。

- 前端调用入口在 [api.ts](/e:/document/airness/project/Attackgraph/apps/frontend/src/api.ts#L19)
- 页面加载逻辑在 [App.tsx](/e:/document/airness/project/Attackgraph/apps/frontend/src/App.tsx#L550)
- 后端取图逻辑在 [graphRepository.ts](/e:/document/airness/project/Attackgraph/apps/backend/src/repositories/graphRepository.ts#L60)

这里拿到的是“建模后的原始图”，包括：

- `asset_nodes`
- `asset_edges`
- `threat_points`
- `do326a_links`
- `graph_version`

### 2.3 图是怎么显示成“模型图”的

前端不是直接画数据库里的图，而是先把图快照转换成 ReactFlow 节点和边：

- 资产节点按安全域分层布局：`buildLanePosition(...)`
  在 [App.tsx](/e:/document/airness/project/Attackgraph/apps/frontend/src/App.tsx#L168)
- 选中攻击路径后，会高亮对应边：`edgeIdSetFromPath(...)`
  在 [App.tsx](/e:/document/airness/project/Attackgraph/apps/frontend/src/App.tsx#L202)
- ReactFlow 画布在 [App.tsx](/e:/document/airness/project/Attackgraph/apps/frontend/src/App.tsx#L884)

所以“模型图”本质上是：

`Neo4j 图数据 -> GET /graph -> 前端状态 -> ReactFlow 画布`

## 3. 你怎么构建出模型

这个系统里，“构建模型”有 3 条路。

### 3.1 用示例数据直接起模型

这是最快的方式。

- DO-356A 示例：后端种子在 [graphRepository.ts](/e:/document/airness/project/Attackgraph/apps/backend/src/repositories/graphRepository.ts#L612)
- 通用简单示例：后端种子在 [graphRepository.ts](/e:/document/airness/project/Attackgraph/apps/backend/src/repositories/graphRepository.ts#L996)

它们会一次性写入：

- 资产
- 连接
- 威胁点
- 合规映射

### 3.2 用 Excel 单表导入来建模

如果你要从资料整理成模型，比较适合走这条路。

- 预览接口：`POST /imports/excel/single-sheet/preview`
- 提交接口：`POST /imports/excel/single-sheet/commit`
- 路由在 [index.ts](/e:/document/airness/project/Attackgraph/apps/backend/src/routes/index.ts#L57)
- 导入整理逻辑在 [importService.ts](/e:/document/airness/project/Attackgraph/apps/backend/src/services/importService.ts#L86)

导入服务会把单表中的每一行解析成四种实体之一：

- `AssetNode`
- `AssetEdge`
- `ThreatPoint`
- `DO326A_Link`

也就是说，这个系统目前不是“上传一张图片自动识别成模型”，而是“把结构化数据导入后形成模型”。

### 3.3 在前端 ChangeSet Studio 里手工建模

你也可以在前端底部的 `ChangeSet Studio` 里逐条新增、修改、删除实体：

- 校验草稿：`handleValidate()` 在 [App.tsx](/e:/document/airness/project/Attackgraph/apps/frontend/src/App.tsx#L679)
- 提交草稿：`handleCommit()` 在 [App.tsx](/e:/document/airness/project/Attackgraph/apps/frontend/src/App.tsx#L694)
- 后端提交逻辑：`commitChangeSet(...)` 在 [graphRepository.ts](/e:/document/airness/project/Attackgraph/apps/backend/src/repositories/graphRepository.ts#L155)

这条链路很重要，因为它说明系统并不是直接改数据库，而是通过 `GraphChangeSet` 做版本化提交。

## 4. 攻击路径分析是怎么跑的

攻击路径分析接口是：

- `POST /analysis/attack-paths/run`
  路由在 [index.ts](/e:/document/airness/project/Attackgraph/apps/backend/src/routes/index.ts#L143)
- 前端触发按钮 `Run DPS Analysis`
  在 [App.tsx](/e:/document/airness/project/Attackgraph/apps/frontend/src/App.tsx#L873)

后端分析入口是 [analysisService.ts](/e:/document/airness/project/Attackgraph/apps/backend/src/services/analysisService.ts#L84) 的 `run(input)`。

它的核心步骤是：

1. 把 `asset_edges` 构造成邻接表
   - `buildAdjacency(...)` 在 [analysisService.ts](/e:/document/airness/project/Attackgraph/apps/backend/src/services/analysisService.ts#L239)
2. 遍历每个 `ThreatPoint`
3. 从 `ThreatPoint.related_asset_id` 对应的资产开始搜索
4. 用 DFS/DPS 一跳一跳向外扩展
5. 每扩展一步就形成一个候选攻击路径
6. 计算路径分数并归一化
7. 返回 `High / Medium / Low` 优先级

系统当前把 `ThreatPoint` 作为分析起点，而不是分析完成后再倒推出 ThreatPoint。

换句话说：

- 先有威胁点
- 再从威胁点出发做路径分析

## 5. 威胁状态识别有吗，体现在分析前还是分析后

这个问题很关键，结论先说：

**有“威胁状态字段”，但目前没有“自动识别威胁状态的独立算法模块”。**

### 5.1 现在系统里已有的“威胁状态”

`ThreatPoint` 上有一个字段叫 `detection_status`，定义在 [domain.ts](/e:/document/airness/project/Attackgraph/apps/backend/src/types/domain.ts#L52)。

可选值是：

- `None`
- `Monitoring`
- `Mitigated`

它在这些地方会被保存和读取：

- 读图查询在 [graphRepository.ts](/e:/document/airness/project/Attackgraph/apps/backend/src/repositories/graphRepository.ts#L71)
- 提交 ThreatPoint 时写入在 [graphRepository.ts](/e:/document/airness/project/Attackgraph/apps/backend/src/repositories/graphRepository.ts#L210)
- 前端编辑表单字段在 [App.tsx](/e:/document/airness/project/Attackgraph/apps/frontend/src/App.tsx#L131)

### 5.2 这个“威胁状态”是在分析前还是分析后

按当前实现，它属于**分析前就存在的建模属性**。

也就是说：

- 你先在 ThreatPoint 上写 `detection_status`
- 然后分析服务再读取 ThreatPoint 去跑路径

但要注意，当前分析打分逻辑并**没有使用** `detection_status`。

当前真正进入评分的是这些因素：

- `entry_likelihood_level`
- `attack_complexity_level`
- `threat_source`
- `expert_modifier`
- 边的 `trust_level`
- 边的 `security_mechanism`

对应代码在：

- 启发式评分 `resolveHeuristicScore(...)`
  [analysisService.ts](/e:/document/airness/project/Attackgraph/apps/backend/src/services/analysisService.ts#L261)
- 边因子评分 `resolveEdgeFactor(...)`
  [analysisService.ts](/e:/document/airness/project/Attackgraph/apps/backend/src/services/analysisService.ts#L269)

所以更准确地说：

- `detection_status` 目前是“威胁建模状态”
- `priority_label` / `is_low_priority` 才是“分析后的路径结果状态”

### 5.3 分析后系统体现了什么状态

分析后会生成的是 `AttackPath` 的结果状态，而不是自动回写 ThreatPoint 状态。

分析后你能看到：

- `raw_score`
- `normalized_score`
- `priority_label`
- `is_low_priority`
- `explanations`

这些定义和返回在 [analysisService.ts](/e:/document/airness/project/Attackgraph/apps/backend/src/services/analysisService.ts#L108)。

如果你点了 `Persist Paths`，这些路径会保存到 Neo4j：

- 前端入口在 [App.tsx](/e:/document/airness/project/Attackgraph/apps/frontend/src/App.tsx#L733)
- 后端保存逻辑在 [graphRepository.ts](/e:/document/airness/project/Attackgraph/apps/backend/src/repositories/graphRepository.ts#L295)

保存后会形成这些关系：

- `(AttackPath)-[:STARTS_FROM]->(ThreatPoint)`
- `(AttackPath)-[:TARGETS]->(AssetNode)`
- `(AttackPath)-[:TRAVERSES]->(AssetNode)`

## 6. 这套系统当前的真实业务顺序

如果按现在代码的真实流程，完整顺序应该理解成：

1. 建模
   - 导入或录入 `AssetNode / AssetEdge / ThreatPoint / DO326A_Link`
2. 展示模型图
   - 前端把资产和边渲染成 ReactFlow 拓扑图
3. 运行分析
   - 从 `ThreatPoint` 出发跑攻击路径
4. 产出风险结果
   - 形成 `AttackPath`，给出优先级
5. 持久化结果
   - 保存 `AttackPath`
6. 做合规和审查
   - `DO326A_Link.review_status`

## 7. 你可以怎么理解“模型”和“分析”的边界

一个很实用的理解方式是：

- `AssetNode + AssetEdge`
  是系统结构模型
- `ThreatPoint`
  是威胁建模输入
- `AttackPath`
  是分析结果模型
- `DO326A_Link`
  是合规追踪模型

所以威胁点不是分析结果，而是分析输入。

## 8. 当前系统还没有做到的部分

按目前代码看，下面这些还没有做成“自动能力”：

- 没有从日志/流量/告警自动识别 ThreatPoint
- 没有根据分析结果自动更新 `ThreatPoint.detection_status`
- 没有把 `detection_status` 纳入路径评分
- 没有“上传一张架构图自动抽模型”的能力

这几点如果后面要扩展，最自然的方向是：

1. 增加“威胁识别层”
   - 从规则、知识库或 LLM 把原始系统描述转成 ThreatPoint
2. 增加“状态回写层”
   - 根据分析结果自动更新 ThreatPoint 的处置状态
3. 增加“图抽取层”
   - 从 Excel、文档、图纸中抽结构关系

## 9. 一句话总结

这套系统当前的运行逻辑不是“先识别威胁再生成模型”，也不是“分析后自动发现威胁状态”，而是：

**先把资产、连接和威胁点建模进去，再基于 ThreatPoint 作为起点做攻击路径分析，最后得到路径优先级和可持久化的分析结果。**
