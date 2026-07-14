# F3532 03 自动生成重构记录

## 1. 改造背景

本次改造目标是根据输入 01《网络安保资产、边界及系统、接口和数据流清单》和输入 02《安保边界及威胁主体》，自动生成输出 03《安保边界数据流梳理表》。

此前审计确认：原实现更接近“技术连通性 + 聚合展示”，不能稳定复现标准 03 的两张 Sheet。本次改造原则是：

```text
结构化事实
→ 确定性图算法
→ 可配置业务规则
→ 待人工确认的模糊结果
→ 可选文本生成
```

本次没有接入大语言模型。BDF、SDF、BI、SI、SB、功能和路径成员关系均由确定性逻辑产生。

## 2. 原实现问题

- 第一张 Sheet 按 `SB + 数据流类型 + enters_internal_propagation` 聚合，标准结果需要“一条 BDF 一行”。
- F3532 导入阶段把所有 BDF 的 `enters_internal_propagation` 写成 `true`，出站 BDF 会被误当成外部进入内部。
- BDF 的 Producer、Consumer、Destination 没有作为结构化字段保存，路径算法只能从描述或 BI 文本猜测。
- 多目标 BI 的入口使用 `access_object` 猜测，BDF32、BDF33、BDF34 可能被统一错误地从 IMS 开始。
- SDF 传播要求数据类型完全相同，合法的 `SENSOR → DATA` 等跨类型传播会漏失。
- 同一边界内相同类型数据流被过度合并，业务主题不同的路径会被混在一起。
- 原路径只展示一条最长链，但成员集合里可能包含其它分支，成员与展示不一致。
- 没有 BDF 种子的纯内部关键路径无法生成。
- 第二张 Sheet 缺少路径名称、起源、SI、简述、状态、证据等字段。
- 旧 `POST /analysis/f3532/generate-03` 会删除旧 FP 后重建，预览不安全。

## 3. 本次改造范围

已完成：

- 扩展 BDF/SDF 结构化事实，保留 Producer、Consumer、Destination、方向、BI、功能、主题和来源行。
- 新增集中系统别名标准化，使用稳定 `system_id` 构建传播图。
- 重写第一张 Sheet 为逐 BDF 确定性 JOIN。
- 新增传播图构建、候选路径搜索、业务规则引擎、路径解释和报告组装模块。
- 新增主题分类、显式类型转换、稳定路径编号、分支 route segment、停止原因和 evidence。
- 支持规则指定的纯内部路径，不对普通内部连通分量自动成路径。
- 新增只读 preview 接口和显式 commit 接口；旧 generate 接口改为兼容性预览。
- 更新前后端类型、前端导出列序和 API 包装。
- 新增后端测试和只读 Golden File 验证脚本。
- 输出 Golden 验证 JSON：`artifacts/f3532-03-generation-validation.json`。

未完成：

```text
未完成
完整人工审核工作流、输入版本失效标记、人工 Approved 路径的细粒度冲突合并。

原因
当前任务重点是生成算法与预览安全；完整审核流涉及产品交互、数据库状态模型和人工确认界面。

当前影响
commit 接口已比旧实现安全，但仍是保守替换 v2 自动生成结果，不是完整审批系统。

建议后续处理方式
增加 03Result/ReviewSession 节点、输入 hash、结果状态流转和人工锁定范围。
```

## 4. 设计决策

1. BDF 继续兼容存储在 `AssetNode`，但增加专用结构化属性；生成算法使用 `BoundaryDataFlowFact` DTO，不从描述文本猜事实。
2. BDF 方向根据 Producer/Consumer 的内外部系统属性确定：
   - 外部到内部：`INBOUND`
   - 内部到外部：`OUTBOUND`
   - 内部到内部：`INTERNAL`
   - 不能识别：`UNKNOWN`
3. 系统身份统一通过 `systemAliases.ts` 标准化，算法节点使用稳定 system ID。
4. 第一张 Sheet 不做图搜索，只做 BDF → BI → SB → 功能的确定性 JOIN。
5. 第二张 Sheet 分两层：
   - `CandidateRouteFinder` 只发现拓扑候选和分支；
   - `BusinessPathRuleEngine` 根据规则选择业务路径、编号和状态。
6. P01-P19 是规则配置里的稳定路径代码，不通过 `if (bdfId === "...")` 写死成员。
7. 无法由 01/02 唯一判断的路径标记 `NEEDS_REVIEW`，不伪造确定性推导。
8. 候选搜索中过滤掉的后继边记录为 `FILTERED_CANDIDATE` evidence，不再自动把路径降级为 warning。
9. 不使用 LLM；文本名称和简述使用模板，仅引用已验证结构化事实。

## 5. 数据结构变化

`AssetNode` 新增或保留以下 BDF 结构化字段：

- `bdf_producer_id`
- `bdf_producer_name`
- `bdf_consumer_id`
- `bdf_consumer_name`
- `bdf_destination_ids`
- `bdf_destination_names`
- `bdf_direction`
- `boundary_interface_ids`
- `bdf_data_description`
- `bdf_function_text`
- `bdf_function_ids`
- `bdf_topic_ids`
- `bdf_continuation_policy`
- `source_sheet`
- `source_row`

`SystemDataFlow` 新增：

- `producer_system_id`
- `consumer_system_id`
- `topic_ids`

新增领域 DTO：

- `BoundaryDataFlowFact`
- `BoundaryInterfaceFact`
- `SystemDataFlowFact`
- `SystemInterfaceFact`
- `TrustBoundaryFact`
- `GeneratedBusinessPath`
- `GeneratedRouteSegment`
- `F353203BoundaryFlowRow`
- `F353203PathRow`
- `F353203GenerationResult`

这些结构解决了以下问题：

- 不再用系统名称文本作为图节点身份。
- 不再从 `description` 或 `BI.access_object` 猜 BDF 入口。
- 每个 `sdf_id` 都必须能追溯到某个 `route_segment`。
- 结果可以携带状态、证据、停止原因和 warning。

## 6. 算法变化

### 第一张 Sheet

算法：

```text
遍历每条 BDF
→ 读取全部 BI
→ 通过 BI 找 SB
→ 读取数据类型和关联功能
→ 输出一条 BDF 一行
```

关键变化：

- 不再按 SB、类型或是否进入内部传播聚合。
- BDF、BI 使用自然排序，避免 `BDF1、BDF10、BDF2`。
- 一条 BDF 对应多个 BI 时全部保留。
- 多个 BI 属于不同 SB 时输出多个 SB 并给 warning。
- 缺少 BI 或缺少 SB 时输出 warning，不静默吞掉。

### 第二张 Sheet

算法：

```text
事实标准化
→ 构建 System 有向图，SDF 为边
→ 根据规则选择 BDF 或内部系统种子
→ 从真实 Producer/Consumer 确定起点
→ 搜索候选 route segment
→ 检查系统范围、主题兼容、类型转换、环路和终止条件
→ 按业务规则合并分支
→ 生成稳定路径编号、状态、名称、简述和证据
```

关键变化：

- INBOUND BDF 从 `consumer_id` 开始，OUTBOUND BDF 从 `producer_id` 开始。
- 出站流不会被反转为外部进入内部。
- 支持显式类型转换，例如 `SENSOR → DATA`、`CONFIG → CMD`。
- 主题不兼容时，即使拓扑相连也不会继续传播。
- 支持分支；不再只保留一条最长链。
- 环路按已访问系统和 SDF 检测，记录证据并停止。
- `max_hops` 只作为防御性上限。
- 纯内部路径只能由规则种子触发。

## 7. 修改文件清单

| 文件 | 修改类型 | 修改内容 | 原因 | 影响 |
| -- | ---- | ---- | -- | -- |
| `docs/f3532-03-generation-refactor-record.md` | 新增 | 本重构记录 | 满足审计和交付要求 | 文档 |
| `apps/backend/package.json` | 修改 | 增加后端测试脚本 | 运行 F3532 单元测试 | 后端测试入口 |
| `apps/backend/src/types/domain.ts` | 修改 | 增加 BDF/SDF 结构化字段和 03 生成 DTO | 路径算法需要稳定事实 | 后端领域类型 |
| `apps/backend/src/types/api.ts` | 修改 | Zod schema 接受新字段；增加 preview/commit 请求 schema | 避免新字段被校验剥离；约束安全接口 | API 校验 |
| `apps/backend/src/config/f3532/systemAliases.ts` | 新增 | 系统别名到稳定 system ID | 统一节点身份 | 事实标准化、图算法 |
| `apps/backend/src/config/f3532/topicTaxonomy.ts` | 新增 | 主题关键词规则 | 确定性主题分类 | 路径过滤 |
| `apps/backend/src/config/f3532/typeTransitions.ts` | 新增 | 显式类型转换矩阵 | 替代“类型必须相同” | 路径搜索 |
| `apps/backend/src/config/f3532/pathRules.ts` | 新增 | P01-P19 规则、稳定编号、终止条件 | 可配置业务路径 | 规则引擎 |
| `apps/backend/src/services/f3532/topicClassifier.ts` | 新增 | 根据描述、类型、功能分类主题 | 不使用 LLM 的主题识别 | BDF/SDF facts |
| `apps/backend/src/services/f3532/naturalSort.ts` | 新增 | 业务 ID 自然排序 | 修复编号排序 | 报告和测试 |
| `apps/backend/src/services/f3532/factNormalizer.ts` | 新增 | 01/02 结构化事实标准化 | 导入、生成、验证共用事实逻辑 | 核心事实层 |
| `apps/backend/src/services/f3532/boundaryFlowReportService.ts` | 新增 | 第一张 Sheet 逐 BDF JOIN | 修复聚合错误 | 03 第一张表 |
| `apps/backend/src/services/f3532/propagationGraphBuilder.ts` | 新增 | 用 system ID 和 SDF 构建有向图 | 稳定图结构 | 路径搜索 |
| `apps/backend/src/services/f3532/candidateRouteFinder.ts` | 新增 | 候选路径搜索、分支、环、过滤 evidence | 替代同类型最长链 DFS | 路径候选 |
| `apps/backend/src/services/f3532/businessPathRuleEngine.ts` | 新增 | 规则选种、归并、编号、状态 | 区分拓扑和业务语义 | 业务路径 |
| `apps/backend/src/services/f3532/pathExplanationBuilder.ts` | 新增 | 从 route segment 生成路径文本 | 修复成员与展示不一致 | 输出解释 |
| `apps/backend/src/services/f3532/reportAssembler.ts` | 新增 | 组装标准 03 行 DTO | 统一输出层 | API/导出 |
| `apps/backend/src/services/f3532/f353203GenerationService.ts` | 新增 | 编排完整 03 生成流程 | 单一生成入口 | API/验证 |
| `apps/backend/src/services/f3532/f353203Generation.test.ts` | 新增 | 12 个后端测试 | 覆盖方向、入口、排序、类型转换、分支、环、内部路径、编号、预览安全 | 自动验证 |
| `apps/backend/src/services/f3532InputImportService.ts` | 修改 | 导入时调用事实标准化并持久化结构化字段 | 入库时不丢事实 | 导入 01/02 |
| `apps/backend/src/repositories/graphRepository.ts` | 修改 | 读写新字段；增加 03 facts 查询和安全 commit | 支持数据库生成和显式提交 | Neo4j 访问 |
| `apps/backend/src/routes/index.ts` | 修改 | 增加 preview/commit；旧 generate 改为只读预览 | 防止预览删除旧 FP | 后端 API |
| `apps/frontend/src/types.ts` | 修改 | 同步新增后端类型 | 前端类型兼容 | UI/API |
| `apps/frontend/src/api.ts` | 修改 | generate 走 preview；新增 commit 调用 | 保留旧入口并支持安全提交 | 前端 API |
| `apps/frontend/src/App.tsx` | 修改 | 更新预览、提交、展示和导出；导出列序贴合标准 03 | 保留前端入口 | 前端工作台 |
| `scripts/validate_f3532_03_generation.mjs` | 新增 | 只读读取桌面 01/02/03，内存生成并对比 Golden | 可重复验证 | 验证工具 |
| `artifacts/f3532-03-generation-validation.json` | 新增 | Golden 对比详细 JSON | 记录验证结果 | 交付证据 |

非本任务既有脏文件：

- `README.md`
- `docs/cxf-multi-sheet-import-guide.md`
- `docs/excel-import-storage-guide.md`

本次未主动修改或清理这些既有变更。

## 8. 每个文件的具体修改

后端领域和校验：

- `domain.ts`：补齐 BDF/SDF 结构化字段，新增生成路径、route segment、evidence、标准 Sheet 行类型。
- `api.ts`：ChangeSet schema 允许新字段；新增 `previewF353203Schema` 和 `commitF353203Schema`。

后端配置：

- `systemAliases.ts`：集中管理 IMS、综合管理系统等别名；未知系统生成稳定待审 ID。
- `topicTaxonomy.ts`：用可审查关键词规则输出主题和命中证据。
- `typeTransitions.ts`：集中管理类型转换，不再散落 if/else。
- `pathRules.ts`：配置 P01-P19 的种子、系统范围、主题、终止条件、状态和模板。

后端服务：

- `factNormalizer.ts`：把 01/02 workbook 行转为事实 DTO；计算方向、主题、BI/SB 关系和 warning。
- `boundaryFlowReportService.ts`：第一张 Sheet 一条 BDF 一行。
- `propagationGraphBuilder.ts`：构建 `System -> SDF -> System` 有向图。
- `candidateRouteFinder.ts`：候选路径搜索，保留分支和 `FILTERED_CANDIDATE` evidence。
- `businessPathRuleEngine.ts`：按规则生成稳定 P 编号、状态、BDF/SDF/SI/BI/功能集合。
- `pathExplanationBuilder.ts`：从 route segment 生成分支路径显示。
- `reportAssembler.ts`：输出标准 03 行 DTO。
- `f353203GenerationService.ts`：统一编排第一张表和第二张表生成。

导入、数据库、路由：

- `f3532InputImportService.ts`：导入时写入 BDF/SDF 结构化事实，`enters_internal_propagation` 由方向派生。
- `graphRepository.ts`：读写新增字段；新增 `getF353203GenerationFacts()` 和 `commitF353203Paths()`。
- `routes/index.ts`：新增 `/analysis/f3532/generate-03/preview`、`/analysis/f3532/generate-03/commit`；旧 `/generate-03` 保持兼容但只读预览。

前端：

- `types.ts`：同步新增 DTO。
- `api.ts`：旧 generate 调 preview，新增 commit API。
- `App.tsx`：保留现有入口，增加预览/提交分离；03 导出列序调整为标准工作簿表头。

测试和验证：

- `f353203Generation.test.ts`：覆盖 12 项核心行为。
- `validate_f3532_03_generation.mjs`：只读导入桌面 01/02/03，输出集合级差异报告。

## 9. 新增配置和规则

新增配置位置：

- `apps/backend/src/config/f3532/systemAliases.ts`
- `apps/backend/src/config/f3532/topicTaxonomy.ts`
- `apps/backend/src/config/f3532/typeTransitions.ts`
- `apps/backend/src/config/f3532/pathRules.ts`

规则特点：

- P01-P19 作为稳定路径代码保存在规则配置中。
- 规则不枚举某条路径包含哪些 BDF/SDF 成员。
- 规则以 SB、BI、Producer/Consumer 系统、方向、主题、系统范围、终止条件选择路径。
- 类型转换显式配置。
- 模糊或无法唯一推导的规则状态为 `NEEDS_REVIEW`。

当前仍然属于 F3532 项目规则，不是通用行业规则；换一套项目数据时需要审查 `pathRules.ts`。

## 10. 测试用例

新增后端测试文件：

`apps/backend/src/services/f3532/f353203Generation.test.ts`

覆盖：

- BDF 方向：外部到内部、内部到外部、内部到内部、未知。
- 第一张表：逐 BDF、多 BI、多功能、缺失 SB warning、自然排序、不按类型聚合。
- BDF32/BDF33/BDF34 真实入口：IMS/FMS/FCS。
- 出站流：PACKS 到地面维护设备不反转。
- 类型转换：导航主题 `SENSOR → DATA` 允许；视频主题不兼容时拒绝。
- 无关边不变性。
- 输入行顺序不变性。
- `path.sdf_ids` 与 `route_segments` 一致。
- 环路检测。
- 规则指定纯内部路径。
- 稳定编号不漂移。
- 预览生成不修改输入状态。

## 11. 执行过的命令

| 阶段 | 命令 | 结果 |
| -- | -- | -- |
| 基线 | `git status --short` | 发现任务开始前已有 `README.md` 修改和两个未跟踪文档；本任务保留不动 |
| 基线 | `npm run build` | 首次失败：依赖未安装，`tsc` 不存在 |
| 基线 | `npm install --ignore-scripts` | 成功；安装 260 个包；npm 报告 1 个 high vulnerability，未自动修复 |
| 基线 | `npm run build` | 成功；仅 Vite chunk size warning |
| 开发 | `npm test -w @attackgraph/backend` | 最终成功：12 passed, 0 failed |
| 开发 | `npm run build -w @attackgraph/backend` | 成功 |
| 开发 | `npm run build` | 成功；后端 tsc、前端 tsc、Vite build 均通过；仅 chunk size warning |
| Golden | `CODEX_NODE_MODULES=... .\node_modules\.bin\tsx scripts/validate_f3532_03_generation.mjs` | 成功；输出 `artifacts/f3532-03-generation-validation.json` |

中途修复过的验证问题：

- 测试 helper 重复指定 `id`，严格 TypeScript 报 `TS2783`，已修复。
- Golden 脚本最初按旧列序解析第二张 Sheet，已按标准 03 真实表头修正。
- 候选过滤原因最初计入 warning，导致 confirmed 规则被误降级，已改为 `FILTERED_CANDIDATE` evidence。

## 12. 测试和验证结果

最终自动测试：

```text
npm test -w @attackgraph/backend
tests 12
pass 12
fail 0
```

最终类型检查和构建：

```text
npm run build -w @attackgraph/backend
通过

npm run build
通过
Vite warning: Some chunks are larger than 500 kB after minification
```

Golden 验证：

```text
输入统计：
BI 24
BDF 57
SI 17
SDF 82
TA 11
SB 3

生成元数据：
confirmed_count 13
needs_review_count 6
unmatched_count 0
```

## 13. 与标准 03 的对比结果

第一张 Sheet：

| 指标 | 结果 |
| -- | --: |
| 标准行数 | 57 |
| 生成行数 | 57 |
| BDF 匹配 | 57 |
| BDF 缺失 | 0 |
| BDF 多出 | 0 |
| SB/BI/类型/功能集合差异 | 0 |

第二张 Sheet：

| 指标 | 结果 |
| -- | --: |
| 标准路径数 | 19 |
| 生成路径数 | 19 |
| 成员集合完全匹配 | 11 |
| 部分匹配或待确认 | 8 |
| 多生成路径 | 0 |
| `NEEDS_REVIEW` | 6 |
| `UNMATCHED` | 0 |
| route segment 一致性问题 | 0 |

完全匹配路径：

```text
P09, P10, P11, P12, P13, P14, P15, P16, P17, P18, P19
```

部分匹配/待确认路径摘要：

| 路径 | 状态 | 主要差异 |
| -- | -- | -- |
| P01 | NEEDS_REVIEW | 漏 SDF3/SDF7/SDF36；多 SDF39/SDF74/SDF75/SDF76/SDF79；漏 BI02；多 SI2/SI14/SI15 |
| P02 | NEEDS_REVIEW | 漏 SDF20/SDF22；多 SDF31/SDF33/SDF34/SDF36/SDF60/SDF61/SDF63/SDF64/SDF73/SDF77/SDF80；多 SI4/SI14/SI15 |
| P03 | NEEDS_REVIEW | 漏 SDF39；多 SDF30；漏 BI01/BI02；功能粒度有 F7.3 与 F7.3.x 差异 |
| P04 | NEEDS_REVIEW | 漏 SDF41/SDF42/SDF65；多音视频上行分支 SDF24-SDF33；漏 SI7，多 SI1/SI2/SI3 |
| P05 | CONFIRMED | BDF/SDF/BI/SI 全匹配；功能集合多 F2/F3/F4.5/F5/F7.1 |
| P06 | NEEDS_REVIEW | 漏 SDF59/SDF78/SDF80；功能集合粒度不同 |
| P07 | NEEDS_REVIEW | 漏 SDF43；功能集合粒度不同 |
| P08 | CONFIRMED | BDF/SDF/BI/SI 全匹配；功能集合多 F5 |

解释：

- P09-P19 为维护边界路径，结构化事实足以确定，已完全匹配。
- P05/P08 的结构成员已匹配，差异主要是功能粒度；当前保留结构化事实中出现的更多功能，不用标准 03 文本反向删减。
- P01-P04/P06/P07 涉及“业务路径语义分组”和“内部关键路径选择”，01/02 中没有足够字段唯一表达标准 03 的人工归并意图，因此保留 `NEEDS_REVIEW`。

## 14. 已知限制

- `pathRules.ts` 是 F3532 当前项目规则，不是跨项目通用规则。
- P01-P04/P06/P07 仍需要人工审核或补充源数据语义，例如业务主题、关键内部路径种子、终止节点和功能粒度映射。
- 功能集合当前采用结构化事实并集，可能比标准 03 文本更细或更多；没有用标准 03 反向硬删功能。
- `commitF353203Paths()` 对已有 Approved 路径采取保守阻断策略，尚未实现按路径范围的细粒度人工结果保护。
- 未实现输入 workbook hash、GraphVersion 过期标记和完整审核工作流。
- 前端展示了预览/提交入口，但没有完整呈现每条 evidence 的审计树。
- 构建仍有 Vite chunk size warning，和本次 F3532 生成逻辑无关。
- 仓库中存在任务开始前的脏文件，本次未处理。

## 15. 尚待人工确认的问题

- P01/P02 中哪些内部状态、告警、维护、控制 SDF 应属于同一业务路径，哪些应拆为独立路径。
- P03 是否应把 `SDF39` 这类下行语音数据归入音视频上行路径。
- P04 中开放环境感知输入是否只保留 DAAS/IMS 避障分支，还是同时包含 AVCS/DLS/RCS 上行分支。
- P06/P07 的内部关键路径应按拓扑闭环、功能闭环还是安全评估关注点来界定。
- 功能 ID 是否需要父子折叠规则，例如 `F7.3.1/F7.3.2/F7.3.3` 是否折叠为 `F7.3`。
- P05/P08 结构成员匹配但功能集合多出时，正式报告应保留事实并集还是按标准文本折叠。

## 16. 后续建议

| 优先级 | 建议改什么 | 为什么要改 | 涉及文件 | 预期收益 | 改造风险 |
| -- | -- | -- | -- | -- | -- |
| P0 | 增加路径规则的人工审核配置字段，如 `expected_function_rollup`、`required_sdf_ids` 的“审核参考”而非算法硬编码 | 解决功能粒度和人工路径语义差异 | `pathRules.ts`、`businessPathRuleEngine.ts`、验证脚本 | P01-P08 可解释地收敛 | 需要明确哪些字段是规则事实，哪些是 Golden 对齐参考 |
| P0 | 增加输入数据中的业务主题、路径种子、终止节点字段 | 01/02 当前缺少唯一推导标准路径的语义 | Excel 模板、导入、`factNormalizer.ts` | 减少 `NEEDS_REVIEW` | 需要模板变更和历史数据迁移 |
| P1 | 增加功能父子折叠规则 | 标准 03 常用父级功能，源数据可能有子功能 | 新增 `functionTaxonomy.ts`、报告组装 | 减少功能集合差异 | 需确认 F 编号层级含义 |
| P1 | 完整实现 03 审核会话和输入 hash | 防止旧输入覆盖新结果，保护人工确认 | `graphRepository.ts`、routes、前端 | 数据库安全闭环 | 涉及状态模型 |
| P1 | 前端展示 evidence/warnings 明细 | 让用户知道路径为什么生成 | `App.tsx`、类型 | 可解释性提升 | UI 复杂度上升 |
| P2 | 把规则配置改为 JSON/YAML 并做启动时 schema 校验 | 非开发人员更容易审查规则 | `config/f3532/*` | 可维护性提升 | TypeScript 类型约束要迁移 |
| P2 | 增加更多真实 Golden case | 防止只适配当前 F3532 工作簿 | 测试、脚本、样例数据 | 泛化能力提升 | 需要更多标注数据 |
