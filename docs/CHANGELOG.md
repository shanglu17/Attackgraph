# 项目修改总记录

整合日期：2026-09-21。今后的修改、验证与实施进度统一追加到本文件。

## 当前状态

已完成研究审计与数据/实验框架、中文论文草稿、特征规则求值/API/CLI和数据导入工作区中的特征规则预览页面。原有业务入口保留；六条领域规则仍禁用待审，论文效果实验未执行。

最近一批验证记录为后端31项、前端5项、研究Python15项测试通过，前后端构建通过，并完成三档视口及页面交互检查。这些是历史执行记录，本次文档合并没有重新运行业务测试。完整数据库端到端回归仍待完成。

## 本次整合步骤与范围

1. 清点并完整收录11份修改说明、执行记录、验证说明和已执行阶段计划。
2. 每份原文以独立锚点、原路径、原始SHA-256及原文块保存；按原始字节核对后删除旧文件。
3. 修复现存文档引用；研究包校验器从总记录读取归档文档，继续校验原始哈希。
4. 运行归档完整性、删除清单、引用和研究包检查。业务代码、原稿及实验数据不因整合发生改变。

当前投稿计划、审计/差距报告、方法文档和文献检索记录是持续使用的研究材料，保留独立文件。JSON哈希清单、来源清单、机器验证输出仍由程序使用，保留原位置；它们不再作为分散的人读修改日志入口。

## 阅读说明

下文逐字收录原记录，保留当时的状态与验证范围。旧记录中的“未实现”“未改代码”等属于该阶段，不能覆盖较新记录。原文块中的路径按原文件所在目录解释；其旧日志文件已合并，使用本页目录定位。原记录里的计划不自动代表已完成，测试数据不代表论文实验。

## 归档目录

- [记录 01：Attackgraph/docs/f3532-03-generation-refactor-record.md](#record-01)
- [记录 02：Attackgraph/docs/superpowers/plans/2026-09-20-f3532-import.md](#record-02)
- [记录 03：论文/母稿V3_修改说明.md](#record-03)
- [记录 04：docs/superpowers/plans/2026-09-21-aerospace-research-package.md](#record-04)
- [记录 05：docs/VALIDATION.md](#record-05)
- [记录 06：docs/cose/EXECUTION_STATUS.md](#record-06)
- [记录 07：docs/cose/VALIDATION.md](#record-07)
- [记录 08：docs/superpowers/plans/2026-09-21-feature-preview.md](#record-08)
- [记录 09：docs/cose/IMPLEMENTATION_STATUS.md](#record-09)
- [记录 10：docs/superpowers/plans/2026-09-21-feature-preview-ui.md](#record-10)
- [记录 11：docs/cose/UI_INTEGRATION_STATUS.md](#record-11)

<a id="record-01"></a>

## 记录 01：Attackgraph/docs/f3532-03-generation-refactor-record.md

原始 SHA-256：`c6ee77dded77ef565d6a9dc4edc3aba93b53945afd786ac7fdeda2074268f1c1`

``````markdown
<!-- ARCHIVE_BEGIN Attackgraph/docs/f3532-03-generation-refactor-record.md -->
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

<!-- ARCHIVE_END Attackgraph/docs/f3532-03-generation-refactor-record.md -->
``````

<a id="record-02"></a>

## 记录 02：Attackgraph/docs/superpowers/plans/2026-09-20-f3532-import.md

原始 SHA-256：`ffdc744ba8b85082cb40d79b235a121cd49137d4342faa765cb53b1ed56c1b7a`

``````markdown
<!-- ARCHIVE_BEGIN Attackgraph/docs/superpowers/plans/2026-09-20-f3532-import.md -->
# F3532 导入体验与性能计划

**Goal:** 导入指定 01/02 文件，明确中文入口并减少导入等待时间。
**Architecture:** 文件读取并发；解析与预览合并；SDF 写入在原事务内分阶段批处理，保留校验、回滚与依赖顺序。
**Tech Stack:** React / TypeScript / SheetJS / Neo4j。

- [x] 浏览器导入用户两份 Excel，验证无警告及提交成功。
- [x] 测量原 SDF 写入时间，在回滚事务中保存结果基线。
- [x] 添加并发读取和 SDF 属性/关系替换/空集合回归测试，先验证失败。
- [x] 更新 f3532Workbook.ts；将 F3532ImportPanel 移到 features/imports，中文文件卡片、解析并预览、耗时与防重复提交。
- [x] 批量写入 SDF，保持事务和业务语义；对比新旧结果与耗时。
- [x] 构建、现有测试、真实数据库回滚测试；浏览器验证 1440/1280/390 视口及四工作区状态。

## 验证结果

- 浏览器原始导入：4c5b3152-fefb-46ec-b109-70d5fcd88cf2。
- 优化后导入：7a578210-2f18-4292-b156-6bee9cf9828d；图谱 JSON 忽略版本号、集合顺序后完全一致。
- 真实工作簿：BI 24、BDF 57、SI 17、SDF 82、TA 11、SB 3，无预览警告。
- 82 条 SDF：246 次查询减少为 3 次；同一数据库回滚事务，预热后 5 轮。
  - 原实现：269.69 / 265.68 / 255.26 / 251.22 / 241.95 ms。
  - 批处理：143.65 / 141.12 / 138.96 / 131.76 / 137.62 ms。
  - 中位数 255.26 → 138.96 ms；每轮属性和关系均与原实现一致。
- 浏览器解析与预览 0.06 秒、提交 4.42 秒；阶段性能不等于端到端性能。
- 后端原 12 项测试、并发读取测试、数据库关系替换/空集合/重复 ID/回滚测试通过。
- 前后端构建通过；1440×900、1280×800、390×844 无页面横向溢出；四工作区切换保留导入状态。
- 复用 panel、preview-card、field-stack、button、status；只增加文件卡片布局类。
- 独立代码审查无新增问题。App.tsx 遗留大文件和其余逐条数据库写入仍是后续技术债。

<!-- ARCHIVE_END Attackgraph/docs/superpowers/plans/2026-09-20-f3532-import.md -->
``````

<a id="record-03"></a>

## 记录 03：论文/母稿V3_修改说明.md

原始 SHA-256：`366b75abfef7ef5af27342d9501c452923dc08fc3610e50d9dea9f97ca512cd5`

``````markdown
<!-- ARCHIVE_BEGIN 论文/母稿V3_修改说明.md -->
# 母稿 V3 修改说明

本轮基于《母稿V2.docx》生成《母稿V3_优化稿.docx》，原稿保留。保留六章结构、两幅原图和七张表，对正文与表格内容进行了重写和整合。

## 使用的 Skill 与资料

- 按用户指定下载并使用 anti-defensive-writing Skill，项目内目录为 `.agents/skills/anti-defensive-writing-Skill`，版本 `102c8b21acf5eda3a0aef3d9779a65db646c8980`。
- 采用“贡献先行、证据支撑、集中讨论验证范围”的写法，删减自我辩护式表述，保留影响结论成立的条件。
- 对照《六维特征式问卷与AI辅助实现方案.docx》《DO-356A_证据点重构说明_V2.pdf》，以及 Attackgraph 的实现与实验归档。

## 主要修改

1. 题目调整为“面向 DO-356A 的航电威胁建模与证据追溯方法”；摘要、引言和结论围绕“工程事实—候选威胁—路径—证据”的主线展开，明确论文贡献。
2. 六维画像改为可核对的事实特征，补充对象域、运行上下文、必备条件、支持特征和保护条件；未知项进入补证流程，避免直接视为低风险。
3. 区分方法设计与已有原型实现。六维规则验证和 AI 辅助属于后续工作，未写成已经完成的实验成果。
4. 将 T.* 编码明确为本文规则库的候选标签，避免未经核实地称作标准官方编码。将 58 项明确为研究材料重构的证据清单，避免等同于标准的 58 条等权要求。
5. 用仓库归档实验补充第 4 章及表 7：无约束 DFS 共 1590 条序列，其中 1534 条含节点回访；原型生成 12 条无环目标路径。明确两者终点口径不同，数量差不能直接证明准确率或处理效率提升。
6. 调整 DO-356A 年份、参考文献及标准映射表述；将内部研究材料和实验记录标为未发表资料。
7. 统一标题、正文和表格样式，修正表格宽度及跨页问题。Word 导出检查版共 9 页，已逐页检查；两幅图与原稿一致。

## 数据与来源

实验数据来自 `Attackgraph/docs/experiments/do356a-baseline-vs-system-EXP-1775632053899.json`，归档日期为 2026-04-08。本轮核对了归档内的数量、循环情况和路径长度分布，没有重新运行实验，也没有修改运行中的数据库。

标准书目信息及方法背景参考以下公开来源：

- [RTCA DO-356A 产品页](https://my.rtca.org/productdetails?id=a1B36000006xdusEAA)
- [RTCA Security](https://www.rtca.org/security/)
- [Microsoft STRIDE 威胁分类说明](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [Bruce Schneier：Attack Trees](https://www.schneier.com/academic/archives/1999/12/attack_trees.html)

## 后续完善重点

- 六维规则识别：建立专家标注集，验证查准率、查全率和规则适用条件。
- 路径算法：统一入口、目标和跳数口径，再做对照与消融；如主张提效，需要记录运行耗时或人工审查工时。
- 证据覆盖：补充 58 项逐项判定矩阵、适用范围、去重规则及审查记录，再报告覆盖率。
- 标准对应关系：以受控版本标准逐项复核条款与候选威胁标签的来源。当前稿件表达方法对分析活动的支持，不构成合规认定。
- 插图：图 2 保留原图 DO326A_Link 字段名，并在正文说明与 DO356A_Link 逻辑对象的关系；正式投稿前建议统一图中文字，同时确认两图来源与使用权限。
- 参考文献：按目标期刊格式整理，并补充直接相关的近期研究和完整实验材料。

本稿完成了文字、结构和已有证据的整合；上述验证材料仍需实际研究补齐。

<!-- ARCHIVE_END 论文/母稿V3_修改说明.md -->
``````

<a id="record-04"></a>

## 记录 04：docs/superpowers/plans/2026-09-21-aerospace-research-package.md

原始 SHA-256：`65d54c8e1548a1a7eea818cfc42f6a084b16747031625e30faf8699053021911`

``````markdown
<!-- ARCHIVE_BEGIN docs/superpowers/plans/2026-09-21-aerospace-research-package.md -->
# Aerospace Research Package Implementation Plan

**Goal:** 审计现有原型并建立可追溯的论文、数据和实验准备包，不改写业务代码，不产生虚构结果。

**Architecture:** 在工作区根目录建立研究侧文件；Scenario Adapter 仅导出供现有原型验证的 ChangeSet 草案及 sidecar，不连接或写入数据库。六维规则独立版本化，来源中的示意规则保留待审状态。

**Tech Stack:** JSON Schema 2020-12、UTF-8 CSV、Python 标准库、Markdown；用已有运行时执行校验。

## Global Constraints

- 母稿 V2 保留；最新问卷优先；PPT 作为结构参考。
- 不发明 Threat ID、标准条款、参考文献和实验值。
- 未知结果采用 null/None/TODO；正文采用 [RESULT_TODO:xxx]。
- legacy 和 feature-based 方法分别保留，不将路径评分等级当成六维等级规则。
- 不改动 Attackgraph 业务文件，不运行清库或 seed。

## Tasks

- [x] 1. 读取四份材料并建立来源文本与 SHA-256 清单；扫描类型、校验、导入、路径、规则、证据、报告及 AI 调用，记录文件与行号。
- [x] 2. 生成 PROJECT_AUDIT、GAP_ANALYSIS、AEROSPACE_TODO；严格采用三种功能状态，记录数据和实验限制。
- [x] 3. 建立六类 JSON Schema、来源 Threat ID 白名单、六条示意规则迁移和 legacy 存档；规则激活前保留人工语义审查门槛。
- [x] 4. 先验证研究模块缺失的失败断言，再实现独立 adapter 和四套实验骨架；补充无标签、空预测、缺映射、重复 ID、未知Threat ID、参考标签一致性等测试。跨文件证据引用验证仍列为接入任务。
- [x] 5. 输出英文 outline 后生成 draft；围绕四个 RQ，保留结果占位和参考文献核验项。
- [x] 6. 校验 schema 与规则引用、运行实验空输入检查与单元测试，核对业务目录文件哈希未变化；形成交付索引和验证记录。

## Verification

运行 `python -m unittest discover -s experiments/tests -v`；运行 `python -m experiments.run_all --output experiments/output`；检查空输入所有指标均为 null 并附原因；校验六个模型与规则文件；审查适配器不把 reference labels 送入预测输入。原型功能结论以代码核查为依据，未复测的运行行为明确标记。


<!-- ARCHIVE_END docs/superpowers/plans/2026-09-21-aerospace-research-package.md -->
``````

<a id="record-05"></a>

## 记录 05：docs/VALIDATION.md

原始 SHA-256：`d96a6baf234450dd5ec3a61fa48b8aeecc9253e8f07cae72f48fb5220bfb847b`

``````markdown
<!-- ARCHIVE_BEGIN docs/VALIDATION.md -->
# Validation record — 2026-09-21

## Executed checks

| 检查 | 结果 |
|---|---|
| `python -m unittest discover -s experiments/tests -v` | 15 tests, OK；测试覆盖未知标签/缺预测/空预测区别、不同参考标签拒算、重复评价单元、消融单位一致性、参考答案隔离、无映射不猜默认值等 |
| `python -m experiments.run_all --output experiments/output` | 四个空输入骨架输出；所有指标 null 并附原因 |
| `python -m experiments.scenario_adapter --output experiments/output/adapter_draft.json` | 空参考集返回 TODO_REVIEW、change_set=null，无原型调用 |
| `python -m docs._work.verify_research_package` | 6 Schema、6规则；拒绝未审启用/未知Threat ID；adapter sidecar通过三类模型校验；legacy副本与来源逐字节一致 |
| 原型与源材料 SHA-256 | 92个原型文件、5份文档未变化 |
| 审计矩阵计数 | IMPLEMENTED 6 / PARTIAL 10 / MISSING 3 |
| PDF直接覆盖列表算术复核 | 去重23点，前期18、后期5；这不是对支撑判定正确性的独立验证 |

## Reproduction environment

执行所用 Python：`C:/Users/97301/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe`。

实验脚本使用标准库。Schema检查额外使用隔离在 `docs/_work/validation_deps` 的 jsonschema 4.23.0（wheel安装）；未改原型package.json或全局Python包。依赖版本：attrs 26.1.0、jsonschema-specifications 2025.9.1、referencing 0.37.0、rpds-py 2026.6.3、typing-extensions 4.16.0。机器可读记录为 `_work/verification.json`，原始哈希记录在 `_work/material_manifest.json` 和 `_work/prototype_hashes_before.json`。

## Not asserted

没有运行E1–E4真实实验；没有实现或接入完整规则求值器；没有验证参考文献案例、官方Threat ID词表、受控标准全文；没有修改或写入数据库；没有将此前路径枚举归档变为本轮识别准确率。未修改网页行为，因此本轮无浏览器交互验证。所有原型能力判断是带文件依据的代码审计，不等于本轮全部端到端复测。

<!-- ARCHIVE_END docs/VALIDATION.md -->
``````

<a id="record-06"></a>

## 记录 06：docs/cose/EXECUTION_STATUS.md

原始 SHA-256：`1a1ab294c3adc2ec97dba120eab9213e00fa0e23d47450ec862c7282dff2fa25`

``````markdown
<!-- ARCHIVE_BEGIN docs/cose/EXECUTION_STATUS.md -->
# Computers & Security 计划执行记录

2026-09-21｜第一批研究整理交付；整体计划尚未完成

后续更新：用户已授权保留功能的原型增量修改；实验性求值、API与CLI已实现，见[第二批实现记录](IMPLEMENTATION_STATUS.md)。下表保留第一批交付时状态，D阶段当前为PARTIAL，领域审查和正式实验仍未通过。

## 已产出

| 阶段 | 交付 | 进度与门控 |
|---|---|---|
| A | 7项文献矩阵；贡献—证据表 | PARTIAL：已排除“规则+图”“考虑保护”作为独有贡献；需补近期及未知/证据相关工作，G1未通过 |
| B | 攻击者模型；四值条件与决策表；6条规则逐项审查表 | PARTIAL：形成可审核提案，实际领域批准0，G2未通过 |
| C | 2项来源登记、5条开发场景、空参考标签、输入隔离与来源族划分 | PARTIAL：全部待独立复核；test为空，G3未通过 |
| D | 明确研究Schema缺口和TDD验收用例 | NOT_STARTED：按原计划先完成G2；未新增求值器或改变原型，G4未通过 |
| E | 实验协议0.1及错误分析登记规范 | DRAFT：未冻结、未执行、无新增实验结果，G5未通过 |
| F | 独立C&S中文提纲与研究草稿；投稿检查表 | DRAFT：保留结果占位；未形成投稿包，G6未通过 |

## 本轮关键决定

1. 论文主贡献候选聚焦证据不完整、保护范围及判定证书，尚不声称已证明新颖。
2. 源规则继续禁用，reviewer和review_basis不代填。尤其审查设备盗取与失窃后影响、静态加密与运行态访问、签名存在与强制验证之间的区别。
3. 五条场景是提取草稿，不是五个独立测试样本；ILS相关来源保守同族。参考Threat ID保持空。
4. 语义提案的机器decision不能混入人工status；现有Schema的自由文本scope和规则级exclusion_effect需在审定后扩展。
5. 当前不重写原型。图、导入、遍历和报告基础继续保留；新方法先在独立研究层验证。

## 下一批工作及依赖

可以继续独立推进：扩充近期/不完整信息相关工作；寻找维护、装载及保护有效性场景；核对ThreatGet的PDF/实现语义；完善特征逐项定义与受控用例设计。

需要领域复核后推进：六条规则最终动作、特征适用范围和标签解释。审查载体为RULE_REVIEW.csv，需真实审查人及依据；这些信息不能由研究助手虚构。

需要独立评价材料：正式E1、完整precision/recall/F1、消融误报/误排除与工程工时。当前均不可报告效果数值。

一周内可合理推进文献比较、语义审查准备及更多开发场景采集；独立规则批准、参考裁定与人员研究取决于领域支持，不能用自动检查替代。

## 文件入口

- [贡献与证据](CONTRIBUTION_AND_CLAIMS.md)
- [文献矩阵](RELATED_WORK_MATRIX.csv)
- [攻击者模型](THREAT_MODEL.md)
- [规则语义提案](RULE_SEMANTICS.md)与[逐规则审查表](RULE_REVIEW.csv)
- [场景采集规范](SCENARIO_CURATION.md)与[开发场景](../../data/cose/reference_scenarios.csv)
- [实验协议](../../experiments/cose_protocol.md)
- [C&S中文提纲](../../paper/Computers_Security_outline_zh.md)与[中文研究草稿](../../paper/Computers_Security_draft_zh.md)
- [投稿检查表](SUBMISSION_CHECKLIST.md)

实际文件校验结果另见VALIDATION.md；不能将结构检查解释为领域有效性。

<!-- ARCHIVE_END docs/cose/EXECUTION_STATUS.md -->
``````

<a id="record-07"></a>

## 记录 07：docs/cose/VALIDATION.md

原始 SHA-256：`a01d6bad3ed8c80ce55b7e861773d6f1215038ebae305cabfd0bba0aa8eb6b8a`

``````markdown
<!-- ARCHIVE_BEGIN docs/cose/VALIDATION.md -->
# 本轮验证记录

2026-09-21，使用Codex随附Python实际执行并检查输出。

## 检查结果

- 既有研究脚本：`python -m unittest discover -s experiments/tests -v`，15项通过。
- 研究包检查：`python -m docs._work.verify_research_package`，6类Schema及6条禁用规则通过；92个已登记原型文件、5份原始材料哈希未变。
- 新数据检查：7项文献、6条规则审查、2项来源、5条开发场景；17列CSV结构与跨文件ID对应通过。
- 两份来源PDF的SHA-256与来源登记一致。
- 正式批准规则0条、独立复核场景0条、测试集0条；没有生成参考Threat ID。
- 输入侧框架不含参考路径或预期标签字段；资产、特征和边仍为空，等待独立抽取，不能运行预测。
- 检查了当时10份新增Markdown的本地链接及编码，结果通过。

结构化结果见[validation.json](validation.json)。这些是文件和软件处理逻辑检查，不是新方法效果、来源标注正确率或领域批准。

本轮未执行原型、seed或数据库操作，未运行正式E1–E4。新增中文研究稿保留RESULT_TODO。原型不变的哈希结论限定于原有清单登记的92个文件，不扩大为整个工作目录逐字节不变。

<!-- ARCHIVE_END docs/cose/VALIDATION.md -->
``````

<a id="record-08"></a>

## 记录 08：docs/superpowers/plans/2026-09-21-feature-preview.md

原始 SHA-256：`48ddd5c52f77e8729c33897777836505f26835c341c118ca1054ec25158a0aa4`

``````markdown
<!-- ARCHIVE_BEGIN docs/superpowers/plans/2026-09-21-feature-preview.md -->
# 特征规则预览 Implementation Plan

**Goal:** 在保留原型已有功能的前提下，增加无数据库写入的可测试条件求值接口。

**Architecture:** 新增纯函数求值服务、版本化请求契约和独立Express路由；既有总路由仅增加挂载。研究记录沿用六类契约中的资产/特征/规则/证据；新增作用域与逐项保护策略作为配套记录，不修改旧数据或默认分析。

**Tech Stack:** TypeScript、Zod、Express、node:test/tsx；复用现有依赖。

## Global Constraints

- 用户已授权保留功能的增量修改；保留所有已有未提交改动。
- 不自动批准6条来源规则，不编造实验、参考标签、审查人或Threat ID。
- 新接口不创建ThreatPoint，不写Neo4j，不调用seed，不取代现有AP/F3532分析。
- 所有拟议语义标记experimental，软件测试夹具不作为论文实验。

## 接口与文件

- 新增 `Attackgraph/apps/backend/src/services/featureRules/contract.ts`：校验完整研究记录及配套scope/policy，限额防止笛卡尔积失控。
- 新增 `.../evaluate.ts`：`evaluateFeatureRules(input: unknown)`，返回每个scope/rule的完整decision及引用。
- 新增 `.../evaluate.test.ts`：使用明确synthetic_test_only夹具验证命中、unknown、冲突、失配范围、未审规则、引用与确定性。
- 新增 `Attackgraph/apps/backend/src/routes/featureRules.ts`，总路由挂载`POST /analysis/feature-rules/preview`。
- 新增 `.../featureRules.test.ts`：真实HTTP验证200/400和旧health端点兼容，随机本地端口且不启动数据库。
- 文档 `Attackgraph/docs/feature-rule-preview.md` 说明请求、语义与限制。

## 顺序与验收

- [x] 写黑盒服务测试，先观察缺失服务导致失败，再实现并检验。
- [x] 实现版本化证据/范围解析；空scope或未审证据保持unknown；不以absence of record作absent。
- [x] 未批准/禁用规则输出rule_not_executed；已批准规则仍需逐项保护动作、阶段政策和可解析审查依据。
- [x] 写真实HTTP路由测试并观察404，然后注册路由并通过测试。
- [x] 执行新测试、原后端/前端回归及整体构建，检查git diff保留现有功能。
- [x] 保存使用文档与当前进度；说明正式领域规则与实验仍待审，不能把软件验证当方法有效性。

补充交付：无数据库离线CLI及明确标注的待审规则模板。验收详见`docs/cose/IMPLEMENTATION_STATUS.md`。

单规则决策优先级：禁用/待审 → 对象域 → 策略/上下文 → required → 逐项保护。机器decision与人工status分开。保护作用域要求精确scope ID，scope记录绑定资产、链路、阶段及攻击者假设；不推断通配范围。

<!-- ARCHIVE_END docs/superpowers/plans/2026-09-21-feature-preview.md -->
``````

<a id="record-09"></a>

## 记录 09：docs/cose/IMPLEMENTATION_STATUS.md

原始 SHA-256：`41c21ef1226173e1448dc33f001009a2aef345df315c4908708db46dd7ce7858`

``````markdown
<!-- ARCHIVE_BEGIN docs/cose/IMPLEMENTATION_STATUS.md -->
# 第二批：特征规则预览实现

本页记录第二批历史状态；后续页面接入和当前验证见 [UI_INTEGRATION_STATUS.md](UI_INTEGRATION_STATUS.md)。

2026-09-21｜用户已授权在保留原有功能前提下修改原型

## 已实现

新增实验性确定性求值服务，支持必备条件组间AND/组内OR、未知/冲突、精确作用范围、阶段和攻击者政策、逐项block/downgrade、未审规则拒绝执行、引用检查、输入哈希和顺序无关的输出。

两种入口使用同一个纯函数：

- `POST /analysis/feature-rules/preview`：已挂载至原后端路由；结构和引用错误返回400。
- `node --import tsx scripts/preview-feature-rules.ts <bundle.json>`：离线运行，无需数据库。

使用说明与模板见[feature-rule-preview.md](../../Attackgraph/docs/feature-rule-preview.md)。源代码位于`Attackgraph/apps/backend/src/services/featureRules/`，接口位于`apps/backend/src/routes/featureRules.ts`。

新增模块不创建正式ThreatPoint、不写Neo4j、不调用seed、不替换旧导入/AP/F3532分析。现有后端文件只修改总路由挂载（2行）与测试命令，其余实现为新增文件；本轮前已有未提交的导入优化保留。六类研究Schema和6条实际规则未修改。

## 实际验证

| 检查 | 结果 | 能说明什么 |
|---|---|---|
| 后端`npm test -w @attackgraph/backend` | 31项通过，含12项旧F3532和19项新求值/API/CLI检查 | 覆盖对应的软件行为，不等于航电规则有效性 |
| 前端`npm test -w @attackgraph/frontend` | 1项通过 | 双文件读取并行回归 |
| `npm run build` | 前后端构建通过；末次后端更新后重新构建通过 | TypeScript与打包检查 |
| 研究Python测试 | 15项通过 | 原有适配器与实验门控未破坏 |
| 原始文件校验 | 92项旧清单中90项不变，2项符合授权变更哈希；5份原材料不变 | 未覆盖全盘文件或数据库状态 |
| 离线模板实际运行 | 返回rule_not_executed，执行数0 | 未审源规则没有被自动启用；不是无威胁结果 |
| 浏览器检查 | 当前页面能切换数据导入，01/02双文件选择和预览入口可见 | 页面入口可用，未执行导入提交或完整数据库端到端流程 |

先观察求值候选测试、HTTP404、攻击者范围及未定保护动作测试失败，再实现通过。完整测试输出见本次任务工具记录。`git diff --check`通过；Git提示本地LF/CRLF转换，未报告空白错误。

当前常规后端4000端口未监听。HTTP集成测试采用真实Express随机本地端口，无需启动数据库；离线CLI可直接使用。未宣称当前主页面已能操作新功能，也未自行导入数据填充页面。

## 尚未完成及下一步

1. G2领域审查未通过：6条实际规则仍禁用。政策与证据的verified/APPROVED是输入声明，当前模块不验证审查人身份或原文真实性。
2. G4为PARTIAL：已完成实验性求值和引用结构检查；尚无审定领域规则回归、完整图路径桥接和最终人审工作流。
3. 新接口采用scope/policy配套契约；逐项保护动作优先于保留的旧规则级动作。下一步需完成领域复核和正式契约升级，不能直接把当前版本写为最终语义。
4. 页面仍使用原有流程，新功能目前供API/CLI研究预览。后续可增加独立的特征审查入口，并显式区分预览与图谱提交。
5. E1–E4仍未执行效果实验。参考场景需要独立输入提取与标签复核；核心F1、误报/误排除及工时不能报告。

当前优先级：规则/作用域复核 → 参考集输入抽取 → 审查界面与路径桥接 → 冻结实验协议。无需重写原型，也无需引入LLM来填补尚缺证据。

<!-- ARCHIVE_END docs/cose/IMPLEMENTATION_STATUS.md -->
``````

<a id="record-10"></a>

## 记录 10：docs/superpowers/plans/2026-09-21-feature-preview-ui.md

原始 SHA-256：`29a176c478303dbe51ad1c5d8b6eb03f40f14849e952b9fb1733f9070ec1631d`

``````markdown
<!-- ARCHIVE_BEGIN docs/superpowers/plans/2026-09-21-feature-preview-ui.md -->
# 特征规则分析页面 Implementation Plan

**Goal:** 在数据导入工作区增加数据包预览、证据查看和导出，保留旧入口与切换状态。
**Architecture:** 提取ImportWorkspace；新增独立FeatureRulesPanel；api.ts统一请求；types.ts定义响应；不扩展App业务状态。
**Tech Stack:** React/TypeScript、已有基础样式、node:test、真实浏览器验证。

## 任务

- [x] 测试输入编辑使旧结果失效、错误输入、零执行不显示零威胁、完整输入输出导出。
- [x] 新增src/features/featureRules/model.ts、FeatureRulesPanel.tsx；新增api.ts接口和types.ts响应类型。
- [x] 提取src/features/imports/ImportWorkspace.tsx，保持旧三种导入组件及回调，增加第四子页；隐藏而不卸载。
- [x] 验证真实HTTP成功、待审、错误、证据详情、切换保留与导出。
- [x] 检查1440×900、1280×800、390×844；运行前后端回归与构建。
- [x] 更新授权变更清单和实现记录，保留原规则及原论文，不创建实验结果。

页面控件：文件选择、可编辑JSON、载入待审模板、运行预览、导出输入和结果。编辑/载入新文件立即清空旧结果；加载中禁用编辑和重复提交。错误保持输入供修改。结果列出每条rule/scope决策及证据定位；明确“未执行”与“候选数”的区别。

<!-- ARCHIVE_END docs/superpowers/plans/2026-09-21-feature-preview-ui.md -->
``````

<a id="record-11"></a>

## 记录 11：docs/cose/UI_INTEGRATION_STATUS.md

原始 SHA-256：`20a0c2bc3fc151ef88e76f7c2784d691f86dbc6d77ac623f1436af6e6f6972c4`

``````markdown
<!-- ARCHIVE_BEGIN docs/cose/UI_INTEGRATION_STATUS.md -->
# 第三批：特征规则页面接入

2026-09-21。入口为“数据导入 → 特征规则分析”。本页更新第二批实施记录中的“页面待接入”状态。

## 已交付

- JSON研究数据包导入、待审模板、编辑、真实HTTP预览、完整输入与结果导出。
- 每个规则/作用域的条件分组、四值状态、保护策略、版本、证据定位与复现哈希。明确区分未执行、候选和人工审查。
- 编辑、文件切换和请求失败均使旧结果失效；处理中禁用重复操作。
- 提取ImportWorkspace，保留原有三种导入组件和回调。四个顶层工作区不变，隐藏而不卸载；App.tsx从本轮前915行降至875行。
- 复用panel、toolbar、button、input-field、status和preview-card样式，仅增加局部换行与编辑器样式。

## 验证记录

| 检查 | 实际结果 |
|---|---|
| 后端测试 | 31/31通过，包含原有12项F3532回归 |
| 前端测试 | 5/5通过，包含原有双文件并行读取与4项新状态/导出检查 |
| 研究Python测试 | 15/15通过 |
| 前后端构建 | npm run build通过，前端578个模块 |
| 浏览器请求 | 待审模板执行数0；合成软件夹具执行数1；可展开条件与来源 |
| 错误路径 | 非法JSON、本地契约错误、HTTP字段错误、服务停止后的连接错误均显示；输入保留、旧结果不可导出 |
| 页面切换 | 报告、变更、图谱、数据工作区往返后，输入与结果保留 |
| 导出 | 浏览器下载的feature-rule-preview.json与提交输入逐字段相等；完整响应与纯函数重算结果相等 |
| 响应式 | 1440×900、1280×800、390×844实际截图检查；页面scrollWidth分别1425、1265、375，无页面横向溢出 |
| 原始清单 | 92项中86项不变，6项与明确授权变更哈希一致；5份原材料不变 |

浏览器成功路径调用临时Express服务中真实的featureRules路由，没有模拟响应，也没有访问数据库。验证结束已停止该临时服务，避免将它误当完整后端。前端开发服务器仍在5173运行；常规后端/Neo4j依赖尚未恢复，本轮未完成带数据库的旧流程端到端回归。

## 保留的缺口

1. 六条领域规则仍是禁用的TODO_REVIEW。测试夹具中的批准状态仅用于软件检查，不构成专家审查或论文样本。
2. 页面是JSON研究预览；问卷式特征录入、最终人审、图路径桥接和完整报告接入仍待实现。
3. 控制台观察到隐藏图谱的ReactFlow容器尺寸警告，尚未处理。没有据此宣称全部页面无警告。
4. 判定原因保留机器代码；后续可补中文释义。当前未做大数据性能结论。
5. E1–E4效果结果仍为空；参考标签复核、审定规则、路径映射与真实工时数据仍是实验前置条件。

下一步先完善有来源的场景输入和待审规则材料，再接通路径追溯。不能用软件测试结果替代论文实验。

<!-- ARCHIVE_END docs/cose/UI_INTEGRATION_STATUS.md -->
``````

## 本次整合核验结果

11份归档原文SHA-256逐项一致，11个旧路径均已删除；剩余研究文档中没有旧日志文件名引用。研究包校验通过：84份原清单文件仍在原位且未变，2份原文档完整迁入本页，6份既有授权代码变更哈希一致，5份源材料不变。原始基线清单未改写。

## 2026-09-28：离线候选路径追溯

总记录已从工作区根目录移入`Attackgraph/docs/CHANGELOG.md`，原始内容SHA-256核对一致；研究文件中的引用及校验器路径已同步更新。此后继续在仓库内维护唯一总记录。

在既有规则求值后增加纯函数路径追溯及离线命令。研究资产须显式映射到原型资产，作用域须显式列出允许的边、目标资产和已定位证据；只为已执行的候选决策搜索给定图中的简单路径。输出保留规则/证据引用、图版本与内容哈希、映射哈希、节点/边序列、反向遍历标记及搜索截断状态。未映射、映射证据未复核、未找到路径和搜索未完成分别记录。原有AttackPath的启发式分值、ThreatPoint与数据库保持独立。

复核时发现跳数上限可能把未搜索完误报为无路、邻接构建在高出度节点产生平方级成本，以及外部改写预览对象可能使路径起点与输入哈希不符。现已补回归测试并修复：明确标记跳数截断，邻接表原位构建且只复用当前作用域，追溯入口从原始数据包重新求值。后端43项、前端5项、研究Python15项通过；前后端TypeScript检查通过。Vite默认配置打包在当前隔离环境被目录读取权限阻断，使用其`--configLoader runner`后前端578模块构建通过。未运行Neo4j集成测试，也没有实际场景、领域审查或论文效果结果。路径仍仅为给定图的拓扑候选；图边目前无逐边证据字段，不能据此宣称攻击可行。

相关工作矩阵补录了Yao等2025年电力系统跨层贝叶斯攻击图研究（其观察节点表达检测证据不确定性）与El Bouzaidi Tiali和Amari于2025年发表的时间攻击建模/检测研究。仅使用出版社可检索的摘要、方法和结论片段核对；两篇全文均未获取，未声称它们缺失未描述的功能，也未把其案例当作本文实验数据。2026-09-28复核[Computers & Security期刊范围](https://shop.elsevier.com/journals/computers-and-security/0167-4048)，AI/ML重要组成部分的投稿暂停考虑这一政策仍在官网显示。

中文研究稿、规则语义和贡献表已同步到当前软件状态：四值预览和离线拓扑追溯属于已实现的软件机制；六条实际来源规则仍待领域审定，逐边证据、参考标签及论文效果尚未完成。未把合成测试写成实验结论。

独立参考资料筛选新增[Trask等的ARINC 429硬件在环研究](https://arxiv.org/abs/2408.16714)与[Khandker等的ADS-B实现测试研究](https://ieeexplore.ieee.org/document/9667309)。只在来源登记与划分清单中标为候选保留来源，未下载归档、未抽取场景或标签、未放入测试集，也未用其内容修改规则。ARINC研究已浏览摘要与方法段，ADS-B研究只核对出版社摘要。两篇题录、阅读范围和暴露记录已分别写入研究资料。

论文、研究方案、场景登记和实验框架仍保存在仓库外的工作区根目录`C:\Users\97301\Desktop\商飞`；本仓库提交包含原型代码、接口说明与本总记录，不包含这些本地研究文件及原始工程资料。

研究协议补充了保留来源的筛选、暴露记录与来源族隔离条件；投稿检查表区分已完成的软件机制和仍需领域复核的工作。中文C&S稿相关工作新增两项已经核实题录及出版社公开摘要的方法研究，限定比较任务，不补造结论或实验数值。

另在工作区`docs/cose/DOMAIN_REVIEW_PACKET.md`整理六条来源规则的逐项裁定问题、证据字段与参考场景的独立复核分工；它是交接模板，所有审核人、动作和参考标签仍待真实填写。

为避免历史审计被误读为当前状态，在首批交付索引、PROJECT_AUDIT、GAP_ANALYSIS和AEROSPACE_TODO页首添加快照说明，原始表格与审计结论保持不变。

工作区新增`docs/cose/SCHEMA_PREVIEW_CROSSWALK.md`，逐项核对六类研究Schema与原型`feature-preview-0.1`的输入、机器日志、结构化scope、逐项policy和路径映射。明确两者不是可互换的JSON契约，ThreatRecord与ReviewRecord仍没有正式原型写入工作流。

中文C&S稿的方法章补充了与当前求值器一致的四值事实合并、组内OR/组间AND、执行门控、保护动作优先顺序和路径截断语义；只描述软件机制，没有补造领域规则批准或实验效果。
