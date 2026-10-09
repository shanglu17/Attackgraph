# Phase 0：适航安保通用架构基线

- 状态：Accepted（合并后重新校准完成）
- 提出日期：2026-10-08
- 重新接受日期：2026-10-09
- 当前代码基线：`06ff8c6`
- 目标标准基线：DO-326A + DO-356A
- 前向兼容目标：DO-326B
- 当前实施范围：架构与治理文档，不修改业务代码或数据库

## 1. 已确认的产品定位

ASTRA 定位为：

> 审计就绪的适航安保工程辅助平台。

系统帮助工程人员建立模型、运行可解释分析、管理工作产品和证据，并维持端到端追踪。系统不自动宣称项目、产品或设计已经取得适航批准，也不以算法输出替代有资质人员的工程判断和批准活动。

第一版可以保持单用户部署，但领域模型和持久化结构必须从一开始支持多项目、多模型和多基线隔离。

## 2. 标准定位

- DO-326A 定义当前项目采用的适航安保过程与符合性目标基线。
- DO-356A 提供支撑该过程的工程方法和考虑事项。
- DO-326B 作为后续标准配置版本，不在首个 MVP 中实现全部差异。
- ASTM F3532 保留为可选适配器，不再定义通用核心模型。
- 标准版本必须通过 `StandardProfile` 显式配置，不得编码在通用实体名称、Neo4j 标签或通用 API 路径中。

## 3. 架构目标

目标架构包含通用核心和三个受控扩展维度：

```text
标准无关核心
  项目与版本、系统模型、安保分析、保证与证据、追踪与审计

标准适配层
  DO-326A profile、DO-356A method profile、F3532 adapter、未来 DO-326B profile

分析方法扩展层
  DFS/DPS、F3532 确定性生成、实验性特征规则预览、证据范围拓扑追踪

项目配置层
  项目编号规则、模板、枚举映射、批准的分析规则、报告布局
```

依赖方向固定为：

```text
项目配置 -----> 标准适配器 ------> 标准无关核心
项目配置 -----> 分析方法扩展 ----> 标准无关核心定义的分析端口
基础设施 -----------------------> 标准无关核心定义的端口
```

标准 profile 与分析方法是不同扩展维度。通用核心不得反向导入 F3532、ZG-ONE、FeatureRule 或某一份工作簿的规则。

## 4. 目标业务闭环

```text
项目范围与假设
  -> 功能、资产、接口、数据流与边界模型
  -> Threat Condition
  -> Threat Scenario
  -> Attack Path 与 Risk Assessment
  -> Security Objective
  -> Security Requirement
  -> Verification Case 与 Evidence
  -> Review / Approval
  -> Baseline / Report / Change Impact
```

每个环节必须可追溯到输入来源、所用规则、生成版本、人工评审和后续证据。

## 5. Phase 0 强制决策

1. 使用 Project、Model、Revision、Baseline 四级上下文隔离业务数据。
2. 数据库内部身份和工程业务编号分离。
3. 明确区分源事实、派生结果、人工评审结果和批准基线。
4. 标准差异通过 profile/adapter 表达。
5. 标准条款映射统一为可扩展 TraceLink，不继续扩展 `DO326ALink`。
6. 所有业务写入都必须具有项目范围、预期版本、事务和审计记录。
7. 数据库迁移必须显式执行；应用启动不得删除、去重或重写业务数据。
8. 生成结果必须保存输入基线、生成器版本、规则版本和可解释证据。
9. 已评审或已批准结果不得被重新生成流程静默覆盖。
10. 只有人工审批状态能够表达接受结论；算法分数不能表达标准符合性。
11. FeatureRule、Scope、Policy 等研究 DTO 作为版本化分析方法契约保留，不成为通用核心持久化实体。
12. `topology_candidate` 仅表示限定图快照中的拓扑候选；未经证据核验和显式晋级不得成为正式 AttackPath。
13. 输入 JSON 声明的 reviewer、verified 或 APPROVED 只是外部断言，不能直接成为平台 ReviewDecision。
14. 分析方法必须使用领域特定的 canonicalization；不得对有序路径步骤、审核事件或工作流历史进行通用数组排序。

详细理由见本目录中的 ADR。

## 6. 当前实现中需要保护的能力

通用化改造必须保留以下已验证能力：

- Neo4j 图结构表达能力；
- GraphChangeSet 的原子提交和冲突检测思想；
- 导入的解析、预览、提交三阶段流程；
- F3532 03 的确定性生成、规则证据和 Golden 对比；
- 攻击路径的循环控制、范围控制和解释信息；
- 特征规则预览的严格契约、四值逻辑、范围/策略门控、输入哈希和拒绝执行解释；
- 离线拓扑追踪的显式映射、证据检查、方向语义、搜索上限和截断状态；
- 系统数据流的批量事务写入优化，但不保留全局 ID 或静默 last-write-wins 语义；
- 前端 analysis/imports/reports/changes 四工作区结构；
- 已抽取的 ImportWorkspace、F3532 导入组件和并行文件解析能力；
- ZG-ONE 数据的稳定业务编号和既有报告输出。

“保留能力”不等于保留现有类、字段或 API 形状。迁移可以改变技术实现，但不得无说明地损失业务数据或可验证行为。

## 7. 本阶段不实施的内容

- 不修改 `domain.ts`、Zod schema 或前端类型；
- 不修改 Neo4j 标签、关系或约束；
- 不迁移已有数据库；
- 不重命名现有 API；
- 不改变 F3532 01/02/03/04 行为；
- 不把 FeatureRule/PathTrace 输出写入 Neo4j 或晋级为正式核心对象；
- 不调整 `/analysis/feature-rules/preview` 的运行时代码；
- 不实现登录、权限或电子签署；
- 不声称已经实现 DO-326A/DO-356A 的完整符合性流程。

## 8. Phase 0 出口条件

进入 Phase 1 前必须同时满足：

- 术语表覆盖现有和目标核心概念；
- 能力矩阵明确已有、部分和缺失能力；
- ADR 明确核心/适配器、版本、身份、追踪和迁移决策；
- ADR 明确标准 profile、分析方法和结果晋级之间的边界；
- 完成 [FeatureRule/Evidence/Scope/Policy 与目标领域模型的 crosswalk](./experimental-analysis-crosswalk.md)；
- 能力矩阵覆盖特征规则预览、拓扑候选追踪和合并后测试能力；
- 遗留数据迁移设计说明保留、转换、弃用与回滚规则；
- Phase 0–7 路线图明确每阶段输入、输出和出口门槛；
- 文档不存在把未来目标表述为当前已实现能力的情况；
- Phase 0 交付范围只有架构与治理文档变更；工作区既有的无关修改不纳入本阶段交付；
- 现有构建与测试基线不因文档变更而退化。

## 9. Phase 1 进入顺序

Phase 1 应按以下顺序实施，避免先改大表和界面：

1. 引入迁移账本和显式迁移命令；
2. 创建 Project/Model/Revision/Baseline；
3. 将现有全局数据挂接到默认遗留项目；
4. 将 GraphVersion 收敛到 Revision；
5. 引入内部 UUID 和项目内业务编号；
6. 增加兼容读取层；
7. 验证隔离、冲突、回滚和既有 F3532 回归结果；
8. 为现有实验分析入口增加 project/revision compatibility context，但暂不改变研究判定语义；
9. 完成后再开始标准适配器和分析方法端口拆分。

## 10. 合并后能力归属

| 当前能力 | Phase 0 定位 | 后续目标 |
| --- | --- | --- |
| FeatureRule preview | 实验性、只读、method-specific DTO | Phase 4 接入 AnalysisRun，不直接持久化为核心实体 |
| Evidence/Scope/Policy 输入 | 调用方声明的研究输入 | 映射 SourceRecord/EvidenceRecord；正式审核另建 ReviewDecision |
| Offline topology trace | 限定图快照中的拓扑候选 | 保持 `topology_only`，经人工审核和 promotion 后才建立核心 Draft |
| `/analysis/feature-rules/preview` | 当前兼容 API | Phase 2/4 纳入版本化、project-scoped API |
| `writeSystemDataFlows` 批量写入 | 应保留的性能优化 | Phase 1/2 加入 scope、版本、重复 ID 诊断和统一审计 |
| ImportWorkspace/导入组件拆分 | 符合四工作区方向 | Phase 6 补入项目、revision、profile 和评审上下文 |

## 11. 重新接受记录

Phase 0 于 2026-10-09 完成合并后重新评审并恢复 `Accepted`：

1. ADR-0006 已接受，并明确 AnalysisMethodDefinition、AnalysisRun、DerivedResult、双阶段评审、晋级溯源、映射隔离、重放和搜索完整性；
2. 目标领域模型已确认 AnalysisRun/DerivedResult 为核心实体，method-specific payload 不属于通用核心领域模型；
3. 能力矩阵、Crosswalk 和迁移设计已覆盖合并后的 FeatureRule preview 与 topology trace；
4. Phase 0–7 路线图已接受，Phase 1 状态调整为 Ready；
5. 前端测试命令的 Windows glob 可移植性登记为 `PH1-TOOLING-001`，责任范围为平台开发，目标在 Phase 1 出口前修复；该问题不影响显式文件运行的 5 项测试和当前构建结果。

## 12. 合并后验证基线（2026-10-08）

| 检查 | 结果 | 说明 |
| --- | --- | --- |
| 后端测试 | 通过，43/43 | 覆盖 F3532 生成、FeatureRule evaluator/API/CLI 和 topology trace |
| 前端测试内容 | 通过，5/5 | 使用显式文件名运行，两文件并行读取和 FeatureRule 前端模型测试均通过 |
| 前端 workspace test script | 未通过 | `tsx --test tests/*.test.ts` 在当前 Windows 环境把 glob 当作字面路径；属于脚本可移植性缺口，不是测试断言失败 |
| `npm run build` | 通过 | 后端 TypeScript 与前端 TypeScript/Vite 均构建成功 |
| 前端构建告警 | 待治理 | 存在超过 500 kB 的 minified chunk，应在 Phase 6 性能与交付检查中处理 |
| 文档链接与格式 | 通过 | 架构目录内部 Markdown 链接可解析，`git diff --check` 无文档格式错误 |

前端测试脚本的 Windows 可移植性问题已作为 `PH1-TOOLING-001` 显式推迟到 Phase 1，必须在 Phase 1 出口前关闭；不得以显式文件命令长期替代 workspace 标准测试入口。
