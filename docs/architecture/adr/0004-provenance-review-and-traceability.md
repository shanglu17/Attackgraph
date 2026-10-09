# ADR-0004：数据来源、生成、评审与追踪

- 状态：Accepted
- 日期：2026-10-08

## 背景

当前数据来源散落在 `source`、sheet、row、description、evidence 字符串和 audit summary 中。生成结果与人工编辑结果有时存储在同一节点，部分流程会删除并重建全部结果，难以证明某项结论来自何处、使用了什么规则、由谁批准。

## 决策

业务记录必须明确属于以下语义之一：

1. `SourceFact`：来自外部资料或人工建模的事实；
2. `DerivedResult`：由确定输入和生成器产生的结果；
3. `ReviewDecision`：人对事实或结果作出的决定；
4. `BaselineContent`：已经冻结的内容引用或快照。

这些语义可以通过公共元数据组合到领域实体中，不要求所有数据存成同一种节点。

## 来源要求

SourceRecord 至少包含：

- source kind；
- file/document identifier；
- source version；
- cryptographic hash（有文件时）；
- sheet/page/row/section locator；
- imported/submitted by and at；
- parser/transformer version；
- original reference；
- authorization/classification metadata（适用时）。

## 生成要求

DerivedResult 至少包含：

- generator id/version；
- rule/config version；
- input revision/baseline id；
- input content hash；
- generated at/by；
- structured evidence；
- status；
- supersedes/superseded-by relation。

重新生成不得覆盖旧结果。新结果作为新版本存在；上游变化后旧结果标记为 `Stale`。

## 评审要求

ReviewDecision 必须记录：

- subject id/version；
- decision；
- rationale/comment；
- reviewer/approver；
- role；
- timestamp；
- applicable revision/baseline；
- 前置决定或被替代决定。

生成器不能创建 Reviewed 或 Approved 决定。

## 追踪要求

统一使用 `TraceLink` 表达跨实体工程关系。TraceLink 自身可评审、可引用来源并具有项目/版本上下文。

旧 `DO326ALink` 与 `StandardMapping` 迁移到 TraceLink，但保留 legacy id、旧 linkage type 和原 review status。

## 结果

- 可以回答“该报告单元格来自哪份资料、哪次生成和哪次批准”；
- 人工结论和算法候选不再相互覆盖；
- 支持输入变化后的 stale 传播和变更影响分析；
- 支持未来的职责分离和电子签署扩展。

## 未采用方案

### 仅在实体上增加 `source` 字符串

未采用。它无法表达一个结果的多个输入、转换链、版本和字段位置。

### 将所有历史复制为完整图快照

不作为唯一机制。Baseline 可以使用快照或内容寻址，但日常来源和评审历史仍需显式事件与关系。

## 验收约束

- 每个导入实体能解析到 SourceRecord；
- 每个算法结果能解析到 AnalysisRun 和输入版本；AnalysisRun、实验结果晋级及重放约束见 ADR-0006；
- Approved 结果不会被导入或生成 API 更新；
- 追踪断链在冻结 baseline 前被校验；
- 导出报告包含 profile、baseline 和生成元数据。

## 关联决策

- ADR-0006：实验性分析方法与结果晋级。
