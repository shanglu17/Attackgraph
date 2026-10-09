# ADR-0001：产品定位与标准版本策略

- 状态：Accepted
- 日期：2026-10-08

## 背景

当前 README 同时声明 DO-326A、DO-356A 和 ASTM F3532 能力，但各自实现深度不同。若不区分过程规范、方法指导、项目配置和算法能力，界面和报告容易产生超出系统证据能力的符合性暗示。

DO-326A/DO-356A 的后续版本也要求标准版本不能继续写死在实体名和 API 中。

## 决策

1. ASTRA 定位为“审计就绪的适航安保工程辅助平台”。
2. 当前验收标准基线固定为 DO-326A + DO-356A。
3. DO-326B 作为前向兼容目标，通过新增/更新 `StandardProfile` 实现，不修改通用实体名称。
4. 标准配置至少记录：
   - standard family；
   - document identifier；
   - edition/revision；
   - effective date；
   - project applicability；
   - tailoring decisions；
   - source reference；
   - profile version。
5. 算法输出、候选工作产品和系统报告不得自动宣称标准符合性。
6. 符合性主张必须关联标准引用、项目裁剪、证据和人工批准。

## 结果

- 可以在同一应用中维护不同标准版本项目。
- 旧的 `DO326ALink` 将进入兼容迁移，不继续扩展。
- UI 必须显示当前项目的标准 profile 和版本。
- 报告必须注明适用 profile、baseline 和生成时间。

## 未采用方案

### 每个标准维护一个长期 Git 分支

未采用。它会导致核心修复、数据库迁移和 UI 组件长期分叉。开发分支可以用于实施隔离，但运行时标准差异必须由 profile/adapter 表达。

### 直接以 DO-326B 替换 DO-326A

未采用。当前用户目标和现有资料以 A 版为基线。架构兼容 B 版，但版本迁移必须通过差异评估和新 profile 显式完成。

## 验收约束

- 通用实体和 API 不包含 `326A`、`356A` 或 `F3532` 硬编码名称；
- 标准专用 DTO、adapter 和 report namespace 可以保留标准编号；
- 每个冻结 baseline 能解析其确切标准 profile；
- 报告不能只显示笼统的 “DO-326/356 compliant”。
