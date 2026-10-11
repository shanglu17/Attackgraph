# Engineering Case v1 API 契约

状态：Accepted  
适用阶段：Phase 3  
契约版本：engineering-case.v1

## 目的

engineering-case.v1 在 Project/Revision/StandardProfileVersion 范围内表达 DO-326A/DO-356A 工程闭环。核心对象不携带某一标准表格的专有字段；标准差异由 ProfileConfiguration、TailoringDecision、标准引用和外层 adapter 表达。

## 对象

- ProfileConfiguration：绑定当前 StandardProfileVersion，声明 DO-326A 活动/工作产品、DO-356A 方法/字段/工作产品和 adapter 开关；
- TailoringDecision：记录适用、不适用或裁剪及理由；
- ThreatPoint、ThreatCondition、ThreatScenario：分别表达入口/暴露点、潜在安保影响条件、主体到目标的行为场景；
- RiskAssessment：computed_result 只保存方法计算值，engineering_judgement 保存工程判断，两者不得互相替代；
- SecurityObjective、SecurityRequirement、Control：表达从风险处置到分配和实现；
- VerificationCase、EvidenceRecord：表达验证方法、环境、程序、接受准则、结果和证据；
- ReviewDecision：独立的人工作出决定，记录对象类型、业务标识、对象版本、角色、理由和可选的被替代决定。

## 状态和权限边界

批量提交端点只接受 status = Draft。Reviewed、Approved、Rejected 或退回 Draft 只能由 POST /api/v2/engineering-cases/review-decisions 产生。adapter 输入中的 reviewer/status 仅是外部断言，不能创建平台 ReviewDecision。

## 端点

- POST /api/v2/engineering-cases/commit：在 Draft revision 内以 command id、payload hash 和乐观版本提交完整工程案例；
- GET /api/v2/engineering-cases：读取一个 revision 的工程案例和人审决定；
- POST /api/v2/engineering-cases/review-decisions：记录独立的人审决定；
- GET /api/v2/adapters/definitions：读取可用标准 adapter；
- GET /api/v2/adapters/f3532/status：解析当前 profile configuration 的 F3532 开关；
- POST /api/v2/adapters/f3532/04/preview：将遗留 04 数据映射为核心 Draft TC/TS，不直接写库。

所有写入由 RevisionUnitOfWork 完成；同一 command_id 同载荷重放返回原结果，不同载荷重用返回冲突。

## 来源与报告

每个工程实体和 TraceLink 必须解析到同一 project/revision 内的 SourceRecord。通用追踪报告包含工程案例、确切 profile、revision/baseline、来源、人审决定和生成器版本。冻结摘要排除会因冻结动作本身变化的 revision 当前版本号，但保留实体创建版本和决定记录。

## F3532 兼容边界

F3532 01/02/03/04 是外层 compatibility adapter，不是核心模型。关闭 adapter 不影响核心工程案例的创建、评审、报告和冻结。遗留全局替换写入口继续处于隔离状态。
