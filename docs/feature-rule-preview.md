# 特征规则研究预览（experimental-0.1）

2026-09-21。新增功能是纯数据求值，不改动原有导入、F3532/AP分析、报告或数据库；新增页面入口位于“数据导入 → 特征规则分析”。结果是机器决策日志，不是正式ThreatPoint、人工审查结论或DO-356A符合性结果。

## 页面使用

选择最大5 MB的JSON研究数据包，或载入待审模板，再运行规则预览。页面保留AND/OR条件分组、T/F/U/C状态、保护策略、作用域及证据定位；支持导出完整输入与响应以重算。编辑或载入其他数据会清空旧结果，失败时禁止导出旧判定。四个工作区切换保留当前输入与预览。

该页面调用4000端口的后端服务；离线时显示连接提示。它尚不是规则批准或图谱提交界面。

## 无数据库运行

在Attackgraph目录执行：

```powershell
node --import tsx scripts/preview-feature-rules.ts examples/feature-rules/draft-preview.json
```

示例使用来源已有的禁用INT_UNAU_001规则和明确标记的模板资产，输出`rule_not_executed`及`executed_count: 0`。这是未执行提示，不是“系统没有威胁”，也不是实验数据。将实际输入保存在单独JSON中，按同一命令读取即可；CLI只读文件并向stdout输出，可自行重定向保存。

后端运行后也可调用：

```powershell
$featurePreviewBody = Get-Content -Raw -Encoding utf8 examples/feature-rules/draft-preview.json
Invoke-RestMethod -Method Post -Uri http://localhost:4000/analysis/feature-rules/preview -ContentType 'application/json; charset=utf-8' -Body ([System.Text.Encoding]::UTF8.GetBytes($featurePreviewBody))
```

实际端口以原后端配置为准。结构或引用错误返回400，附issues；正常预览返回200，包括未执行决策。接口不访问Neo4j、不读取标准库、不自动批准规则。

## 输入契约

顶层严格字段：`contract_version: feature-preview-0.1`、`scenario_id`、`assets`、`features`、`rules`、`evidence`、`scopes`、`policies`。资产/特征/规则/证据字段对应研究侧既有四类记录；新增配套记录不改变原型资产类型。

`scopes`每项必须有scope_id、asset_id、boundary_id、operational_phase、attacker_profile、evidence_refs。Fact.scope中的字符串必须引用这些scope_id，作用范围精确匹配，不支持隐式全局或继承。不同链路、阶段或攻击者应建立不同scope。

`policies`每项必须有rule_id、rule_version、version、feature_version、applicable_phases、applicable_attacker_profiles、review_evidence_refs和protection_actions。每个保护动作包含feature_id、action（block/downgrade）、effect_description及basis_evidence_refs，必须逐项覆盖规则excluding_features。逐项动作是本预览的权威执行策略，原规则级exclusion_effect保留用于旧契约兼容且不得仍为TODO_REVIEW；二者的具体含义须在领域审查时一并记录。

显式运行阶段/攻击者清单是准入门控。空context_requirements只表示在已审定配套政策的阶段门控之外无额外特征组，不能仅凭空数组宣称全阶段适用。每个资产本轮只接受一个活动FeatureRecord；多版本须分批求值。规则ID、scopeID和证据ID等不能重复。

规则执行需要enabled、APPROVED、审查人、审查依据及匹配版本的policy。已声明verified且至少有一项source_locator的证据才能支持确定事实；引用缺失为输入错误，未复核/无定位为未知。这里检查的是调用者提供的审查元数据，不验证签名、审查人身份或原文真实性，不能当成正式签发系统。

## 判定

必备条件组间AND/组内OR，保留T/F/U/C。真/假优先按运算短路语义决定总体结果，但各项unknown/conflict继续保存在checks中。没有适用事实为U，不当absent；同作用域有已支持的present与absent为C。

| decision | 含义 |
|---|---|
| rule_not_executed | 规则待审、策略或版本不满足执行门控 |
| not_applicable | 对象域、阶段、攻击者或已证实的上下文不适用 |
| needs_evidence | 上下文/必备条件缺失、未知或冲突 |
| requirements_not_met | 必备条件被证据明确否定 |
| blocked | 同作用范围下存在已支持的block保护 |
| candidate_scoped | 已支持downgrade保护；effect_description记录缩小/降级说明 |
| candidate_protection_unresolved | 必备成立，但保护未知或冲突 |
| candidate | 必备成立，保护不存在/无适用保护项 |

downgrade当前仅输出被审查的effect_description，不计算量化风险、不自动改写图或运行窗口。多个规则独立记录，某条blocked不抹去另一条candidate。supporting只解释，不改变判定或评分。

结果保存input_sha256、规则/特征/政策版本、各类checks、blocked_by、来源索引与scope索引；保存原始请求和响应可重算。数组按集合处理以使输入顺序不影响结果。最多10000个scope/rule对，不是性能保证。

## 当前界限

6条实际领域规则仍禁用待审。已实现的是实验性求值语义，领域正确性、正式场景评价、人工身份签发、图路径桥接、前端复核以及完整报告集成尚未完成。既有六类JSON Schema原件保持不变；HTTP采用上述版本化Zod契约，可接收待审规则以解释拒绝执行原因。

运行验证：`npm test -w @attackgraph/backend`（含旧F3532回归、新求值/API/CLI测试）、`npm test -w @attackgraph/frontend`、`npm run build`。合成测试不进入论文E1–E4。
