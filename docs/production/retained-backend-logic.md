# 保留的后端专用及历史逻辑

本轮只收敛正式工作台入口，没有清理以下历史能力：

| 位置 | 保留原因 / 当前边界 |
| --- | --- |
| `services/cxfImportService.ts` | AMS 核心控制器、别名、自动连接与自动威胁；由 `do356a-ams/v1` 包装，不能推广为任意机型规则 |
| `services/workbenchMapping.ts` | v2 与 DPS 的明确转换层；版本、适用性、来源和人工覆盖均进入快照 |
| `services/f3532/`、`services/f3532InputImportService.ts`、`services/f353204Service.ts` | 后端专用转换及报表兼容，正式前端不调用 |
| `repositories/f3532AnalysisRepository.ts`、旧 `routes/index.ts` 中相关只读接口 | 历史读取和既有服务调用仍保留 |
| `services/fpAnalysisService.ts`、`services/featureRules/` | 非 F3532 的研究和传播能力保留；研究前端位于高级入口 |
| `repositories/graphRepository.ts`、`services/importService.ts` | 旧模型读取和历史导入实现保留；全局写入继续隔离 |
| `src/scripts/runPhase*`、`runVg1Demo.ts`、种子与转换脚本 | 历史运维和技术验收工具保留，不构成浏览器 Demo 运行模式 |
| 历史迁移、标准资料、来源工作簿及旧测试 | 保留可追溯性，不删除历史数据或改写原始文件 |

补充的边界接口和系统数据流在 v2 核心中保存。原 CXF→DPS 规则未将这些独立记录逐条作为额外 DPS 边，因此包装层将其标为 `analysis.dps_enabled=false` 并在预览说明；不能把“保存了清单”误称为“这些连接已经参与搜索”。若要启用，必须明确设置覆盖并审查差异，不能暗中更换边集合。无法唯一绑定端点时给出定位诊断，不猜测。

前端仍有未接入主流程的旧单表/CXF 组件及 F3532 工作簿兼容解析类型/测试；本轮没有做全仓库历史清理。它们不进入正式应用的可达构建图，也不构成新工作台的依赖。
