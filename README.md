# ASTRA — 航空语义威胁推理与分析系统

正式工作台围绕 DO-326A / DO-356A 提供“选择项目与修订 → 导入系统资产清单 → 检查模型 → 编辑保存 → 运行攻击路径 → 查看评分解释 → 导出结果”的操作闭环。模型、修订、审计与分析快照以 Neo4j 为准。

四个工作区为数据导入、图谱分析、变更管理、报告中心。工程审查和研究工具在高级入口。评分用于相对排序，不代表实际攻击成功概率。

## 启动

需要 Node.js 20、npm 和 Neo4j 5.26。

```powershell
npm ci
Copy-Item .env.example .env
# 编辑 .env，填写本地数据库配置。不要提交凭据。
docker compose up -d
npm run db:migrate -- plan
npm run db:migrate -- apply --actor local-engineer
npm run build
npm run dev
# 另开终端
npm run dev:frontend
```

打开 http://localhost:5173。迁移器遇到破坏性迁移会停止；请先核对目标库和实际备份，详见启动说明。默认 Vite 代理访问本机 4000 端口，部署时使用同源 `/api` 反向代理或 `VITE_API_BASE_URL`。

## 文档

- [正式版本交付、启动和数据库配置](docs/production/README.md)
- [项目归档、回收恢复与历史分页](docs/production/project-management.md)
- [项目管理增量验收与加载对比](docs/production/improvements-2026-10-20.md)
- [导入 → 检查 → 修改 → 分析 → 导出演示](docs/production/walkthrough.md)
- [九类 Sheet 模板填写指南](docs/production/inventory-template.md)
- [正式接口及模型映射契约](docs/architecture/production-workbench.md)
- [验收、干净交付与性能记录](docs/production/acceptance.md)
- [保留的后端专用及历史逻辑](docs/production/retained-backend-logic.md)
- [前端开发规范](docs/frontend-development-standard.md)

## 检查

```powershell
npm run build
npm test -w @attackgraph/backend
npm test -w @attackgraph/frontend
# 数据库及浏览器验收必须使用独立测试库，按交付说明设置环境后执行
npm run test:integration -w @attackgraph/backend
npm run test:workbench:integration -w @attackgraph/backend
npm run verify:workbench
```

保留 `cxf_asset_inventory_v1` 和九类工作表，兼容旧“接口资产”及五列数据资产格式。AMS 转换是有明确适用范围的 `do356a-ams/v1`，未宣称适用于任意机型。空模板与填写示例都通过正常解析、预览和提交进入当前修订。

原有 F3532 后端、历史数据、标准资料、CLI 脚本及迁移继续保留。正式前端不提供相应入口；旧全局写入接口继续处于隔离状态。没有浏览器模拟数据库、Demo 服务或运行模式切换。
