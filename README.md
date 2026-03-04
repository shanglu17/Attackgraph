# Attackgraph 平台

基于 `docs/system-architecture.md` 的可运行最小实现，包含：

- 资产图与 Threat Overlay 的后端语义模型
- Draft ChangeSet 校验与提交 API
- 静态攻击路径推演与评分 API
- AttackPath 结果持久化到 Neo4j
- 前端审查工作台（左中右+底栏）骨架

## 快速启动

1. 启动 Neo4j

```bash
docker compose up -d
```

2. 安装依赖

```bash
npm install
```

3. 启动后端

```bash
npm run dev
```

4. 启动前端（另开终端）

```bash
npm run dev:frontend
```

5. 一键初始化示例数据（另开终端）

```bash
npm run seed:sample
```

初始化后可在前端点击“刷新图数据”，或直接使用前端的“一键初始化示例数据”按钮。

## 默认配置

- Neo4j URI: `bolt://localhost:7687`
- Neo4j User: `neo4j`
- Neo4j Password: `YB52013140402hh`
- Backend: `http://localhost:4000`
- Frontend: `http://localhost:5173`

## 示例数据接口

- `POST /admin/seed/sample`

用于重置并写入一套演示资产图（AssetNode / AssetEdge / ThreatPoint），便于快速演示路径推演与审查流程。
