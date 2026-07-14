export interface SystemAliasDefinition {
  system_id: string;
  display_name: string;
  aliases: string[];
  classification: "INTERNAL" | "EXTERNAL";
}

export interface ResolvedSystemIdentity {
  system_id: string;
  display_name: string;
  original_name: string;
  classification?: "INTERNAL" | "EXTERNAL";
  recognized: boolean;
  warning?: string;
}

export const f3532SystemAliases: SystemAliasDefinition[] = [
  { system_id: "SYS.CCS", display_name: "指挥控制系统", aliases: ["指挥控制系统", "CCS", "C2"], classification: "EXTERNAL" },
  {
    system_id: "SYS.GROUND_MAINTENANCE",
    display_name: "地面维护设备",
    aliases: ["地面维护设备", "地面维护系统", "维护设备", "GSE"],
    classification: "EXTERNAL"
  },
  { system_id: "SYS.GNSS", display_name: "GNSS", aliases: ["GNSS", "卫星导航系统"], classification: "EXTERNAL" },
  {
    system_id: "SYS.OPEN_ENVIRONMENT",
    display_name: "开放环境",
    aliases: ["开放环境", "环境音频源", "环境视频目标", "环境激光反射目标"],
    classification: "EXTERNAL"
  },
  { system_id: "SYS.RCS", display_name: "RCS", aliases: ["RCS", "遥控站系统", "遥控站"], classification: "INTERNAL" },
  { system_id: "SYS.DLS", display_name: "DLS", aliases: ["DLS", "数据链系统"], classification: "INTERNAL" },
  { system_id: "SYS.IMS", display_name: "IMS", aliases: ["IMS", "综合管理系统", "综合管理系统（IMS）", "综合管理系统(IMS)"], classification: "INTERNAL" },
  { system_id: "SYS.FMS", display_name: "FMS", aliases: ["FMS", "飞行管理系统", "飞行管理系统（FMS）"], classification: "INTERNAL" },
  { system_id: "SYS.FCS", display_name: "FCS", aliases: ["FCS", "飞行控制系统", "飞控系统"], classification: "INTERNAL" },
  { system_id: "SYS.NAVS", display_name: "NAVS", aliases: ["NAVS", "导航系统"], classification: "INTERNAL" },
  { system_id: "SYS.DAAS", display_name: "DAAS", aliases: ["DAAS", "探测与避让系统"], classification: "INTERNAL" },
  { system_id: "SYS.AVCS", display_name: "AVCS", aliases: ["AVCS", "音视频通信系统"], classification: "INTERNAL" },
  { system_id: "SYS.EPS", display_name: "EPS", aliases: ["EPS", "电推进系统"], classification: "INTERNAL" },
  { system_id: "SYS.PACKS", display_name: "PACKS", aliases: ["PACKS", "动力电池系统"], classification: "INTERNAL" },
  { system_id: "SYS.HVDS", display_name: "HVDS", aliases: ["HVDS", "高压配电系统"], classification: "INTERNAL" },
  { system_id: "SYS.ES", display_name: "ES", aliases: ["ES", "电气系统"], classification: "INTERNAL" },
  { system_id: "SYS.PES", display_name: "PES", aliases: ["PES", "伞降系统"], classification: "INTERNAL" },
  { system_id: "SYS.RA", display_name: "RA", aliases: ["RA", "无线电高度表"], classification: "INTERNAL" }
];

export function normalizeSystemAlias(value: string | undefined): string {
  return (value ?? "")
    .normalize("NFKC")
    .trim()
    .toUpperCase()
    .replace(/[\s\u3000]+/g, "")
    .replace(/[()（）]/g, "");
}

const aliasRegistry = new Map<string, SystemAliasDefinition>();
const definitionById = new Map<string, SystemAliasDefinition>();

for (const definition of f3532SystemAliases) {
  if (definitionById.has(definition.system_id)) {
    throw new Error(`duplicate F3532 system_id in alias configuration: ${definition.system_id}`);
  }
  definitionById.set(definition.system_id, definition);
  for (const alias of [definition.system_id, definition.display_name, ...definition.aliases]) {
    const normalized = normalizeSystemAlias(alias);
    const existing = aliasRegistry.get(normalized);
    if (existing && existing.system_id !== definition.system_id) {
      throw new Error(`conflicting F3532 system alias '${alias}': ${existing.system_id} / ${definition.system_id}`);
    }
    aliasRegistry.set(normalized, definition);
  }
}

function stableHash(value: string): string {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(36).toUpperCase();
}

export function resolveSystemIdentity(rawName: string | undefined): ResolvedSystemIdentity {
  const originalName = (rawName ?? "").trim();
  const normalized = normalizeSystemAlias(originalName);
  const exact = aliasRegistry.get(normalized);
  if (exact) {
    return {
      system_id: exact.system_id,
      display_name: exact.display_name,
      original_name: originalName,
      classification: exact.classification,
      recognized: true
    };
  }

  const acronym = originalName.match(/[（(]\s*([A-Za-z][A-Za-z0-9-]*)\s*[）)]/)?.[1];
  const byAcronym = acronym ? aliasRegistry.get(normalizeSystemAlias(acronym)) : undefined;
  if (byAcronym) {
    return {
      system_id: byAcronym.system_id,
      display_name: byAcronym.display_name,
      original_name: originalName,
      classification: byAcronym.classification,
      recognized: true
    };
  }

  const fallbackLabel = normalized || "EMPTY";
  return {
    system_id: `SYS.UNRESOLVED.${stableHash(fallbackLabel)}`,
    display_name: originalName || "未识别系统",
    original_name: originalName,
    recognized: false,
    warning: `未识别系统名称 '${originalName || "<empty>"}'，已分配稳定待审核 ID`
  };
}

export function splitSystemNames(value: string | undefined): string[] {
  return Array.from(
    new Set(
      (value ?? "")
        .split(/[、,，/\n\r;；]+/)
        .map((item) => item.trim())
        .filter((item) => item.length > 0 && item !== "/")
    )
  );
}

export function getSystemDisplayName(systemId: string): string {
  return definitionById.get(systemId)?.display_name ?? systemId.replace(/^SYS\.UNRESOLVED\./, "未识别系统-");
}

export function getConfiguredSystemClassification(systemId: string): "INTERNAL" | "EXTERNAL" | undefined {
  return definitionById.get(systemId)?.classification;
}
