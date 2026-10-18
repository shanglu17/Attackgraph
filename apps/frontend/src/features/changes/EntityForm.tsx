import type {
  AnalysisConfiguration,
  SystemModelImportPayload,
} from "@attackgraph/contracts";
type Entities = SystemModelImportPayload["entities"];
export type EditableKind = "assets" | "data_flows" | "draft_threats";
interface Props {
  kind: EditableKind;
  record: Entities[EditableKind][number];
  configuration: AnalysisConfiguration;
  disabled: boolean;
  onChange: (field: string, value: unknown) => void;
  onThreat: (field: string, value: string | number) => void;
}
const selectOptions: Record<string, string[]> = {
  criticality: ["Low", "Medium", "High", "Catastrophic"],
  category: ["Terminal", "Interface", "Data", "Link"],
  entry_likelihood_level: ["High", "Medium", "Low"],
  attack_complexity_level: ["Low", "Medium", "High"],
  threat_source: ["internal", "external", "third-party"],
  stride_category: [
    "Spoofing",
    "Tampering",
    "Repudiation",
    "InformationDisclosure",
    "DenialOfService",
    "ElevationOfPrivilege",
  ],
  attack_vector: [
    "Network",
    "Wireless",
    "Physical",
    "Maintenance",
    "SupplyChain",
  ],
};
const labels: Record<string, string> = {
  business_id: "编号",
  name: "名称",
  description: "说明",
  criticality: "重要性",
  category: "资产类别",
  producer_asset_business_id: "源资产编号",
  consumer_asset_business_id: "目标资产编号",
  target_asset_business_id: "关联资产编号",
  entry_likelihood_level: "入口可能性",
  attack_complexity_level: "攻击复杂度",
  threat_source: "威胁来源",
  stride_category: "STRIDE 类别",
  attack_vector: "攻击向量",
  expert_modifier: "专家修正因子",
  expert_adjustment_note: "修正依据",
};
export function EntityForm({
  kind,
  record,
  configuration,
  disabled,
  onChange,
  onThreat,
}: Props) {
  const fields =
    kind === "assets"
      ? ["name", "description", "category", "criticality"]
      : kind === "data_flows"
        ? [
            "name",
            "description",
            "producer_asset_business_id",
            "consumer_asset_business_id",
          ]
        : ["name", "target_asset_business_id"];
  const item = record as unknown as Record<string, unknown>;
  const threat = configuration.threat_overrides[record.business_id] ?? {
    entry_likelihood_level: "Medium",
    attack_complexity_level: "Medium",
    threat_source: "external",
    stride_category: "Tampering",
    attack_vector: "Network",
  };
  const input = (
    field: string,
    value: unknown,
    change: (value: string) => void,
  ) => (
    <label key={field} className="field-stack">
      {labels[field] ?? field}
      {selectOptions[field] ? (
        <select
          aria-label={labels[field] ?? field}
          className="input-field"
          value={String(value ?? "")}
          disabled={disabled}
          onChange={(e) => change(e.target.value)}
        >
          {!value && <option value="">未声明</option>}
          {selectOptions[field].map((v) => (
            <option key={v}>{v}</option>
          ))}
        </select>
      ) : (
        <input
          className="input-field"
          disabled={disabled}
          value={String(value ?? "")}
          onChange={(e) => change(e.target.value)}
        />
      )}
    </label>
  );
  const metadata = item.analysis as Record<string, unknown> | undefined;
  return (
    <div className="workbench-form-grid">
      <p className="pill">编号：{record.business_id}</p>
      {fields.map((f) => input(f, item[f], (v) => onChange(f, v)))}
      {kind === "assets" && (
        <label className="field-stack">
          安全域
          <select
            className="input-field"
            disabled={disabled}
            value={String(metadata?.security_domain ?? "Shared")}
            onChange={(e) =>
              onChange("analysis", {
                ...metadata,
                security_domain: e.target.value,
              })
            }
          >
            {["Internal", "Shared", "DMZ", "External"].map((v) => (
              <option key={v}>{v}</option>
            ))}
          </select>
        </label>
      )}
      {kind === "data_flows" && (
        <>
          {[
            "direction",
            "link_type",
            "trust_level",
            "protocol_or_medium",
            "security_mechanism",
          ].map((field) => (
            <label key={field} className="field-stack">
              {
                {
                  direction: "连接方向",
                  link_type: "连接类型",
                  trust_level: "信任等级",
                  protocol_or_medium: "协议 / 介质",
                  security_mechanism: "安全机制",
                }[field]
              }
              {["direction", "link_type", "trust_level"].includes(field) ? (
                <select
                  className="input-field"
                  disabled={disabled}
                  value={String(
                    metadata?.[field] ??
                      (field === "direction"
                        ? "Unidirectional"
                        : field === "link_type"
                          ? "DataFlow"
                          : ""),
                  )}
                  onChange={(e) => {
                    const next={...metadata};if(e.target.value)next[field]=e.target.value;else delete next[field];onChange("analysis",next);
                  }}
                >
                  {field === "trust_level" && <option value="">未声明（沿用原算法默认因子）</option>}
                  {(field === "direction"
                    ? ["Unidirectional", "Bidirectional"]
                    : field === "link_type"
                      ? ["Physical", "Logical", "DataFlow", "Control"]
                      : ["Trusted", "Semi-Trusted", "Untrusted"]
                  ).map((v) => (
                    <option key={v}>{v}</option>
                  ))}
                </select>
              ) : (
                <input
                  className="input-field"
                  disabled={disabled}
                  value={String(metadata?.[field] ?? "")}
                  onChange={(e) =>
                    onChange("analysis", {
                      ...metadata,
                      [field]: e.target.value,
                    })
                  }
                />
              )}
            </label>
          ))}
        </>
      )}
      {kind === "draft_threats" && (
        <>
          <p>威胁为待核对候选；修改参数不会自动将其升级为已确认事实。</p>
          {[
            "entry_likelihood_level",
            "attack_complexity_level",
            "threat_source",
            "stride_category",
            "attack_vector",
            "expert_modifier",
            "expert_adjustment_note",
          ].map((f) =>
            input(f, (threat as Record<string, unknown>)[f], (v) =>
              onThreat(f, f === "expert_modifier" ? Number(v) : v),
            ),
          )}
        </>
      )}
    </div>
  );
}
