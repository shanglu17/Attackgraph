export interface F3532TypeTransition {
  from: string;
  to: string;
  rule_id: string;
}

export const f3532TypeTransitions: F3532TypeTransition[] = [
  { from: "SENSOR", to: "SENSOR", rule_id: "TYPE_SENSOR_SENSOR" },
  { from: "SENSOR", to: "DATA", rule_id: "TYPE_SENSOR_DATA" },
  { from: "SENSOR", to: "STATE", rule_id: "TYPE_SENSOR_STATE" },
  { from: "CONFIG", to: "CONFIG", rule_id: "TYPE_CONFIG_CONFIG" },
  { from: "CONFIG", to: "CMD", rule_id: "TYPE_CONFIG_CMD" },
  { from: "CMD", to: "CMD", rule_id: "TYPE_CMD_CMD" },
  { from: "CMD", to: "STATE", rule_id: "TYPE_CMD_STATE" },
  { from: "CMD", to: "ALERT", rule_id: "TYPE_CMD_ALERT" },
  { from: "STATE", to: "STATE", rule_id: "TYPE_STATE_STATE" },
  { from: "STATE", to: "DATA", rule_id: "TYPE_STATE_DATA" },
  { from: "STATE", to: "ALERT", rule_id: "TYPE_STATE_ALERT" },
  { from: "ALERT", to: "ALERT", rule_id: "TYPE_ALERT_ALERT" },
  { from: "ALERT", to: "STATE", rule_id: "TYPE_ALERT_STATE" },
  { from: "ALERT", to: "DATA", rule_id: "TYPE_ALERT_DATA" },
  { from: "DATA", to: "DATA", rule_id: "TYPE_DATA_DATA" },
  { from: "DATA", to: "STATE", rule_id: "TYPE_DATA_STATE" },
  { from: "DATA", to: "ALERT", rule_id: "TYPE_DATA_ALERT" },
  { from: "LOAD", to: "LOAD", rule_id: "TYPE_LOAD_LOAD" },
  { from: "LOAD", to: "CONFIG", rule_id: "TYPE_LOAD_CONFIG" }
];

const transitionKeys = new Set<string>();
for (const transition of f3532TypeTransitions) {
  const key = `${transition.from.toUpperCase()}->${transition.to.toUpperCase()}`;
  if (transitionKeys.has(key)) {
    throw new Error(`duplicate F3532 type transition: ${key}`);
  }
  transitionKeys.add(key);
}

export function findTypeTransition(fromType: string, toType: string): F3532TypeTransition | undefined {
  const from = fromType.trim().toUpperCase();
  const to = toType.trim().toUpperCase();
  return f3532TypeTransitions.find((transition) => transition.from === from && transition.to === to);
}
