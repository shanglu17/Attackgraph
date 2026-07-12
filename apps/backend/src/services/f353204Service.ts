import type { GenerateF353204Request } from "../types/api.js";
import type { AttackVector, CiaAttribute, ThreatCondition, ThreatScenario } from "../types/domain.js";
import type {
  FailureConditionContext,
  ThreatPathActorContext,
  ThreatPathContext
} from "../repositories/f3532AnalysisRepository.js";

export const f353204Defaults = {
  cia_modes: [
    { value: "single", label: "单属性丧失（C / I / A）" },
    { value: "all_non_empty", label: "CIA 全排列（7 种非空组合）" }
  ],
  aircraft_effect_options: ["无明显影响", "性能或能力降级", "偏离预期航迹", "功能部分丧失", "功能完全丧失", "非指令动作", "可能导致迫降或坠落"],
  system_effect_options: ["无明显影响", "输出错误或不可信", "响应延迟", "服务中断", "进入降级模式", "执行非指令动作", "功能完全不可用"],
  crew_effect_options: ["无明显影响", "增加工作负荷", "需要人工处置或接管", "误导操作或决策", "丧失态势感知", "无法完成预期操作"],
  occupant_effect_options: ["无明显影响", "舒适性受影响", "可能导致轻微伤害", "可能导致严重伤害", "可能导致人员伤亡"],
  reference_notes: [
    "威胁状况描述默认留空，用户可参考既有 04 范例填写。",
    "严重程度默认继承 FHA；人工修改后应将 severity_source 改为 manual。",
    "攻击路径默认格式为：威胁主体 -> 关键路径。",
    "攻击路径上现有安全措施默认留空，由用户在评审时填写。"
  ]
} as const;

export interface F353204GenerationResult {
  defaults: typeof f353204Defaults;
  threat_conditions: ThreatCondition[];
  threat_scenarios: ThreatScenario[];
  coverage: {
    total_failure_conditions: number;
    linked_failure_conditions: number;
    unlinked_failure_condition_ids: string[];
    generated_tc_count: number;
    generated_ts_count: number;
  };
}

export class F353204Service {
  generate(
    input: GenerateF353204Request,
    failureConditions: FailureConditionContext[],
    paths: ThreatPathContext[]
  ): F353204GenerationResult {
    const ciaCombinations = this.ciaCombinations(input.cia_mode);
    const threatConditions: ThreatCondition[] = [];
    const linkedFailureConditionIds = new Set<string>();

    const eligibleFailureConditions = input.include_unlinked_failure_conditions
      ? failureConditions
      : failureConditions.filter((fc) => fc.function_ids.length > 0 || fc.path_ids.length > 0);

    for (const fc of eligibleFailureConditions) {
      const resolvedFunctionIds = this.resolveFunctionIds(fc, paths);
      const functionIds: Array<string | undefined> = resolvedFunctionIds.length > 0 ? resolvedFunctionIds : [undefined];
      for (const functionId of functionIds) {
        const pathIds = this.resolvePathIds(fc.path_ids, functionId, paths);
        const affectedAssets =
          fc.affected_assets.length > 0 ? fc.affected_assets : this.inferAffectedAssets(pathIds, paths);
        const linked = Boolean(functionId) && pathIds.length > 0;
        if (linked) {
          linkedFailureConditionIds.add(fc.failure_condition_id);
        }
        for (const ciaAttributes of ciaCombinations) {
          threatConditions.push({
            tc_id: `TC-${String(threatConditions.length + 1).padStart(3, "0")}`,
            function_id: functionId,
            failure_condition_ids: [fc.failure_condition_id],
            flight_phases: fc.flight_phases,
            affected_assets: affectedAssets,
            cia_attributes: ciaAttributes,
            description: undefined,
            aircraft_effect: undefined,
            system_effect: undefined,
            crew_effect: undefined,
            occupant_effect: undefined,
            severity: fc.severity,
            severity_source: "FHA",
            path_ids: pathIds,
            coverage_status: linked ? "linked" : "unlinked",
            review_status: "Draft",
            is_default: true
          });
        }
      }
    }

    const threatScenarios = this.buildThreatScenarios(threatConditions, paths);

    const unlinked = failureConditions
      .filter((fc) => !linkedFailureConditionIds.has(fc.failure_condition_id))
      .map((fc) => fc.failure_condition_id);
    return {
      defaults: f353204Defaults,
      threat_conditions: threatConditions,
      threat_scenarios: threatScenarios,
      coverage: {
        total_failure_conditions: failureConditions.length,
        linked_failure_conditions: failureConditions.length - unlinked.length,
        unlinked_failure_condition_ids: unlinked,
        generated_tc_count: threatConditions.length,
        generated_ts_count: threatScenarios.length
      }
    };
  }

  private ciaCombinations(mode: GenerateF353204Request["cia_mode"]): CiaAttribute[][] {
    if (mode === "all_non_empty") {
      return [["C"], ["I"], ["A"], ["C", "I"], ["C", "A"], ["I", "A"], ["C", "I", "A"]];
    }
    return [["C"], ["I"], ["A"]];
  }

  private buildThreatScenarios(
    threatConditions: ThreatCondition[],
    paths: ThreatPathContext[]
  ): ThreatScenario[] {
    const pathById = new Map(paths.map((path) => [path.path_id, path]));
    const groups = new Map<
      string,
      {
        actor?: ThreatPathActorContext;
        path?: ThreatPathContext;
        attackVector?: AttackVector;
        tcIds: Set<string>;
      }
    >();

    for (const tc of threatConditions) {
      let matched = false;
      for (const pathId of tc.path_ids) {
        const path = pathById.get(pathId);
        if (!path) {
          continue;
        }
        const actors = [...path.threat_actors].sort((a, b) => a.actor_id.localeCompare(b.actor_id));
        for (const actor of actors) {
          const attackVector = this.inferAttackVector(actor, path);
          const key = `${path.path_id}|${actor.actor_id}|${attackVector ?? ""}`;
          const group = groups.get(key) ?? { actor, path, attackVector, tcIds: new Set<string>() };
          group.tcIds.add(tc.tc_id);
          groups.set(key, group);
          matched = true;
        }
      }

      if (!matched) {
        groups.set(`unlinked|${tc.tc_id}`, { tcIds: new Set([tc.tc_id]) });
      }
    }

    return Array.from(groups.entries())
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([, group], index) => ({
        ts_id: `TS-${String(index + 1).padStart(3, "0")}`,
        threat_actor_id: group.actor?.actor_id,
        tc_ids: Array.from(group.tcIds).sort(),
        attack_vector: group.attackVector,
        attack_path: this.buildAttackPath(group.actor, group.path),
        existing_security_measures: undefined,
        review_status: "Draft",
        is_default: true
      } satisfies ThreatScenario));
  }

  private resolveFunctionIds(fc: FailureConditionContext, paths: ThreatPathContext[]): string[] {
    const match = fc.failure_condition_id.match(/^FC\s*(\d+(?:\.\d+)*)/i);
    if (!match) {
      return [...fc.function_ids].sort();
    }
    const failureFunctionPath = `F${match[1]}`;
    const inferred = this.functionFamily(failureFunctionPath);
    const directCandidates = fc.function_ids
      .filter((functionId) => this.functionFamily(functionId) === inferred)
      .filter((functionId) => failureFunctionPath === functionId || failureFunctionPath.startsWith(`${functionId}.`));
    if (directCandidates.length > 0) {
      const maxDepth = Math.max(...directCandidates.map((functionId) => functionId.split(".").length));
      return Array.from(new Set(directCandidates.filter((functionId) => functionId.split(".").length === maxDepth))).sort();
    }
    const available = new Set(paths.flatMap((path) => path.function_ids));
    if (available.has(inferred)) {
      return [inferred];
    }
    const sameFamily = Array.from(available).filter((functionId) => this.functionFamily(functionId) === inferred).sort();
    return sameFamily.length > 0 ? [sameFamily[0]] : [inferred];
  }

  private resolvePathIds(
    directPathIds: string[],
    functionId: string | undefined,
    paths: ThreatPathContext[]
  ): string[] {
    const direct = directPathIds
      .map((pathId) => paths.find((path) => path.path_id === pathId))
      .filter((path): path is ThreatPathContext => Boolean(path));
    if (direct.length > 0) {
      const compatible = direct.filter((path) => this.pathSupportsFunction(path, functionId));
      return (compatible.length > 0 ? compatible : direct).map((path) => path.path_id).sort();
    }
    if (!functionId) {
      return [];
    }
    return paths
      .filter((path) => this.pathSupportsFunction(path, functionId))
      .map((path) => path.path_id)
      .sort();
  }

  private pathSupportsFunction(path: ThreatPathContext, functionId: string | undefined): boolean {
    if (!functionId) {
      return false;
    }
    const family = this.functionFamily(functionId);
    return path.function_ids.some((candidate) => candidate === functionId || this.functionFamily(candidate) === family);
  }

  private functionFamily(functionId: string): string {
    return functionId.match(/^F\d+/i)?.[0].toUpperCase() ?? functionId.toUpperCase();
  }

  private inferAffectedAssets(pathIds: string[], paths: ThreatPathContext[]): string[] {
    const assets = new Set<string>();
    for (const pathId of pathIds) {
      const systemPath = paths.find((path) => path.path_id === pathId)?.system_path ?? "";
      const nodes = systemPath.split(/\s*(?:→|->)\s*/).map((item) => item.trim()).filter(Boolean);
      if (nodes.length > 0) {
        assets.add(nodes[nodes.length - 1]);
      }
    }
    return Array.from(assets).sort();
  }

  private buildAttackPath(actor: ThreatPathActorContext | undefined, path: ThreatPathContext | undefined): string {
    const actorText = actor ? `${actor.actor_id}（${actor.actor_name}）` : "待关联威胁主体";
    const pathText = path?.system_path || path?.path_id || "待关联关键路径";
    return `${actorText} -> ${pathText}`;
  }

  private inferAttackVector(
    actor: ThreatPathActorContext | undefined,
    path: ThreatPathContext | undefined
  ): AttackVector | undefined {
    if (!actor) {
      return undefined;
    }
    const text = `${actor.actor_id} ${actor.actor_name} ${(path?.boundary_ids ?? []).join(" ")}`.toLowerCase();
    if (actor.actor_type === "third-party" || /供应链|supplier|vendor|ta-t/.test(text)) {
      return "SupplyChain";
    }
    if (/维护|maintenance|sb03|sb-03/.test(text)) {
      return "Maintenance";
    }
    if (/gnss|射频|无线|wireless/.test(text)) {
      return "Wireless";
    }
    if (/物理|physical/.test(text)) {
      return "Physical";
    }
    return "Network";
  }
}
