import type { F3532DataTopic, F353203GenerationFacts } from "../../types/domain.js";
import { compareNaturalBusinessIds } from "./naturalSort.js";

export interface PropagationGraphEdge {
  sdf_id: string;
  from_system_id: string;
  to_system_id: string;
  system_interface_id?: string;
  data_type: string;
  data_description?: string;
  function_ids: string[];
  topic_ids: F3532DataTopic[];
}

export interface PropagationGraph {
  node_ids: string[];
  edges: PropagationGraphEdge[];
  outgoing: Map<string, PropagationGraphEdge[]>;
}

export class PropagationGraphBuilder {
  build(facts: F353203GenerationFacts): PropagationGraph {
    const nodeIds = new Set<string>();
    const outgoing = new Map<string, PropagationGraphEdge[]>();
    const edges = [...facts.system_data_flows]
      .sort((left, right) => compareNaturalBusinessIds(left.id, right.id))
      .map((sdf) => {
        const edge: PropagationGraphEdge = {
          sdf_id: sdf.id,
          from_system_id: sdf.producer_system_id,
          to_system_id: sdf.consumer_system_id,
          system_interface_id: sdf.system_interface_id,
          data_type: sdf.data_type,
          data_description: sdf.data_description,
          function_ids: sdf.function_ids,
          topic_ids: sdf.topic_ids
        };
        nodeIds.add(edge.from_system_id);
        nodeIds.add(edge.to_system_id);
        const bucket = outgoing.get(edge.from_system_id) ?? [];
        bucket.push(edge);
        outgoing.set(edge.from_system_id, bucket);
        return edge;
      });
    for (const bucket of outgoing.values()) {
      bucket.sort((left, right) => compareNaturalBusinessIds(left.sdf_id, right.sdf_id));
    }
    return { node_ids: Array.from(nodeIds).sort(), edges, outgoing };
  }
}
