import { GovernanceRepository } from "../../repositories/governanceRepository.js";
import {
  approveBaselineSchema,
  createProjectWorkspaceSchema,
  freezeRevisionSchema,
} from "./contracts.js";

export class GovernanceService {
  constructor(private readonly repository = new GovernanceRepository()) {}

  async createProjectWorkspace(input: unknown) {
    return this.repository.createProjectWorkspace(createProjectWorkspaceSchema.parse(input));
  }

  async freezeRevision(input: unknown) {
    return this.repository.freezeRevision(freezeRevisionSchema.parse(input));
  }

  async approveBaseline(input: unknown) {
    return this.repository.approveBaseline(approveBaselineSchema.parse(input));
  }
}
