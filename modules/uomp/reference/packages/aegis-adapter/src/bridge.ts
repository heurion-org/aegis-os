import type { Scopes } from '@uomp/core';
import { aggregateDecisions, scopesToResources } from './mapping.js';
import type {
  AegisEscalation,
  AegisLease,
  AegisPolicyClient,
  AegisScopeDecision,
  MemoryAction,
} from './types.js';

/**
 * UOMP-side facade over an Aegis policy client.
 *
 * The bridge only evaluates consent. It does not read or write memory data;
 * the UOMP Memory Guard keeps that responsibility until the native memory
 * module lands.
 */
export class AegisConsentBridge {
  constructor(private readonly client: AegisPolicyClient) {}

  async evaluateResource(action: MemoryAction, resource: string) {
    return this.client.evaluate(action, resource);
  }

  async evaluateScopes(scopes: Scopes): Promise<AegisScopeDecision> {
    const requests = scopesToResources(scopes);
    const decisions = [];
    for (const request of requests) {
      decisions.push(await this.client.evaluate(request.action, request.resource));
    }
    return aggregateDecisions(decisions, requests);
  }

  /**
   * Trusted approval surface only. Never expose this through the Agent MCP
   * channel: the agent must not be able to approve its own escalation.
   */
  async approveEscalations(escalationIds: string[], ttlSecs: number): Promise<AegisLease[]> {
    const leases: AegisLease[] = [];
    for (const escalationId of escalationIds) {
      leases.push(await this.client.approveEscalation(escalationId, ttlSecs));
    }
    return leases;
  }

  /**
   * Trusted denial surface. Closes the matching Aegis escalations without
   * issuing a lease.
   */
  async denyEscalations(escalationIds: string[]): Promise<void> {
    for (const escalationId of escalationIds) {
      await this.client.denyEscalation(escalationId);
    }
  }

  async listEscalations(): Promise<AegisEscalation[]> {
    return this.client.listEscalations();
  }
}
