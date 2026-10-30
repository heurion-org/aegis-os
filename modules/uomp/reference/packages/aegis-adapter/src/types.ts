export type MemoryAction = 'read' | 'write' | 'delete';

export type AegisDecisionKind = 'allow' | 'ask' | 'deny';

export interface AegisMemoryRequest {
  action: MemoryAction;
  resource: string;
}

export interface AegisMemoryDecision {
  protocol: 'uomp';
  decision: AegisDecisionKind;
  action: string;
  resource: string;
  escalation_id?: string;
  reason?: string;
  matched_rule?: string;
  suggested_lease_scope?: string;
}

export interface AegisLease {
  lease_id: string;
  org_id: string;
  agent_id: string;
  action_pattern: string;
  resource_pattern: string;
  expires_at_ms: number;
  granted_by: string;
}

export interface AegisEscalation {
  escalation_id: string;
  org_id: string;
  agent_id: string;
  action: string;
  target_resource: string;
  reason: string;
  suggested_lease_scope: string;
  status: string;
  created_at_ms: number;
}

export interface AegisScopeDecision {
  decision: AegisDecisionKind;
  requests: AegisMemoryRequest[];
  decisions: AegisMemoryDecision[];
  escalationIds: string[];
}

/**
 * Minimal policy client used by the UOMP bridge.
 *
 * `approveEscalation` is for the trusted local approval surface only. It must
 * never be reachable from an Agent's MCP channel.
 */
export interface AegisPolicyClient {
  evaluate(action: MemoryAction, resource: string): Promise<AegisMemoryDecision>;
  approveEscalation(escalationId: string, ttlSecs: number): Promise<AegisLease>;
  denyEscalation(escalationId: string): Promise<void>;
  listEscalations(): Promise<AegisEscalation[]>;
}
