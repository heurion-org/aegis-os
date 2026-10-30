import type { ScopeAction, Scopes } from '@uomp/core';
import type {
  AegisDecisionKind,
  AegisMemoryDecision,
  AegisMemoryRequest,
  AegisScopeDecision,
} from './types.js';

/**
 * UOMP tag/key -> Aegis resource naming.
 *
 * Deny lists are deliberately not emitted as leases. They are enforced by the
 * memory module after a lease matches, because Aegis lease patterns only
 * express positive scope.
 */
export function scopeResources(scope: ScopeAction): string[] {
  const resources: string[] = [];
  for (const tag of scope.tags) {
    if (tag) resources.push(`memory:tag:${tag}`);
  }
  for (const key of scope.keys) {
    if (key) resources.push(`memory:key:${key}`);
  }
  return resources;
}

export function scopesToResources(scopes: Scopes): AegisMemoryRequest[] {
  return [
    ...scopeResources(scopes.read).map((resource) => ({ action: 'read' as const, resource })),
    ...scopeResources(scopes.write).map((resource) => ({ action: 'write' as const, resource })),
  ];
}

/**
 * Aegis decisions are combined with deny > ask > allow. A single denied
 * resource must fail the whole request; a single escalation makes the request
 * pending approval.
 */
export function aggregateDecisions(
  decisions: AegisMemoryDecision[],
  requests: AegisMemoryRequest[],
): AegisScopeDecision {
  if (requests.length === 0) {
    return {
      decision: 'deny',
      requests,
      decisions,
      escalationIds: [],
    };
  }

  const hasDeny = decisions.some((item) => item.decision === 'deny');
  const hasAsk = decisions.some((item) => item.decision === 'ask');
  const decision: AegisDecisionKind = hasDeny ? 'deny' : hasAsk ? 'ask' : 'allow';

  return {
    decision,
    requests,
    decisions,
    escalationIds: decisions
      .map((item) => item.escalation_id)
      .filter((id): id is string => Boolean(id)),
  };
}
