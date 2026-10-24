import type { DiscoveryAction, DiscoveryDocument } from '@trailgate/core';
import type { SiteContext } from './discovery.ts';
import type { StoredGrantRecord } from './store.ts';

/**
 * The action catalog a validated discovery document advertises (spec
 * section 5.2). Descriptors are advisory: they tell the agent which method,
 * path, and permission an action needs. They authorize nothing by
 * themselves; the server pipeline remains the only authority.
 */
export function siteActions(site: SiteContext | DiscoveryDocument): DiscoveryAction[] {
  const document: DiscoveryDocument =
    (site as SiteContext).document === undefined
      ? (site as DiscoveryDocument)
      : (site as SiteContext).document;
  return document.actions ?? [];
}

/** One advertised action plus the local view of what a stored grant covers. */
export interface ActionCoverage {
  action: DiscoveryAction;
  /** Whether some unexpired stored grant plausibly covers this action. */
  covered: boolean;
  /** The covering grant, when `covered` is true. */
  grant?: StoredGrantRecord;
  /** Permissions the action needs that no candidate grant holds. */
  missing?: string[];
}

function resourcePrefix(template: string): string {
  const marker = template.indexOf('{');
  return marker === -1 ? template : template.slice(0, marker);
}

/**
 * Local advisory coverage: does a stored grant plausibly let the agent run
 * each advertised action right now? Permission match plus, when the action
 * names a `resource` template, a stored resource sharing its static prefix.
 * Expired grants are ignored. This is a planning view for intent mapping;
 * the server decides authorization on every request.
 */
export function actionCoverage(
  actions: readonly DiscoveryAction[],
  grants: readonly StoredGrantRecord[],
  issuer: string,
  now: number,
): ActionCoverage[] {
  const candidates = grants.filter((g) => g.issuer === issuer && g.expiresAt > now);
  return actions.map((action) => {
    const prefix = action.resource === undefined ? undefined : resourcePrefix(action.resource);
    const permitted = candidates.filter((g) => g.permissions.includes(action.permission));
    const covering =
      prefix === undefined
        ? permitted[0]
        : permitted.find((g) => g.resources.some((r) => r.startsWith(prefix)));
    if (covering !== undefined) {
      return { action, covered: true, grant: covering };
    }
    const out: ActionCoverage = { action, covered: false };
    if (permitted.length === 0) {
      out.missing = [action.permission];
    }
    return out;
  });
}
