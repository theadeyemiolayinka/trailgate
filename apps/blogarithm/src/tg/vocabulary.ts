/**
 * Blogarithm's TrailGate vocabulary. Site-level choices: the spec defines
 * formats and semantics; the site defines the concrete permission
 * identifiers and resource selector types it advertises.
 *
 * The permission split is the point of the demo: drafting is not
 * publishing, and comment settings are not post deletion.
 */

export const PERMISSIONS = [
  'tg.posts.read',
  'tg.posts.create',
  'tg.posts.update',
  'tg.posts.publish',
  'tg.posts.delete',
  'tg.posts.settings',
  'tg.comments.read',
  'tg.comments.delete',
  'tg.notifications.read',
  'tg.notifications.write',
  'tg.profile.read',
] as const;

/** Human-readable labels shown verbatim on the consent page. */
export const PERMISSION_LABELS: Record<
  string,
  { label: string; risk: 'read' | 'write' | 'publish' | 'delete' }
> = {
  'tg.posts.read': { label: 'Read my posts, including private drafts', risk: 'read' },
  'tg.posts.create': { label: 'Create drafts', risk: 'write' },
  'tg.posts.update': { label: 'Edit my posts and drafts', risk: 'write' },
  'tg.posts.publish': { label: 'Publish and unpublish my posts', risk: 'publish' },
  'tg.posts.delete': { label: 'Delete and restore my posts', risk: 'delete' },
  'tg.posts.settings': { label: 'Change post settings such as comments', risk: 'write' },
  'tg.comments.read': { label: 'Read comments on my posts', risk: 'read' },
  'tg.comments.delete': { label: 'Delete comments on my posts', risk: 'delete' },
  'tg.notifications.read': { label: 'Read my notifications', risk: 'read' },
  'tg.notifications.write': { label: 'Mark my notifications as read', risk: 'write' },
  'tg.profile.read': { label: 'Read my public author profile', risk: 'read' },
};

/** Resource selector types this site accepts inside a grant scope. */
export const RESOURCE_TYPES = ['post', 'comment'] as const;

export function postSelector(postId: string): string {
  return `post:${postId}`;
}

export function commentSelector(commentId: string): string {
  return `comment:${commentId}`;
}

const SELECTOR_RE = /^(post|comment):[A-Za-z0-9_-]+$/;
const TEMPLATE_RE = /^post:\{user\}$/;

export function isBlogSelector(selector: string): boolean {
  return SELECTOR_RE.test(selector) || TEMPLATE_RE.test(selector);
}

/**
 * Consent-time binding for `{user}` templates: `post:{user}` expands to
 * the subject's existing posts. Concrete selectors pass through. The
 * selector set may only narrow, never widen.
 */
export function bindBlogSelectors(
  resources: readonly string[],
  subject: string,
  existingPostIds: (subject: string) => string[],
): string[] {
  return resources
    .flatMap((selector) =>
      selector === 'post:{user}' ? existingPostIds(subject).map(postSelector) : [selector],
    )
    .filter((s) => s !== undefined);
}
