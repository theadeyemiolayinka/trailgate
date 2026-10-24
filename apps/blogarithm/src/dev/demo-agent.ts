/**
 * Scripted TrailGate demonstration for Blogarithm. Run with the app
 * up: `pnpm demo`. Every step goes through the real Agent SDK, Server
 * SDK, enforcement pipeline, and database. Denials shown are real
 * protocol denials - nothing is simulated.
 *
 * The story: an agent gets draft-writing authority, is denied when it
 * tries to publish, gains publication through a second consent, changes
 * comment settings, cannot delete, and is cut off by revocation.
 *
 * Flags:
 *   --manual   stop at each consent step and wait for browser approval
 */
import { createAgentClient, SoftwareKeyProvider } from '@trailgate/agent';
import { loopbackTransport } from './loopback.ts';

const ISSUER = process.env.BLOG_ISSUER ?? 'https://localhost:3444';
const HTTP_BASE = `http://127.0.0.1:${process.env.BLOG_PORT ?? '3301'}`;
const MANUAL = process.argv.includes('--manual');
const EMAIL = 'demo@blogarithm.dev';
const PASSWORD = 'demo-password-1';

const ok = (label: string, detail: string) => console.log(`   ${label}: ${detail}`);
const step = (n: string, title: string) => console.log(`\n${n}. ${title}`);

function printOutcome(status: number, code: string | undefined, receipt: string): void {
  ok('status', `${status}`);
  if (code !== undefined) {
    const kind = code.startsWith('tg.')
      ? 'protocol denial'
      : code.startsWith('blog.')
        ? 'business failure'
        : 'error';
    ok('outcome', `${code} (${kind})`);
  }
  if (receipt !== '') {
    ok('receipt', receipt);
  }
}

async function loginCookie(): Promise<string> {
  const login = await fetch(`${HTTP_BASE}/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ email: EMAIL, password: PASSWORD, next: '/' }).toString(),
    redirect: 'manual',
  });
  return (login.headers.get('set-cookie') ?? '').split(';')[0] as string;
}

/** Approves a grant request through the real login + consent form. */
async function consentViaBrowserPath(requestId: string, perms: string[]): Promise<void> {
  const cookie = await loginCookie();
  const page = await fetch(`${HTTP_BASE}/tg/consent?request_id=${requestId}`, {
    headers: { cookie },
  });
  const html = await page.text();
  const csrf = html.match(/name="_csrf" value="([^"]+)"/)?.[1];
  if (csrf === undefined) {
    throw new Error('consent page did not render a CSRF token');
  }
  // The consent form renders a tri-state radio per permission
  // (`mode_<perm>` = allow|approval|deny); submit the page's checked
  // defaults, which mark site-suggested permissions as approval.
  const body = new URLSearchParams({ _csrf: csrf, request_id: requestId, decision: 'approve' });
  const groups = [
    ...new Set([...html.matchAll(/name="mode_([^"]+)"/g)].map((m) => m[1] as string)),
  ].filter((p) => perms.includes(p));
  if (groups.length === 0) {
    throw new Error('consent page rendered no permission controls');
  }
  for (const perm of groups) {
    const checked = html.match(
      new RegExp(`name="mode_${perm.replace(/\./g, '\\.')}" value="([^"]+)" checked`),
    );
    body.append(`mode_${perm}`, checked?.[1] ?? 'allow');
  }
  const decide = await fetch(`${HTTP_BASE}/tg/consent`, {
    method: 'POST',
    headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
    redirect: 'manual',
  });
  if (decide.status !== 303 && decide.status !== 200) {
    throw new Error(`consent decision failed: ${decide.status}`);
  }
}

/** Approves a pending action through the real workspace approvals page. */
async function approveActionViaBrowserPath(actionId: string): Promise<void> {
  const cookie = await loginCookie();
  const page = await fetch(`${HTTP_BASE}/workspace/approvals/${actionId}`, {
    headers: { cookie },
  });
  const html = await page.text();
  const csrf = html.match(/name="_csrf" value="([^"]+)"/)?.[1];
  if (csrf === undefined) {
    throw new Error('approvals page did not render a CSRF token');
  }
  const res = await fetch(`${HTTP_BASE}/workspace/approvals/decide`, {
    method: 'POST',
    headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ _csrf: csrf, action_id: actionId, decision: 'approve' }).toString(),
    redirect: 'manual',
  });
  if (res.status !== 303 && res.status !== 200) {
    throw new Error(`pending action decision failed: ${res.status}`);
  }
}

/** Revokes a grant through the real workspace access page. */
async function revokeViaBrowserPath(jti: string): Promise<void> {
  const cookie = await loginCookie();
  const page = await fetch(`${HTTP_BASE}/workspace/access`, { headers: { cookie } });
  const html = await page.text();
  const csrf = html.match(/name="_csrf" value="([^"]+)"/)?.[1];
  if (csrf === undefined) {
    throw new Error('access page did not render a CSRF token');
  }
  const res = await fetch(`${HTTP_BASE}/workspace/access/${jti}/revoke`, {
    method: 'POST',
    headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ _csrf: csrf }).toString(),
    redirect: 'manual',
  });
  if (res.status !== 303 && res.status !== 200) {
    throw new Error(`revoke failed: ${res.status}`);
  }
}

const transport = loopbackTransport(ISSUER, HTTP_BASE);
const client = createAgentClient({ transport });
client.useKey(SoftwareKeyProvider.generate());

step('1', 'discovery');
const site = await client.discover(ISSUER);
ok('issuer', `${site.issuer}  protocol ${site.protocolVersion}`);

step('2', 'protected request with no grant (expect denial)');
const unsigned = await transport.send({ method: 'GET', url: `${ISSUER}/api/posts` });
const unsignedErr = JSON.parse(new TextDecoder().decode(unsigned.body)) as {
  error?: { code: string };
};
printOutcome(unsigned.status, unsignedErr.error?.code, 'none issued');

step('3', 'consent: draft-writing scope only (no publish, no delete, no settings)');
const DRAFT_PERMS = ['tg.posts.read', 'tg.posts.create', 'tg.posts.update'];
const session = await client.requestGrant(site, { permissions: DRAFT_PERMS });
ok('request', session.requestId);
if (MANUAL) {
  console.log(`   approve in the browser: ${HTTP_BASE}/tg/consent?request_id=${session.requestId}`);
  console.log(`   (${EMAIL} / ${PASSWORD})`);
} else {
  console.log('   auto-approving through the real login + consent form...');
  await consentViaBrowserPath(session.requestId, DRAFT_PERMS);
}
const grant1 = await client.awaitApproval(session.requestId, { intervalMs: 50 });
ok('grant', grant1.jti);

step('4', 'allowed action inside scope: create a draft');
const created = await client.fetchProtected(site, {
  method: 'POST',
  grantId: grant1.jti,
  target: '/api/posts',
  body: JSON.stringify({
    title: 'How AI agents are changing software development',
    excerpt: 'Delegation is becoming a first-class interface for the web.',
    body: '## The shift\n\nAgents now act on our behalf inside real applications. The hard part is not capability - it is authority.\n\n- Scoped grants replace shared credentials\n- Enforcement lives on the website, not in the prompt\n- Every action leaves a signed receipt\n\nThe protocols being built today will decide whether that authority is meaningful.',
    tags: ['agents', 'software'],
  }),
});
printOutcome(
  created.status,
  created.error?.code,
  created.receipt?.verified === true ? 'verified' : '',
);
const draft = JSON.parse(new TextDecoder().decode(created.body ?? new Uint8Array())) as {
  post?: { id: string; status: string };
};
const postId = draft.post?.id as string;
ok('draft', `${postId} status=${draft.post?.status}`);
ok('visible', `open ${HTTP_BASE}/workspace/posts/${postId}/edit in the dashboard`);

step('5', 'the key moment: publish without tg.posts.publish (expect denial)');
const denied = await client.fetchProtected(site, {
  method: 'POST',
  grantId: grant1.jti,
  target: `/api/posts/${postId}/publish`,
});
printOutcome(
  denied.status,
  denied.error?.code,
  denied.receipt?.verified === true ? 'denial receipt verified' : '',
);

step('6', 'user grants publication + settings through a second consent');
const PUB_PERMS = [...DRAFT_PERMS, 'tg.posts.publish', 'tg.posts.settings'];
const session2 = await client.requestGrant(site, {
  permissions: PUB_PERMS,
  // post:{user} binds to the consenting user's existing posts at approval
  // time, which now includes the draft created in step 4.
  resources: ['post:{user}'],
});
if (MANUAL) {
  console.log(
    `   approve in the browser: ${HTTP_BASE}/tg/consent?request_id=${session2.requestId}`,
  );
} else {
  await consentViaBrowserPath(session2.requestId, PUB_PERMS);
}
const grant2 = await client.awaitApproval(session2.requestId, { intervalMs: 50 });
ok('grant', grant2.jti);

step('7', 'publish is approval-gated: the call queues, a human approves, then it runs');
const published = await client.fetchProtected(site, {
  method: 'POST',
  grantId: grant2.jti,
  target: `/api/posts/${postId}/publish`,
});
printOutcome(
  published.status,
  published.error?.code,
  published.receipt?.verified === true ? 'verified' : '',
);
const actionId = published.pending?.id as string;
ok('queued', `${actionId}  review: ${HTTP_BASE}/workspace/approvals/${actionId}`);
if (MANUAL) {
  console.log('   approve it in the browser; polling status...');
} else {
  console.log('   auto-approving through the real approvals page...');
  await approveActionViaBrowserPath(actionId);
}
let actionStatus = await client.actionStatus(site, actionId, { grantId: grant2.jti });
for (let i = 0; i < 120 && actionStatus.status === 'pending'; i += 1) {
  await new Promise((r) => setTimeout(r, 1000));
  actionStatus = await client.actionStatus(site, actionId, { grantId: grant2.jti });
}
ok('action status', `${actionStatus.status}  result=${actionStatus.result?.status}`);
const pubPost = (actionStatus.result?.body ?? {}) as { post?: { slug: string } };
ok('live', `${HTTP_BASE}/post/${pubPost.post?.slug}`);

step('8', 'disable comments through tg.posts.settings');
const settings = await client.fetchProtected(site, {
  method: 'POST',
  grantId: grant2.jti,
  target: `/api/posts/${postId}/settings`,
  body: JSON.stringify({ comments_enabled: false }),
});
printOutcome(
  settings.status,
  settings.error?.code,
  settings.receipt?.verified === true ? 'verified' : '',
);

step('9', 'comment form now rejects submissions (server-side, not just UI)');
const publicComment = await fetch(`${HTTP_BASE}/post/${pubPost.post?.slug}/comments`, {
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({ name: 'Visitor', body: 'Hello?' }).toString(),
});
ok('public comment attempt', `${publicComment.status} (rejected)`);

step('10', 'delete without tg.posts.delete (expect denial)');
const del = await client.fetchProtected(site, {
  method: 'DELETE',
  grantId: grant2.jti,
  target: `/api/posts/${postId}`,
});
printOutcome(
  del.status,
  del.error?.code,
  del.receipt?.verified === true ? 'denial receipt verified' : '',
);

step('11', 'user revokes the grant; next protected call fails');
await revokeViaBrowserPath(grant2.jti);
const afterRevoke = await client.fetchProtected(site, {
  method: 'GET',
  grantId: grant2.jti,
  target: '/api/posts',
});
printOutcome(
  afterRevoke.status,
  afterRevoke.error?.code,
  afterRevoke.receipt?.verified === true ? 'denial receipt verified' : '',
);

console.log('\nDone. The same protocol governed drafting, publishing, settings, and revocation.');
