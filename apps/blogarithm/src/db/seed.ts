import { addComment } from '../domain/comments.ts';
import { notify } from '../domain/notifications.ts';
import { createDraft, publishPost } from '../domain/posts.ts';
import { createUser, hashPassword } from '../domain/users.ts';
import type { Db } from './database.ts';

/**
 * Deterministic demo dataset: one author, a mix of published posts and
 * drafts, comments, and notifications. All timestamps are fixed offsets
 * from seed time so the app looks alive immediately.
 */
export function seedIfEmpty(db: Db): void {
  const row = db.prepare('SELECT COUNT(*) AS n FROM users').get() as { n: number };
  if (row.n > 0) {
    return;
  }
  const now = Math.floor(Date.now() / 1000);
  const day = 86_400;

  const user = createUser(db, {
    email: 'demo@blogarithm.dev',
    name: 'Ada Osei',
    username: 'ada',
    password: 'demo-password-1',
  });
  db.prepare('UPDATE users SET bio = ?, avatar = ? WHERE id = ?').run(
    'Writes about software, systems, and the craft of publishing.',
    '',
    user.id,
  );

  const posts: {
    title: string;
    excerpt: string;
    tags: string[];
    body: string;
    ageDays: number;
    draft?: boolean;
  }[] = [
    {
      title: 'Why delegated authority beats shared credentials',
      excerpt: 'Giving an agent your password is not delegation. Scoped, revocable grants are.',
      tags: ['security', 'agents'],
      ageDays: 12,
      body: [
        'When people connect an AI agent to a service, the default move is still to hand over credentials: a password, a session cookie, or a personal access token with broad scope.',
        '## The problem with credentials',
        'Credentials answer "who are you", not "what may you do". A token that can post can usually also delete, export, and change settings. Revoking it often means rotating everything.',
        '> Delegation should describe intent: read my drafts, but do not publish them.',
        '## What scoped grants give you',
        '- A defined permission set the site enforces server-side.',
        '- Expiry and revocation that take effect without a password reset.',
        '- Receipts, so you can audit what the agent actually did.',
        'The interesting part is not the cryptography. It is that the website stays in charge: its own rules, its own storage, its own definition of each permission.',
      ].join('\n\n'),
    },
    {
      title: 'A field guide to writing useful drafts',
      excerpt: 'Drafts are where thinking happens. Treat them as a workspace, not a waiting room.',
      tags: ['writing', 'workflow'],
      ageDays: 8,
      body: [
        'Most publishing advice focuses on the publish button. But the quality of a post is decided much earlier, in the draft.',
        '## Keep drafts cheap',
        'A draft is not a commitment. Write the ugly version first; nobody sees it until you say so.',
        '## Three passes that work',
        '1. Get the argument down in order.',
        '2. Cut every paragraph that does not move the argument.',
        '3. Read it aloud once. Fix what sounds like a committee wrote it.',
        'That is the whole method.',
      ].join('\n\n'),
    },
    {
      title: 'Comment sections are a feature, not a liability',
      excerpt: 'Moderation tooling matters more than the comment box itself.',
      tags: ['community', 'moderation'],
      ageDays: 5,
      body: [
        'Every blogging platform eventually faces the comment question. The honest answer: comments work when the owner has real controls.',
        '## What real controls look like',
        '- Per-post switches, not a global on/off.',
        '- The ability to close comments without deleting the discussion that already happened.',
        '- Notifications that tell you a comment arrived.',
        'Readers notice the difference between a managed space and an abandoned one.',
      ].join('\n\n'),
    },
    {
      title: 'Notes on building software you can put down',
      excerpt: 'The best systems are the ones you can leave alone for a week.',
      tags: ['software', 'craft'],
      ageDays: 3,
      body: [
        'A system you cannot leave alone is a system that owns you. Operability is a feature.',
        '## Signs your system can be put down',
        '- State lives in one place, with a real schema.',
        '- Background jobs are idempotent.',
        '- You can explain the failure modes in one paragraph.',
        'Complexity is unavoidable. Unexplained complexity is a choice.',
      ].join('\n\n'),
    },
    {
      title: 'What agents should never be allowed to do',
      excerpt: 'An incomplete list, kept short on purpose.',
      tags: ['agents', 'policy'],
      ageDays: 1,
      body: [
        'Conversations about AI agents usually start with what they can do. The more interesting question is what they should never do on your behalf.',
        '## My working list',
        '- Change authentication settings: password, email, recovery methods.',
        '- Grant itself more permissions.',
        '- Delete without a recovery path.',
        'Everything else is negotiable per task, per grant, per session. That is the point of scoped delegation.',
      ].join('\n\n'),
    },
    {
      title: 'Draft: typography choices for long-form reading',
      excerpt: 'Line length, measure, and why your article page feels wrong.',
      tags: ['design', 'typography'],
      ageDays: 0,
      draft: true,
      body: [
        'Work in progress.',
        '## The measure problem',
        'Lines over about 75 characters make readers lose their place. Lines under 45 feel choppy.',
        'TODO: measure this article page and adjust.',
      ].join('\n\n'),
    },
    {
      title: 'Draft: a checklist for reviewing agent actions',
      excerpt: 'Before you approve anything, read the permission list twice.',
      tags: ['agents', 'security'],
      ageDays: 0,
      draft: true,
      body: [
        'Working notes.',
        '- Does the agent need write access, or just read?',
        '- Is publication in the permission set? If so, why?',
        '- What happens when the grant expires?',
      ].join('\n\n'),
    },
  ];

  for (const p of posts) {
    const created = now - p.ageDays * day;
    const post = createDraft(
      db,
      user.id,
      { title: p.title, excerpt: p.excerpt, body: p.body, tags: p.tags },
      created,
    );
    if (p.draft !== true) {
      publishPost(db, post.id, user.id, created + 3600);
    }
  }

  // comments on two published posts
  const published = db
    .prepare("SELECT id FROM posts WHERE status = 'published' ORDER BY published_at")
    .all() as { id: string }[];
  const first = published[0]?.id;
  const second = published[1]?.id;
  if (first !== undefined) {
    addComment(
      db,
      first,
      {
        authorName: 'Marcus',
        body: 'The credential-vs-delegation framing is the clearest I have seen.',
      },
      now - 2 * day,
    );
    addComment(
      db,
      first,
      {
        authorName: 'Priya',
        body: 'Receipts for agent actions would change how my team audits automation.',
      },
      now - day,
    );
  }
  if (second !== undefined) {
    addComment(
      db,
      second,
      { authorName: 'June', body: 'Pass two is where every post I respect gets made.' },
      now - day,
    );
  }

  notify(
    db,
    user.id,
    'grant_hint',
    'Tip',
    'An agent can request access to your blog through TrailGate. You approve each permission set before it acts.',
    undefined,
    now - 3600,
  );
}

export const DEMO_CREDENTIALS = { email: 'demo@blogarithm.dev', password: 'demo-password-1' };

export function ensureDemoPassword(db: Db): void {
  const row = db.prepare('SELECT id FROM users WHERE email = ?').get(DEMO_CREDENTIALS.email) as
    | { id: string }
    | undefined;
  if (row !== undefined) {
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(
      hashPassword(DEMO_CREDENTIALS.password),
      row.id,
    );
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { openDatabase } = await import('./database.ts');
  const { loadConfig } = await import('../config.ts');
  const config = loadConfig();
  const db = openDatabase(config.dbPath);
  seedIfEmpty(db);
  console.log(`seeded ${config.dbPath}`);
}
