// Produces self-contained single-file executables in bundle/:
//   trailgate.mjs      the agent CLI (`node trailgate.mjs <command>`)
//   trailgate-mcp.mjs  the MCP stdio server (`node trailgate-mcp.mjs`)
//
// Each file bundles all workspace deps, so it runs on any machine with
// Node >= 22.18 and no npm install. Node builtins (node:sqlite included)
// are left external.

import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { build } from 'esbuild';

const root = new URL('..', import.meta.url).pathname;
const out = join(root, 'bundle');
mkdirSync(out, { recursive: true });

const targets = [
  { entry: 'packages/agent-cli/src/cli.ts', name: 'trailgate.mjs' },
  { entry: 'packages/mcp-adapter/src/mcp.ts', name: 'trailgate-mcp.mjs' },
];

for (const { entry, name } of targets) {
  await build({
    entryPoints: [join(root, entry)],
    outfile: join(out, name),
    bundle: true,
    platform: 'node',
    format: 'esm',
    target: 'node22',
    external: ['node:*'],
  });
  console.log(`wrote bundle/${name}`);
}
