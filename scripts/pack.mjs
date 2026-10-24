// Assembles release artifacts in dist-release/:
//   trailgate.mjs, trailgate-mcp.mjs      self-contained agent bundles
//   trailgate-<pkg>-<ver>.tgz            npm tarballs of every packages/* project
//   SHA256SUMS                            checksums for all artifacts
//
// Tarballs carry resolved version deps (workspace:* -> real versions) but can
// only be installed where those deps resolve; the .mjs bundles are the
// supported zero-install path (docs/INSTALL_AND_DEPLOY.md).
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFileSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';

const root = new URL('..', import.meta.url).pathname;
const out = join(root, 'dist-release');
rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });

for (const file of ['trailgate.mjs', 'trailgate-mcp.mjs']) {
  copyFileSync(join(root, 'bundle', file), join(out, file));
}

for (const pkg of readdirSync(join(root, 'packages'))) {
  const dir = join(root, 'packages', pkg);
  let name;
  let version;
  try {
    ({ name, version } = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')));
  } catch {
    continue;
  }
  const result = execFileSync('pnpm', ['pack', '--pack-destination', out], {
    cwd: dir,
    encoding: 'utf8',
  }).trim();
  console.log(`packed ${name}@${version} -> ${basename(result)}`);
}

const sums = readdirSync(out)
  .filter((f) => f !== 'SHA256SUMS')
  .sort()
  .map(
    (f) =>
      `${createHash('sha256')
        .update(readFileSync(join(out, f)))
        .digest('hex')}  ${f}`,
  );
writeFileSync(join(out, 'SHA256SUMS'), `${sums.join('\n')}\n`);
console.log(`dist-release/: ${sums.length + 1} artifacts`);
