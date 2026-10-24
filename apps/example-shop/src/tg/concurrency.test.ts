import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { openDatabase } from '../db/database.ts';

const workerEntry = fileURLToPath(new URL('./concurrency-worker.ts', import.meta.url));

interface WorkerResult {
  state: string;
  code?: string;
}

function runWorker(dbPath: string, grantId: string, amount: number, budget: number) {
  return new Promise<WorkerResult>((resolve, reject) => {
    const proc = spawn(
      process.execPath,
      [workerEntry, dbPath, grantId, String(amount), String(budget)],
      { stdio: ['ignore', 'pipe', 'pipe'] },
    );
    let out = '';
    let err = '';
    proc.stdout?.on('data', (c) => {
      out += c;
    });
    proc.stderr?.on('data', (c) => {
      err += c;
    });
    proc.on('exit', (code) => {
      if (code !== 0) {
        reject(new Error(`worker exited ${String(code)}: ${err}`));
        return;
      }
      try {
        resolve(JSON.parse(out.trim()) as WorkerResult);
      } catch {
        reject(new Error(`bad worker output: ${out} ${err}`));
      }
    });
    proc.on('error', reject);
  });
}

describe('cross-process ledger atomicity', () => {
  it('two processes cannot both spend the same remaining budget', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'tg-ledger-race-'));
    const dbPath = join(dir, 'shop.db');
    // openDatabase runs migrations and sets busy_timeout so concurrent
    // writers serialize instead of failing.
    openDatabase(dbPath).close();

    // Budget 10_000; each process tries to reserve 6_000. With correct
    // check-and-insert atomicity exactly one can win.
    const results = await Promise.all(
      Array.from({ length: 4 }, () => runWorker(dbPath, 'grt_race', 6_000, 10_000)),
    );
    const winners = results.filter((r) => r.state === 'reserved');
    const losers = results.filter((r) => r.state === 'denied');
    assert.equal(winners.length, 1, `expected exactly one winner, got ${JSON.stringify(results)}`);
    assert.equal(losers.length, 3);
    for (const loser of losers) {
      assert.equal(loser.code, 'tg.constraint.violated');
    }

    // The DB itself is the source of truth: one live reservation, 6000 held.
    const db = openDatabase(dbPath);
    const rows = db
      .prepare(
        "SELECT COUNT(*) AS n, COALESCE(SUM(amount_minor),0) AS held FROM tg_ledger_reservations WHERE grant_id = 'grt_race' AND state = 'reserved'",
      )
      .get() as { n: number; held: number };
    assert.equal(rows.n, 1);
    assert.equal(rows.held, 6000);
    db.close();
  });
});
