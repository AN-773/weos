/**
 * Generator for the WeOS golden-token fixture (not run by Go).
 *
 * Produces a real medai-accounts token with medai-accounts' own test harness:
 * sign-up -> sign-in -> GET /api/auth/token, plus the public JWKS it was signed
 * with (an ephemeral key from a throwaway test database; no private key leaves
 * the test). To regenerate:
 *
 *   cd medai-accounts
 *   COMPOSE_PROJECT_NAME=acc-w2g-golden eval "$(scripts/test-db.sh up)"
 *   cp <this file> test/integration/zz-golden-w2g.int.test.ts
 *   GOLDEN_OUT=<weos-fork>/rest/testdata/accounts-golden \
 *     pnpm vitest run --project integration test/integration/zz-golden-w2g.int.test.ts
 *   rm test/integration/zz-golden-w2g.int.test.ts
 *   COMPOSE_PROJECT_NAME=acc-w2g-golden scripts/test-db.sh down
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { decodeJwt } from 'jose';
import { afterAll, beforeAll, expect, it } from 'vitest';
import { createTestDatabase } from '../support/db.ts';
import type { TestDatabase } from '../support/db.ts';
import { createTestService, TEST_AUDIENCE } from '../support/service.ts';

const ISSUER = 'https://auth.medicalstudent.ai';

let db: TestDatabase;
let svc: ReturnType<typeof createTestService>;

beforeAll(async () => {
  db = await createTestDatabase();
  svc = createTestService(db.pool, db.url, undefined, { env: { JWT_ISSUER: ISSUER } });
});
afterAll(async () => {
  await db.drop();
});

it('writes the golden token fixture', async () => {
  const out = process.env['GOLDEN_OUT'];
  if (!out) throw new Error('GOLDEN_OUT is not set');
  await svc.signUp('golden.user@example.com', 'correct horse battery', 'Golden User');
  const { sessionToken } = await svc.signIn('golden.user@example.com', 'correct horse battery');
  const token = await svc.token(sessionToken ?? '');
  const jwks = await (await svc.request('/oauth2/certs')).json();
  const discovery = await (await svc.request('/.well-known/openid-configuration')).json();
  const { rows } = await db.pool.query<{ id: string; accountId: string }>('SELECT id, "accountId" FROM "user"');
  const user = rows[0];
  if (!user) throw new Error('no user');
  const claims = decodeJwt(token);
  expect(claims.iss).toBe(ISSUER);
  expect(claims.aud).toEqual([TEST_AUDIENCE]);

  mkdirSync(out, { recursive: true });
  writeFileSync(join(out, 'token.jwt'), `${token}\n`);
  writeFileSync(join(out, 'jwks.json'), `${JSON.stringify(jwks, null, 2)}\n`);
  writeFileSync(join(out, 'discovery.json'), `${JSON.stringify(discovery, null, 2)}\n`);
  writeFileSync(
    join(out, 'expected.json'),
    `${JSON.stringify({ issuer: ISSUER, audience: TEST_AUDIENCE, userId: user.id, accountId: user.accountId, claims }, null, 2)}\n`,
  );
});
