/**
 * Tests for the GM-KMS JavaScript SDK.
 *
 * The fake server below enforces the same credential contract as the real
 * one: the API key has to arrive in the `x-api-key` header, and anything else
 * is refused with 401. That is what makes these tests worth running - an SDK
 * that puts the key in the wrong header fails here instead of in production.
 */

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, Server, IncomingMessage, ServerResponse } from 'node:http';
import { AddressInfo } from 'node:net';

import { Client, Error as KmsError, PolicyEffect } from '../src/index';

const API_KEY = 'test-api-key';
const TENANT = 'tenant-a';

interface RecordedRequest {
  method: string;
  path: string;
  headers: Record<string, string | string[] | undefined>;
  body: any;
}

function policyJson(policyId: string, overrides: Record<string, unknown> = {}) {
  return {
    id: policyId,
    name: 'default-allow',
    effect: 'Allow',
    condition: { operator: 'always' },
    resources: ['*'],
    subjects: ['*'],
    tenant: TENANT,
    enabled: true,
    ...overrides,
  };
}

function sendJson(res: ServerResponse, status: number, payload: unknown): void {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

function sendEmpty(res: ServerResponse, status: number): void {
  res.writeHead(status);
  res.end();
}

async function startFakeServer() {
  const requests: RecordedRequest[] = [];
  const policies: Record<string, any> = {};

  const server: Server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      const record: RecordedRequest = {
        method: req.method ?? '',
        path: req.url ?? '',
        headers: req.headers,
        body: raw ? JSON.parse(raw) : undefined,
      };
      requests.push(record);

      // The real server reads the credential from `x-api-key` only.
      if (req.headers['x-api-key'] !== API_KEY) {
        sendJson(res, 401, { error: 'unauthorized' });
        return;
      }

      const path = (req.url ?? '').split('?')[0];

      if (req.method === 'GET' && path === '/v1/keys') {
        sendJson(res, 200, []);
        return;
      }

      if (req.method === 'GET' && path === '/v1/policies') {
        sendJson(res, 200, Object.values(policies));
        return;
      }

      if (req.method === 'GET' && path.startsWith('/v1/policies/')) {
        const id = path.split('/').pop() as string;
        if (!policies[id]) {
          sendJson(res, 404, { error: `policy ${id} not found` });
          return;
        }
        sendJson(res, 200, policies[id]);
        return;
      }

      if (req.method === 'POST' && path === '/v1/policies') {
        const id = `policy-${Object.keys(policies).length + 1}`;
        const body = record.body;
        const effect = String(body.effect);
        const policy = policyJson(id, {
          name: body.name,
          effect: effect.charAt(0).toUpperCase() + effect.slice(1),
          condition: body.condition,
          resources: body.resources,
          subjects: body.subjects,
          enabled: body.enabled ?? true,
          tenant: body.tenant,
        });
        policies[id] = policy;
        sendJson(res, 201, policy);
        return;
      }

      if (req.method === 'DELETE') {
        if (path.startsWith('/v1/policies/')) {
          const id = path.split('/').pop() as string;
          if (!policies[id]) {
            sendJson(res, 404, { error: `policy ${id} not found` });
            return;
          }
          delete policies[id];
          // 204 No Content: no body at all.
          sendEmpty(res, 204);
          return;
        }
        if (path.startsWith('/v1/keys/')) {
          // 204 No Content as well.
          sendEmpty(res, 204);
          return;
        }
      }

      sendJson(res, 404, { error: 'not found' });
    });
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address() as AddressInfo;

  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    requests,
    policies,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

let fake: Awaited<ReturnType<typeof startFakeServer>>;
let client: Client;

before(async () => {
  fake = await startFakeServer();
});

after(async () => {
  await fake.close();
});

beforeEach(() => {
  for (const key of Object.keys(fake.policies)) {
    delete fake.policies[key];
  }
  fake.requests.length = 0;
  client = new Client({
    serverUrl: fake.baseUrl,
    apiKey: API_KEY,
    tenantId: TENANT,
  });
});

test('the API key travels in the x-api-key header', async () => {
  // The fake server refuses anything but `x-api-key`, so reaching it at all
  // proves the credential is presented the way the real server expects it.
  await client.listKeys();

  const sent = fake.requests[fake.requests.length - 1];
  assert.equal(sent.headers['x-api-key'], API_KEY);
  assert.equal(sent.headers['authorization'], undefined);
});

test('a wrong credential is reported as unauthorized', async () => {
  const wrong = new Client({ serverUrl: fake.baseUrl, apiKey: 'not-the-key' });
  await assert.rejects(
    () => wrong.listKeys(),
    (err: unknown) => {
      assert.ok(err instanceof KmsError);
      assert.equal((err as KmsError).status, 401);
      return true;
    }
  );
});

test('createPolicy sends the policy and the tenant', async () => {
  const policy = await client.createPolicy({
    name: 'tenant-scoped-allow',
    effect: PolicyEffect.ALLOW,
    condition: { operator: 'always' },
    resources: ['*'],
    subjects: ['*'],
    tenant: TENANT,
  });

  const sent = fake.requests[fake.requests.length - 1];
  assert.equal(sent.method, 'POST');
  assert.equal(sent.path, '/v1/policies');
  assert.equal(sent.body.name, 'tenant-scoped-allow');
  assert.equal(sent.body.effect, 'allow');
  assert.deepEqual(sent.body.condition, { operator: 'always' });
  assert.deepEqual(sent.body.resources, ['*']);
  assert.deepEqual(sent.body.subjects, ['*']);
  assert.equal(sent.body.tenant, TENANT);
  assert.equal(sent.body.enabled, true);

  assert.equal(policy.id, 'policy-1');
  assert.equal(policy.name, 'tenant-scoped-allow');
  assert.equal(policy.tenant, TENANT);
  assert.equal(policy.enabled, true);
});

test('createPolicy without a tenant leaves the field out', async () => {
  await client.createPolicy({
    name: 'unscoped-allow',
    effect: PolicyEffect.ALLOW,
    condition: { operator: 'always' },
    resources: ['*'],
    subjects: ['*'],
  });

  const sent = fake.requests[fake.requests.length - 1];
  assert.equal('tenant' in sent.body, false);
});

test('the effect is read back as the server spells it', async () => {
  // The server answers "Allow" and "Deny" while accepting "allow" and
  // "deny".
  fake.policies['policy-1'] = policyJson('policy-1', { effect: 'Deny' });
  const policy = await client.getPolicy('policy-1');
  assert.equal(policy.effect, 'Deny');
});

test('listPolicies returns every policy', async () => {
  fake.policies['policy-1'] = policyJson('policy-1');
  fake.policies['policy-2'] = policyJson('policy-2', { name: 'second' });

  const policies = await client.listPolicies();
  assert.deepEqual(
    policies.map((p) => p.id),
    ['policy-1', 'policy-2']
  );
  assert.equal(fake.requests[fake.requests.length - 1].path, '/v1/policies');
});

test('getPolicy returns the policy', async () => {
  fake.policies['policy-1'] = policyJson('policy-1');
  const policy = await client.getPolicy('policy-1');
  assert.equal(policy.id, 'policy-1');
  assert.equal(policy.tenant, TENANT);
});

test('deletePolicy answers 204 without a body', async () => {
  fake.policies['policy-1'] = policyJson('policy-1');

  // A 204 carries no body; the SDK must not choke on the empty payload.
  await client.deletePolicy('policy-1');

  const sent = fake.requests[fake.requests.length - 1];
  assert.equal(sent.method, 'DELETE');
  assert.equal(sent.path, '/v1/policies/policy-1');
  assert.equal('policy-1' in fake.policies, false);
});

test('deletePolicy reports an unknown policy', async () => {
  await assert.rejects(
    () => client.deletePolicy('policy-missing'),
    (err: unknown) => {
      assert.ok(err instanceof KmsError);
      assert.equal((err as KmsError).status, 404);
      assert.match((err as KmsError).message, /policy-missing/);
      return true;
    }
  );
});

test('deleteKey tolerates an empty answer', async () => {
  // Same empty-body situation as the policy deletion: the key deletion
  // answers 204 as well.
  await client.deleteKey('key-1');
  assert.equal(fake.requests[fake.requests.length - 1].method, 'DELETE');
});
