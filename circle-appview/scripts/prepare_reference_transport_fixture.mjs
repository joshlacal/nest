// Additive fixture provisioning for an already-running, synthetic local reference lab.
// The input account file and output credential context must remain outside version control.
import { readFile, writeFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';

const [accountsPath, outputPath, plcOrigin = 'http://localhost:16580'] = process.argv.slice(2);
if (!accountsPath || !outputPath) throw new Error('Usage: node prepare_reference_transport_fixture.mjs ACCOUNTS_JSON PRIVATE_CONTEXT_JSON [PLC_ORIGIN]');
const loopback = (origin) => {
  const parsed = new URL(origin);
  if (!['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname)) throw new Error('Only a loopback synthetic lab is allowed');
  return parsed;
};
const localService = (origin) => {
  const parsed = loopback(origin);
  // Docker publishes this lab on IPv4; avoid a localhost AAAA address with no listener.
  if (parsed.hostname === 'localhost') parsed.hostname = '127.0.0.1';
  return parsed.origin;
};
loopback(plcOrigin);
const accounts = JSON.parse(await readFile(accountsPath, 'utf8'));
async function request(origin, method, name, input, accessToken) {
  const target = new URL(`/xrpc/${name}`, loopback(origin));
  if (method === 'GET') target.search = new URLSearchParams(input).toString();
  const response = await fetch(target, {
    method, redirect: 'error', signal: AbortSignal.timeout(15000),
    headers: { 'content-type': 'application/json', ...(accessToken ? { authorization: `Bearer ${accessToken}` } : {}) },
    body: method === 'POST' ? JSON.stringify(input) : undefined,
  });
  if (!response.ok) throw new Error(`${name}: HTTP ${response.status}`);
  const body = await response.text();
  return body ? JSON.parse(body) : {};
}
async function login(name) {
  const account = accounts.find((item) => item.name === name);
  if (!account) throw new Error(`Missing synthetic account ${name}`);
  const session = await request(account.service, 'POST', 'com.atproto.server.createSession', { identifier: account.handle, password: account.password });
  return { ...session, service: account.service };
}
async function document(did) {
  const response = await fetch(new URL(`/${did}`, loopback(plcOrigin)), { redirect: 'error', signal: AbortSignal.timeout(15000) });
  if (!response.ok) throw new Error(`PLC: HTTP ${response.status}`);
  return response.json();
}
const [authority, alice, bob] = await Promise.all(['authority', 'alice', 'bob'].map(login));
const skey = `circles-rust-${randomBytes(8).toString('hex')}`;
const spaceType = 'app.bsky.group';
const space = `at://${authority.did}/space/${spaceType}/${skey}`;
await request(authority.service, 'POST', 'com.atproto.simplespace.createSpace', {
  spaceType, skey,
  readPolicy: { $type: 'com.atproto.simplespace.defs#memberListPolicy' },
  writePolicy: { $type: 'com.atproto.simplespace.defs#memberListPolicy' },
  appAccess: { $type: 'com.atproto.simplespace.defs#open' },
}, authority.accessJwt);
for (const [index, member] of [alice, bob].entries()) {
  await request(authority.service, 'POST', 'com.atproto.simplespace.putMember', { space, did: member.did, read: true, write: true }, authority.accessJwt);
  await request(member.service, 'POST', 'com.atproto.space.putRecord', {
    space, repo: member.did, collection: 'app.bsky.feed.post', rkey: '3jzfcijpj2m2a',
    record: { $type: 'app.bsky.feed.post', text: `Local Rust transport qualification fixture ${index + 1}`, createdAt: new Date().toISOString() },
  }, member.accessJwt);
}
const delegated = await request(alice.service, 'GET', 'com.atproto.space.getDelegationToken', { space }, alice.accessJwt);
const context = {
  sourceRevision: 'ac0c9f15392f6f0298d71dc52aa88c05036150be', space,
  authority: { did: authority.did, service: localService(authority.service), document: await document(authority.did) },
  delegationToken: delegated.token,
  repos: await Promise.all([alice, bob].map(async (account) => ({ did: account.did, service: localService(account.service), document: await document(account.did), expectedRecords: 1 }))),
};
await writeFile(outputPath, JSON.stringify(context), { mode: 0o600, flag: 'wx' });
console.log(JSON.stringify({ prepared: true, sourceRevision: context.sourceRevision, repositoryHosts: context.repos.length, expectedRecords: 2 }));
