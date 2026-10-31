import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createOwnerConnectorClient, OwnerConnectorTransportError } from '@atum/verification/owner-connector-client';
const flow = '123e4567-e89b-42d3-a456-426614174000';
const handle = 'A'.repeat(43);
const registration = { issuer:'atum:issuer', audience:'merx:resource', environment:'sandbox', tenant_id:'tenant-1', resource_id:'resource-1', quota_scope_id:'scope-1' };
function answer() { return { flow_id: flow, state:'offered', expires_at_ms:1700000300000, context:{...registration}, scoped_subject:null, offer_handle:null, material:{reservation:null,statement:null,resource_confirmation:null,activation_receipt:null,outcome:null} }; }
function openssl(dir, ...args) { execFileSync('openssl', args, { cwd: dir, stdio: 'ignore' }); }
function certificates() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'atum-resource-client-'));
  writeFileSync(path.join(dir, 'server.ext'), 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n');
  writeFileSync(path.join(dir, 'client.ext'), 'extendedKeyUsage=clientAuth\n');
  openssl(dir, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '1', '-subj', '/CN=atum-test-ca');
  openssl(dir, 'req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'server.key', '-out', 'server.csr', '-subj', '/CN=localhost');
  openssl(dir, 'x509', '-req', '-in', 'server.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'server.pem', '-days', '1', '-extfile', 'server.ext');
  openssl(dir, 'req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'client.key', '-out', 'client.csr', '-subj', '/CN=atum-client');
  openssl(dir, 'x509', '-req', '-in', 'client.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'client.pem', '-days', '1', '-extfile', 'client.ext');
  return { dir, ca: readFileSync(path.join(dir, 'ca.pem'), 'utf8'), cert: readFileSync(path.join(dir, 'client.pem'), 'utf8'), key: readFileSync(path.join(dir, 'client.key'), 'utf8'), serverCert: readFileSync(path.join(dir, 'server.pem')), serverKey: readFileSync(path.join(dir, 'server.key')) };
}

async function host(handler) {
  const certs = certificates();
  const server = https.createServer({ cert: certs.serverCert, key: certs.serverKey, ca: certs.ca, requestCert: true, rejectUnauthorized: true }, handler);
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const port = server.address().port;
  return { certs, url: `https://localhost:${port}`, close: async () => { await new Promise(resolve => server.close(resolve)); rmSync(certs.dir, { recursive: true, force: true }); } };
}
function respond(res, status, body, headers = {}) { const bytes = Buffer.from(body); res.writeHead(status, { 'content-type': 'application/json', 'content-length': String(bytes.length), 'cache-control': 'no-store', ...headers }); res.end(bytes); }
function config(h, extra = {}) { return { baseUrl: h.url, registration: registration, tls: { ca: h.certs.ca, cert: h.certs.cert, key: h.certs.key }, timeoutMs: 500, maxConcurrent: 1, ...extra }; }
function expectCode(code) { return error => error instanceof OwnerConnectorTransportError && error.code === code; }

test('all six methods use actual mTLS, exact paths and snapshotted input; response is deeply immutable', async t => {
  const seen = [];
  const h = await host((req,res) => {
    assert.equal(req.socket.authorized, true); assert.equal(req.method,'POST');
    let bytes=''; req.setEncoding('utf8'); req.on('data', c => {bytes+=c}); req.on('end', () => {
      seen.push([req.url,JSON.parse(bytes)]); respond(res,200,JSON.stringify(answer()));
    });
  }); t.after(h.close);
  const client = createOwnerConnectorClient(config(h));
  const inputs = {open:{flow_id:flow,channel_id:handle,expires_at_ms:1700000300000},pair:{flow_id:flow,return_handle:handle},reservation:{flow_id:flow,reservation:'a.b.c'},confirmation:{flow_id:flow,resource_confirmation:'a.b.c'},outcome:{flow_id:flow,outcome:'a.b.c'},read:{flow_id:flow}};
  for (const [name,input] of Object.entries(inputs)) {
    const copy=structuredClone(input); const pending=client[name](copy); copy.flow_id='changed';
    const result=await pending;
    assert.deepEqual(result,answer()); assert(Object.isFrozen(result.material)); assert(Object.isFrozen(result.context));
    assert.deepEqual(seen.at(-1), [`/v1/owner-connector/${name}`,input]);
  }
  await client.close(); assert.equal(seen.length,6);
});

test('invalid local requests and mutated context/phase/shape replies fail closed', async t => {
  let value=answer(); let calls=0;
  const h=await host((req,res)=>{calls++; req.resume();respond(res,200,JSON.stringify(value));});t.after(h.close);
  const client=createOwnerConnectorClient(config(h));
  for(const input of [{flow_id:flow,mode:'recovery'},{flow_id:'wrong'}, {flow_id:[flow]}]) await assert.rejects(client.read(input),expectCode('invalid_request'));
  await assert.rejects(client.open({flow_id:flow,channel_id:'B'.repeat(43),expires_at_ms:1}),expectCode('invalid_request'));
  await assert.rejects(client.open({flow_id:flow,channel_id:handle,expires_at_ms:-0}),expectCode('invalid_request'));
  assert.equal(calls,0);
  for(const mutate of [v=>{v.context.tenant_id='foreign'},v=>{v.flow_id='223e4567-e89b-42d3-a456-426614174000'},v=>{v.extra=1},v=>{v.state='ready'},v=>{v.scoped_subject='subject-1'},v=>{v.offer_handle=handle}]) {
    value=answer(); mutate(value); await assert.rejects(client.read({flow_id:flow}),expectCode('temporarily_unavailable'));
  }
  value=answer();value.state='expired';value.scoped_subject='subject-1';
  value.material.reservation='a.b.c';value.material.statement='{"original":true}';
  assert.deepEqual(await client.read({flow_id:flow}),value);
  value.material.reservation=null;
  await assert.rejects(client.read({flow_id:flow}),expectCode('temporarily_unavailable')); await client.close();
});

test('known server errors preserve code; malformed, duplicate, chunked, oversized and truncated replies stay unknown', async t=>{
  let mode='known';
  const h=await host((req,res)=>{req.resume();
    if(mode==='known')return respond(res,409,'{"error":{"code":"already_consumed"}}');
    if(mode.startsWith('numeric:')) return respond(res,200,JSON.stringify(answer()).replace('1700000300000',mode.slice(8)));
    if(mode==='duplicate')return respond(res,200,'{"flow_id":"x","flow_id":"y"}');
    if(mode==='chunked'){res.writeHead(200,{'content-type':'application/json','cache-control':'no-store'});return res.end(JSON.stringify(answer()));}
    if(mode==='oversize')return respond(res,200,' '.repeat(131073));
    if(mode==='truncated'){res.writeHead(200,{'content-type':'application/json','cache-control':'no-store','content-length':'2000'});res.write('{}');setImmediate(()=>res.destroy());return;}
    return respond(res,302,JSON.stringify(answer()),{location:'/other'});
  });t.after(h.close);const client=createOwnerConnectorClient(config(h));
  await assert.rejects(client.read({flow_id:flow}),expectCode('already_consumed'));
  for(mode of ['duplicate','chunked','oversize','truncated','redirect'])await assert.rejects(client.read({flow_id:flow}),expectCode('temporarily_unavailable'));
  await client.close();
});

test('deadline, saturation and close never retry mutations; TLS name and CA are verified', async t=>{
  let calls=0;const h=await host(req=>{calls++;req.resume()});t.after(h.close);
  const client=createOwnerConnectorClient(config(h,{timeoutMs:200}));
  const pending=client.pair({flow_id:flow,return_handle:handle});
  await assert.rejects(client.pair({flow_id:flow,return_handle:handle}),expectCode('temporarily_unavailable'));
  await assert.rejects(pending,expectCode('temporarily_unavailable'));await client.close();assert.equal(calls,1);
  await assert.rejects(client.read({flow_id:flow}),expectCode('temporarily_unavailable'));
  const wrong=createOwnerConnectorClient(config(h,{baseUrl:h.url.replace('localhost','127.0.0.1')}));
  await assert.rejects(wrong.read({flow_id:flow}),expectCode('temporarily_unavailable'));await wrong.close();assert.equal(calls,1);
  const foreign=certificates();t.after(()=>rmSync(foreign.dir,{recursive:true,force:true}));
  const wrongCA=createOwnerConnectorClient(config(h,{tls:{ca:foreign.ca,cert:h.certs.cert,key:h.certs.key}}));
  await assert.rejects(wrongCA.read({flow_id:flow}),expectCode('temporarily_unavailable'));await wrongCA.close();assert.equal(calls,1);
  for(const key of Object.keys(registration)) {
    const bad={...registration,[key]:[registration[key]]};assert.throws(()=>createOwnerConnectorClient(config(h,{registration:bad})),/invalid config/);
  }
});


test('numeric expiry tokens are checked before JSON number rounding', async t => {
  let numeric='8640000000000000.1';let calls=0;
  const h=await host((req,res)=>{calls++;req.resume();respond(res,200,JSON.stringify(answer()).replace('1700000300000',numeric));});t.after(h.close);
  for(numeric of ['8640000000000000.1','1000.0','1e3','-0']) {
    const client=createOwnerConnectorClient(config(h));
    try { await assert.rejects(client.read({flow_id:flow}),expectCode('temporarily_unavailable')); }
    finally {await client.close();}
  }
  assert.equal(calls,4);
});
