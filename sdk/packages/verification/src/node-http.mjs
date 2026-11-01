import { createCurrentAuthorizationVerifier, VerificationError, AuthorityError, ResourceTransportError } from './current-authorization.mjs';
import { createNonceChallengeVerifier } from './nonce-challenge.mjs';

const PUBLIC = new Map([['invalid_request',400],['invalid_proof',401],['use_dpop_nonce',401],['not_found',404],['grant_limit_exhausted',409],['authorization_expired',409],['action_not_supported',422],['temporarily_unavailable',503],['conflict',409]]);
const safe = error => error instanceof VerificationError || error instanceof AuthorityError || error instanceof ResourceTransportError || (error?.name === 'UsageError' && PUBLIC.has(error.code));
const send = (res, status, value, headers = {}) => { const bytes = Buffer.from(JSON.stringify(value)); res.writeHead(status, { 'content-type':'application/json', 'content-length':String(bytes.length), 'cache-control':'no-store', ...headers }); res.end(bytes); };
const fail = (code, status = PUBLIC.get(code) ?? 400) => { const e = new Error(code); e.code = code; e.status = status; throw e; };

function requestHeaders(req, endpoint, maxBody) {
  if (!Array.isArray(req.rawHeaders) || req.rawHeaders.length % 2) fail('invalid_request');
  const map = new Map();
  for (let i=0;i<req.rawHeaders.length;i+=2) { const name=req.rawHeaders[i]?.toLowerCase(), value=req.rawHeaders[i+1]; if (typeof name !== 'string' || typeof value !== 'string') fail('invalid_request'); const a=map.get(name) ?? []; a.push(value); map.set(name,a); }
  for (const name of ['host','authorization','dpop','content-type','content-length','transfer-encoding','expect']) if ((map.get(name)?.length ?? 0) > 1) fail('invalid_request');
  const expected = new URL(endpoint.url), length = map.get('content-length')?.[0];
  if (req.method !== endpoint.method || req.url !== expected.pathname || map.get('host')?.[0] !== expected.host || !map.get('authorization')?.[0] || !map.get('dpop')?.[0] || map.get('content-type')?.[0] !== 'application/json' || map.has('transfer-encoding') || map.has('expect') || typeof length !== 'string' || !/^(?:0|[1-9][0-9]*)$/.test(length) || Number(length)>maxBody) fail(req.method !== endpoint.method || req.url !== expected.pathname ? 'not_found':'invalid_request');
  return { authorization:map.get('authorization')[0], dpop:map.get('dpop')[0], length:Number(length) };
}
async function readBody(req, length, maxBody, timeoutMs) {
  const chunks=[]; let bytes=0; let timer; try { const expired=new Promise((_,reject)=>{ timer=setTimeout(()=>reject(Object.assign(new Error('timeout'),{code:'temporarily_unavailable'})),timeoutMs); }); await Promise.race([(async()=>{for await(const chunk of req){bytes+=chunk.length;if(bytes>maxBody)fail('invalid_request');chunks.push(chunk);}})(),expired]); const body=Buffer.concat(chunks); if(body.length!==length)fail('invalid_request'); return body; } finally { clearTimeout(timer); }
}

/** Mount this before body parsers. It accepts only direct TLS Node requests. */
export async function createProtectedHttpHandler({ authorization, endpoint, onAuthorized, maxBodyBytes = 32 * 1024, readTimeoutMs = 5_000 } = {}) {
  if (!endpoint || typeof endpoint !== 'object' || typeof endpoint.method !== 'string' || typeof endpoint.url !== 'string' || typeof onAuthorized !== 'function' || !Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 1 || maxBodyBytes > 1_048_576 || !Number.isSafeInteger(readTimeoutMs) || readTimeoutMs < 1 || readTimeoutMs > 30_000) throw new TypeError('invalid protected HTTP config');
  const verifier=await createCurrentAuthorizationVerifier(authorization);
  const challenge=await createNonceChallengeVerifier({ registration:authorization.registration, ...(Object.hasOwn(authorization,'descriptor')?{descriptor:authorization.descriptor}:{}), issuerKeys:authorization.proof.issuerKeys, endpoint:authorization.proof.endpoint, clock:authorization.clock });
  let closed=false, work=0, drain;
  const handle=async (req,res) => { work++; try { if (closed) return send(res,503,{error:{code:'temporarily_unavailable'}}); if (!req.socket?.encrypted) return send(res,400,{error:{code:'invalid_request'}}); const headers=requestHeaders(req,endpoint,maxBodyBytes); const body=await readBody(req,headers.length,maxBodyBytes,readTimeoutMs); const protectedRequest={authorization:headers.authorization,dpop:headers.dpop,body,method:req.method,url:endpoint.url}; let current; try { current=await verifier.verifyCurrent(protectedRequest); } catch(error) { if (!(error instanceof VerificationError) || error.code!=='invalid_proof') throw error; const verified=await challenge.verifyNonceChallengeRequest(protectedRequest,{deadlineAt:performance.now()+Math.min(5_000,authorization.authority.timeoutMs)}); const issued=await authorization.proof.replayStore.issueNonce({agent_key_thumbprint:verified.agent_key_thumbprint}); return send(res,401,{error:'use_dpop_nonce'},{'www-authenticate':'DPoP error="use_dpop_nonce", algs="ES256"','dpop-nonce':issued.nonce}); }
    const result=await onAuthorized(Object.freeze(current)); if (!result || typeof result !== 'object' || Array.isArray(result)) return send(res,200,{permission_checked:true,result}); return send(res,Number.isSafeInteger(result.status)?result.status:200,Object.hasOwn(result,'body')?result.body:result);
  } catch(error) { const code=safe(error) && PUBLIC.has(error.code) ? error.code : 'temporarily_unavailable'; return send(res,PUBLIC.get(code),{error:{code}}); } finally { work--; if(!work) drain?.(); } };
  return Object.freeze({handle, async close(){closed=true; if(work) await new Promise(resolve=>{drain=resolve;}); await verifier.close();}});
}
