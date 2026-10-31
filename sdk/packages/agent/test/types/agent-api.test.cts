import agent = require('@atum/agent');
import client = require('@atum/agent/client');
import key = require('@atum/agent/key');
import requestProof = require('@atum/agent/request-proof');
import resourceProof = require('@atum/agent/resource-proof');

const rootFactory: typeof agent.createAgentClient = client.createAgentClient;
const keyFactory: typeof agent.createAgentKey = key.createAgentKey;
const requestFactory: typeof agent.createRequestProofClient = requestProof.createRequestProofClient;
const signerFactory: typeof agent.createProtectedRequestSigner = resourceProof.createProtectedRequestSigner;

void rootFactory;
void keyFactory;
void requestFactory;
void signerFactory;
