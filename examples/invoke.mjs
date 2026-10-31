import { createProtectedResourceClient } from '@atum/agent/resource-client';

// Call with trusted resource configuration and actual owner-authorized token/context.
// The caller persists its original operation BEFORE entering this function.
export async function invokeOriginalOperation(config, input) {
  const resource = createProtectedResourceClient(config);
  try {
    return await resource.invoke(input);
  } finally {
    await resource.close();
  }
}
