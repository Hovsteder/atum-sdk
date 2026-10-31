CREATE INDEX nonces_active_key_expiry_idx
  ON atum_request_proofs.nonces (issuer, audience, agent_key_thumbprint, expires_at_ms)
  WHERE consumed_at_ms IS NULL;
