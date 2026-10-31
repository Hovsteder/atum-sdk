CREATE SCHEMA atum_request_proofs;

CREATE TABLE atum_request_proofs.nonces (
  nonce_hash CHAR(64) COLLATE "C" PRIMARY KEY CHECK (nonce_hash ~ '^[0-9a-f]{64}$'),
  issuer VARCHAR(256) COLLATE "C" NOT NULL CHECK (length(issuer) BETWEEN 1 AND 256),
  audience VARCHAR(256) COLLATE "C" NOT NULL CHECK (length(audience) BETWEEN 1 AND 256),
  agent_key_thumbprint VARCHAR(43) COLLATE "C" NOT NULL CHECK (length(agent_key_thumbprint) = 43),
  endpoint_url VARCHAR(2048) COLLATE "C" NOT NULL CHECK (length(endpoint_url) BETWEEN 1 AND 2048),
  issued_at_ms BIGINT NOT NULL CHECK (issued_at_ms BETWEEN 0 AND 8640000000000000),
  expires_at_ms BIGINT NOT NULL CHECK (expires_at_ms BETWEEN 0 AND 8640000000000000),
  consumed_at_ms BIGINT CHECK (consumed_at_ms BETWEEN 0 AND 8640000000000000),
  CHECK (expires_at_ms > issued_at_ms)
);

CREATE INDEX nonces_expiry_idx ON atum_request_proofs.nonces (expires_at_ms);

CREATE TABLE atum_request_proofs.proofs (
  issuer VARCHAR(256) COLLATE "C" NOT NULL CHECK (length(issuer) BETWEEN 1 AND 256),
  audience VARCHAR(256) COLLATE "C" NOT NULL CHECK (length(audience) BETWEEN 1 AND 256),
  agent_key_thumbprint VARCHAR(43) COLLATE "C" NOT NULL CHECK (length(agent_key_thumbprint) = 43),
  proof_jti VARCHAR(128) COLLATE "C" NOT NULL CHECK (length(proof_jti) BETWEEN 16 AND 128),
  intent_hash CHAR(71) COLLATE "C" NOT NULL CHECK (intent_hash ~ '^sha256:[0-9a-f]{64}$'),
  first_seen_ms BIGINT NOT NULL CHECK (first_seen_ms BETWEEN 0 AND 8640000000000000),
  expires_at_ms BIGINT NOT NULL CHECK (expires_at_ms BETWEEN 0 AND 8640000000000000),
  PRIMARY KEY (issuer, audience, agent_key_thumbprint, proof_jti),
  CHECK (expires_at_ms >= first_seen_ms)
);

CREATE INDEX proofs_expiry_idx ON atum_request_proofs.proofs (expires_at_ms);
