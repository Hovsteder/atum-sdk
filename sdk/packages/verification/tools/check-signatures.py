"""Independent public-vector signature check with Python cryptography (not jose).

This checks cryptography, not the complete Node acceptance policy. Fixed synthetic clock;
no network, secrets, production issuer, nonce database or admission authorization.
"""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils


ROOT = Path(__file__).resolve().parents[1]
data = json.loads((ROOT / "test/fixtures/proof-vectors.json").read_text())
reference_path = ROOT.parents[1] / "candidate/reference.py"
spec = importlib.util.spec_from_file_location("atum_context_reference", reference_path)
reference = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reference)


def decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def number(value):
    return int.from_bytes(decode(value), "big")


issuer_jwk = data["issuer_keys"][0]
agent_jwk = data["agent_public_key"]
issuer = rsa.RSAPublicNumbers(number(issuer_jwk["e"]), number(issuer_jwk["n"])).public_key()
agent = ec.EllipticCurvePublicNumbers(number(agent_jwk["x"]), number(agent_jwk["y"]), ec.SECP256R1()).public_key()
thumbprint = base64.urlsafe_b64encode(hashlib.sha256(json.dumps(
    {k: agent_jwk[k] for k in ("crv", "kty", "x", "y")}, separators=(",", ":"), sort_keys=True
).encode()).digest()).decode().rstrip("=")


def signature_valid(compact, public_key, is_ec=False):
    header, payload, signature = compact.split(".")
    message = f"{header}.{payload}".encode("ascii")
    signature = decode(signature)
    try:
        if is_ec:
            assert len(signature) == 64
            signature = utils.encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        else:
            public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        return False
    return True


checked = 0
for case in data["cases"]:
    token = case["input"]["authorization"].split(" ", 1)[1]
    proof = case["input"]["dpop"]
    assert signature_valid(token, issuer) is case["signatures"]["token_valid"], case["name"]
    assert signature_valid(proof, agent, is_ec=True) is case["signatures"]["proof_valid"], case["name"]
    checked += 2
    if case["expected"] == "proof_verified":
        body = json.loads(case["input"]["body"])
        claims = json.loads(decode(token.split(".")[1]))
        proof_claims = json.loads(decode(proof.split(".")[1]))
        reference.validate_bound_intent(body["context"], body["action_request"], data["registration"])
        assert reference.intent_hash(body["context"]) == proof_claims["atum_intent_hash"]
        assert reference.action_hash(body["action_request"]) == body["context"]["action_hash"]
        assert thumbprint == body["context"]["agent_key_thumbprint"] == claims["cnf"]["jkt"]
        assert proof_claims["ath"] == base64.urlsafe_b64encode(hashlib.sha256(token.encode("ascii")).digest()).decode().rstrip("=")

assert len(data["cases"]) == 48, "Update documented case count deliberately when vectors change"
print(f"Python cryptography: {checked} signature expectations; positive context/action/thumbprint/ath match.")
