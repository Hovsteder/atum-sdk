"""Pure, closed-record reference helpers for the ATUM draft.2 candidate."""
import base64
import hashlib
import json
import math
import re


MAX_SAFE_INT = 9007199254740991
PROFILE_HASH = "sha256:dc6f6409a47da2a97ea7b4ace313985d7fcd4c6b8459a59ea06b014de304a175"
PROTOCOL_VERSION = "0.1.0-draft.2"
ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
PARTY_RE = re.compile(r"^[A-Za-z0-9:/._-]{1,256}$")
HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
BASE64URL_43_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
KNOWN_ACTIONS = frozenset(("prices.read", "order.preview", "sandbox.execute"))
CONTEXT_FIELDS = frozenset((
    "protocol_version", "resource_profile_version", "resource_profile_hash", "issuer", "audience",
    "environment", "tenant_id", "resource_id", "quota_scope_id", "operation_namespace",
    "scoped_subject", "operation_id", "grant_id", "grant_version", "policy_version",
    "agent_key_thumbprint", "consent_hash", "action_hash", "account_binding_id",
    "account_binding_version", "action",
))
REGISTRATION_FIELDS = frozenset((
    "issuer", "audience", "environment", "tenant_id", "resource_id", "quota_scope_id",
    "operation_namespace", "resource_profile_version", "resource_profile_hash", "policy_version",
    "account_required_actions",
))
DECISION_FIELDS = frozenset((
    "protocol_version", "synthetic", "authorization_effect", "context", "intent_hash", "admission_id",
    "decision", "reason", "evaluated_at_ms", "evaluated_uncertainty_ms", "grant_expires_at_ms",
    "acceptance_expires_at_ms", "first_submit_expires_at_ms",
))
STATEMENT_FIELDS = frozenset((
    "protocol_version", "purpose", "issuer", "audience", "environment", "tenant_id", "resource_id",
    "quota_scope_id", "scoped_subject", "account_binding_id", "account_binding_version", "account_ref",
    "request_id", "nonce", "created_at_ms", "expires_at_ms",
))


def _exact_object(value, fields, label):
    if type(value) is not dict or set(value) != fields:
        raise ValueError(f"invalid {label} fields")


def _string(value, pattern, label):
    if type(value) is not str or not pattern.fullmatch(value):
        raise ValueError(f"invalid {label}")


def _integer(value, lower, upper=MAX_SAFE_INT, label="integer"):
    return _json_integral(value, lower, upper, label)


def _json_integral(value, lower, upper, label):
    if type(value) is int:
        normalized = value
    elif type(value) is float and math.isfinite(value) and value.is_integer():
        normalized = int(value)
    else:
        raise ValueError(f"invalid {label}")
    if not lower <= normalized <= upper:
        raise ValueError(f"invalid {label}")
    return normalized


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _hash(domain, canonical):
    return "sha256:" + hashlib.sha256(domain.encode("ascii") + canonical.encode("utf-8")).hexdigest()


def _base64url_32(value, label):
    _string(value, BASE64URL_43_RE, label)
    try:
        decoded = base64.urlsafe_b64decode(value + "=")
    except (ValueError, UnicodeError) as error:
        raise ValueError(f"invalid {label}") from error
    if len(decoded) != 32 or base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value:
        raise ValueError(f"invalid {label}")


def _validate_action(request):
    _exact_object(request, frozenset(("action", "parameters")), "action request")
    action = request["action"]
    if type(action) is not str or action not in KNOWN_ACTIONS:
        raise ValueError("invalid action")
    parameters = request["parameters"]
    if type(parameters) is not dict:
        raise ValueError("invalid action parameters")
    if action == "prices.read":
        if parameters:
            raise ValueError("invalid action parameters")
        return {"action": action, "parameters": {}}
    allowed = {"resource", "amount", "duration", "max_price_sun"}
    required = {"resource", "amount", "duration"}
    if not required <= set(parameters) <= allowed:
        raise ValueError("invalid action parameters")
    if parameters["resource"] not in ("ENERGY", "BANDWIDTH"):
        raise ValueError("invalid resource")
    result = {
        "resource": parameters["resource"],
        "amount": _json_integral(parameters["amount"], 1, 1_000_000_000, "amount"),
        "duration": _json_integral(parameters["duration"], 1, 2_592_000, "duration"),
    }
    if "max_price_sun" in parameters:
        result["max_price_sun"] = _json_integral(parameters["max_price_sun"], 1, 1_000_000_000_000, "max_price_sun")
    return {"action": action, "parameters": result}


def canonical_action(request):
    """Return closed action JSON with its contract-mandated member order."""
    action = _validate_action(request)
    parameters = action["parameters"]
    if action["action"] != "prices.read":
        ordered = {key: parameters[key] for key in ("amount", "duration", "max_price_sun", "resource") if key in parameters}
        action = {"action": action["action"], "parameters": ordered}
    return json.dumps(action, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def action_hash(request):
    return _hash("merx.atum.intent.v1\n", canonical_action(request))


def _validate_context(context):
    _exact_object(context, CONTEXT_FIELDS, "context")
    if context["protocol_version"] != PROTOCOL_VERSION:
        raise ValueError("invalid protocol version")
    if context["resource_profile_version"] != "v1-draft.1" or context["resource_profile_hash"] != PROFILE_HASH:
        raise ValueError("invalid resource profile")
    _string(context["issuer"], PARTY_RE, "issuer")
    _string(context["audience"], PARTY_RE, "audience")
    if context["environment"] != "sandbox":
        raise ValueError("invalid environment")
    for field in ("tenant_id", "resource_id", "quota_scope_id", "operation_namespace", "scoped_subject", "operation_id", "grant_id", "policy_version"):
        _string(context[field], ID_RE, field)
    grant_version = _integer(context["grant_version"], 1, label="grant version")
    _base64url_32(context["agent_key_thumbprint"], "agent key thumbprint")
    _string(context["consent_hash"], HASH_RE, "consent hash")
    _string(context["action_hash"], HASH_RE, "action hash")
    if type(context["action"]) is not str or context["action"] not in KNOWN_ACTIONS:
        raise ValueError("invalid action")
    account_id = context["account_binding_id"]
    account_version = context["account_binding_version"]
    if account_id is None:
        if account_version is not None:
            raise ValueError("unpaired account binding")
    else:
        _string(account_id, ID_RE, "account binding id")
        account_version = _integer(account_version, 1, label="account binding version")
    normalized = dict(context)
    normalized["grant_version"] = grant_version
    normalized["account_binding_version"] = account_version
    return normalized


def canonical_context(context):
    return _canonical(_validate_context(context))


def intent_hash(context):
    return _hash("atum.admission.context.v1\n", canonical_context(context))


def validate_bound_intent(context, action_request, registration):
    context = _validate_context(context)
    canonical = _validate_action(action_request)
    _exact_object(registration, REGISTRATION_FIELDS, "registration")
    for field in REGISTRATION_FIELDS - {"account_required_actions"}:
        if registration[field] != context[field]:
            raise ValueError(f"registration mismatch: {field}")
    actions = registration["account_required_actions"]
    if (type(actions) is not list or any(type(action) is not str or action not in KNOWN_ACTIONS for action in actions)
            or len(set(actions)) != len(actions)):
        raise ValueError("invalid account required actions")
    if canonical["action"] != context["action"] or action_hash(action_request) != context["action_hash"]:
        raise ValueError("action binding mismatch")
    if context["action"] in actions and context["account_binding_id"] is None:
        raise ValueError("account binding required")


def operation_key(context):
    context = _validate_context(context)
    return tuple(context[field] for field in ("issuer", "environment", "tenant_id", "resource_id", "quota_scope_id", "operation_namespace", "scoped_subject", "operation_id"))


def quota_key(context):
    context = _validate_context(context)
    return tuple(context[field] for field in ("issuer", "environment", "tenant_id", "resource_id", "quota_scope_id", "scoped_subject"))


def _timestamp(value, label):
    return _integer(value, 0, label=label)


def validate_decision(decision):
    _exact_object(decision, DECISION_FIELDS, "decision")
    if decision["protocol_version"] != PROTOCOL_VERSION or decision["synthetic"] is not True or decision["authorization_effect"] != "none":
        raise ValueError("invalid synthetic decision envelope")
    context = _validate_context(decision["context"])
    if decision["intent_hash"] != intent_hash(context):
        raise ValueError("intent hash mismatch")
    _string(decision["admission_id"], ID_RE, "admission id")
    if decision["decision"] not in ("would_accept", "would_reject"):
        raise ValueError("invalid decision")
    evaluated = _timestamp(decision["evaluated_at_ms"], "evaluated at")
    uncertainty = _integer(decision["evaluated_uncertainty_ms"], 0, 1000, "evaluated uncertainty")
    grant_expiry = _timestamp(decision["grant_expires_at_ms"], "grant expiry")
    if decision["decision"] == "would_accept":
        if decision["reason"] != "synthetic_example_only":
            raise ValueError("invalid accept reason")
        if evaluated > MAX_SAFE_INT - 30_000:
            raise ValueError("deadline arithmetic overflow")
        acceptance = min(evaluated + 10_000, grant_expiry)
        first_submit = min(evaluated + 30_000, grant_expiry)
        actual_acceptance = _timestamp(decision["acceptance_expires_at_ms"], "acceptance expiry")
        actual_first_submit = _timestamp(decision["first_submit_expires_at_ms"], "first submit expiry")
        if actual_acceptance != acceptance or actual_first_submit != first_submit:
            raise ValueError("invalid decision deadlines")
        if acceptance <= evaluated or first_submit <= evaluated:
            raise ValueError("expired decision deadlines")
    else:
        if decision["reason"] not in ("grant_not_active", "evidence_insufficient", "action_not_permitted", "account_not_bound"):
            raise ValueError("invalid reject reason")
        if decision["acceptance_expires_at_ms"] is not None or decision["first_submit_expires_at_ms"] is not None:
            raise ValueError("rejection has deadlines")
    normalized = dict(decision)
    normalized.update({"context": context, "evaluated_at_ms": evaluated,
                       "evaluated_uncertainty_ms": uncertainty, "grant_expires_at_ms": grant_expiry})
    if decision["decision"] == "would_accept":
        normalized["acceptance_expires_at_ms"] = actual_acceptance
        normalized["first_submit_expires_at_ms"] = actual_first_submit
    return normalized


def eligible(decision, clock, stage, already_accepted=False):
    decision = validate_decision(decision)
    _exact_object(clock, frozenset(("now_ms", "uncertainty_ms", "healthy")), "clock")
    now = _timestamp(clock["now_ms"], "clock now")
    clock_uncertainty = _integer(clock["uncertainty_ms"], 0, 1000, "clock uncertainty")
    if type(clock["healthy"]) is not bool or stage not in ("acceptance", "first_submit") or type(already_accepted) is not bool:
        raise ValueError("invalid eligibility input")
    if decision["decision"] != "would_accept" or not clock["healthy"]:
        return False
    if now > MAX_SAFE_INT - clock_uncertainty:
        raise ValueError("clock arithmetic overflow")
    latest_now = now + clock_uncertainty
    if latest_now > MAX_SAFE_INT - decision["evaluated_uncertainty_ms"]:
        raise ValueError("clock arithmetic overflow")
    if decision["evaluated_at_ms"] > latest_now + decision["evaluated_uncertainty_ms"]:
        return False
    if stage == "first_submit" and not already_accepted:
        return False
    deadline = decision["acceptance_expires_at_ms"] if stage == "acceptance" else decision["first_submit_expires_at_ms"]
    return latest_now < deadline


def _validate_statement(statement):
    _exact_object(statement, STATEMENT_FIELDS, "account statement")
    if statement["protocol_version"] != PROTOCOL_VERSION or statement["purpose"] != "bind_account" or statement["environment"] != "sandbox":
        raise ValueError("invalid account statement envelope")
    _string(statement["issuer"], PARTY_RE, "issuer")
    _string(statement["audience"], PARTY_RE, "audience")
    for field in ("tenant_id", "resource_id", "quota_scope_id", "scoped_subject", "account_binding_id", "account_ref", "request_id"):
        _string(statement[field], ID_RE, field)
    account_version = _integer(statement["account_binding_version"], 1, label="account binding version")
    _base64url_32(statement["nonce"], "nonce")
    created = _timestamp(statement["created_at_ms"], "created at")
    expires = _timestamp(statement["expires_at_ms"], "expires at")
    if expires <= created:
        raise ValueError("statement expiry must follow creation")
    normalized = dict(statement)
    normalized.update({"account_binding_version": account_version, "created_at_ms": created, "expires_at_ms": expires})
    return normalized


def canonical_account_statement(statement):
    return _canonical(_validate_statement(statement))


def account_statement_hash(statement):
    return _hash("atum.account.binding.v1\n", canonical_account_statement(statement))
