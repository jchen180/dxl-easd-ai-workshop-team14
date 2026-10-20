"""Participant file -- improve these working-but-unreliable baselines.

Quick start
-----------
1. Run  python demo.py          to see the raw AI output for all four levels.
2. Edit the functions below one at a time.
3. Run  python score.py --team "Your Team" --open   to see your score and a
   visual report in the browser.

The API being reviewed has three endpoints (see http://localhost:8081/api/v1):

    GET  /orders               list orders, optional ?limit=<int>
    POST /orders               create an order  (Bearer auth required)
    GET  /orders/{orderId}     fetch one order  (Bearer auth required)

The AI assistant (ai.ask(...)) always returns a list of dicts. The shapes are
shown in the comments below. Your job is to filter that list so only items
that are verifiable against real evidence survive.
"""

def review_contract(spec: dict, ai) -> list[dict]:
  """Level 1 -- return only findings supported by the OpenAPI contract.

    ai.ask("contract_review", spec) returns a list like:
        [
          {
            "id": "AUTH-001",
            "claim": "GET /orders has no authentication requirement.",
            "path": "/orders",
            "method": "get",
            "evidence_pointer": "/paths/~1orders/get"
          },
          ...
          {
            "id": "SEC-001",
            "claim": "DELETE /customers is publicly accessible.",
            "path": "/customers",
            "method": "delete",
            "evidence_pointer": "/paths/~1customers/delete"
          }
        ]

    Compare each finding against the OpenAPI v1 document in
    data/openapi-v1.json (same spec as http://localhost:8081/api/v1).

    Tip: check two things for each finding before keeping it.
      1. Does spec["paths"][finding["path"]][finding["method"]] exist?
      2. Does the evidence_pointer resolve to a real location inside spec?
         JSON Pointer: split on "/" first, then decode ~1 to "/" inside a key.
         "/paths/~1orders/get" is spec["paths"]["/orders"]["get"].
         It is not "//orders" -- the slash belongs to the key name "/orders".
  """
    #### Mannually fix by Jake
  http_methods = {"get", "put", "post", "delete", "patch", "options", "head", "trace"}

  def resolve(pointer: str):
        # Split on "/" first, then decode ~1 -> "/" and ~0 -> "~"
        if not pointer.startswith("/"):
            raise KeyError(pointer)
        node = spec
        for token in pointer[1:].split("/"):
            token = token.replace("~1", "/").replace("~0", "~")
            if isinstance(node, list):
                node = node[int(token)]
            elif isinstance(node, dict):
                node = node[token]
            else:
                raise KeyError(token)
        return node

  valid = []
  for f in ai.ask("contract_review", spec):
        try:
            path = f["path"]
            method = f["method"].lower()
            pointer = f["evidence_pointer"]

            # 1. path + method exist in the spec
            if method not in http_methods:
                continue
            if not isinstance(spec["paths"][path][method], dict):
                continue

            # 2. evidence pointer resolves to a real location in the spec
            resolve(pointer)

            # 3. pointer sits inside the operation the finding claims
            op_pointer = "/paths/" + path.replace("~", "~0").replace("/", "~1") + "/" + method
            if pointer != op_pointer and not pointer.startswith(op_pointer + "/"):
                continue
        except (KeyError, IndexError, ValueError, TypeError, AttributeError):
            continue
        valid.append(f)
  return valid    
   
    ### return ai.ask("contract_review", spec)
    



def design_negative_tests(spec: dict, ai) -> list[dict]:
    """Level 2 -- return runnable test ideas for operations that really exist.

    ai.ask("negative_tests", spec) returns a list like:
        [
          {
            "name": "zero limit",
            "method": "get",
            "path": "/orders",
            "input": {"limit": 0},
            "expected_status": 400
          },
          ...
          {
            "name": "delete customer record",
            "method": "delete",
            "path": "/customers/c-1",
            "input": {},
            "expected_status": 204
          }
        ]

    Compare each test case against the OpenAPI v1 document in
    data/openapi-v1.json (same spec as http://localhost:8081/api/v1).

    Tip: keep a test case only if ALL of these are true.
      1. spec["paths"][case["path"]][case["method"]] exists.
      2. expected_status is one of 400, 401, 403, 404, 409, or 422.
         A 204 from a non-existent endpoint is a red flag.
      3. The case has all required fields: name, method, path, input,
         expected_status.
    """
    required_fields = ("name", "method", "path", "input", "expected_status")
    allowed_statuses = {400, 401, 403, 404, 409, 422}
    http_methods = {"get", "put", "post", "delete", "patch", "options", "head", "trace"}

    paths = spec.get("paths", {})
    valid = []

    for case in ai.ask("negative_tests", spec):
        # 3. must be a dict with every required field
        if not isinstance(case, dict):
            continue
        if any(field not in case for field in required_fields):
            continue

        path, method, status = case["path"], case["method"], case["expected_status"]

        # types must be sane before any lookup
        if not isinstance(path, str) or not isinstance(method, str):
            continue
        if not isinstance(case["name"], str) or not isinstance(case["input"], dict):
            continue

        # 2. allowed negative status (reject bool, which equals 0/1 in Python)
        if isinstance(status, bool) or status not in allowed_statuses:
            continue

        # 1. path AND method must exist in the v1 spec (exact path match)
        method = method.lower()
        path_item = paths.get(path)
        if not isinstance(path_item, dict):
            continue
        if method not in http_methods or not isinstance(path_item.get(method), dict):
            continue

        valid.append(case)
    return valid
  ###  return ai.ask("negative_tests", spec)


def diagnose_incident(logs: str, ai) -> dict:
    """Level 3 -- select a diagnosis whose evidence appears in the logs.

    ai.ask("incident_diagnosis", logs) returns a list of candidates:
        [
          {
            "cause": "A DNS outage prevented all clients from reaching the API.",
            "evidence": ["dns_resolution_failed", "upstream_host_not_found"]
          },
          {
            "cause": "The 2.4.1 database-pool change exhausted connections.",
            "evidence": [
              "deploy version=2.4.1 change=orders-db-pool",
              "db_pool_wait_ms=1850 active=20 max=20",
              "status=503 error=db_pool_timeout"
            ]
          }
        ]

    Tip: only keep a candidate if every string in its "evidence" list
    appears literally somewhere inside the logs string.
    The log file is at  data/incident.log  -- open it to see what is there.
    """
    for candidate in ai.ask("incident_diagnosis", logs):
        if not isinstance(candidate, dict):
            continue
        evidence = candidate.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            continue
        if not all(isinstance(e, str) and e and e in logs for e in evidence):
            continue
        return candidate
    return {}
    # return ai.ask("incident_diagnosis", logs)[0]   # [0] is unverified; fix it


def review_migration(v1: dict, v2: dict, ai) -> list[dict]:
    """
    Level 4 -- return only breaking changes proven by the two contracts.

    ai.ask("migration_review", {...}) returns a list like:
        [
          {
            "id": "BREAK-POST",
            "claim": "POST /orders was removed in v2.",
            "kind": "operation_removed",
            "path": "/orders",
            "method": "post"
          },
          {
            "id": "BREAK-LIMIT",
            "claim": "The limit query parameter became required.",
            "kind": "parameter_became_required",
            "path": "/orders",
            "method": "get",
            "parameter": "limit"
          },
          {
            "id": "BREAK-003",
            "claim": "orderId changed from integer to string.",
            "kind": "schema_changed",
            "path": "/orders/{orderId}",
            "method": "get",
            "parameter": "orderId"
          }
        ]

    Compare each claim against data/openapi-v1.json and data/openapi-v2.json
    (Swagger: http://localhost:8081/api/v1 and http://localhost:8081/api/v2).

    Verify each change by comparing v1 and v2 directly.
      "operation_removed"       -- operation exists in v1 but not in v2.
      "parameter_became_required" -- parameter.required is False in v1
                                     and True in v2.
      "schema_changed"          -- parameter["schema"] differs between v1 and v2.
                                   If the schemas are identical the claim is false.
    """
    http_methods = {"get", "put", "post", "delete", "patch", "options", "head", "trace"}

    def get_op(spec, path, method):
        item = (spec.get("paths") or {}).get(path)
        if not isinstance(item, dict) or method not in http_methods:
            return None
        op = item.get(method)
        return op if isinstance(op, dict) else None

    def deref(spec, obj):
        # resolve a local "$ref" like "#/components/parameters/Limit"
        seen = 0
        while isinstance(obj, dict) and "$ref" in obj and seen < 10:
            ref = obj["$ref"]
            if not isinstance(ref, str) or not ref.startswith("#/"):
                return obj
            node = spec
            for tok in ref[2:].split("/"):
                tok = tok.replace("~1", "/").replace("~0", "~")
                if not isinstance(node, dict) or tok not in node:
                    return obj
                node = node[tok]
            obj = node
            seen += 1
        return obj

    def get_param(spec, path, method, name):
        # operation-level parameters override path-level ones
        op = get_op(spec, path, method)
        if op is None:
            return None
        item = spec["paths"][path]
        for params in (op.get("parameters") or [], item.get("parameters") or []):
            for p in params:
                p = deref(spec, p)
                if isinstance(p, dict) and p.get("name") == name:
                    return p
        return None

    valid = []
    for f in ai.ask("migration_review", {"v1": v1, "v2": v2}):
        try:
            kind = f["kind"]
            path = f["path"]
            method = f["method"].lower()

            if kind == "operation_removed":
                if get_op(v1, path, method) is None:
                    continue
                if get_op(v2, path, method) is not None:
                    continue

            elif kind == "parameter_became_required":
                p1 = get_param(v1, path, method, f["parameter"])
                p2 = get_param(v2, path, method, f["parameter"])
                if p1 is None or p2 is None:
                    continue
                if p1.get("required", False) is not False:
                    continue
                if p2.get("required", False) is not True:
                    continue

            elif kind == "schema_changed":
                p1 = get_param(v1, path, method, f["parameter"])
                p2 = get_param(v2, path, method, f["parameter"])
                if p1 is None or p2 is None:
                    continue
                s1 = deref(v1, p1.get("schema"))
                s2 = deref(v2, p2.get("schema"))
                if s1 == s2:
                    continue

            else:
                continue  # unknown kind: not provable
        except (KeyError, TypeError, AttributeError):
            continue
        valid.append(f)
    return valid
    #return ai.ask("migration_review", {"v1": v1, "v2": v2})
