# Verbatim producer functions from GioNob/ouf-deploy at 9403e2cfe67e58ec177413cb5279d865a0d1e4e7
# tools/chatbot_file_cohort/gateway.py; isolated public synthetic contract fixture.
import json
import re
MAX_ROUTES = 256
ROUTE_ID = re.compile(r'[A-Za-z0-9._-]{1,128}')
def encoded(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def require(ok,code):
    if not ok: raise ValueError(code)

def route_value(doc):
    # Same APISIX envelope normalization used by the qualified route installers.
    value = doc.get('value', doc)
    if type(value) is dict and type(value.get('value')) is dict:
        value = value['value']
    require(type(value) is dict, 'APISIX_ROUTE_OBJECT_REQUIRED')
    return {k: v for k, v in value.items() if k not in ('create_time', 'update_time')}


def route_map(rows):
    require(type(rows) is list and 0 < len(rows) <= MAX_ROUTES, 'COMPLETE_BOUNDED_GATEWAY_ROUTES_REQUIRED')
    result = {}
    for row in rows:
        value = route_value(row)
        rid = value.get('id')
        require(type(rid) is str and ROUTE_ID.fullmatch(rid) and rid not in result,
                'UNIQUE_EXACT_GATEWAY_ROUTE_ID_REQUIRED')
        require(len(encoded(value)) <= 262144, 'GATEWAY_ROUTE_BOUND_EXCEEDED')
        result[rid] = value
    return result
