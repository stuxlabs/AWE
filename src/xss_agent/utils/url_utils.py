"""
URL manipulation utilities
"""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import Optional


def inject_payload_into_url(base_url: str, payload: str, param_name: Optional[str] = None) -> str:
    """Inject payload into URL query parameters"""
    parsed = urlparse(base_url)
    params = parse_qs(parsed.query)

    if param_name and param_name in params:
        params[param_name] = [payload]
    elif params:
        first_param = list(params.keys())[0]
        params[first_param] = [payload]
    else:
        params['xss'] = [payload]

    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))