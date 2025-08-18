import json
from typing import Any, Dict, List, Sequence

def proxy_sources() -> Dict[str, List[Any]]:
    with open('proxy_sources.json', 'r', encoding='utf-8') as file:
        data = json.load(file)
    # Backward compatible: ensure values are lists and keep items as-is (str or dict)
    result: Dict[str, List[Any]] = {}
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, list):
                result[str(k)] = v
            elif isinstance(v, (tuple, set)):
                result[str(k)] = list(v)
            else:
                # Single string or dict -> wrap into list
                result[str(k)] = [v]
    return result