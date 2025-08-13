import json

def proxy_sources():
    with open('proxy_sources.json', 'r', encoding='utf-8') as file:
        return json.load(file)