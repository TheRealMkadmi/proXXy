import contextlib
import os
import json
import time
import logging
import requests
from tqdm import tqdm
from yaspin import yaspin
from concurrent.futures import ThreadPoolExecutor

def proxy_sources():
    with open('proxy_sources.json', 'r') as file:
        return json.load(file)