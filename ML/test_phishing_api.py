#!/usr/bin/env python3
"""
test_phishing_api.py
====================
Sends test cases to the ML API's `/predict-phishing` endpoint to verify the service.
Run this on the VM-ML after starting the FastAPI service.
"""

import urllib.request
import json
import sys

API_URL = "http://localhost:8000/predict-phishing"

test_urls = [
    # Benign
    {"url": "https://google.com", "srcip": "192.168.1.50"},
    {"url": "https://github.com/login", "srcip": "192.168.1.51"},
    # Phishing
    {"url": "http://secure-login-paypal.com/update", "srcip": "10.0.0.12"},
    {"url": "http://192.168.22.44/verify", "srcip": "10.0.0.13"},
    {"url": "https://login.microsoft.com@suspiciousdomain.net/login.html", "srcip": "182.8.100.43"}
]

print(f"Sending requests to {API_URL}...\n")

for item in test_urls:
    req_data = json.dumps(item).encode("utf-8")
    req = urllib.request.Request(
        API_URL,
        data=req_data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            res = json.loads(resp.read().decode("utf-8"))
            print(f"URL       : {res['url']}")
            print(f"Result    : {res['label']} (Score: {res['score']})")
            print(f"Features  : {res['features']}")
            print("-" * 50)
    except Exception as e:
        print(f"Failed to query API for URL: {item['url']}")
        print(f"Error: {e}")
        print("-" * 50)

print("\nTests completed.")
