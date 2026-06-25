#!/usr/bin/env python3
"""
custom-ml-predict.py — Wazuh Custom Integration Script
=======================================================
Called by Wazuh Manager's integrator when a matching alert fires.
Sends the alert to the ML FastAPI for classification (TP vs FP).
"""

import json
import sys
import logging
import urllib.request
import urllib.error
import re
from datetime import datetime

# ---------------------------------------------------------------------------
# CONFIG — Update ML_API_URL if VM-ML IP changes
# ---------------------------------------------------------------------------
ML_API_URL = "http://20.41.107.48:8000/predict"
# Compute Phishing API URL dynamically from ML_API_URL
if ML_API_URL.endswith("/predict"):
    ML_PHISHING_API_URL = ML_API_URL.replace("/predict", "/predict-phishing")
else:
    ML_PHISHING_API_URL = ML_API_URL + "-phishing"

LOG_FILE = "/var/ossec/logs/ml-predictions.log"
MIN_CONFIDENCE_TO_BLOCK = 0.85

# Don't block these administrative IPs
ALLOWLIST_IPS = {
    "127.0.0.1",
    "localhost",
    "20.41.96.43",   # Wazuh Manager
    "20.41.107.48",  # VM ML
    "182.8.97.126",  # Kali (SEMENTARA)
}

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("custom-ml-predict")


def post_json(url, payload, timeout=10):
    req_data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=req_data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8")
        try:
            return json.loads(body)
        except Exception:
            return {"raw_response": body}


def extract_alert_fields(alert_data):
    rule = alert_data.get("rule", {})
    data = alert_data.get("data", {})
    agent = alert_data.get("agent", {})

    return {
        "rule_level": int(rule.get("level", 0)),
        "rule_id": str(rule.get("id", "0")),
        "rule_description": rule.get("description", "-"),
        "srcip": data.get("srcip", alert_data.get("srcip", "unknown")),
        "timestamp": alert_data.get("timestamp"),
        "agent_id": agent.get("id", "000"),
        "agent_name": agent.get("name", "unknown"),
        "full_log": alert_data.get("full_log", ""),
    }


def is_true_positive(label):
    label_upper = str(label).upper().replace(" ", "_")
    return label_upper in {
        "TP",
        "TRUE_POSITIVE",
        "MALICIOUS",
        "ATTACK",
        "SERANGAN",
    }


def main():
    if len(sys.argv) < 2:
        logger.error("No alert file provided.")
        sys.exit(1)

    alert_file = sys.argv[1]
    shuffle_hook_url = sys.argv[3] if len(sys.argv) >= 4 else ""

    try:
        with open(alert_file, "r") as f:
            alert_data = json.load(f)
    except Exception as e:
        logger.error("Failed to read alert file %s: %s", alert_file, e)
        sys.exit(1)

    fields = extract_alert_fields(alert_data)
    rule_id = fields["rule_id"]
    timestamp = fields["timestamp"]

    # Check if this is a phishing alert
    is_phishing = rule_id in ("100120", "100121")

    if is_phishing:
        full_log = fields["full_log"]
        # Regex to find URL. Try query param check= first
        url = "unknown"
        check_match = re.search(r"check=([^\s&\"']+)", full_log, re.IGNORECASE)
        if check_match:
            import urllib.parse
            url = urllib.parse.unquote(check_match.group(1).strip())
        else:
            url_match = re.search(r"url:\s*([^\s'\"]+)", full_log, re.IGNORECASE)
            if url_match:
                url = url_match.group(1).strip()
            else:
                http_match = re.search(r"(https?://[^\s'\"]+)", full_log, re.IGNORECASE)
                if http_match:
                    url = http_match.group(1).strip()

        # Regex to find srcip if not parsed
        srcip = fields["srcip"]
        if srcip == "unknown":
            srcip_match = re.search(r"(?:srcip|ip):\s*([0-9a-fA-F.:]+)", full_log, re.IGNORECASE)
            if srcip_match:
                srcip = srcip_match.group(1).strip()
            fields["srcip"] = srcip

        payload = {
            "url": url,
            "srcip": srcip,
            "timestamp": timestamp
        }
        logger.info("Sending phishing verification request to ML API: %s", json.dumps(payload))
        target_url = ML_PHISHING_API_URL
    else:
        srcip = fields["srcip"]
        payload = {
            "rule_level": fields["rule_level"],
            "rule_id": rule_id,
            "srcip": srcip,
            "timestamp": timestamp,
        }
        logger.info("Sending alert to ML API: %s", json.dumps(payload))
        target_url = ML_API_URL

    try:
        ml_result = post_json(target_url, payload)
    except Exception as e:
        logger.error("ML API request failed: %s", e)
        soar_payload = {
            "decision": "ignore",
            "reason": "ML API error, no automated block executed",
            "ml_error": str(e),
            **fields,
        }
        if shuffle_hook_url:
            try:
                post_json(shuffle_hook_url, soar_payload)
            except Exception as se:
                logger.error("Failed to send ML error to Shuffle: %s", se)
        sys.exit(1)

    label = ml_result.get("label", "UNKNOWN")
    # Phishing API uses 'score', standard API uses 'confidence'
    confidence = float(ml_result.get("confidence", ml_result.get("score", 0)))
    srcip = fields["srcip"]

    should_block = (
        is_true_positive(label)
        and confidence >= MIN_CONFIDENCE_TO_BLOCK
        and srcip not in ALLOWLIST_IPS
        and srcip not in ["unknown", "", None]
    )

    decision = "block" if should_block else "ignore"

    if decision == "block":
        reason = "ML classified alert as true positive with high confidence"
    elif srcip in ALLOWLIST_IPS:
        reason = "Source IP is allowlisted, no block executed"
    elif confidence < MIN_CONFIDENCE_TO_BLOCK:
        reason = "Confidence below blocking threshold"
    else:
        reason = "ML classified alert as false positive or unknown"

    # Adapt features list for unified schema
    feats = ml_result.get("features_used", ml_result.get("features", {}))

    soar_payload = {
        "decision": decision,
        "reason": reason,
        "ml_label": label,
        "confidence": confidence,
        "prediction": ml_result.get("prediction"),
        "features_used": feats,
        **fields,
        "raw_alert": alert_data,
    }

    if is_phishing and "url" in ml_result:
        soar_payload["url"] = ml_result["url"]
        url_info = f" | url={ml_result['url']}"
    else:
        url_info = ""

    logger.info("ML_RESULT | decision=%s | label=%s | conf=%.4f | rule_id=%s | srcip=%s | reason=%s%s | features=%s",
                decision, label, confidence, rule_id, srcip, reason, url_info, json.dumps(feats))

    # Tulis penanda block agar Wazuh bisa memicu Active Response
    if decision == "block":
        try:
            with open("/var/ossec/logs/ml-block.log", "a") as bf:
                bf.write("ML_BLOCK srcip=%s rule_id=%s conf=%.4f\n" % (srcip, rule_id, confidence))
        except Exception as e:
            logger.error("Gagal tulis ml-block.log: %s", e)

    if shuffle_hook_url:
        try:
            post_json(shuffle_hook_url, soar_payload)
            logger.info("Sent decision to Shuffle: %s", decision)
        except Exception as e:
            logger.error("Failed to send to Shuffle: %s", e)
    else:
        logger.warning("No Shuffle hook URL provided by Wazuh integration.")

    print(f"ml-predict: decision={decision} label={label} conf={confidence:.4f} rule={rule_id} ip={srcip}{url_info}")


if __name__ == "__main__":
    main()
