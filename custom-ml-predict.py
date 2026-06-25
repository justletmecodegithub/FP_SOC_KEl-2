#!/usr/bin/env python3

import json
import sys
import logging
import urllib.request
import urllib.error

ML_API_URL = "http://20.41.107.48:8000/predict"
LOG_FILE = "/var/ossec/logs/ml-predictions.log"

MIN_CONFIDENCE_TO_BLOCK = 0.85

# Sesuaikan. Jangan sampai sistem ngeblok IP milik Wazuh Manager sendiri.
ALLOWLIST_IPS = {
    "127.0.0.1",
    "localhost",
    "20.41.96.43",   # Wazuh Manager
    "20.41.107.48", # VM ML, hapus kalau VM ini dipakai sebagai attacker demo
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

    ml_payload = {
        "rule_level": fields["rule_level"],
        "rule_id": fields["rule_id"],
        "srcip": fields["srcip"],
        "timestamp": fields["timestamp"],
    }

    logger.info("Sending alert to ML API: %s", json.dumps(ml_payload))

    try:
        ml_result = post_json(ML_API_URL, ml_payload)
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
    confidence = float(ml_result.get("confidence", 0))
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

    soar_payload = {
        "decision": decision,
        "reason": reason,
        "ml_label": label,
        "confidence": confidence,
        "prediction": ml_result.get("prediction"),
        "features_used": ml_result.get("features_used", {}),
        **fields,
        "raw_alert": alert_data,
    }

    logger.info("ML_RESULT | decision=%s | label=%s | conf=%.4f | rule_id=%s | srcip=%s | reason=%s",
                decision, label, confidence, fields["rule_id"], srcip, reason)

    if shuffle_hook_url:
        try:
            post_json(shuffle_hook_url, soar_payload)
            logger.info("Sent decision to Shuffle: %s", decision)
        except Exception as e:
            logger.error("Failed to send to Shuffle: %s", e)
    else:
        logger.warning("No Shuffle hook URL provided by Wazuh integration.")

    print(f"ml-predict: decision={decision} label={label} conf={confidence:.4f} rule={fields['rule_id']} ip={srcip}")


if __name__ == "__main__":
    main()
