"""
sentinel_monitor.py
────────────────────────────────────────────────────────────────────────────────
AWS Lambda function that probes the Sentinel Security Monitor and pushes
custom metrics to CloudWatch.

Tracked metrics (all under the "Sentinel/Performance" namespace):
  • ResponseTime_ms   – HTTP round-trip latency per endpoint
  • AnomalyDetectionLatency_ms – time to call GET /anomalies specifically
  • StatusCode        – HTTP status code per endpoint (alerts you to 4xx/5xx)
  • ErrorCount        – 1 if a request fails completely (connection error etc.)

Memory / CPU:
  Lambda itself has no OS-level CPU metric, but the Lambda platform automatically
  publishes:
    - aws/lambda: Duration, MaxMemoryUsed, MemorySize
  into CloudWatch Logs Insights / Lambda metrics.  No extra code is needed —
  just enable "Enhanced monitoring" on the function.

Deployment
──────────
1.  Package:
      zip monitor.zip sentinel_monitor.py

2.  Create Lambda (Python 3.12, arm64 recommended):
      aws lambda create-function \
        --function-name sentinel-monitor \
        --zip-file fileb://monitor.zip \
        --handler sentinel_monitor.lambda_handler \
        --runtime python3.12 \
        --role arn:aws:iam::<ACCOUNT>:role/<ROLE> \
        --environment Variables="{
            TARGET_BASE_URL=https://your-sentinel-host:8080,
            CLOUDWATCH_NAMESPACE=Sentinel/Performance,
            PROBE_TIMEOUT_SECONDS=10
          }"

3.  Schedule with EventBridge (every 1 minute):
      aws events put-rule \
        --schedule-expression "rate(1 minute)" \
        --name sentinel-monitor-schedule
      aws lambda add-permission \
        --function-name sentinel-monitor \
        --statement-id EventBridgeInvoke \
        --action lambda:InvokeFunction \
        --principal events.amazonaws.com \
        --source-arn arn:aws:events:<REGION>:<ACCOUNT>:rule/sentinel-monitor-schedule
      aws events put-targets \
        --rule sentinel-monitor-schedule \
        --targets "Id=1,Arn=arn:aws:lambda:<REGION>:<ACCOUNT>:function:sentinel-monitor"

4.  IAM: the Lambda execution role needs:
      cloudwatch:PutMetricData

Required dependencies: none beyond the Python stdlib + boto3 (pre-installed in Lambda).
────────────────────────────────────────────────────────────────────────────────
"""

import json
import logging
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ── Configuration ─────────────────────────────────────────────────────────────

BASE_URL        = os.environ.get("TARGET_BASE_URL", "http://localhost:8080")
NAMESPACE       = os.environ.get("CLOUDWATCH_NAMESPACE", "Sentinel/Performance")
PROBE_TIMEOUT   = int(os.environ.get("PROBE_TIMEOUT_SECONDS", "10"))

# Endpoints to probe on every invocation.
ENDPOINTS: list[dict[str, Any]] = [
    {
        "name":   "PostEvent",
        "method": "POST",
        "path":   "/events",
        "body":   json.dumps({"type": "FAILED_LOGIN", "source_ip": "monitor-probe"}).encode(),
        "headers": {"Content-Type": "application/json"},
    },
    {
        "name":   "ListEvents",
        "method": "GET",
        "path":   "/events",
        "body":   None,
        "headers": {},
    },
    {
        "name":   "GetAnomalies",
        "method": "GET",
        "path":   "/anomalies",
        "body":   None,
        "headers": {},
    },
]

cw = boto3.client("cloudwatch")

# ── Metric helpers ────────────────────────────────────────────────────────────

def _metric(name: str, value: float, unit: str, dimensions: list[dict]) -> dict:
    """Build a single MetricDatum dict for PutMetricData."""
    return {
        "MetricName": name,
        "Dimensions": dimensions,
        "Timestamp":  datetime.now(tz=timezone.utc),
        "Value":      value,
        "Unit":       unit,
    }


def _push(metrics: list[dict]) -> None:
    """Push a batch of metrics to CloudWatch (max 1,000 per call)."""
    for i in range(0, len(metrics), 1000):
        batch = metrics[i : i + 1000]
        cw.put_metric_data(Namespace=NAMESPACE, MetricData=batch)
        logger.info("Pushed %d metric(s) to %s", len(batch), NAMESPACE)


# ── Probing logic ─────────────────────────────────────────────────────────────

def _probe(endpoint: dict[str, Any]) -> dict[str, Any]:
    """
    Make one HTTP request to the target and return a result dict containing:
      latency_ms, status_code, error (bool), anomaly_latency_ms (for /anomalies only)
    """
    url = BASE_URL.rstrip("/") + endpoint["path"]
    req = urllib.request.Request(
        url,
        data=endpoint["body"],
        method=endpoint["method"],
        headers=endpoint["headers"],
    )

    # Measure anomaly detection latency separately for /anomalies
    anomaly_latency_ms = None
    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=PROBE_TIMEOUT) as resp:
            elapsed_ms = (time.monotonic() - start) * 1000
            status     = resp.status

            if endpoint["name"] == "GetAnomalies":
                # The latency to decode the anomaly payload is what matters most —
                # this forces the full response body to be read.
                _ = resp.read()
                anomaly_latency_ms = (time.monotonic() - start) * 1000

        return {
            "latency_ms":         elapsed_ms,
            "status_code":        status,
            "error":              False,
            "anomaly_latency_ms": anomaly_latency_ms,
        }

    except urllib.error.HTTPError as exc:
        elapsed_ms = (time.monotonic() - start) * 1000
        logger.warning("HTTP error probing %s: %s", url, exc)
        return {
            "latency_ms":         elapsed_ms,
            "status_code":        exc.code,
            "error":              False,   # got a response — not a connection error
            "anomaly_latency_ms": None,
        }

    except Exception as exc:
        elapsed_ms = (time.monotonic() - start) * 1000
        logger.error("Connection error probing %s: %s", url, exc)
        return {
            "latency_ms":         elapsed_ms,
            "status_code":        0,
            "error":              True,
            "anomaly_latency_ms": None,
        }


# ── Lambda entry-point ────────────────────────────────────────────────────────

def lambda_handler(event: dict, context: Any) -> dict:
    """
    Invoked by EventBridge on a schedule.
    Probes every endpoint, collects metrics, and pushes them to CloudWatch.
    """
    metrics: list[dict] = []

    for ep in ENDPOINTS:
        result = _probe(ep)
        dims   = [{"Name": "Endpoint", "Value": ep["name"]}]

        logger.info(
            "Endpoint=%-12s  latency=%.1fms  status=%d  error=%s",
            ep["name"], result["latency_ms"], result["status_code"], result["error"],
        )

        # ── Response time ──────────────────────────────────────────────────
        metrics.append(_metric(
            name="ResponseTime_ms",
            value=result["latency_ms"],
            unit="Milliseconds",
            dimensions=dims,
        ))

        # ── HTTP status code ───────────────────────────────────────────────
        metrics.append(_metric(
            name="StatusCode",
            value=result["status_code"],
            unit="None",
            dimensions=dims,
        ))

        # ── Connection errors ──────────────────────────────────────────────
        metrics.append(_metric(
            name="ErrorCount",
            value=1.0 if result["error"] else 0.0,
            unit="Count",
            dimensions=dims,
        ))

        # ── Anomaly detection latency (GetAnomalies endpoint only) ─────────
        if result["anomaly_latency_ms"] is not None:
            metrics.append(_metric(
                name="AnomalyDetectionLatency_ms",
                value=result["anomaly_latency_ms"],
                unit="Milliseconds",
                dimensions=[{"Name": "Endpoint", "Value": "GetAnomalies"}],
            ))

    _push(metrics)

    return {"statusCode": 200, "body": f"Pushed {len(metrics)} metrics"}


# ── Local smoke-test ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Run locally against a running Sentinel instance.
    # Usage: TARGET_BASE_URL=http://localhost:8080 python sentinel_monitor.py
    logging.basicConfig(level=logging.INFO)
    for ep in ENDPOINTS:
        result = _probe(ep)
        print(f"{ep['name']:15s}  {result['latency_ms']:.1f}ms  HTTP {result['status_code']}")
