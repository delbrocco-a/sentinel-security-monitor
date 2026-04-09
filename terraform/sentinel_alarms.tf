# sentinel_alarms.tf
# ────────────────────────────────────────────────────────────────────────────
# CloudWatch alarms that fire on metrics emitted by sentinel_monitor.py.
# Adjust thresholds to match your SLOs.
# ────────────────────────────────────────────────────────────────────────────

variable "alarm_email" {
  description = "SNS email address for alarm notifications"
  type        = string
}

resource "aws_sns_topic" "sentinel_alerts" {
  name = "sentinel-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.sentinel_alerts.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

# ── High response latency — any endpoint ────────────────────────────────────
resource "aws_cloudwatch_metric_alarm" "high_latency" {
  for_each = toset(["PostEvent", "ListEvents", "GetAnomalies"])

  alarm_name          = "sentinel-high-latency-${each.key}"
  namespace           = "Sentinel/Performance"
  metric_name         = "ResponseTime_ms"
  dimensions          = { Endpoint = each.key }
  extended_statistic  = "p95"
  period              = 60       # 1 minute (matches probe schedule)
  evaluation_periods  = 3
  threshold           = 500      # ms — alert if p95 exceeds 500 ms for 3 consecutive minutes
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.sentinel_alerts.arn]
  treat_missing_data  = "breaching"
}

# ── Anomaly detection latency ────────────────────────────────────────────────
resource "aws_cloudwatch_metric_alarm" "anomaly_detection_latency" {
  alarm_name          = "sentinel-anomaly-detection-latency"
  namespace           = "Sentinel/Performance"
  metric_name         = "AnomalyDetectionLatency_ms"
  dimensions          = { Endpoint = "GetAnomalies" }
  extended_statistic  = "p95"
  period              = 60
  evaluation_periods  = 3
  threshold           = 1000     # ms — detection should complete within 1 second
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.sentinel_alerts.arn]
  treat_missing_data  = "breaching"
}

# ── HTTP errors (4xx / 5xx from the probe) ───────────────────────────────────
resource "aws_cloudwatch_metric_alarm" "http_errors" {
  for_each = toset(["PostEvent", "ListEvents", "GetAnomalies"])

  alarm_name          = "sentinel-http-errors-${each.key}"
  namespace           = "Sentinel/Performance"
  metric_name         = "StatusCode"
  dimensions          = { Endpoint = each.key }
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 2
  threshold           = 399      # fire if any non-2xx/3xx response is observed
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.sentinel_alerts.arn]
  treat_missing_data  = "notBreaching"
}

# ── Connection errors (probe could not reach the service at all) ─────────────
resource "aws_cloudwatch_metric_alarm" "connection_errors" {
  for_each = toset(["PostEvent", "ListEvents", "GetAnomalies"])

  alarm_name          = "sentinel-connection-error-${each.key}"
  namespace           = "Sentinel/Performance"
  metric_name         = "ErrorCount"
  dimensions          = { Endpoint = each.key }
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 2
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.sentinel_alerts.arn]
  treat_missing_data  = "breaching"
}

# ── Lambda memory usage (built-in Lambda metric — no custom code needed) ─────
resource "aws_cloudwatch_metric_alarm" "lambda_memory" {
  alarm_name          = "sentinel-monitor-high-memory"
  namespace           = "AWS/Lambda"
  metric_name         = "MaxMemoryUsed"
  dimensions          = { FunctionName = "sentinel-monitor" }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 3
  threshold           = 100      # MB — alert if monitor Lambda itself is near its limit
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.sentinel_alerts.arn]
  treat_missing_data  = "notBreaching"
}
