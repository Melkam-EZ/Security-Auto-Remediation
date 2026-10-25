"""Tell humans, and emit metrics. Notifications fire on state CHANGES only, so a persistent problem is not spam."""
from __future__ import annotations

import json
import sys
import time


class Notifier:
    """Publishes to SNS. Never raises: a broken notification channel must not stop remediation."""

    def __init__(self, topic_arn=None, sns=None):
        self.topic_arn, self.sns = topic_arn, sns

    def send(self, subject: str, message: str):
        if not (self.topic_arn and self.sns):
            print(f"[notify-skipped] {subject}", file=sys.stderr)
            return False
        try:
            self.sns.publish(TopicArn=self.topic_arn, Subject=subject[:100], Message=message[:200_000])
            return True
        except Exception as exc:  # noqa: BLE001
            print(f"[notify-failed] {subject}: {type(exc).__name__}: {exc}", file=sys.stderr)
            return False


class Metrics:
    """CloudWatch Embedded Metric Format: one JSON log line becomes a metric, no API call and no extra permission."""

    def __init__(self, namespace="SecRem", out=None):
        self.namespace, self.out = namespace, out or sys.stdout

    def emit(self, name: str, value: float = 1, **dimensions):
        record = {
            "_aws": {"Timestamp": int(time.time() * 1000),
                     "CloudWatchMetrics": [{"Namespace": self.namespace, "Dimensions": [sorted(dimensions)] if dimensions else [[]],
                                            "Metrics": [{"Name": name, "Unit": "Count"}]}]},
            name: value, **dimensions,
        }
        print(json.dumps(record), file=self.out, flush=True)
