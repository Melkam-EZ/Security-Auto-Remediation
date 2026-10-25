"""What rules need to talk to AWS: clients per service and region, and a clock you can control in tests."""
from __future__ import annotations

from datetime import datetime, timezone

import boto3
from botocore.config import Config

RETRY = Config(retries={"max_attempts": 8, "mode": "standard"})


class Context:
    def __init__(self, regions, session=None, clock=None):
        self.regions = list(regions)
        self.session = session or boto3.session.Session()
        self._clock = clock
        self._clients = {}

    def client(self, service, region=None):
        region = region or self.regions[0]
        key = (service, region)
        if key not in self._clients:
            self._clients[key] = self.session.client(service, region_name=region, config=RETRY)
        return self._clients[key]

    def now(self) -> datetime:
        return self._clock() if self._clock else datetime.now(timezone.utc)


def regional(resource_id: str):
    """'eu-west-1:sg-123' -> ('eu-west-1', 'sg-123'). Regional resources carry their region in their id."""
    region, _, ident = resource_id.partition(":")
    if not ident:
        raise ValueError(f"not a regional resource id: {resource_id}")
    return region, ident
