from dataclasses import dataclass
from datetime import datetime

@dataclass
class Event:

    timestamp: datetime
    host: str
    service: str
    event_type: str
    user: str | None
    source_ip: str | None
    port: int | None
    raw: str