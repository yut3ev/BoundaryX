import json
from typing import Any, Dict, Optional
import uuid

from pydantic import BaseModel, Field

from boundaryx.domain.models import utc_now_iso

PROTOCOL_VERSION = "1.0"
MAX_PAYLOAD_BYTES = 10 * 1024 * 1024  # 10 MB maximum IPC message size


class IPCRequest(BaseModel):
    protocol_version: str = PROTOCOL_VERSION
    request_id: str
    command: str
    payload: Dict[str, Any] = Field(default_factory=dict)


class IPCResponse(BaseModel):
    protocol_version: str = PROTOCOL_VERSION
    request_id: str
    success: bool
    data: Optional[Any] = None
    error: Optional[Dict[str, Any]] = None


class IPCEvent(BaseModel):
    protocol_version: str = PROTOCOL_VERSION
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    job_id: Optional[str] = None
    event_type: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    timestamp: str = Field(default_factory=utc_now_iso)


class IPCError(Exception):
    def __init__(self, code: str, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "details": self.details,
        }


def parse_ipc_line(line: str) -> IPCRequest:
    raw_bytes = line.encode("utf-8")
    if len(raw_bytes) > MAX_PAYLOAD_BYTES:
        raise IPCError("PAYLOAD_TOO_LARGE", f"Message exceeded maximum allowed size of {MAX_PAYLOAD_BYTES} bytes")

    try:
        data = json.loads(line)
    except json.JSONDecodeError as err:
        raise IPCError("INVALID_JSON", f"Malformed JSON: {str(err)}") from err

    if not isinstance(data, dict):
        raise IPCError("INVALID_FORMAT", "IPC request must be a JSON object")

    req_id = data.get("request_id")
    command = data.get("command")

    if not req_id or not command:
        raise IPCError("MISSING_FIELDS", "IPC request requires 'request_id' and 'command'")

    version = data.get("protocol_version", PROTOCOL_VERSION)
    if version.split(".")[0] != PROTOCOL_VERSION.split(".")[0]:
        raise IPCError("INCOMPATIBLE_VERSION", f"Protocol version {version} is incompatible with {PROTOCOL_VERSION}")

    return IPCRequest(
        protocol_version=version,
        request_id=str(req_id),
        command=str(command),
        payload=data.get("payload", {}),
    )


def serialize_ipc_response(resp: IPCResponse) -> str:
    return json.dumps(resp.model_dump(), separators=(",", ":"))


def serialize_ipc_event(event: IPCEvent) -> str:
    return json.dumps(event.model_dump(), separators=(",", ":"))
