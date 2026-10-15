"""Unit tests for traffic importers (HAR 1.2, Raw HTTP, and BoundaryX JSON)."""

import json
from pathlib import Path
from uuid import uuid4

from boundaryx.infrastructure.imports import (
    BoundaryXImporter,
    HarImporter,
    RawHttpImporter,
)


def test_har_importer_valid_file(tmp_path: Path):
    project_id = uuid4()
    har_content = {
        "log": {
            "version": "1.2",
            "creator": {"name": "TestTool", "version": "1.0"},
            "entries": [
                {
                    "startedDateTime": "2026-10-15T12:00:00.000Z",
                    "time": 42.5,
                    "request": {
                        "method": "POST",
                        "url": "https://api.target.com/v1/orders",
                        "httpVersion": "HTTP/1.1",
                        "headers": [
                            {"name": "Content-Type", "value": "application/json"},
                            {"name": "Authorization", "value": "Bearer test-secret-token"},
                        ],
                        "postData": {
                            "mimeType": "application/json",
                            "text": '{"order_id": 12345}',
                        },
                    },
                    "response": {
                        "status": 201,
                        "statusText": "Created",
                        "httpVersion": "HTTP/1.1",
                        "headers": [
                            {"name": "Content-Type", "value": "application/json"},
                        ],
                        "content": {
                            "size": 25,
                            "mimeType": "application/json",
                            "text": '{"status": "success"}',
                        },
                    },
                }
            ],
        }
    }
    har_file = tmp_path / "traffic.har"
    har_file.write_text(json.dumps(har_content), encoding="utf-8")

    importer = HarImporter()
    res = importer.import_file(har_file, project_id)

    assert res.total_entries == 1
    assert res.imported_count == 1
    assert res.skipped_count == 0
    assert len(res.records) == 1

    rec = res.records[0]
    assert rec["method"] == "POST"
    assert rec["url"] == "https://api.target.com/v1/orders"
    assert rec["status_code"] == 201
    assert rec["request_headers"]["Content-Type"] == "application/json"
    assert rec["response_body"] == '{"status": "success"}'
    assert rec["source"] == "har"


def test_har_importer_nonexistent_and_invalid_json(tmp_path: Path):
    project_id = uuid4()
    importer = HarImporter()

    # Nonexistent file
    res = importer.import_file(tmp_path / "missing.har", project_id)
    assert len(res.errors) > 0
    assert "File not found" in res.errors[0]["message"]

    # Invalid JSON
    bad_json = tmp_path / "corrupted.har"
    bad_json.write_text("NOT A VALID JSON", encoding="utf-8")
    res_bad = importer.import_file(bad_json, project_id)
    assert len(res_bad.errors) > 0
    assert "Invalid JSON" in res_bad.errors[0]["message"]


def test_raw_http_importer_paired_file(tmp_path: Path):
    project_id = uuid4()
    raw_traffic = """POST /api/v1/profile HTTP/1.1
Host: api.target.com
Content-Type: application/json
Authorization: Bearer test_auth_token

{"name": "Alice"}

HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 20

{"status": "updated"}
"""
    raw_file = tmp_path / "traffic.txt"
    raw_file.write_text(raw_traffic, encoding="utf-8")

    importer = RawHttpImporter()
    res = importer.import_file(raw_file, project_id)

    assert res.imported_count == 1
    assert len(res.records) == 1
    rec = res.records[0]
    assert rec["method"] == "POST"
    assert rec["url"] == "https://api.target.com/api/v1/profile"
    assert rec["status_code"] == 200
    assert rec["response_body"] == '{"status": "updated"}'


def test_raw_http_importer_request_only(tmp_path: Path):
    project_id = uuid4()
    raw_req = """GET /admin/dashboard HTTP/1.1
Host: secure.corp.local:8080
Cookie: session=xyz123

"""
    req_file = tmp_path / "request.txt"
    req_file.write_text(raw_req, encoding="utf-8")

    importer = RawHttpImporter()
    res = importer.import_request_file(req_file, project_id)

    assert res.imported_count == 1
    rec = res.records[0]
    assert rec["method"] == "GET"
    assert "secure.corp.local:8080/admin/dashboard" in rec["url"]
    assert rec["status_code"] == 0


def test_boundaryx_importer_and_schema(tmp_path: Path):
    project_id = uuid4()
    importer = BoundaryXImporter()
    schema = importer.get_schema()
    assert "records" in schema["required"]

    valid_payload = {
        "boundaryx_version": "1.0",
        "exported_at": "2026-10-15T12:00:00Z",
        "records": [
            {
                "method": "GET",
                "url": "https://target.com/items/42",
                "status_code": 200,
                "request_headers": {"Accept": "application/json"},
                "response_body": '{"item": 42}',
            }
        ],
    }
    json_file = tmp_path / "boundaryx_traffic.json"
    json_file.write_text(json.dumps(valid_payload), encoding="utf-8")

    res = importer.import_file(json_file, project_id)
    assert res.imported_count == 1
    assert len(res.records) == 1
    rec = res.records[0]
    assert rec["method"] == "GET"
    assert rec["url"] == "https://target.com/items/42"
    assert rec["source"] == "boundaryx"
