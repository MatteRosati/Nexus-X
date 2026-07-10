def test_api_requires_key(client):
    response = client.get("/api/v1/scans")
    assert response.status_code == 401


def test_create_and_read_scan(client, auth_headers):
    created = client.post("/api/v1/scans", headers=auth_headers, json={"domain": "api.example.com"})
    assert created.status_code == 202
    body = created.json()
    assert body["target"] == "api.example.com"
    assert body["status"] == "queued"

    detail = client.get(f"/api/v1/scans/{body['id']}", headers=auth_headers)
    assert detail.status_code == 200
    assert detail.json()["id"] == body["id"]


def test_rejects_out_of_scope_target(client, auth_headers):
    response = client.post("/api/v1/scans", headers=auth_headers, json={"domain": "example.org"})
    assert response.status_code == 403
