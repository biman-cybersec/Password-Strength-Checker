"""Tests for the Flask backend (app.py). Run with:  pytest"""
from pathlib import Path

import pytest

import app as app_module
from app import WEB_FILES

HERE = Path(app_module.__file__).parent


@pytest.fixture
def client():
    app_module.app.config["TESTING"] = True
    return app_module.app.test_client()


# ---------- /api/check ----------

def test_check_strong_password(client):
    r = client.post("/api/check", json={"password": "Xk9$mP2#vL7@qR4!"})
    assert r.status_code == 200
    assert r.get_json() == {"score": 6, "label": "Strong", "feedback": []}


def test_check_weak_password_has_feedback(client):
    data = client.post("/api/check", json={"password": "abc"}).get_json()
    assert data["score"] == 1 and data["label"] == "Low"
    assert len(data["feedback"]) > 0


@pytest.mark.parametrize("body", [{}, {"password": ""}])
def test_check_empty_password(client, body):
    r = client.post("/api/check", json=body)
    assert r.status_code == 200
    assert r.get_json()["score"] == 0
    assert r.get_json()["feedback"] == ["Enter a password."]


def test_check_bad_json_is_treated_as_empty(client):
    r = client.post("/api/check", data="not json", content_type="application/json")
    assert r.status_code == 200
    assert r.get_json()["score"] == 0


@pytest.mark.parametrize("value", [123, None, ["a"], {"x": 1}, True])
def test_check_non_text_password_is_rejected(client, value):
    r = client.post("/api/check", json={"password": value})
    assert r.status_code == 400
    assert "error" in r.get_json()


def test_check_common_and_leet_passwords_score_zero(client):
    for pw in ("password", "PASSWORD", "p@ssw0rd"):
        assert client.post("/api/check", json={"password": pw}).get_json()["score"] == 0


def test_check_unicode_password_does_not_crash(client):
    assert client.post("/api/check", json={"password": "pässwörd-日本語-42!"}).status_code == 200


def test_check_rejects_get(client):
    assert client.get("/api/check").status_code == 405


# ---------- /api/bulk ----------

def test_bulk_good_input(client):
    pws = ["password", "abc", "Xk9$mP2#vL7@qR4!"]
    r = client.post("/api/bulk", json={"passwords": pws})
    assert r.status_code == 200
    results = r.get_json()["results"]
    assert [x["password"] for x in results] == pws          # same order
    assert [x["score"] for x in results] == [0, 1, 6]
    assert [x["label"] for x in results] == ["Low", "Low", "Strong"]
    assert all(set(x) == {"password", "score", "label"} for x in results)


def test_bulk_empty_list(client):
    r = client.post("/api/bulk", json={"passwords": []})
    assert r.status_code == 200 and r.get_json() == {"results": []}


def test_bulk_missing_key_is_treated_as_empty(client):
    assert client.post("/api/bulk", json={}).get_json() == {"results": []}


@pytest.mark.parametrize("passwords", ["abc", 5, {"a": "b"}, [1, 2], ["ok", 3], ["ok", None], [["nested"]]])
def test_bulk_non_text_items_are_rejected(client, passwords):
    r = client.post("/api/bulk", json={"passwords": passwords})
    assert r.status_code == 400
    assert "error" in r.get_json()


def test_bulk_too_many_items_returns_413(client, monkeypatch):
    monkeypatch.setattr(app_module, "MAX_BULK", 3)
    assert client.post("/api/bulk", json={"passwords": ["a"] * 3}).status_code == 200   # exactly the limit
    r = client.post("/api/bulk", json={"passwords": ["a"] * 4})
    assert r.status_code == 413
    assert "too many" in r.get_json()["error"]


def test_bulk_handles_a_big_list(client):
    r = client.post("/api/bulk", json={"passwords": ["Xk9$mP2#vL7@qR4!"] * 5000})
    assert r.status_code == 200 and len(r.get_json()["results"]) == 5000


# ---------- Serving the website ----------

def test_home_serves_the_page(client):
    if not (HERE / "index.html").exists():
        pytest.skip("index.html not found")
    r = client.get("/")
    assert r.status_code == 200
    assert b"Password Strength Checker" in r.data
    r.close()


@pytest.mark.parametrize("name", sorted(WEB_FILES))
def test_listed_web_files_are_served(client, name):
    if not (HERE / name).exists():
        pytest.skip(name + " not found")
    r = client.get("/" + name)
    assert r.status_code == 200
    r.close()


@pytest.mark.parametrize("path", [
    "/app.py", "/password_checker.py", "/passwords.txt", "/common_passwords.txt",
    "/test_app.py", "/test_password_checker.py", "/index.html", "/nothing-here",
    "/%2e%2e%2fapp.py",
])
def test_private_or_unknown_files_return_404(client, path):
    assert client.get(path).status_code == 404


def test_web_file_whitelist_never_lists_python_or_data_files():
    assert not any(n.endswith((".py", ".txt")) for n in WEB_FILES)
