"""Extra tests for password_checker.py: common list, leetspeak, CSV report."""
import csv

import pytest

from password_checker import (
    COMMON_PASSWORDS, check_password, is_common, leet_variants, save_csv_report, _safe,
)


def test_common_list_is_big_and_lowercase():
    assert len(COMMON_PASSWORDS) > 1000
    assert all(p == p.lower() for p in COMMON_PASSWORDS)


def test_leet_variants_undo_swaps():
    assert "password" in leet_variants("p@ssw0rd")
    assert "password" in leet_variants("Password!")          # trailing ! also tried as plain
    assert "dragon" in leet_variants("Dr@gon")


@pytest.mark.parametrize("pw", ["p@ssw0rd", "Passw0rd", "PA55W0RD", "Password!", "Qwerty123", "Dr@gon"])
def test_leet_and_case_variants_of_common_passwords_are_common(pw):
    assert is_common(pw)
    r = check_password(pw)
    assert r["score"] == 0 and r["label"] == "Low"


def test_leet_common_gets_its_own_feedback():
    assert "look-alike" in check_password("Dr@gon")["feedback"][0]


def test_unique_passwords_are_not_flagged_common():
    assert not is_common("Xk9$mP2#vL7@qR4!")
    assert not is_common("correct-Horse-battery-staple-9!")


def test_safe_blocks_spreadsheet_formulas():
    assert _safe("=1+1") == "'=1+1"
    assert _safe("+cmd") == "'+cmd" and _safe("-2") == "'-2" and _safe("@SUM") == "'@SUM"
    assert _safe("normal") == "normal"


def test_csv_report_contents(tmp_path):
    rows = [{"password": "=evil()", "score": 0, "label": "Low"},
            {"password": 'a,"b"', "score": 3, "label": "Medium"}]
    path = save_csv_report(rows, tmp_path / "r.csv")
    data = list(csv.reader(open(path, encoding="utf-8")))
    assert data[0] == ["Password", "Score", "Strength"]
    assert data[1] == ["'=evil()", "0", "Low"]
    assert data[2] == ['a,"b"', "3", "Medium"]
