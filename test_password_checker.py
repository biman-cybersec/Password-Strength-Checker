import pytest

from password_checker import (
    check_password, check_file, has_sequence, has_repeat, label_for,
)


@pytest.mark.parametrize("password, score, label", [
    ("", 0, "Low"),
    ("password", 0, "Low"),
    ("12345678", 0, "Low"),
    ("abc", 1, "Low"),
    ("aaaaaaaa", 1, "Low"),
    ("abcd1234", 2, "Medium"),
    ("Summer2024", 4, "Moderate"),
    ("Qwerty123!", 4, "Moderate"),
    ("Tr0ub4dor&3", 5, "Strong"),
    ("Xk9$mP2#vL7@qR4!", 6, "Strong"),
    ("correct-Horse-battery-staple-9!", 6, "Strong"),
])
def test_known_passwords(password, score, label):
    result = check_password(password)
    assert result["score"] == score
    assert result["label"] == label


def test_common_password_is_case_insensitive():
    assert check_password("PASSWORD")["score"] == 0


def test_sequence_detection():
    assert has_sequence("xxabcdxx")
    assert has_sequence("4321")
    assert has_sequence("QWERty")
    assert not has_sequence("a1b2c3")


def test_repeat_detection():
    assert has_repeat("heyyyy")
    assert not has_repeat("hello")


@pytest.mark.parametrize("score, label", [
    (0, "Low"), (1, "Low"), (2, "Medium"), (3, "Medium"),
    (4, "Moderate"), (5, "Strong"), (6, "Strong"),
])
def test_label_boundaries(score, label):
    assert label_for(score) == label


def test_feedback_is_given_for_weak_password():
    assert len(check_password("abc")["feedback"]) > 0


def test_strong_password_has_no_feedback():
    assert check_password("Xk9$mP2#vL7@qR4!")["feedback"] == []


def test_check_file_skips_blank_lines(tmp_path):
    f = tmp_path / "pw.txt"
    f.write_text("password\n\n  \nXk9$mP2#vL7@qR4!\n", encoding="utf-8")
    results = check_file(str(f))
    assert [r["password"] for r in results] == ["password", "Xk9$mP2#vL7@qR4!"]
    assert [r["label"] for r in results] == ["Low", "Strong"]

