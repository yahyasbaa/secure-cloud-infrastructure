from sci_app.auth import extract_bearer, token_is_valid


def test_extract_bearer():
    assert extract_bearer("Bearer abc") == "abc"
    assert extract_bearer("bearer abc") == "abc"
    assert extract_bearer("Basic abc") is None
    assert extract_bearer("Bearer ") is None
    assert extract_bearer(None) is None
    assert extract_bearer("Bearer " + "x" * 600) is None


def test_token_validation():
    assert token_is_valid("a" * 40, ["a" * 40])
    assert token_is_valid("b" * 40, ["a" * 40, "b" * 40])  # previous token during rotation grace
    assert not token_is_valid("c" * 40, ["a" * 40, "b" * 40])
    assert not token_is_valid(None, ["a" * 40])
    assert not token_is_valid("", [""])
    assert not token_is_valid("a" * 40, [])
