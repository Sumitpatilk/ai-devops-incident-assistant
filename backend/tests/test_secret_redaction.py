import json
import pytest

from app.services.secret_redaction import redact_secrets


@pytest.mark.parametrize(
    ("source", "secret"),
    [
        ("Authorization: Bearer abc.def.ghi", "abc.def.ghi"),
        ("password=hunter2", "hunter2"),
        ('api_key="sample-secret-value"', "sample-secret-value"),
        ("AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF", "AKIA1234567890ABCDEF"),
        ("token=ghp_abcdefghijklmnopqrstuvwxyz123456", "ghp_abcdefghijklmnopqrstuvwxyz123456"),
        ("https://user:supersecret@example.com/path", "supersecret"),
    ],
)
def test_redacts_common_secrets(source, secret):
    result = redact_secrets(source)

    assert secret not in result
    assert "[REDACTED" in result


def test_redacts_private_key_block():
    source = (
        "key follows\n"
        "-----BEGIN PRIVATE KEY-----\n"
        "example-private-key-material\n"
        "-----END PRIVATE KEY-----\n"
        "startup failed"
    )

    result = redact_secrets(source)

    assert "example-private-key-material" not in result
    assert "[REDACTED_PRIVATE_KEY]" in result
    assert "startup failed" in result


def test_preserves_non_secret_diagnostic_evidence():
    source = "Container terminated: OOMKilled"

    assert redact_secrets(source) == source


def test_rejects_non_string_input():
    with pytest.raises(TypeError):
        redact_secrets(None)
@pytest.mark.parametrize(
    ("source", "secret"),
    [
        ("token=sample-token-123", "sample-token-123"),
        ('session_token="session-secret-456"', "session-secret-456"),
        ("credential: deployment-secret-789", "deployment-secret-789"),
        ("glpat-abcdefghijklmnopqrstuvwxyz1234",
         "glpat-abcdefghijklmnopqrstuvwxyz1234"),
        ("token=synthetic-provider-secret-1234567890",
         "synthetic-provider-secret-1234567890"),
    ],
)
def test_redacts_additional_secret_formats(source, secret):
    result = redact_secrets(source)

    assert secret not in result
    assert "[REDACTED" in result
def test_redacts_bearer_token_without_authorization_header():
    source = "request failed with Bearer abc.def.ghi"

    result = redact_secrets(source)

    assert "abc.def.ghi" not in result
    assert "[REDACTED]" in result
    assert "request failed" in result


def test_redacts_quoted_secret_with_spaces():
    source = 'password="my secret value"'

    result = redact_secrets(source)

    assert "my secret value" not in result
    assert "[REDACTED]" in result


def test_preserves_diagnostic_text_around_secret():
    source = "Deployment failed: token=sample-secret-123; reason=OOMKilled"

    result = redact_secrets(source)

    assert "sample-secret-123" not in result
    assert "Deployment failed" in result
    assert "OOMKilled" in result
def test_redacts_json_secret_and_preserves_diagnostic_evidence():
    source = (
        '{"token": "json-secret-123", '
        '"reason": "OOMKilled"}'
    )

    result = redact_secrets(source)

    assert "json-secret-123" not in result
    assert "OOMKilled" in result
def test_redacts_json_secret_and_preserves_valid_json():
    source = '{"token": "json-secret-123", "reason": "OOMKilled"}'

    result = redact_secrets(source)
    parsed = json.loads(result)

    assert parsed["token"] == "[REDACTED]"
    assert parsed["reason"] == "OOMKilled"
    assert "json-secret-123" not in result
