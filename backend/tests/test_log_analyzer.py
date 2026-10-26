import pytest

from app.services.log_analyzer import analyze_log


def test_detects_kubernetes_image_pull_error():
    result = analyze_log(
        "kubernetes",
        "Warning: ErrImagePull",
    )

    assert result["status"] == "findings"
    assert result["findings"][0]["rule_id"] == (
        "K8S_IMAGE_PULL_FAILURE"
    )


def test_detects_oom_killed():
    result = analyze_log(
        "kubernetes",
        "Last termination reason: OOMKilled",
    )

    assert result["status"] == "findings"
    assert any(
        item["rule_id"] == "K8S_OOM_KILLED"
        for item in result["findings"]
    )


def test_detects_docker_build_failure():
    result = analyze_log(
        "docker",
        "failed to compute cache key",
    )

    assert result["status"] == "findings"
    assert result["findings"][0]["rule_id"] == (
        "DOCKER_BUILD_FAILURE"
    )


def test_detects_ci_test_failure():
    result = analyze_log(
        "github-actions",
        "AssertionError: expected 200, got 500",
    )

    assert result["status"] == "findings"


def test_unknown_error_returns_no_match():
    result = analyze_log(
        "docker",
        "Build completed successfully",
    )

    assert result["status"] == "no_match"
    assert result["findings"] == []


def test_rejects_unknown_source():
    with pytest.raises(ValueError):
        analyze_log("jenkins", "Some error")


def test_rejects_empty_logs():
    with pytest.raises(ValueError):
        analyze_log("docker", "   ")
