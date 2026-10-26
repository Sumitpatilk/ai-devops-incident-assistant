RULES = [
    {
        "id": "K8S_IMAGE_PULL_FAILURE",
        "source": "kubernetes",
        "patterns": [
            "ImagePullBackOff",
            "ErrImagePull",
            "manifest unknown",
        ],
        "possible_cause": (
            "The container image may be missing, "
            "incorrectly tagged, or inaccessible."
        ),
        "recommended_checks": [
            "Verify the image repository and tag.",
            "Confirm the image exists in the registry.",
            "Check image pull credentials and permissions.",
        ],
    },
    {
        "id": "K8S_CRASH_LOOP",
        "source": "kubernetes",
        "patterns": [
            "CrashLoopBackOff",
        ],
        "possible_cause": (
            "The container may be exiting repeatedly."
        ),
        "recommended_checks": [
            "Inspect current and previous container logs.",
            "Check the container exit code.",
            "Review startup configuration and dependencies.",
        ],
    },
    {
        "id": "K8S_OOM_KILLED",
        "source": "kubernetes",
        "patterns": [
            "OOMKilled",
        ],
        "possible_cause": (
            "The container was terminated due to memory pressure."
        ),
        "recommended_checks": [
            "Inspect container memory usage.",
            "Review memory requests and limits.",
            "Investigate possible memory leaks.",
        ],
    },
    {
        "id": "DOCKER_BUILD_FAILURE",
        "source": "docker",
        "patterns": [
            "failed to solve",
            "failed to compute cache key",
            "no such file or directory",
        ],
        "possible_cause": (
            "The Docker build may reference a missing file "
            "or encounter a build-stage error."
        ),
        "recommended_checks": [
            "Inspect the first failing Docker build step.",
            "Verify COPY paths and build context.",
            "Check the Dockerfile and required files.",
        ],
    },
    {
        "id": "CI_TEST_FAILURE",
        "source": "github-actions",
        "patterns": [
            "AssertionError",
            "Error: Process completed with exit code 1",
            "npm ERR!",
        ],
        "possible_cause": (
            "A CI command, test, or dependency operation failed."
        ),
        "recommended_checks": [
            "Find the first meaningful error in the workflow log.",
            "Reproduce the failing command locally.",
            "Review dependencies and recent code changes.",
        ],
    },
    {
        "id": "PERMISSION_FAILURE",
        "source": "all",
        "patterns": [
            "permission denied",
            "access denied",
        ],
        "possible_cause": (
            "The operation may lack the required permissions."
        ),
        "recommended_checks": [
            "Identify which user or service account ran the operation.",
            "Inspect the affected resource permissions.",
            "Check least-privilege access policies.",
        ],
    },
]
