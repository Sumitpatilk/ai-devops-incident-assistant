# AI DevOps Incident Assistant

A local-first DevOps troubleshooting assistant that investigates failures across GitHub Actions, Docker, and Kubernetes.

## Initial Goals

- Analyze DevOps logs using a rule-based engine.
- Present possible causes with supporting evidence.
- Store incidents and verified fixes locally.
- Compare new incidents with historical incidents.
- Verify selected fixes in an isolated Docker test environment.
- Optionally use a local language model for explanations.

## Technology Stack

- Frontend: React, Vite, TypeScript
- Backend: Python, FastAPI
- Database: SQLite
- Testing: Pytest
- Containers: Docker
- Optional local AI: Ollama

## Safety Principles

- Do not automatically modify production systems.
- Redact secrets from logs.
- Distinguish evidence from AI-generated hypotheses.
- Run verification tests in a restricted environment.

## Development Status

Phase 1 — Project setup in progress.