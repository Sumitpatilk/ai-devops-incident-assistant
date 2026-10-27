# AI DevOps Incident Assistant

A local-first DevOps troubleshooting assistant for GitHub Actions, Docker, and Kubernetes.

## Current Status

- FastAPI backend and React frontend implemented.
- Rule-based log analysis and incident management APIs implemented.
- Backend tests: 17 passing in the current development environment.
- Frontend lint: passing with zero warnings and errors.
- Frontend production build: passing.
- End-to-end and additional security validation are still in progress.

## Technology Stack

- Frontend: React, Vite, TypeScript
- Backend: Python, FastAPI
- Database: SQLite
- Testing: Pytest
- Containers: Docker, Docker Compose
- Optional future integration: Ollama

## Features

- Analyze GitHub Actions, Docker, and Kubernetes logs.
- Detect known failure patterns using rule-based analysis.
- Store and retrieve incidents using SQLite.
- Record fix descriptions and verification results.
- Browse incident history in the web interface.

## Run with Docker Compose

Prerequisites:
- Docker Engine or Docker Desktop with Docker Compose.
- Git, if cloning this repository.

From the project root, create the required external Docker volume if it does not already exist:

```bash
docker volume create incident-assistant-db-data
```

Start the application:

```bash
docker compose up --build -d
docker compose ps
docker compose logs --tail=100
```

Open the frontend:

- Application: http://localhost:8080
- Health check: http://localhost:8080/health

The backend listens on port 8000 inside the Docker network. Its host port is intentionally not published. API requests are accessed through the frontend's Nginx proxy. The FastAPI `/docs` interface is not exposed by the current Nginx configuration.

Stop the containers:

```bash
docker compose down
```

The database is stored in the external Docker volume `incident-assistant-db-data`. Stopping the containers with `docker compose down` preserves this volume. **Do not run `docker compose down -v`** if you want to preserve the database.

On a fresh installation, the application initializes the SQLite database tables automatically.

## Run Tests

Run the backend tests from the project root using the Python virtual environment configured for this project:

```bash
cd backend
source .venv/bin/activate
python -m pytest tests/ -v
```

Run frontend checks:

```bash
cd frontend
npm ci
npm run lint
npm run build
```

## API Endpoints

These endpoints are available through the frontend proxy at `http://localhost:8080`.

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Health check |
| POST | `/api/v1/analyze` | Analyze logs |
| POST | `/api/v1/incidents` | Create an incident |
| GET | `/api/v1/incidents` | List incidents |
| GET | `/api/v1/incidents/{incident_id}` | Retrieve an incident |
| POST | `/api/v1/incidents/{incident_id}/verification` | Record verification |
| PUT | `/api/v1/incidents/{incident_id}/fix` | Update fix description |

## Safety

- Treat findings as diagnostic suggestions, not guaranteed fixes.
- Do not submit secrets or sensitive production logs.
- Do not automatically modify production systems.
- Verify proposed fixes in a controlled environment.

## Remaining Work

- [ ] Complete end-to-end UI testing.
- [ ] Validate database persistence across container restarts.
- [ ] Review secret redaction and security controls.
- [ ] Validate isolated fix-verification workflows.
- [ ] Confirm CI automation.
- [ ] Complete final code and configuration review.
- [ ] Publish the reviewed project to GitHub.

This project is under active development; passing tests do not by themselves establish production readiness.
