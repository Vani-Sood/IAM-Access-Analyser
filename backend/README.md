# Backend — IAM Policy Analyzer

FastAPI backend. Runs inside Docker Compose; see root `README.md` for quick start.

## Environment variables

Copy `.env.example` to `.env` and fill in the required values before starting.

### Core (required)

| Variable | Description | Example |
|---|---|---|
| `SECRET_KEY` | Django / session secret (min 32 chars) | `openssl rand -hex 32` |
| `JWT_SECRET` | JWT signing secret (min 32 chars) | `openssl rand -hex 32` |
| `DATABASE_URL` | SQLAlchemy async URL | `postgresql+asyncpg://user:pass@db:5432/iam` |
| `REDIS_URL` | Celery broker + result backend | `redis://redis:6379/0` |
| `NEO4J_URI` | Neo4j bolt URI | `bolt://neo4j:7687` |
| `NEO4J_USER` | Neo4j username | `neo4j` |
| `NEO4J_PASSWORD` | Neo4j password | — |
| `GEMINI_API_KEY` | Google Gemini API key for AI suggestions | — |
| `GEMINI_MODEL` | Gemini model name | `gemini-2.5-flash-lite` |

### Rate limiting

| Variable | Default | Description |
|---|---|---|
| `RATE_LIMIT_PER_HOUR` | `1000` | Requests per user per hour |

### AWS live scanner (optional)

Required only when `cloud=aws` is passed to `POST /api/v1/analyze`.

| Variable | Description |
|---|---|
| `AWS_ROLE_ARN` | IAM role ARN to assume for scanning |
| `AWS_REGION` | AWS region (e.g. `us-east-1`) |
| `AWS_ACCESS_KEY_ID` | Static credentials (dev/CI only) |
| `AWS_SECRET_ACCESS_KEY` | Static credentials (dev/CI only) |

### Azure live scanner (optional)

Required only when `cloud=azure` is passed to `POST /api/v1/analyze`.
Create a service principal with `Reader` + `User Access Administrator` roles on the target subscription.

| Variable | Description | Example |
|---|---|---|
| `AZURE_TENANT_ID` | Azure AD tenant GUID | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` |
| `AZURE_CLIENT_ID` | Service principal application (client) ID | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` |
| `AZURE_CLIENT_SECRET` | Service principal client secret | — |
| `AZURE_SUBSCRIPTION_ID` | Subscription to scan | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` |

### GCP live scanner (optional)

Required only when `cloud=gcp` is passed to `POST /api/v1/analyze`.
The service account needs `roles/iam.securityReviewer` on the target project/folder/org.

| Variable | Description |
|---|---|
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to service-account JSON key file |
| `GOOGLE_APPLICATION_CREDENTIALS_JSON` | Inline JSON key (alternative to path-based) |
| `GCP_PROJECT_ID` | GCP project to scan |

> Only one of `GOOGLE_APPLICATION_CREDENTIALS` or `GOOGLE_APPLICATION_CREDENTIALS_JSON` is required.

## Running tests

```bash
# From repo root
make test

# Or directly inside the container
docker compose exec backend pytest -v

# From backend/ directory (outside Docker)
cd backend
python -m pytest -v
```

## API reference

Interactive docs available at `http://localhost:8000/docs` when the container is running.
