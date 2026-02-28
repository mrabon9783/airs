# AIRS - Azure Identity Risk Scanner (Single Tenant MVP)

## Features
- Scans Entra applications and service principals for password/key credential expiry (expired/7/30/90).
- Optional stale service principal detection using `GET /beta/reports/servicePrincipalSignInActivities` controlled by `AIRS_USE_BETA_SIGNIN_ACTIVITY`.
- Hygiene findings: ownerless entities and entities without credentials.
- Stores metadata + derived fields only (no secrets or token values persisted).
- API endpoints:
  - `POST /scan/run`
  - `GET /scan/latest`
  - `GET /findings?severity=&category=&type=`
  - `GET /export/findings.csv`
- Basic web UI at `/`.

## Structure
- `src/Api`
- `src/Worker`
- `src/Shared`
- `infra/docker-compose.yml`
- `migrations/001_init.sql`

## One-command run
```bash
docker compose -f infra/docker-compose.yml up --build
```

## Configuration
Set these environment variables (examples in compose):
- `AIRS_TENANT_ID`
- `AIRS_CLIENT_ID`
- `AIRS_CLIENT_SECRET`
- `AIRS_USE_BETA_SIGNIN_ACTIVITY` (`true/false`)
- `AIRS_STALE_DAYS_THRESHOLD` (default 90)

## Tests
```bash
python -m pytest tests
```
