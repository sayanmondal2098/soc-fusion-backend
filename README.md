# soc-fusion-backend

Backend repository scaffold for the SoC Fusion platform.

## Layout

- `app/` contains API, connectors, normalization, fusion, database, services, scheduler, worker, core, schemas, and storage modules.
- `tests/` contains unit, integration, replay, and source fixture directories.
- `ops/` contains Docker-related operational assets and monitoring placeholders.

## Configuration

- Settings load from a repository-root `.env` file by default, or from `ENV_FILE` when it is set.
- Process environment variables override `.env` values, which lets secret managers or container runtime env injection take precedence.
- Critical startup settings are `DATABASE_URL`, `OTX_API_KEY`, `MISP_URL`, `MISP_API_KEY`, `ADMIN_AUTH_SECRET`, and either `RAW_STORAGE_PATH` or `RAW_STORAGE_BUCKET`.
- A demo [.env](e:/SoC_Threat/soc-fusion-backend/.env) is included for local scaffolding only. Replace those values before using the service outside development.

## Running

- Install dependencies from [requirements.txt](e:/SoC_Threat/soc-fusion-backend/requirements.txt).
- Start the API with `uvicorn api:app --reload`.
- Use [base.http](e:/SoC_Threat/soc-fusion-backend/base.http) for local request examples.

## Status

This repository currently contains only the requested backend structure and starter files.
