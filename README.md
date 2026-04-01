# soc-fusion-backend

Backend repository scaffold for the SoC Fusion platform.

## Layout

- `app/` contains API, connectors, normalization, fusion, database, services, scheduler, worker, core, schemas, and storage modules.
- `tests/` contains unit, integration, replay, and source fixture directories.
- `ops/` contains Docker-related operational assets and monitoring placeholders.
- `mitre/` contains MITRE ATT&CK sync, storage, and search code plus the local cache/database.

## Configuration

- Settings load from a repository-root `.env` file by default, or from `ENV_FILE` when it is set.
- Process environment variables override `.env` values, which lets secret managers or container runtime env injection take precedence.
- Critical startup settings are `DATABASE_URL`, `OTX_API_KEY`, `MISP_URL`, `MISP_API_KEY`, `ADMIN_AUTH_SECRET`, and either `RAW_STORAGE_PATH` or `RAW_STORAGE_BUCKET`.
- A demo [.env](e:/SoC_Threat/soc-fusion-backend/.env) is included for local scaffolding only. Replace those values before using the service outside development.

## Running

- Install dependencies from [requirements.txt](e:/SoC_Threat/soc-fusion-backend/requirements.txt).
- Start the API with `python app.py`.
- Use [base.http](e:/SoC_Threat/soc-fusion-backend/base.http) for local request examples.

## MITRE ATT&CK Data

- `POST /mitre/refresh` downloads the official ATT&CK STIX bundles for Enterprise, Mobile, and ICS and builds a local SQLite index.
- `GET /mitre/status` shows sync state, cached raw files, and indexed object counts.
- `GET /mitre/search?q=T1059` searches techniques, sub-techniques, mitigations, data sources, data components, detection strategies, analytics, and log sources.
- `GET /mitre/object?stix_id=...` returns the full indexed document for a search result.
- `python -m mitre sync` rebuilds the MITRE index from the command line.
- `python -m mitre search "powershell"` searches the local MITRE index from the command line.

## Status

This repository currently contains only the requested backend structure and starter files.

