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
- LLM settings support both Gemini and OpenAI-compatible providers.
- Generic settings are `LLM_PROVIDER`, `LLM_API_KEY`, `LLM_BASE_URL`, `LLM_MODEL`, `LLM_TEMPERATURE`, and `LLM_MAX_OUTPUT_TOKENS`.
- Gemini settings are `GEMINI_API_KEY`, `GEMINI_MODEL`, `GEMINI_TEMPERATURE`, and `GEMINI_MAX_OUTPUT_TOKENS`.
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

## LLM Support

- `POST /llm/generate` sends a prompt to the configured provider and returns generated text.
- Default request body: `{"prompt": "Summarize T1059 in one paragraph."}`
- Optional fields for `/llm/generate`:
	- `system_prompt`: override the default prompt defined in `utils/prompt.py` for this request.
	- `prompt_file`: load prompt text from a file path on disk.
- `GET /llm/settings` returns resolved provider/model settings and default prompt module status.
- Provider resolution order:
	- `LLM_PROVIDER` when explicitly set.
	- OpenAI-compatible if both `LLM_API_KEY` and `LLM_MODEL` are set.
	- Gemini if `GEMINI_API_KEY` is set.

## Status

This repository currently contains only the requested backend structure and starter files.


