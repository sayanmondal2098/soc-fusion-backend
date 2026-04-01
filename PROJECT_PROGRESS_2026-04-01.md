# SoC Fusion Backend Progress Report and Handbook

Date: April 1, 2026
Project Snapshot Time: April 1, 2026 17:13:25 UTC
Document Purpose: This file is both a dated progress report and a working handbook for the current backend scaffold.

## 1. Executive Summary

As of April 1, 2026, the repository has moved from a bare scaffold to a working FastAPI-based backend entrypoint with a dedicated API layer and a functioning MITRE ATT&CK ingestion and search subsystem.

The project can now:
- Start through `python app.py`
- Expose HTTP endpoints through `api.py`
- Download official MITRE ATT&CK STIX bundles for Enterprise, Mobile, and ICS
- Store the raw ATT&CK data locally
- Normalize and index ATT&CK content into SQLite
- Search techniques, sub-techniques, mitigations, detection strategies, analytics, and log sources
- Return full indexed objects by internal STIX ID

This is still an early-stage backend. It is currently useful as a knowledge retrieval service and as a base for later SoC workflow features, but it is not yet a full production platform.

## 2. Current Repository State

Key active files and folders:
- `app.py`: launcher only; starts Uvicorn and hands off to the local virtual environment when needed
- `api.py`: owns the FastAPI application and all HTTP endpoints
- `mitre/service.py`: ATT&CK sync, normalization, indexing, local search, and CLI commands
- `mitre/__main__.py`: CLI entry for `python -m mitre ...`
- `mitre/data/raw/`: raw downloaded ATT&CK JSON bundles
- `mitre/data/attack.sqlite3`: local searchable ATT&CK database
- `README.md`: short repo overview and run instructions

Practical architecture today:
- `app.py` is the bootstrap and process runner
- `api.py` is the HTTP boundary layer between the app and internal modules
- `mitre/service.py` is the main business/data logic module currently implemented

## 3. What Has Been Completed

### 3.1 Server Bootstrapping

The project now supports direct startup using:

```powershell
python app.py
```

This was important because the base system Python in the workspace did not have `uvicorn` installed, while the project virtual environment already did. `app.py` now checks for that case and relaunches itself through `venv\Scripts\python.exe` when necessary.

Result:
- The user does not need to manually activate the virtual environment just to run the app from this repo.
- The startup command stays simple and stable.

### 3.2 API Layer Separation

A dedicated `api.py` file was created so endpoint definitions are not mixed with the process bootstrap.

Current responsibility split:
- `app.py`: startup only
- `api.py`: all current routes
- `mitre/service.py`: all MITRE data logic

This is a cleaner base for future expansion because new modules can be added behind `api.py` without turning `app.py` into a large monolith.

### 3.3 MITRE ATT&CK Ingestion

The project now pulls ATT&CK data from the official MITRE ATT&CK STIX bundle sources configured in code:
- Enterprise ATT&CK
- Mobile ATT&CK
- ICS ATT&CK

Raw files are cached locally in:
- `mitre/data/raw/enterprise-attack.json`
- `mitre/data/raw/mobile-attack.json`
- `mitre/data/raw/ics-attack.json`

This means the project stores a local copy after sync and does not need to depend on live browsing for every search request.

### 3.4 Local Searchable ATT&CK Database

The project builds a SQLite database at:

```text
mitre/data/attack.sqlite3
```

This database currently stores normalized searchable documents containing:
- Techniques
- Sub-techniques
- Mitigations
- Data components
- Detection strategies
- Analytics
- Log source records derived from ATT&CK log source definitions

The current indexed snapshot is:
- Total indexed documents: `6747`
- Techniques: `376`
- Sub-techniques: `522`
- Mitigations: `108`
- Detection strategies: `898`
- Analytics: `2032`
- Data components: `119`
- Log sources: `2692`

Raw cache status at the time of this report:
- `enterprise-attack.json`: `50,713,170` bytes
- `mobile-attack.json`: `4,924,785` bytes
- `ics-attack.json`: `3,491,940` bytes

### 3.5 Tactic Coverage

Tactics are currently captured from ATT&CK technique and sub-technique `kill_chain_phases` and included in each technique document and its searchable text.

Distinct tactic values confirmed in the current local index:
- `reconnaissance`
- `resource-development`
- `initial-access`
- `execution`
- `persistence`
- `privilege-escalation`
- `defense-evasion`
- `credential-access`
- `discovery`
- `lateral-movement`
- `collection`
- `command-and-control`
- `exfiltration`
- `impact`
- `evasion`
- `inhibit-response-function`
- `impair-process-control`

Important limitation:
- Tactics are searchable, but they are not yet stored as first-class standalone `tactic` objects in the database.
- A search for a tactic returns related techniques rather than a dedicated tactic record.

## 4. Current API Surface

All current endpoints are defined in `api.py`.

### 4.1 Health Endpoint

```http
GET /health
```

Purpose:
- Simple liveness check

Current response:

```json
{
  "status": "ok"
}
```

### 4.2 MITRE Status

```http
GET /mitre/status
```

Purpose:
- Returns whether the MITRE database exists and is populated
- Shows cached raw files
- Shows source URLs
- Shows document counts
- Shows last sync time

Use this first if MITRE search is not behaving as expected.

### 4.3 MITRE Refresh

```http
POST /mitre/refresh
```

Purpose:
- Downloads the current configured ATT&CK STIX bundles
- Rebuilds the SQLite index from scratch

Operational note:
- This is a synchronous request right now. The caller waits until download and reindex complete.

### 4.4 MITRE Search

```http
GET /mitre/search?q=<query>
```

Optional query parameters:
- `object_type`
- `domain`
- `limit`

Example requests:

```http
GET /mitre/search?q=T1059
GET /mitre/search?q=powershell
GET /mitre/search?q=process%20creation&object_type=log-source&limit=10
```

Purpose:
- Searches the local indexed ATT&CK content
- Supports ATT&CK IDs and free text
- Supports filtering by object type and domain

### 4.5 MITRE Object Lookup

```http
GET /mitre/object?stix_id=<stix_id>
```

Purpose:
- Returns the full stored document for a record found through search

This is useful when search results provide only summary information and the caller wants the full normalized object.

## 5. Command-Line Operations

The project also supports CLI use for the MITRE subsystem.

### 5.1 Rebuild the Index

```powershell
python -m mitre sync
```

What it does:
- Downloads ATT&CK bundles
- Updates raw JSON cache
- Rebuilds the SQLite index

### 5.2 Check Status

```powershell
python -m mitre status
```

What it does:
- Prints database and cache status
- Shows sync time and object counts

### 5.3 Search from CLI

```powershell
python -m mitre search T1059
python -m mitre search "process creation" --type log-source --limit 5
```

What it does:
- Searches the local index without going through HTTP

### 5.4 Show a Full Record

```powershell
python -m mitre show <stix_id>
```

What it does:
- Prints the full stored object JSON for one indexed record

## 6. How the MITRE Pipeline Works Today

The current MITRE flow is:

1. Download raw ATT&CK STIX bundles.
2. Save the bundles into `mitre/data/raw/`.
3. Parse ATT&CK STIX objects and relationships.
4. Normalize selected object types into local documents.
5. Build search text by flattening relevant fields.
6. Store documents and metadata into SQLite.
7. Serve search and object retrieval from the local database.

The current search implementation is simple and pragmatic:
- It uses SQLite with `LIKE` matching, not FTS yet.
- It computes a lightweight relevance score using attack ID, name, description, and search text.
- It is sufficient for a functional first version, but it is not yet optimized for very large-scale or precision-heavy search use cases.

## 7. Data Coverage Notes

The current indexed objects are broad enough for a first ATT&CK intelligence lookup layer, but they are not yet exhaustive in the sense of "every ATT&CK concept as its own first-class local object type."

Currently covered well:
- Techniques
- Sub-techniques
- Mitigations
- Detection strategies
- Analytics
- Log source details derived from ATT&CK data component log source references
- Technique detection text
- Tactic names attached to techniques

Currently not modeled as dedicated first-class objects:
- Tactics as standalone records
- ATT&CK groups/software/campaigns
- External citation records as searchable entities
- Custom SoC correlation logic
- User-defined tagging, notes, or curation layers

This means the system is already useful for ATT&CK-oriented search, but it is not yet a complete ATT&CK graph explorer.

## 8. Operational Handbook

### 8.1 Normal Local Startup

Recommended from the repo root:

```powershell
python app.py
```

Default behavior:
- Host: `0.0.0.0`
- Port: `8000`
- Reload: disabled unless explicitly enabled through environment variable

Optional environment variables:
- `HOST`
- `PORT`
- `RELOAD`

Example:

```powershell
$env:PORT = "8012"
python app.py
```

### 8.2 When Port 8000 Is Busy

If `8000` is already in use, set another port:

```powershell
$env:PORT = "8012"
python app.py
```

### 8.3 When System Python Lacks Dependencies

This repo already contains a local virtual environment. `app.py` attempts to relaunch itself through that virtual environment automatically if `uvicorn` is missing from the base interpreter.

If that handoff still fails, verify the venv exists here:

```text
venv\Scripts\python.exe
```

### 8.4 When MITRE Search Returns No Results

Check the current status first:

```powershell
python -m mitre status
```

If the database is empty or missing, rebuild it:

```powershell
python -m mitre sync
```

### 8.5 When Refresh Fails

Likely causes:
- No outbound network access
- Temporary GitHub raw content failure
- Interrupted local write
- SQLite write conflict or corruption

Recovery steps:
1. Run `python -m mitre status`
2. Re-run `python -m mitre sync`
3. If the database becomes inconsistent, delete `mitre/data/attack.sqlite3` and sync again

## 9. Known Limitations and Technical Debt

The current project has meaningful progress, but there are several gaps that should be treated as expected next work, not hidden defects.

### 9.1 Search Engine Simplicity

The current search uses flattened text and SQLite `LIKE` queries. This is serviceable for now, but it will become limiting when:
- query precision matters
- ranking quality matters
- response speed matters under heavier load
- advanced filters are needed

Recommended future upgrade:
- SQLite FTS5 or a dedicated search engine layer

### 9.2 API Design Still Minimal

The API is functional but thin. It currently lacks:
- pagination strategy beyond a simple `limit`
- authentication and authorization
- versioning
- structured error models
- background job handling for long refresh tasks
- request logging and observability hooks

### 9.3 No Automated Test Suite Yet

There is no meaningful automated test coverage for:
- MITRE sync behavior
- normalization rules
- search ranking expectations
- API endpoint behavior
- bootstrap handoff behavior in `app.py`

This is the biggest engineering gap right now.

### 9.4 Windows-Oriented Bootstrap Assumption

`app.py` currently assumes a Windows virtual environment layout:
- `venv\Scripts\python.exe`

That is acceptable for the current workspace but should be generalized before cross-platform use.

### 9.5 ATT&CK Object Coverage Is Focused, Not Complete

The current data model does not yet ingest every ATT&CK object family that may be useful for a mature SoC knowledge service.

Examples of likely future additions:
- threat groups
- malware/software
- campaigns
- relationships between groups and techniques
- richer ATT&CK graph traversal APIs

## 10. Recommended Next Milestones

These are the next high-value steps in a sensible order.

### Milestone 1: Stabilize the Existing Base

Recommended work:
- add unit tests for `mitre/service.py`
- add API tests for `api.py`
- add basic error and response schemas
- clean up stale generated files such as obsolete `__pycache__` artifacts before commit

Reason:
- The code now does enough real work that regression risk has become non-trivial.

### Milestone 2: Improve Search Quality

Recommended work:
- add first-class tactic records
- add better ranking
- add ATT&CK group and software coverage
- move from raw `LIKE` search to FTS or a stronger search backend

Reason:
- The current system is useful, but its retrieval model is still shallow.

### Milestone 3: Move Toward SoC Workflows

Recommended work:
- add ingestion for detection content from other sources
- map ATT&CK data to detection use cases
- introduce tagging, notes, saved searches, and enrichment layers
- support analyst workflows rather than only raw reference lookup

Reason:
- This is where the project becomes a true SoC fusion backend rather than an ATT&CK cache/search service.

## 11. Suggested Commit or Milestone Summary

If this progress were summarized as a milestone, it would read like this:

"Established the backend runtime entrypoint, separated API routing into `api.py`, and implemented a working local MITRE ATT&CK ingestion and search subsystem backed by SQLite. The project can now sync official ATT&CK bundles, persist raw and normalized data, and serve searchable ATT&CK content through HTTP and CLI interfaces."

## 12. Final Assessment

The project is now at a meaningful foundation stage.

What is strong right now:
- clear startup path
- clean separation between launcher, API layer, and ATT&CK service logic
- working local MITRE data sync
- working searchable local index
- practical utility already present

What is still missing before this should be called mature:
- tests
- broader domain modeling
- stronger search implementation
- auth, validation, and observability
- more backend modules beyond MITRE knowledge retrieval

As of April 1, 2026, this repository should be treated as an early but functional backend foundation with one real service domain implemented well enough to build on.
