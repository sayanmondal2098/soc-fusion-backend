from __future__ import annotations

import argparse
import json
import re
import sqlite3
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
RAW_DIR = DATA_DIR / "raw"
DB_PATH = DATA_DIR / "attack.sqlite3"

ATTACK_BUNDLE_URLS = {
    "enterprise-attack": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    "mobile-attack": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json",
    "ics-attack": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json",
}

SUPPORTED_STIX_TYPES = {
    "attack-pattern",
    "course-of-action",
    "x-mitre-data-source",
    "x-mitre-data-component",
    "x-mitre-detection-strategy",
    "x-mitre-analytic",
}

OBJECT_TYPE_MAP = {
    "course-of-action": "mitigation",
    "x-mitre-data-source": "data-source",
    "x-mitre-data-component": "data-component",
    "x-mitre-detection-strategy": "detection-strategy",
    "x-mitre-analytic": "analytic",
}


class DatabaseNotReadyError(RuntimeError):
    """Raised when the MITRE search database has not been built yet."""


def ensure_storage_dirs() -> None:
    RAW_DIR.mkdir(parents=True, exist_ok=True)


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def is_active_attack_object(obj: dict[str, Any]) -> bool:
    return not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False)


def normalize_domain_list(obj: dict[str, Any], fallback_domain: str) -> list[str]:
    domains = set(obj.get("x_mitre_domains", []))
    if fallback_domain:
        domains.add(fallback_domain)
    return sorted(domain for domain in domains if domain)


def merge_attack_object(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    merged = dict(existing)

    for key, value in incoming.items():
        if key in {"x_mitre_domains", "x_mitre_platforms"}:
            merged[key] = sorted(set(existing.get(key, [])) | set(value or []))
            continue

        if key not in merged or merged[key] in (None, "", [], {}):
            merged[key] = value

    return merged


def extract_attack_id(obj: dict[str, Any]) -> str | None:
    for reference in obj.get("external_references", []):
        external_id = reference.get("external_id")
        if external_id:
            return external_id
    return None


def extract_external_url(obj: dict[str, Any]) -> str | None:
    for reference in obj.get("external_references", []):
        url = reference.get("url")
        if url:
            return url
    return None


def normalize_object_type(obj: dict[str, Any]) -> str:
    if obj.get("type") == "attack-pattern":
        return "sub-technique" if obj.get("x_mitre_is_subtechnique") else "technique"

    return OBJECT_TYPE_MAP.get(obj.get("type"), obj.get("type", "unknown"))


def object_summary(obj: dict[str, Any]) -> dict[str, Any]:
    return {
        "stix_id": obj["id"],
        "attack_id": extract_attack_id(obj),
        "name": obj.get("name", ""),
        "object_type": normalize_object_type(obj),
        "url": extract_external_url(obj),
    }


def unique_sorted_summaries(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[str, dict[str, Any]] = {}
    for item in items:
        key = item.get("stix_id") or json.dumps(item, sort_keys=True)
        deduped[key] = item

    return sorted(
        deduped.values(),
        key=lambda item: (
            item.get("attack_id") or "",
            item.get("name") or "",
            item.get("stix_id") or "",
        ),
    )


def flatten_search_text(*values: Any) -> str:
    parts: list[str] = []

    def visit(value: Any) -> None:
        if value is None:
            return
        if isinstance(value, str):
            stripped = value.strip()
            if stripped:
                parts.append(stripped)
            return
        if isinstance(value, dict):
            for nested in value.values():
                visit(nested)
            return
        if isinstance(value, (list, tuple, set)):
            for nested in value:
                visit(nested)
            return
        parts.append(str(value))

    for item in values:
        visit(item)

    return " ".join(parts)


def create_log_source_id(data_component_id: str, name: str, channel: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", f"{name}-{channel}".lower()).strip("-")
    return f"{data_component_id}:log-source:{slug}"


def fetch_json(url: str) -> tuple[bytes, dict[str, Any]]:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "soc-fusion-backend-mitre-sync/1.0",
            "Accept": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            payload = response.read()
    except urllib.error.URLError as exc:
        raise RuntimeError(f"failed to download MITRE ATT&CK data from {url}: {exc}") from exc

    try:
        return payload, json.loads(payload.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"received invalid JSON from {url}: {exc}") from exc


def open_connection() -> sqlite3.Connection:
    ensure_storage_dirs()
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS documents (
            stix_id TEXT PRIMARY KEY,
            attack_id TEXT,
            name TEXT NOT NULL,
            object_type TEXT NOT NULL,
            domains_json TEXT NOT NULL,
            domains_text TEXT NOT NULL,
            url TEXT,
            description TEXT,
            search_text TEXT NOT NULL,
            raw_json TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_documents_attack_id ON documents(attack_id);
        CREATE INDEX IF NOT EXISTS idx_documents_object_type ON documents(object_type);
        CREATE INDEX IF NOT EXISTS idx_documents_name ON documents(name);

        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        """
    )
    connection.commit()


def database_ready() -> bool:
    if not DB_PATH.exists():
        return False

    with open_connection() as connection:
        initialize_database(connection)
        row = connection.execute("SELECT COUNT(*) AS count FROM documents").fetchone()
        return bool(row and row["count"] > 0)


def require_database() -> None:
    if not database_ready():
        raise DatabaseNotReadyError(
            "MITRE database is empty. Call POST /mitre/refresh or run `python -m mitre sync` first."
        )


def write_documents(documents: list[dict[str, Any]], metadata: dict[str, Any]) -> None:
    with open_connection() as connection:
        initialize_database(connection)
        connection.execute("DELETE FROM documents")
        connection.execute("DELETE FROM metadata")
        connection.executemany(
            """
            INSERT INTO documents (
                stix_id,
                attack_id,
                name,
                object_type,
                domains_json,
                domains_text,
                url,
                description,
                search_text,
                raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    document["stix_id"],
                    document.get("attack_id"),
                    document["name"],
                    document["object_type"],
                    json.dumps(document.get("domains", []), ensure_ascii=True),
                    " ".join(document.get("domains", [])),
                    document.get("url"),
                    document.get("description", ""),
                    document["search_text"],
                    json.dumps(document, ensure_ascii=True),
                )
                for document in documents
            ],
        )
        connection.executemany(
            "INSERT INTO metadata (key, value) VALUES (?, ?)",
            [(key, json.dumps(value, ensure_ascii=True)) for key, value in metadata.items()],
        )
        connection.commit()

def build_documents(bundles: dict[str, dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    objects: dict[str, dict[str, Any]] = {}
    relationships: list[dict[str, Any]] = []

    for fallback_domain, bundle in bundles.items():
        for item in bundle.get("objects", []):
            item_type = item.get("type")

            if item_type == "relationship":
                if is_active_attack_object(item):
                    relationships.append(item)
                continue

            if item_type not in SUPPORTED_STIX_TYPES or not is_active_attack_object(item):
                continue

            normalized = dict(item)
            normalized["x_mitre_domains"] = normalize_domain_list(normalized, fallback_domain)

            existing = objects.get(normalized["id"])
            objects[normalized["id"]] = (
                merge_attack_object(existing, normalized) if existing else normalized
            )

    parent_by_child: dict[str, str] = {}
    children_by_parent: dict[str, set[str]] = defaultdict(set)
    mitigations_by_technique: dict[str, set[str]] = defaultdict(set)
    techniques_by_mitigation: dict[str, set[str]] = defaultdict(set)
    detections_by_technique: dict[str, set[str]] = defaultdict(set)
    techniques_by_detector: dict[str, set[str]] = defaultdict(set)
    components_by_source: dict[str, set[str]] = defaultdict(set)
    source_by_component: dict[str, str] = {}
    strategies_by_analytic: dict[str, set[str]] = defaultdict(set)
    analytics_by_strategy: dict[str, set[str]] = defaultdict(set)

    for stix_id, obj in objects.items():
        if obj.get("type") == "x-mitre-data-component":
            source_ref = obj.get("x_mitre_data_source_ref")
            if source_ref and source_ref in objects:
                source_by_component[stix_id] = source_ref
                components_by_source[source_ref].add(stix_id)

        if obj.get("type") == "x-mitre-detection-strategy":
            for analytic_ref in obj.get("x_mitre_analytic_refs", []):
                if analytic_ref in objects:
                    analytics_by_strategy[stix_id].add(analytic_ref)
                    strategies_by_analytic[analytic_ref].add(stix_id)

    for relationship in relationships:
        source_ref = relationship.get("source_ref")
        target_ref = relationship.get("target_ref")
        relationship_type = relationship.get("relationship_type")

        if source_ref not in objects or target_ref not in objects:
            continue

        if relationship_type == "subtechnique-of":
            parent_by_child[source_ref] = target_ref
            children_by_parent[target_ref].add(source_ref)
        elif relationship_type == "mitigates":
            mitigations_by_technique[target_ref].add(source_ref)
            techniques_by_mitigation[source_ref].add(target_ref)
        elif relationship_type == "detects":
            detections_by_technique[target_ref].add(source_ref)
            techniques_by_detector[source_ref].add(target_ref)

    log_source_documents: list[dict[str, Any]] = []

    for component_id, component in objects.items():
        if component.get("type") != "x-mitre-data-component":
            continue

        for log_source in component.get("x_mitre_log_sources", []) or []:
            name = log_source.get("name")
            channel = log_source.get("channel")
            if not name or not channel:
                continue

            source_summary = None
            source_ref = source_by_component.get(component_id)
            if source_ref and source_ref in objects:
                source_summary = object_summary(objects[source_ref])

            document = {
                "stix_id": create_log_source_id(component_id, name, channel),
                "attack_id": None,
                "name": f"{name} [{channel}]",
                "object_type": "log-source",
                "domains": component.get("x_mitre_domains", []),
                "url": None,
                "description": component.get("description", ""),
                "log_source_name": name,
                "channel": channel,
                "data_component": object_summary(component),
                "data_source": source_summary,
                "raw": {
                    "log_source": log_source,
                    "data_component_id": component_id,
                    "data_source_id": source_ref,
                },
            }
            document["search_text"] = flatten_search_text(document, document["raw"])
            log_source_documents.append(document)

    documents: list[dict[str, Any]] = []

    for stix_id, obj in sorted(objects.items(), key=lambda item: (item[1].get("name", ""), item[0])):
        attack_id = extract_attack_id(obj)
        common = {
            "stix_id": stix_id,
            "attack_id": attack_id,
            "name": obj.get("name", ""),
            "object_type": normalize_object_type(obj),
            "domains": obj.get("x_mitre_domains", []),
            "url": extract_external_url(obj),
            "description": obj.get("description", ""),
            "raw": obj,
        }

        if obj.get("type") == "attack-pattern":
            document = {
                **common,
                "platforms": obj.get("x_mitre_platforms", []),
                "tactics": [
                    phase.get("phase_name")
                    for phase in obj.get("kill_chain_phases", [])
                    if phase.get("phase_name")
                ],
                "detection_text": obj.get("x_mitre_detection", ""),
                "legacy_data_sources": obj.get("x_mitre_data_sources", []),
                "parent": object_summary(objects[parent_by_child[stix_id]])
                if stix_id in parent_by_child and parent_by_child[stix_id] in objects
                else None,
                "children": unique_sorted_summaries(
                    [object_summary(objects[item_id]) for item_id in children_by_parent.get(stix_id, set())]
                ),
                "mitigations": unique_sorted_summaries(
                    [object_summary(objects[item_id]) for item_id in mitigations_by_technique.get(stix_id, set())]
                ),
                "detections": unique_sorted_summaries(
                    [object_summary(objects[item_id]) for item_id in detections_by_technique.get(stix_id, set())]
                ),
            }
        elif obj.get("type") == "course-of-action":
            document = {
                **common,
                "techniques": unique_sorted_summaries(
                    [object_summary(objects[item_id]) for item_id in techniques_by_mitigation.get(stix_id, set())]
                ),
            }
        elif obj.get("type") == "x-mitre-data-source":
            document = {
                **common,
                "platforms": obj.get("x_mitre_platforms", []),
                "collection_layers": obj.get("x_mitre_collection_layers", []),
                "data_components": unique_sorted_summaries(
                    [object_summary(objects[item_id]) for item_id in components_by_source.get(stix_id, set())]
                ),
            }
        elif obj.get("type") == "x-mitre-data-component":
            source_summary = None
            source_ref = source_by_component.get(stix_id)
            if source_ref and source_ref in objects:
                source_summary = object_summary(objects[source_ref])

            document = {
                **common,
                "platforms": obj.get("x_mitre_platforms", []),
                "data_source": source_summary,
                "log_sources": obj.get("x_mitre_log_sources", []),
                "techniques": unique_sorted_summaries(
                    [object_summary(objects[item_id]) for item_id in techniques_by_detector.get(stix_id, set())]
                ),
            }
        elif obj.get("type") == "x-mitre-detection-strategy":
            document = {
                **common,
                "techniques": unique_sorted_summaries(
                    [object_summary(objects[item_id]) for item_id in techniques_by_detector.get(stix_id, set())]
                ),
                "analytics": unique_sorted_summaries(
                    [object_summary(objects[item_id]) for item_id in analytics_by_strategy.get(stix_id, set())]
                ),
            }
        elif obj.get("type") == "x-mitre-analytic":
            document = {
                **common,
                "detection_strategies": unique_sorted_summaries(
                    [object_summary(objects[item_id]) for item_id in strategies_by_analytic.get(stix_id, set())]
                ),
                "log_source_references": obj.get("x_mitre_log_source_references", []),
            }
        else:
            document = common

        document["search_text"] = flatten_search_text(document, obj)
        documents.append(document)

    documents.extend(log_source_documents)

    deduped_documents: dict[str, dict[str, Any]] = {}
    for document in documents:
        deduped_documents[document["stix_id"]] = document

    counts: dict[str, int] = defaultdict(int)
    for document in deduped_documents.values():
        counts[document["object_type"]] += 1

    return list(deduped_documents.values()), dict(sorted(counts.items()))

def sync_attack_content() -> dict[str, Any]:
    ensure_storage_dirs()

    bundles: dict[str, dict[str, Any]] = {}
    raw_files: dict[str, str] = {}

    for domain, url in ATTACK_BUNDLE_URLS.items():
        payload_bytes, bundle = fetch_json(url)
        raw_path = RAW_DIR / f"{domain}.json"
        raw_path.write_bytes(payload_bytes)
        bundles[domain] = bundle
        raw_files[domain] = str(raw_path)

    documents, counts = build_documents(bundles)
    synced_at = now_iso()

    metadata = {
        "synced_at": synced_at,
        "source_urls": ATTACK_BUNDLE_URLS,
        "counts": counts,
        "document_count": len(documents),
        "raw_files": raw_files,
    }
    write_documents(documents, metadata)

    return {
        "status": "ok",
        "synced_at": synced_at,
        "documents_indexed": len(documents),
        "counts": counts,
        "raw_files": raw_files,
    }


def get_attack_status() -> dict[str, Any]:
    ensure_storage_dirs()

    raw_cache = {
        path.name: {
            "path": str(path),
            "size_bytes": path.stat().st_size,
            "modified_at": datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
            .replace(microsecond=0)
            .isoformat(),
        }
        for path in sorted(RAW_DIR.glob("*.json"))
    }

    status: dict[str, Any] = {
        "database_ready": database_ready(),
        "database_path": str(DB_PATH),
        "raw_cache": raw_cache,
        "source_urls": ATTACK_BUNDLE_URLS,
    }

    if not DB_PATH.exists():
        return status

    with open_connection() as connection:
        initialize_database(connection)
        counts = {
            row["object_type"]: row["count"]
            for row in connection.execute(
                "SELECT object_type, COUNT(*) AS count FROM documents GROUP BY object_type ORDER BY object_type"
            )
        }
        metadata_rows = connection.execute("SELECT key, value FROM metadata").fetchall()

    status["counts"] = counts
    for row in metadata_rows:
        status[row["key"]] = json.loads(row["value"])

    return status


def search_attack_content(
    query: str,
    object_type: str | None = None,
    domain: str | None = None,
    limit: int = 20,
) -> dict[str, Any]:
    require_database()

    cleaned_query = query.strip()
    if not cleaned_query:
        raise ValueError("search query cannot be empty")

    lowered_query = cleaned_query.lower()
    terms = list(dict.fromkeys(re.findall(r"[a-z0-9._-]+", lowered_query) or [lowered_query]))

    where_clauses = ["1=1"]
    where_params: list[Any] = []

    for term in terms:
        where_clauses.append("lower(search_text) LIKE ?")
        where_params.append(f"%{term}%")

    if object_type:
        where_clauses.append("object_type = ?")
        where_params.append(object_type)

    if domain:
        where_clauses.append("lower(domains_text) LIKE ?")
        where_params.append(f"%{domain.lower()}%")

    sql = f"""
        SELECT
            stix_id,
            attack_id,
            name,
            object_type,
            domains_json,
            url,
            description,
            (
                CASE WHEN lower(COALESCE(attack_id, '')) = ? THEN 100 ELSE 0 END +
                CASE WHEN lower(name) = ? THEN 60 ELSE 0 END +
                CASE WHEN lower(COALESCE(attack_id, '')) LIKE ? THEN 40 ELSE 0 END +
                CASE WHEN lower(name) LIKE ? THEN 25 ELSE 0 END +
                CASE WHEN lower(description) LIKE ? THEN 10 ELSE 0 END +
                CASE WHEN lower(search_text) LIKE ? THEN 5 ELSE 0 END
            ) AS score
        FROM documents
        WHERE {' AND '.join(where_clauses)}
        ORDER BY score DESC, name ASC, stix_id ASC
        LIMIT ?
    """

    score_params = [
        lowered_query,
        lowered_query,
        f"{lowered_query}%",
        f"%{lowered_query}%",
        f"%{lowered_query}%",
        f"%{lowered_query}%",
    ]

    with open_connection() as connection:
        initialize_database(connection)
        rows = connection.execute(sql, score_params + where_params + [limit]).fetchall()

    results = [
        {
            "stix_id": row["stix_id"],
            "attack_id": row["attack_id"],
            "name": row["name"],
            "object_type": row["object_type"],
            "domains": json.loads(row["domains_json"]),
            "url": row["url"],
            "description": row["description"],
            "score": row["score"],
        }
        for row in rows
    ]

    return {
        "query": cleaned_query,
        "object_type": object_type,
        "domain": domain,
        "count": len(results),
        "results": results,
    }


def get_attack_object(stix_id: str) -> dict[str, Any] | None:
    require_database()

    with open_connection() as connection:
        initialize_database(connection)
        row = connection.execute(
            "SELECT raw_json FROM documents WHERE stix_id = ?",
            (stix_id,),
        ).fetchone()

    if row is None:
        return None

    return json.loads(row["raw_json"])


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Sync and search MITRE ATT&CK data.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("sync", help="Download ATT&CK data and rebuild the local index.")
    subparsers.add_parser("status", help="Show MITRE cache and database status.")

    search_parser = subparsers.add_parser("search", help="Search the local MITRE index.")
    search_parser.add_argument("query", help="Free-text search or ATT&CK ID, for example T1059")
    search_parser.add_argument("--type", dest="object_type", default=None)
    search_parser.add_argument("--domain", default=None)
    search_parser.add_argument("--limit", type=int, default=10)

    show_parser = subparsers.add_parser("show", help="Show a full indexed object by STIX ID.")
    show_parser.add_argument("stix_id", help="STIX ID returned by the search command")

    args = parser.parse_args(argv)

    if args.command == "sync":
        print(json.dumps(sync_attack_content(), indent=2))
        return

    if args.command == "status":
        print(json.dumps(get_attack_status(), indent=2))
        return

    if args.command == "search":
        print(
            json.dumps(
                search_attack_content(
                    query=args.query,
                    object_type=args.object_type,
                    domain=args.domain,
                    limit=args.limit,
                ),
                indent=2,
            )
        )
        return

    if args.command == "show":
        document = get_attack_object(args.stix_id)
        if document is None:
            raise SystemExit(f"MITRE object not found: {args.stix_id}")
        print(json.dumps(document, indent=2))

