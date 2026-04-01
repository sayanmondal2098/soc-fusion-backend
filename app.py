import os
import subprocess
import sys
from pathlib import Path


_BOOTSTRAP_FLAG = "SOC_FUSION_APP_BOOTSTRAPPED"


def _handoff_to_local_venv() -> None:
    if os.getenv(_BOOTSTRAP_FLAG) == "1":
        return

    venv_python = Path(__file__).resolve().parent / "venv" / "Scripts" / "python.exe"
    if not venv_python.exists():
        return

    env = os.environ.copy()
    env[_BOOTSTRAP_FLAG] = "1"
    completed = subprocess.run([str(venv_python), __file__, *sys.argv[1:]], env=env)
    raise SystemExit(completed.returncode)


try:
    import uvicorn
    from fastapi import FastAPI
except ImportError as exc:
    if __name__ == "__main__":
        _handoff_to_local_venv()

    missing = getattr(exc, "name", "fastapi/uvicorn")
    raise SystemExit(
        f"Missing dependency: {missing}. Install requirements or run inside the project venv."
    ) from exc

from mitre.router import router as mitre_router


app = FastAPI(title="SoC Fusion Backend")
app.include_router(mitre_router)


# @app.get("/")
# async def read_root() -> dict[str, str]:
#     return {"message": "SoC Fusion backend is running"}


@app.get("/health")
async def health_check() -> dict[str, str]:
    return {"status": "ok"}


def main() -> None:
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    reload_enabled = os.getenv("RELOAD", "false").lower() in {"1", "true", "yes"}

    uvicorn.run("app:app", host=host, port=port, reload=reload_enabled)


if __name__ == "__main__":
    main()
