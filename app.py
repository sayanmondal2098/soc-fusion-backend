import os
import subprocess
import sys
from pathlib import Path

from dotenv import load_dotenv


_BOOTSTRAP_FLAG = "SOC_FUSION_APP_BOOTSTRAPPED"


def _load_env_file() -> None:
    env_file = os.getenv("ENV_FILE", ".env")
    env_path = Path(env_file)

    if not env_path.is_absolute():
        env_path = Path(__file__).resolve().parent / env_path

    if env_path.exists():
        load_dotenv(dotenv_path=env_path, override=False)


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
except ImportError as exc:
    if __name__ == "__main__":
        _handoff_to_local_venv()

    missing = getattr(exc, "name", "uvicorn")
    raise SystemExit(
        f"Missing dependency: {missing}. Install requirements or run inside the project venv."
    ) from exc


def main() -> None:
    _load_env_file()

    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    reload_enabled = os.getenv("RELOAD", "false").lower() in {"1", "true", "yes"}

    uvicorn.run("api:app", host=host, port=port, reload=reload_enabled)


if __name__ == "__main__":
    main()
