import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run(code: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-I", "-c", code], capture_output=True, text=True, cwd=ROOT / "src"
    )


def test_importing_authz_does_not_import_asyncpg():
    result = run(
        "import sys, authz; "
        "assert 'asyncpg' not in sys.modules, 'asyncpg imported'; "
        "assert 'authz.storage.postgres' not in sys.modules"
    )
    assert result.returncode == 0, result.stderr


def test_postgres_storage_is_importable_lazily_when_asyncpg_is_installed():
    result = run(
        "import sys, authz; "
        "from authz import PostgresStorage; "
        "assert PostgresStorage.__name__ == 'PostgresStorage'; "
        "assert 'asyncpg' in sys.modules"
    )
    assert result.returncode == 0, result.stderr


def test_missing_asyncpg_gives_a_clear_install_hint():
    result = run(
        "import sys; sys.modules['asyncpg'] = None; "
        "import authz\n"
        "try:\n"
        "    authz.PostgresStorage\n"
        "except ImportError as e:\n"
        "    assert 'python-authz[postgres]' in str(e), str(e)\n"
        "else:\n"
        "    raise SystemExit('no ImportError')\n"
        "assert authz.SqliteStorage and authz.Client\n"
    )
    assert result.returncode == 0, result.stderr


def test_unknown_attribute_still_raises_attribute_error():
    result = run(
        "import authz\n"
        "try:\n"
        "    authz.nope\n"
        "except AttributeError:\n"
        "    pass\n"
        "else:\n"
        "    raise SystemExit('no AttributeError')\n"
    )
    assert result.returncode == 0, result.stderr


def test_project_metadata():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert project["dependencies"] == ["aiosqlite>=0.21.0"]
    assert project["optional-dependencies"]["postgres"] == ["asyncpg>=0.31.0"]
    assert project["optional-dependencies"]["fastapi"] == ["fastapi>=0.141.1"]
    assert "scripts" not in project
    assert "Typing :: Typed" in project["classifiers"]
    assert all("tensor-forge-ai/python-authz" in url for url in project["urls"].values())


def test_py_typed_marker_ships():
    assert (ROOT / "src" / "authz" / "py.typed").is_file()
