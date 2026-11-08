from fwlens.db.session import DEFAULT_DATABASE_URL, database_url, get_engine


def test_default_url_points_at_local_compose(monkeypatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert database_url() == DEFAULT_DATABASE_URL
    assert "@127.0.0.1:5432/" in DEFAULT_DATABASE_URL


def test_environment_overrides_default(monkeypatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@db.internal:5432/x")
    assert database_url() == "postgresql+psycopg://u:p@db.internal:5432/x"


def test_engine_uses_psycopg_without_connecting() -> None:
    engine = get_engine("postgresql+psycopg://u:p@127.0.0.1:1/x")  # create_engine is lazy
    assert engine.dialect.driver == "psycopg"
