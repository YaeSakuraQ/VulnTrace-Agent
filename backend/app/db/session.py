from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from app.db.models import Base


class Database:
    def __init__(self, database_url: str | Path) -> None:
        if isinstance(database_url, Path):
            database_url = f"sqlite:///{database_url.as_posix()}"
        self.database_url = database_url

        # Extract SQLite file path for raw connections
        self._sqlite_path: str | None = None
        if database_url.startswith("sqlite:///"):
            self._sqlite_path = database_url.removeprefix("sqlite:///")

        self.engine: Engine | None = None
        self._session_factory: sessionmaker[Session] | None = None

    @property
    def _is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    def init(self) -> None:
        if self._is_sqlite:
            self.engine = create_engine(
                self.database_url,
                connect_args={"check_same_thread": False},
            )
        else:
            self.engine = create_engine(self.database_url)

        # Enable PRAGMA foreign_keys for SQLite connections
        if self._is_sqlite:

            @event.listens_for(self.engine, "connect")
            def _set_sqlite_pragma(
                dbapi_connection: object, connection_record: object
            ) -> None:
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA foreign_keys = ON")
                cursor.close()

        self._session_factory = sessionmaker(bind=self.engine)

        # Create all tables via ORM
        Base.metadata.create_all(self.engine)

    @contextmanager
    def session(self) -> Iterator[Session]:
        """Yield a SQLAlchemy Session for ORM operations."""
        if self._session_factory is None:
            raise RuntimeError("Database not initialized. Call init() first.")
        session = self._session_factory()
        try:
            yield session
        finally:
            session.close()

    def connection(self):
        """Backward-compatible alias for raw_connection()."""
        return self.raw_connection()

    @contextmanager
    def raw_connection(self) -> Iterator[sqlite3.Connection]:
        """Yield a raw sqlite3.Connection (backward compatibility for existing services)."""
        if self._sqlite_path is None:
            raise RuntimeError(
                "raw_connection() is only supported for SQLite databases."
            )
        conn = sqlite3.connect(self._sqlite_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
        finally:
            conn.close()
