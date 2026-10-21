"""Additive SQLite upgrades with an on-disk backup before changing old schemas."""
from datetime import datetime, timezone
from contextlib import closing
from pathlib import Path
import sqlite3
from sqlalchemy import inspect


def upgrade_legacy_schema(engine):
    additions = {'findings': {'remediation_patch': 'TEXT', 'cve_id': 'VARCHAR'},
                 'exploit_logs': {'exploit_type': 'VARCHAR'}}
    inspector = inspect(engine)
    pending = []
    for table, columns in additions.items():
        if inspector.has_table(table):
            existing = {c['name'] for c in inspector.get_columns(table)}
            pending.extend((table, name, sql_type) for name, sql_type in columns.items() if name not in existing)
    if not pending:
        return None
    if engine.dialect.name != 'sqlite':
        raise RuntimeError('Legacy schema requires a reviewed migration for this database provider')
    backup_path = None
    database = engine.url.database
    if database and database != ':memory:':
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        backup_path = Path(database).resolve().with_name(Path(database).name + f'.pre-upgrade-{stamp}.db')
        with engine.connect() as connection:
            with closing(sqlite3.connect(backup_path)) as backup:
                connection.connection.driver_connection.backup(backup)
    with engine.begin() as connection:
        for table, name, sql_type in pending:
            # Identifiers and SQL types come exclusively from the static allowlist above.
            connection.exec_driver_sql(f'ALTER TABLE "{table}" ADD COLUMN "{name}" {sql_type}')
    return backup_path
