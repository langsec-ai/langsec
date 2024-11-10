import sqlite3
from sqlglot import parse_one, exp

from ...config import LangSecConfig
from ..security_schema import SecuritySchema


def _parse_sql_ddl(schema: SecuritySchema, connection: sqlite3.Connection) -> SecuritySchema:
    from ..security_schema import ColumnSchema, TableSchema

    cursor = connection.cursor()
    try:
        cursor.execute("SELECT name, sql FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
    except sqlite3.Error as e:
        raise RuntimeError(f"Failed to fetch table information from the database: {e}")

    for table_name, ddl in tables:
        parsed = parse_one(ddl)
        table_schema = TableSchema()

        for column in parsed.find_all(exp.Column):
            column_name = column.name.lower()
            table_schema.columns[column_name] = ColumnSchema()

        schema.tables[table_name.lower()] = table_schema


def sql_security_schema(config: LangSecConfig, connection: sqlite3.Connection) -> SecuritySchema:
    schema = SecuritySchema()
    _parse_sql_ddl(schema, connection)
    # TODO: Apply config here
    return schema