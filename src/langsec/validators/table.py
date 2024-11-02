from typing import Set
from sqlglot import exp
from .base import BaseQueryValidator
from ..exceptions.errors import TableAccessError


class TableValidator(BaseQueryValidator):
    def _get_actual_table_name(self, table: exp.Table) -> str:
        """Get the actual table name, ignoring alias."""
        return table.name.lower()

    def validate(self, parsed: exp.Expression) -> None:
        if not self.schema.tables:
            return

        for table in parsed.find_all(exp.Table):
            table_name = self._get_actual_table_name(table)
            if table_name not in self.schema.tables:
                raise TableAccessError(f"Access to table '{table_name}' is not allowed")

    def get_tables_from_select(self, select: exp.Select) -> Set[str]:
        """Gets all table names referenced in a SELECT statement."""
        tables = set()
        for table in select.find_all(exp.Table):
            tables.add(self._get_actual_table_name(table))
        return tables
