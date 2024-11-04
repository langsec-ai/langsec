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
            schema_tables_lower = {t.lower() for t in self.schema.tables}
            if table_name not in schema_tables_lower:
                raise TableAccessError(f"Access to table '{table_name}' is not allowed")
