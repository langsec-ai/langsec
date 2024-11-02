from typing import Set
from sqlglot import exp
from .base import BaseQueryValidator
from ..exceptions.errors import TableAccessError


class TableValidator(BaseQueryValidator):
    def validate(self, parsed: exp.Expression) -> None:
        if not self.schema.tables:
            return

        for table in parsed.find_all(exp.Table):
            if table.name.lower() not in self.schema.tables:
                raise TableAccessError(f"Access to table '{table.name}' is not allowed")

    def get_tables_from_select(self, select: exp.Select) -> Set[str]:
        """Gets all table names referenced in a SELECT statement."""
        tables = set()
        for table in select.find_all(exp.Table):
            tables.add(table.name.lower())
        return tables
