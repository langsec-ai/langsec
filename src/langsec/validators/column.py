from typing import Dict, Optional
from sqlglot import exp
from .base import BaseQueryValidator
from ..schema import ColumnAccess
from ..exceptions.errors import ColumnAccessError


class ColumnValidator(BaseQueryValidator):
    def _resolve_table_name(
        self, parsed: exp.Expression, table_alias: str
    ) -> Optional[str]:
        """Resolve table alias to actual table name."""
        for table in parsed.find_all(exp.Table):
            if table.alias and table.alias.lower() == table_alias.lower():
                return table.name.lower()
        return None

    def _get_table_aliases(self, parsed: exp.Expression) -> Dict[str, str]:
        """Get mapping of aliases to actual table names."""
        aliases = {}
        for table in parsed.find_all(exp.Table):
            if table.alias:
                aliases[table.alias.lower()] = table.name.lower()
        return aliases

    def validate(self, parsed: exp.Expression) -> None:
        aliases = self._get_table_aliases(parsed)

        for column in parsed.find_all(exp.Column):
            table_name = None
            if column.table:
                # If column has a table reference, try to resolve alias
                table_name = aliases.get(column.table.lower()) or column.table.lower()
            else:
                table_name = self._get_default_table(parsed, column)

            if not table_name:
                continue

            column_name = str(column.name).lower()
            column_rule = self.schema.get_column_schema(table_name, column_name)

            # Check if column exists in schema
            if not column_rule:
                raise ColumnAccessError(
                    f"Column '{column_name}' not found in table '{table_name}' schema"
                )

            # Check column access
            if column_rule.access == ColumnAccess.DENIED:
                raise ColumnAccessError(
                    f"Access denied to column '{column_name}' in table '{table_name}'"
                )
