from sqlglot import exp
from .base import BaseQueryValidator
from ..models.enums import ColumnAccess
from ..exceptions.errors import ColumnAccessError

class ColumnValidator(BaseQueryValidator):
    def validate(self, parsed: exp.Expression) -> None:
        for column in parsed.find_all(exp.Column):
            table_name = column.table or self._get_default_table(parsed, column)
            if not table_name:
                continue
            
            table_schema = self.schema.tables.get(table_name)
            if not table_schema:
                continue
            
            column_name = str(column.name).lower()
            column_rule = table_schema.columns.get(column_name)
            if column_rule and column_rule.access == ColumnAccess.DENIED:
                raise ColumnAccessError(f"Access denied to column: {column_name}")