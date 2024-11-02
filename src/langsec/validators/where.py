from sqlglot import exp
from .base import BaseQueryValidator
from ..exceptions.errors import QueryComplexityError

class WhereValidator(BaseQueryValidator):
    def validate(self, parsed: exp.Expression) -> None:
        """Validates WHERE clauses against schema rules."""
        for select in parsed.find_all(exp.Select):
            where_expr = select.args.get('where')
            if not where_expr:
                # Check tables that require WHERE clause
                tables = self._get_tables_from_select(select)
                for table_name in tables:
                    table_schema = self.schema.tables.get(table_name)
                    if table_schema and table_schema.require_where_clause:
                        raise QueryComplexityError(
                            f"Table '{table_name}' requires a WHERE clause"
                        )
            else:
                self._validate_where_conditions(where_expr)

    def _validate_where_conditions(self, where: exp.Expression) -> None:
        """Validates WHERE conditions against allowed columns."""
        for column in where.find_all(exp.Column):
            table_name = column.table or self._get_default_table(where, column)
            if not table_name:
                continue
                
            table_schema = self.schema.tables.get(table_name)
            if not table_schema or not table_schema.allowed_where_columns:
                continue
                
            if column.name not in table_schema.allowed_where_columns:
                raise QueryComplexityError(
                    f"Column '{column.name}' not allowed in WHERE clause"
                )
                
    def _get_tables_from_select(self, select: exp.Select) -> set[str]:
        """Gets all table names referenced in a SELECT statement."""
        tables = set()
        for table in select.find_all(exp.Table):
            tables.add(table.name.lower())
        return tables