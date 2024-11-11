from typing import List, Set
from sqlglot import exp
from .base import BaseQueryValidator
from ..exceptions.errors import QueryComplexityError


class GroupByValidator(BaseQueryValidator):
    def validate(self, parsed: exp.Expression) -> None:
        """Validates GROUP BY clauses against schema rules."""
        for select in parsed.find_all(exp.Select):
            group_by_exprs = select.args.get("group_by", [])
            if group_by_exprs:
                tables = self._get_tables_from_select(select)
                for table_name in tables:
                    table_schema = self.schema.get_table_schema(table_name)
                    if table_schema:
                        if table_schema.allow_group_by is False:
                            raise QueryComplexityError(
                                f"GROUP BY not allowed for table {table_name}"
                            )
                        if table_schema.allowed_group_by_columns:
                            self._validate_group_by_columns(
                                group_by_exprs,
                                table_schema.allowed_group_by_columns,
                                table_name,
                            )

    def _validate_group_by_columns(
        self,
        group_by_exprs: List[exp.Expression],
        allowed_columns: Set[str],
        table_name: str,
    ) -> None:
        """Validates columns used in GROUP BY."""
        for expr in group_by_exprs:
            for column in expr.find_all(exp.Column):
                if column.table == table_name or (
                    not column.table and len(allowed_columns) > 0
                ):
                    if column.name not in allowed_columns:
                        raise QueryComplexityError(
                            f"Column {column.name} not allowed in GROUP BY for table {table_name}"
                        )

    def _get_tables_from_select(self, select: exp.Select) -> set[str]:
        """Gets all table names referenced in a SELECT statement."""
        tables = set()
        for table in select.find_all(exp.Table):
            tables.add(table.name.lower())
        return tables
