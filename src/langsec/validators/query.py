from typing import List, Optional, Set, Any
from sqlglot import parse_one, exp
from ..models.schema import SecuritySchema
from ..models.config import LangSecConfig
from ..exceptions.errors import (
    TableAccessError,
    ColumnAccessError,
    JoinViolationError,
    QueryComplexityError,
    SQLInjectionError
)
from ..models.enums import ColumnAccess, JoinType, AggregationType

class QueryValidator:
    def __init__(self, schema: Optional[SecuritySchema] = None, config: Optional[LangSecConfig] = None):
        self.schema = schema or SecuritySchema()
        self.config = config or LangSecConfig()

    def validate(self, query: str) -> bool:
            """Validates a query against all configured rules."""
            if self.schema.forbidden_keywords:
                self._validate_forbidden_keywords(query)

            if not self.schema.tables:  # If no schema defined, consider valid
                return True
                
            parsed = parse_one(query)
            
            self._validate_tables(parsed)
            self._validate_columns(parsed)
            self._validate_joins(parsed)
            self._validate_where_clauses(parsed)
            self._validate_aggregations(parsed)
            self._validate_group_by(parsed)
            
            return True

    def _validate_forbidden_keywords(self, query: str) -> None:
        """Validates that no forbidden keywords are present in the query."""
        if not self.schema.forbidden_keywords:
            return

        query_upper = query.upper()
        for keyword in self.schema.forbidden_keywords:
            if keyword.upper() in query_upper:
                raise SQLInjectionError(f"Forbidden keyword found: {keyword}")

    def _validate_query_length(self, query: str) -> None:
        if (
            self.schema.max_query_length and 
            len(query) > self.schema.max_query_length
        ):
            raise QueryComplexityError(
                f"Query length exceeds maximum allowed "
                f"({len(query)} > {self.schema.max_query_length})"
            )

    def _validate_forbidden_keywords(self, query: str) -> None:
        if not self.schema.forbidden_keywords:
            return
            
        query_upper = query.upper()
        for keyword in self.schema.forbidden_keywords:
            if keyword.upper() in query_upper:
                raise QueryComplexityError(f"Forbidden keyword found: {keyword}")

    def _validate_tables(self, parsed: exp.Expression) -> None:
        if not self.schema.tables:
            return
            
        for table in parsed.find_all(exp.Table):
            if table.name not in self.schema.tables:
                raise TableAccessError(f"Access to table '{table.name}' is not allowed")

    def _validate_columns(self, parsed: exp.Expression) -> None:
        """Validates column access permissions."""
        for column in parsed.find_all(exp.Column):
            table_name = column.table or self._get_default_table(column)
            if not table_name:
                continue
                
            table_schema = self.schema.tables.get(table_name)
            if not table_schema or not table_schema.columns:
                continue
                
            column_rule = table_schema.columns.get(column.name)
            if column_rule and column_rule.access:
                if column_rule.access == ColumnAccess.DENIED:
                    raise ColumnAccessError(f"Access denied to column: {column.name}")

    def _validate_projection(self, projection: exp.Expression) -> None:
        if not self.schema.tables:
            return
            
        for column in projection.find_all(exp.Column):
            table_name = column.table or self._get_default_table(projection)
            if not table_name:
                return  # Skip if we can't determine table
                
            table_schema = self.schema.tables.get(table_name)
            if not table_schema or not table_schema.columns:
                return
                
            column_rule = table_schema.columns.get(column.name)
            if column_rule and column_rule.access:
                self._check_column_access(column_rule, column)

    def _check_column_access(self, rule: Any, column: exp.Column) -> None:
        if rule.access == ColumnAccess.DENIED:
            raise ColumnAccessError(f"Access denied to column: {column.name}")

    def _get_default_table(self, expr: exp.Expression) -> Optional[str]:
        tables = list(expr.find_all(exp.Table))
        return tables[0].name if len(tables) == 1 else None

    def _validate_joins(self, parsed: exp.Expression) -> None:
        if not self.schema.tables:
            return
            
        joins = list(parsed.find_all(exp.Join))
        
        if self.schema.max_joins and len(joins) > self.schema.max_joins:
            raise JoinViolationError(
                f"Number of joins ({len(joins)}) exceeds maximum allowed ({self.schema.max_joins})"
            )

        for join in joins:
            self._validate_join(join)

    def _validate_aggregations(self, parsed: exp.Expression) -> None:
            """Validates aggregation functions against schema rules."""
            for agg in parsed.find_all(exp.Max, exp.Min, exp.Sum, exp.Avg, exp.Count):
                for column in agg.find_all(exp.Column):
                    table_name = column.table or self._get_default_table(agg)
                    if not table_name:
                        continue
                        
                    table_schema = self.schema.tables.get(table_name)
                    if not table_schema or not table_schema.columns:
                        continue
                        
                    column_rule = table_schema.columns.get(column.name)
                    if column_rule and column_rule.allowed_aggregations:
                        agg_type = self._get_aggregation_type(agg)
                        if agg_type not in column_rule.allowed_aggregations:
                            raise QueryComplexityError(
                                f"Aggregation {agg_type} not allowed for column {column.name}"
                            )

    def _validate_join(self, join: exp.Join) -> None:
            """Validates a JOIN operation against schema rules."""
            if not self.schema.tables:
                return

            # Get the joined table (right side)
            joined_table = None
            if isinstance(join.this, exp.Table):
                joined_table = join.this.name
            
            # Get the base table (left side)
            base_table = None
            if isinstance(join.parent, exp.From):
                if isinstance(join.parent.this, exp.Table):
                    base_table = join.parent.this.name
                elif isinstance(join.parent.this, exp.Join):
                    base_table = join.parent.this.this.name
                    
            if not (joined_table and base_table):
                return

            table_schema = self.schema.tables.get(base_table)
            if not table_schema or not table_schema.allowed_joins:
                return

            join_rule = table_schema.allowed_joins.get(joined_table)
            if not join_rule:
                raise JoinViolationError(
                    f"Join between {base_table} and {joined_table} is not allowed"
                )

            join_type = self._get_join_type(join)
            if join_type not in join_rule.allowed_types:
                raise JoinViolationError(
                    f"Join type {join_type} not allowed between {base_table} and {joined_table}"
                )

    def _get_join_type(self, join: exp.Join) -> JoinType:
        """Determines the type of join from the sqlglot Join expression."""
        if hasattr(join, 'side'):
            if join.side == 'RIGHT':
                return JoinType.RIGHT
            elif join.side == 'LEFT':
                return JoinType.LEFT
            elif join.side == 'FULL':
                return JoinType.FULL
        return JoinType.INNER
    
    def _get_aggregation_type(self, agg: exp.Expression) -> Optional[AggregationType]:
            """Maps sqlglot aggregation to AggregationType."""
            agg_map = {
                exp.Sum: AggregationType.SUM,
                exp.Avg: AggregationType.AVG,
                exp.Min: AggregationType.MIN,
                exp.Max: AggregationType.MAX,
                exp.Count: AggregationType.COUNT
            }
            return agg_map.get(type(agg))
        
    def _validate_group_by(self, parsed: exp.Expression) -> None:
        """Validates GROUP BY clauses against schema rules."""
        for select in parsed.find_all(exp.Select):
            if select.group_by:
                tables = self._get_tables_from_select(select)
                for table_name in tables:
                    table_schema = self.schema.tables.get(table_name)
                    if table_schema:
                        if table_schema.allow_group_by is False:
                            raise QueryComplexityError(
                                f"GROUP BY not allowed for table {table_name}"
                            )
                        if table_schema.allowed_group_by_columns:
                            self._validate_group_by_columns(
                                select.group_by,
                                table_schema.allowed_group_by_columns,
                                table_name
                            )

    def _validate_group_by_columns(
        self,
        group_by: List[exp.Expression],
        allowed_columns: Set[str],
        table_name: str
    ) -> None:
        """Validates columns used in GROUP BY."""
        for expr in group_by:
            for column in expr.find_all(exp.Column):
                if column.name not in allowed_columns:
                    raise QueryComplexityError(
                        f"Column {column.name} not allowed in GROUP BY"
                    )

    def _get_tables_from_select(self, select: exp.Select) -> Set[str]:
        """Gets all table names referenced in a SELECT statement."""
        tables = set()
        for table in select.find_all(exp.Table):
            tables.add(table.name)
        return tables

    def _validate_where_clauses(self, parsed: exp.Expression) -> None:
        """Validates WHERE clauses against schema rules."""
        for select in parsed.find_all(exp.Select):
            where_expr = select.args.get('where')  # Get where expression directly
            if not where_expr:
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
        """Validates WHERE conditions against allowed columns and values."""
        for column in where.find_all(exp.Column):
            table_name = column.table or self._get_default_table(where)
            if not table_name:
                continue
                
            table_schema = self.schema.tables.get(table_name)
            if not table_schema or not table_schema.allowed_where_columns:
                continue
                
            if (
                table_schema.allowed_where_columns and
                column.name not in table_schema.allowed_where_columns
            ):
                raise QueryComplexityError(
                    f"Column '{column.name}' not allowed in WHERE clause"
                )

    def _get_table_from_expression(self, expr: exp.Expression) -> Optional[str]:
        """Extracts table name from an expression."""
        if isinstance(expr, exp.Table):
            return expr.name
        elif isinstance(expr, exp.Identifier):
            return expr.this
        return None