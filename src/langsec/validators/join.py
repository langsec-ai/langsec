from typing import Dict, Tuple, Optional
from sqlglot import exp
from .base import BaseQueryValidator
from ..schema.sql.enums import JoinType
from ..exceptions.errors import JoinViolationError


class JoinValidator(BaseQueryValidator):
    def validate(self, parsed: exp.Expression) -> None:
        """Validates all JOIN operations in the query."""
        aliases = self._collect_table_aliases(parsed)
        joins = list(parsed.find_all(exp.Join))

        if self.schema.max_joins and len(joins) > self.schema.max_joins:
            raise JoinViolationError(
                f"Number of joins ({len(joins)}) exceeds maximum allowed ({self.schema.max_joins})"
            )

        for join in joins:
            self._validate_single_join(join, aliases)

    def _validate_single_join(self, join: exp.Join, aliases: Dict[str, str]) -> None:
        """Validates a single JOIN operation."""
        left_table, right_table = self._get_join_tables(join)
        if not left_table or not right_table:
            return

        # Resolve aliases to actual table names
        left_table = aliases.get(left_table.lower(), left_table.lower())
        right_table = aliases.get(right_table.lower(), right_table.lower())

        join_type = self._get_join_type(join)

        # Get schema for both tables
        left_schema = self.schema.get_table_schema(left_table)
        right_schema = self.schema.get_table_schema(right_table)

        left_join_rule = left_schema.get_table_allowed_joins(right_table)
        right_join_rule = right_schema.get_table_allowed_joins(left_table)

        # For FULL JOIN, check both directions
        if join_type == JoinType.FULL:
            if not left_join_rule or not right_join_rule:
                raise JoinViolationError(
                    f"FULL JOIN between {left_table} and {right_table} is not allowed"
                )

            if (
                JoinType.FULL not in left_join_rule
                or JoinType.FULL not in right_join_rule
            ):
                raise JoinViolationError(
                    f"FULL JOIN not allowed between {left_table} and {right_table}"
                )

        # Handle RIGHT JOIN by checking if equivalent LEFT JOIN is allowed in reverse direction
        elif join_type == JoinType.RIGHT:
            if not right_join_rule or JoinType.LEFT not in right_join_rule:
                raise JoinViolationError(
                    f"RIGHT JOIN from {left_table} to {right_table} is not allowed as {right_table} "
                    f"does not allow LEFT JOIN with {left_table}"
                )

        elif join_type == JoinType.CROSS:
            if not left_join_rule and not right_join_rule:
                raise JoinViolationError(
                    f"CROSS JOIN between {left_table} and {right_table} is not allowed"
                )
            if JoinType.CROSS not in (
                left_join_rule if left_join_rule else set()
            ) and JoinType.CROSS not in (right_join_rule if right_join_rule else set()):
                raise JoinViolationError(
                    f"CROSS JOIN not allowed between {left_table} and {right_table}"
                )

        # For LEFT and INNER joins, validate normally
        else:
            if not left_join_rule:
                raise JoinViolationError(
                    f"Join between {left_table} and {right_table} is not allowed"
                )

            if join_type not in left_join_rule:
                raise JoinViolationError(
                    f"Join type {join_type} not allowed between {left_table} and {right_table}. "
                    f"Allowed types: {left_join_rule}"
                )

    def _collect_table_aliases(self, parsed: exp.Expression) -> Dict[str, str]:
        """Collects all table aliases in the query."""
        aliases = {}

        for table in parsed.find_all(exp.Table):
            if table.alias:
                aliases[str(table.alias).lower()] = str(table.name).lower()

        for join in parsed.find_all(exp.Join):
            if isinstance(join.this, exp.Table) and join.this.alias:
                aliases[str(join.this.alias).lower()] = str(join.this.name).lower()

        return aliases

    def _get_join_tables(self, join: exp.Join) -> Tuple[Optional[str], Optional[str]]:
        """Gets the two tables involved in a join."""
        right_table = None
        left_table = None

        if isinstance(join.this, exp.Table):
            right_table = join.this.name

        # Get the table from the Select that the Join operates on.
        left_table = self._get_default_table(join, None)

        return left_table, right_table

    def _get_join_type(self, join: exp.Join) -> JoinType:
        """Determines the type of join from the sqlglot Join expression."""
        if join.kind == "CROSS":
            return JoinType.CROSS

        if not join.side:
            return JoinType.INNER

        join_side = join.side.upper()
        if join_side == "RIGHT":
            return JoinType.RIGHT
        elif join_side == "LEFT":
            return JoinType.LEFT
        elif join_side in ("FULL", "OUTER"):  # Handle both FULL and OUTER as FULL
            return JoinType.FULL

        return JoinType.INNER
