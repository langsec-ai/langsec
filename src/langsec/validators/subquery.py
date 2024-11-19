from sqlglot import exp
from .base import BaseQueryValidator
from ..exceptions.errors import QueryComplexityError


class SubqueryValidator(BaseQueryValidator):
    """Validator for checking subquery permissions and constraints."""

    def validate(self, parsed: exp.Expression) -> None:
        """
        Validates that subqueries are allowed if present in the query.

        Args:
            parsed: The parsed SQL expression

        Raises:
            QueryComplexityError: If subqueries are found when not allowed
        """
        if not self.schema.allow_subqueries:
            # Find all SELECT expressions that are not the root query
            # and not part of a UNION
            subqueries = [
                node
                for node in parsed.find_all(exp.Select)
                if (node.parent is not None and not isinstance(node.parent, exp.Union))
            ]

            if subqueries:
                raise QueryComplexityError("Subqueries are not allowed in the current security configuration")
