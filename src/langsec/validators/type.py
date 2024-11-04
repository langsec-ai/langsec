from sqlglot import exp
from .base import BaseQueryValidator
from ..exceptions.errors import QueryComplexityError
from ..models.enums import QueryType


class QueryTypeValidator(BaseQueryValidator):
    """Validator for checking if the query type is allowed."""

    def validate(self, parsed: exp.Expression) -> None:
        """
        Validates that the query type is allowed in the current configuration.

        Args:
            parsed: The parsed SQL expression

        Raises:
            QueryComplexityError: If the query type is not allowed
        """
        query_type = self._get_query_type(parsed)
        if query_type not in self.schema.allowed_query_types:
            allowed_types = ", ".join(
                qt.value for qt in self.schema.allowed_query_types
            )
            raise QueryComplexityError(
                f"Query type '{query_type.value}' is not allowed. Allowed types: {allowed_types}"
            )

    def _get_query_type(self, parsed: exp.Expression) -> QueryType:
        """Determine the type of the SQL query."""
        if isinstance(parsed, exp.Select):
            return QueryType.SELECT
        elif isinstance(parsed, exp.Insert):
            return QueryType.INSERT
        elif isinstance(parsed, exp.Update):
            return QueryType.UPDATE
        elif isinstance(parsed, exp.Delete):
            return QueryType.DELETE
        elif isinstance(parsed, exp.Create):
            return QueryType.CREATE
        elif isinstance(parsed, exp.Drop):
            return QueryType.DROP
        elif isinstance(parsed, exp.Alter):
            return QueryType.ALTER
        elif isinstance(parsed, exp.TruncateTable):
            return QueryType.TRUNCATE
        else:
            raise QueryComplexityError(f"Unsupported query type: {type(parsed)}")
