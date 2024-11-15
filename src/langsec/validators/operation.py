# from sqlglot import exp
# from typing import Set, Optional
# from .base import BaseQueryValidator
# from ..exceptions.errors import QueryComplexityError

# class OperationsValidator(BaseQueryValidator):
#     """Validator for checking operations."""

#     def _get_operations_per_column(self, parsed: exp.Expression) -> Set[str]:
#         """Extracts all operations from the parsed query."""
#         return {node.name.upper() for node in parsed.iter_expressions()}
    
#     def validate(self, parsed: exp.Expression) -> None:
#         """
#         Validates that the query does not contain any forbidden operations.

#         Args:
#             parsed: The parsed SQL expression

#         Raises:
#             QueryComplexityError: If any forbidden operations are found
#         """
#         for table_name, table in self.schema.tables.items():
#             if not table.columns:
#                 continue



#         operations = self._get_operations(parsed)
#         forbidden = operations & self.schema.forbidden_operations

#         if forbidden:
#             raise QueryComplexityError(
#                 f"Query contains forbidden operations: {', '.join(forbidden)}"
#             )