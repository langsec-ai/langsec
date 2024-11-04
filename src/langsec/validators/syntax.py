from sqlglot import parse_one
from ..exceptions.errors import SQLSyntaxError


class SyntaxValidator:
    def validate(self, query: str) -> bool:
        """Validates basic SQL syntax."""
        try:
            _ = parse_one(query)
            return True
        except Exception as e:
            raise SQLSyntaxError(f"Invalid SQL syntax: {str(e)}")
