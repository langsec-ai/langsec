from typing import List, Pattern, Set, Optional
from ..exceptions.errors import SQLInjectionError
from .base import BaseQueryValidator
from ..models.schema import SecuritySchema
import re
from sqlglot import exp


class SQLInjectionValidator(BaseQueryValidator):
    def __init__(self, schema: Optional[SecuritySchema] = None):
        super().__init__(schema)
        # Common SQL injection patterns
        self.patterns: List[Pattern] = [
            # Comments
            re.compile(r"--", re.IGNORECASE),
            re.compile(r"/\*.*?\*/", re.IGNORECASE | re.DOTALL),
            # UNION-based attacks
            re.compile(r"UNION\s+(?:ALL\s+)?SELECT", re.IGNORECASE),
            # Command execution
            re.compile(
                r"(?:EXEC(?:UTE)?|xp_cmdshell|sp_executesql)\s*[\(\s]", re.IGNORECASE
            ),
            # Boolean-based injection patterns
            re.compile(r"\bOR\s+[\'\"0-9]\s*=\s*[\'\"0-9]", re.IGNORECASE),
            re.compile(r"\bAND\s+[\'\"0-9]\s*=\s*[\'\"0-9]", re.IGNORECASE),
            # String concatenation
            re.compile(r"\|\|", re.IGNORECASE),
            re.compile(r"CONCAT\s*\(", re.IGNORECASE),
            # Time-based injection patterns
            re.compile(r"SLEEP\s*\(", re.IGNORECASE),
            re.compile(r"WAITFOR\s+DELAY", re.IGNORECASE),
            re.compile(r"BENCHMARK\s*\(", re.IGNORECASE),
            # System table access
            re.compile(r"information_schema", re.IGNORECASE),
            re.compile(r"sys\.", re.IGNORECASE),
            # Dangerous functions
            re.compile(r"(?:LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE)", re.IGNORECASE),
        ]

        # Common SQL special characters and sequences that might indicate injection
        self.suspicious_tokens: Set[str] = {
            "'='",
            "''=''",
            "1=1",
            "1=2",
            "1=0",
            "or 1",
            "or true",
            "or false",
            "\\",
            "%27",
            "'--",
        }

    def _check_suspicious_tokens(self, query: str) -> bool:
        """Check for suspicious token combinations that might indicate SQL injection."""
        normalized_query = query.lower()
        return any(
            token.lower() in normalized_query for token in self.suspicious_tokens
        )

    def _check_quote_balance(self, query: str) -> bool:
        """Check if quotes are properly balanced in the query."""
        single_quotes = query.count("'") % 2
        double_quotes = query.count('"') % 2
        return single_quotes == 0 and double_quotes == 0

    def _check_expression_recursively(self, expr: exp.Expression) -> None:
        """
        Recursively check an expression and its children for SQL injection patterns.
        """
        # Convert the expression to a string for pattern matching
        expr_str = str(expr)

        # Check for pattern matches
        for pattern in self.patterns:
            match = pattern.search(expr_str)
            if match:
                raise SQLInjectionError(
                    f"Potential SQL injection detected - matches pattern: {pattern.pattern}"
                )

        # Check for suspicious tokens
        if self._check_suspicious_tokens(expr_str):
            raise SQLInjectionError(
                "Potential SQL injection detected - contains suspicious token combination"
            )

        # Special checks for different expression types
        if isinstance(expr, exp.Literal) and isinstance(expr.this, str):
            # Check string literals more thoroughly
            if not self._check_quote_balance(expr.this):
                raise SQLInjectionError(
                    "Potential SQL injection detected - unbalanced quotes in string literal"
                )

        elif isinstance(expr, exp.Select):
            # Additional checks specific to SELECT statements
            if any(isinstance(e, exp.Union) for e in expr.find_all(exp.Union)):
                # Verify UNION usage
                union_expr = next(expr.find_all(exp.Union))
                if not (
                    isinstance(union_expr.left, exp.Select)
                    and isinstance(union_expr.right, exp.Select)
                ):
                    raise SQLInjectionError(
                        "Potential SQL injection detected - suspicious UNION usage"
                    )

        # Recursively check all child expressions
        for child in expr.expressions:
            self._check_expression_recursively(child)

    def validate(self, parsed: exp.Expression) -> None:
        """
        Validates the given SQL query for potential SQL injection attempts.

        Args:
            parsed: The parsed SQL expression to validate

        Raises:
            SQLInjectionError: If potential SQL injection is detected
            ValueError: If the input is invalid
        """
        if not parsed:
            raise ValueError("Expression must not be empty")

        try:
            self._check_expression_recursively(parsed)
        except SQLInjectionError as e:
            raise e
        except Exception as e:
            raise ValueError(f"Invalid SQL expression: {str(e)}")
