import re
from typing import List, Pattern, Set
from ..exceptions.errors import SQLInjectionError


class SQLInjectionValidator:
    def __init__(self):
        # Common SQL injection patterns
        self.patterns: List[Pattern] = [
            # Multiple query execution
            re.compile(
                r";\s*(?:DROP|DELETE|INSERT|UPDATE|CREATE|ALTER|TRUNCATE)\s+",
                re.IGNORECASE,
            ),
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
            ";",
            "';",
            "\\",
            "%27",
            "'--",
        }

    def _check_suspicious_tokens(self, query: str) -> bool:
        """Check for suspicious token combinations that might indicate SQL injection."""
        normalized_query = query.lower()
        for token in self.suspicious_tokens:
            if token.lower() in normalized_query:
                return True
        return False

    def _check_quote_balance(self, query: str) -> bool:
        """Check if quotes are properly balanced in the query."""
        single_quotes = query.count("'") % 2
        double_quotes = query.count('"') % 2
        return single_quotes == 0 and double_quotes == 0

    def validate(self, query: str) -> bool:
        """
        Validates a query for SQL injection patterns.
        Returns True if safe, raises SQLInjectionError if potentially malicious.

        Args:
            query: The SQL query string to validate

        Returns:
            bool: True if the query is considered safe

        Raises:
            SQLInjectionError: If potential SQL injection is detected
        """
        if not query or not isinstance(query, str):
            raise ValueError("Query must be a non-empty string")

        # Check for pattern matches
        for pattern in self.patterns:
            match = pattern.search(query)
            if match:
                raise SQLInjectionError(
                    f"Potential SQL injection detected - matches pattern: {pattern.pattern}"
                )

        # Check for suspicious tokens
        if self._check_suspicious_tokens(query):
            raise SQLInjectionError(
                "Potential SQL injection detected - contains suspicious token combination"
            )

        # Check quote balance
        if not self._check_quote_balance(query):
            raise SQLInjectionError(
                "Potential SQL injection detected - unbalanced quotes"
            )

        return True
