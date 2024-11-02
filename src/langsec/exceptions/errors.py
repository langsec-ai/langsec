class LangSecError(Exception):
    """Base exception for all langsec errors."""


class TableAccessError(LangSecError):
    """Raised when attempting to access unauthorized tables."""


class ColumnAccessError(LangSecError):
    """Raised when attempting to access unauthorized columns."""


class JoinViolationError(LangSecError):
    """Raised when join operations violate security rules."""


class QueryComplexityError(LangSecError):
    """Raised when query exceeds complexity limits."""


class SQLSyntaxError(LangSecError):
    """Raised when SQL syntax is invalid."""


class SQLInjectionError(LangSecError):
    """Raised when potential SQL injection is detected."""
