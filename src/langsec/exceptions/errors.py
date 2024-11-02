class LangSecError(Exception):
    """Base exception for all langsec errors."""
    pass

class TableAccessError(LangSecError):
    """Raised when attempting to access unauthorized tables."""
    pass

class ColumnAccessError(LangSecError):
    """Raised when attempting to access unauthorized columns."""
    pass

class JoinViolationError(LangSecError):
    """Raised when join operations violate security rules."""
    pass

class QueryComplexityError(LangSecError):
    """Raised when query exceeds complexity limits."""
    pass

class SQLSyntaxError(LangSecError):
    """Raised when SQL syntax is invalid."""
    pass

class SQLInjectionError(LangSecError):
    """Raised when potential SQL injection is detected."""
    pass