import re
from typing import List, Pattern
from ..exceptions.errors import SQLInjectionError

class SQLInjectionValidator:
    def __init__(self):
        self.patterns: List[Pattern] = [
            re.compile(r";\s*DROP\s+TABLE", re.IGNORECASE),
            re.compile(r";\s*DELETE\s+FROM", re.IGNORECASE),
            re.compile(r";\s*INSERT\s+INTO", re.IGNORECASE),
            re.compile(r";\s*UPDATE\s+", re.IGNORECASE),
            re.compile(r"--", re.IGNORECASE),
            re.compile(r"/\*.*?\*/", re.IGNORECASE|re.DOTALL),
            re.compile(r"UNION\s+ALL\s+SELECT", re.IGNORECASE),
            re.compile(r"UNION\s+SELECT", re.IGNORECASE),
            re.compile(r"EXEC\s*\(", re.IGNORECASE),
            re.compile(r"EXECUTE\s*\(", re.IGNORECASE),
            re.compile(r"xp_cmdshell", re.IGNORECASE),
            re.compile(r"sp_executesql", re.IGNORECASE),
        ]
        
    def validate(self, query: str) -> bool:
        """
        Validates a query for common SQL injection patterns.
        Returns True if safe, raises SQLInjectionError if potentially malicious.
        """
        for pattern in self.patterns:
            if pattern.search(query):
                raise SQLInjectionError(
                    "Potential SQL injection detected - matches pattern: " + 
                    pattern.pattern
                )
        return True