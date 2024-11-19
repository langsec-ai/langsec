import pytest
from langsec.exceptions.errors import SQLInjectionError, QueryComplexityError, TableAccessError


class TestSQLInjection:
    def test_basic_injection(self, security_guard):
        """Test basic SQL injection prevention."""
        queries = [
            "SELECT * FROM users WHERE id = 1 OR 1=1",
            "SELECT * FROM users -- Drop everything",
            "SELECT * FROM users /* malicious comment */",
            "SELECT * FROM users UNION SELECT * FROM secrets",
        ]
        for query in queries:
            with pytest.raises((SQLInjectionError, QueryComplexityError, TableAccessError)):
                security_guard.validate_query(query)
