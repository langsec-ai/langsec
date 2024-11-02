import pytest
from langsec.exceptions.errors import SQLInjectionError, SQLSyntaxError


class TestSQLInjection:
    def test_basic_injection(self, security_guard):
        """Test basic SQL injection prevention."""
        queries = [
            "SELECT * FROM users; DROP TABLE users",
            "SELECT * FROM users WHERE id = 1 OR 1=1",
            "SELECT * FROM users -- Drop everything",
            "SELECT * FROM users /* malicious comment */",
            "SELECT * FROM users UNION SELECT * FROM secrets",
        ]
        for query in queries:
            with pytest.raises(SQLInjectionError):
                security_guard.validate_query(query)

    def test_complex_injection(self, security_guard):
        """Test more complex SQL injection patterns."""
        queries = [
            """SELECT * FROM users WHERE username = '' OR '1'='1'""",
            """SELECT * FROM users WHERE id = 1; EXEC xp_cmdshell('dir')""",
            """SELECT * FROM users WHERE id = 1; EXECUTE('DROP TABLE users')""",
        ]
        for query in queries:
            with pytest.raises((SQLInjectionError, SQLSyntaxError)):
                security_guard.validate_query(query)
