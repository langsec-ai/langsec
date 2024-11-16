import pytest
from langsec.exceptions.errors import QueryComplexityError

def test_forbidden_keyword_drop(security_guard):
    with pytest.raises(QueryComplexityError, match="Forbidden keyword found: DROP"):
        security_guard.validate_query("DROP TABLE Genres;")

def test_forbidden_keyword_truncate(security_guard):
    with pytest.raises(QueryComplexityError, match="Forbidden keyword found: TRUNCATE"):
        security_guard.validate_query("TRUNCATE TABLE orders;")

def test_forbidden_keyword_alter(security_guard):
    with pytest.raises(QueryComplexityError, match="Forbidden keyword found: ALTER"):
        security_guard.validate_query("ALTER TABLE users ADD COLUMN age INT;")

def test_forbidden_keyword_grant(security_guard):
    with pytest.raises(QueryComplexityError, match="Forbidden keyword found: GRANT"):
        security_guard.validate_query("GRANT SELECT ON users TO role;")

def test_forbidden_keyword_revoke(security_guard):
    with pytest.raises(QueryComplexityError, match="Forbidden keyword found: REVOKE"):
        security_guard.validate_query("REVOKE SELECT ON users FROM role;")

def test_forbidden_keyword_execute(security_guard):
    with pytest.raises(QueryComplexityError, match="Forbidden keyword found: EXECUTE"):
        security_guard.validate_query("EXECUTE some_procedure;")

def test_forbidden_keyword_sysadmin(security_guard):
    with pytest.raises(QueryComplexityError, match="Forbidden keyword found: SYSADMIN"):
        security_guard.validate_query("SYSADMIN some_command;")

def test_forbidden_keyword_dbadmin(security_guard):
    with pytest.raises(QueryComplexityError, match="Forbidden keyword found: DBADMIN"):
        security_guard.validate_query("DBADMIN some_command;")
