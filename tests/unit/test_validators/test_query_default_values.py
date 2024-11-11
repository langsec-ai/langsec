import pytest
from langsec.exceptions.errors import (
    AllowedJoinNotDefinedViolationError,
    TableAccessError,
    ColumnAccessError,
    JoinViolationError,
    QueryComplexityError,
)
from langsec.schema.sql import QueryType
from langsec.core.security import SQLSecurityGuard


class TestBasicQueriesWithDefaultContext:
    def test_simple_select(self, security_guard_allow_all):
        """Test basic SELECT query validation."""
        query = "SELECT id, username FROM users WHERE created_at > '2024-01-01'"
        assert security_guard_allow_all.validate_query(query)

    def test_denied_column(self, security_guard_deny_all):
        """Test that denied columns are caught."""
        query = "SELECT email FROM users WHERE created_at > '2024-01-01'"
        with pytest.raises(ColumnAccessError):
            security_guard_deny_all.validate_query(query)

    def test_missing_where_clause(self, security_guard_require_where_clause_all):
        """Test that missing WHERE clause is caught."""
        query = "SELECT id, username FROM users"
        with pytest.raises(QueryComplexityError):
            security_guard_require_where_clause_all.validate_query(query)


class TestColumnAccessWithDefaultContext:
    def test_allowed_column(self, security_guard_allow_all):
        """Test that allowed columns are allowed."""
        query = "SELECT id, username FROM users WHERE created_at > '2024-01-01'"
        assert security_guard_allow_all.validate_query(query)

    def test_denied_column(self, security_guard_deny_all):
        """Test that denied columns are caught."""
        query = "SELECT email FROM users WHERE created_at > '2024-01-01'"
        with pytest.raises(ColumnAccessError):
            security_guard_deny_all.validate_query(query)

    def test_allowed_aggregation(self, security_guard_allow_all):
        """Test that allowed aggregations are allowed."""
        query = "SELECT SUM(amount) as total_amount FROM orders"
        assert security_guard_allow_all.validate_query(query)

    def test_denied_aggregation(self, security_guard_deny_AVG):
        """Test that denied aggregations are caught."""
        query = "SELECT AVG(amount) as avg_amount FROM orders"
        with pytest.raises(QueryComplexityError):
            security_guard_deny_AVG.validate_query(query)

    def test_allowed_where_column(self, security_guard_allow_all):
        """Test that allowed WHERE columns are allowed."""
        query = "SELECT * FROM users WHERE created_at > '2024-01-01'"
        assert security_guard_allow_all.validate_query(query)

    def test_denied_where_column(self, security_deny_only_email_column):
        """Test that denied WHERE columns are caught."""
        query = "SELECT * FROM users WHERE email = 'a@a.com'"
        with pytest.raises(ColumnAccessError):
            security_deny_only_email_column.validate_query(query)

    def test_column_not_in_schema(self, security_guard_deny_all):
        """Test that columns not in the schema are caught."""
        query = "SELECT * FROM users WHERE foo = 'bar'"
        with pytest.raises(ColumnAccessError):
            security_guard_deny_all.validate_query(query)


class TestJoinsWithDefaultContext:
    def test_valid_joins(self, security_guard_allow_all):
        """Test that valid joins are allowed."""
        # Test RIGHT JOIN (equivalent to LEFT JOIN from orders perspective)
        query1 = """
            SELECT users.username, orders.amount
            FROM users
            RIGHT JOIN orders ON users.id = orders.user_id
            WHERE users.created_at > '2024-01-01'
        """
        security_guard_allow_all.validate_query(query1)  # Should not raise

        # Test LEFT JOIN
        query2 = """
            SELECT users.username, orders.amount
            FROM users
            LEFT JOIN orders ON users.id = orders.user_id
            WHERE users.created_at > '2024-01-01'
        """
        security_guard_allow_all.validate_query(query2)  # Should not raise

        # Test INNER JOIN
        query3 = """
            SELECT users.username, orders.amount
            FROM users
            INNER JOIN orders ON users.id = orders.user_id
            WHERE users.created_at > '2024-01-01'
        """
        security_guard_allow_all.validate_query(query3)  # Should not raise

    def test_allowed_join(self, security_guard_allow_all):
        """Test allowed JOIN operations."""
        query = """
            SELECT users.username, orders.amount 
            FROM users 
            INNER JOIN orders ON users.id = orders.user_id
            WHERE users.created_at > '2024-01-01'
        """
        assert security_guard_allow_all.validate_query(query)

    def test_invalid_join_type(self, security_guard_allow_all):
        """Test that invalid join types are caught."""
        # FULL JOIN is not allowed in the schema
        query = """
            SELECT users.username, orders.amount
            FROM users
            FULL JOIN orders ON users.id = orders.user_id
            WHERE users.created_at > '2024-01-01'
        """
        with pytest.raises(JoinViolationError):
            security_guard_allow_all.validate_query(query)


class TestAggregationsWithDefaultContext:
    def test_allowed_aggregation(self, security_guard_allow_all):
        """Test allowed aggregation functions."""
        query = """
            SELECT users.username, SUM(orders.amount) as total_amount
            FROM users 
            WHERE users.created_at > '2024-01-01'
            GROUP BY users.username
        """
        assert security_guard_allow_all.validate_query(query)

    def test_invalid_aggregation(self, security_guard_allow_all):
        """Test that invalid aggregations are caught."""
        query = """
            SELECT users.username, MIN(orders.amount) as min_amount
            FROM users 
            WHERE users.created_at > '2024-01-01'
            GROUP BY users.username
        """
        with pytest.raises(QueryComplexityError):
            security_guard_allow_all.validate_query(query)


class TestAliasesWithDefaultContext:
    def test_table_aliases(self, security_guard_allow_all):
        """Test that queries with table aliases are validated correctly."""
        query = """
            SELECT u.id, u.username 
            FROM users u
            WHERE u.created_at > '2024-01-01'
        """
        assert security_guard_allow_all.validate_query(query)

    def test_column_aliases(self, security_guard_allow_all):
        """Test that queries with column aliases are validated correctly."""
        query = """
            SELECT 
                users.username AS user_name,
                users.created_at AS registration_date
            FROM users
            WHERE users.created_at > '2024-01-01'
        """
        assert security_guard_allow_all.validate_query(query)

    def test_complex_aliases(self, security_guard_allow_all):
        """Test that queries with both table and column aliases in joins are validated."""
        query = """
            SELECT 
                u.username AS customer_name,
                o.amount AS order_total,
                o.id AS order_number
            FROM users u
            WHERE u.created_at > '2024-01-01'
        """
        assert security_guard_allow_all.validate_query(query)

    def test_aliased_aggregations(self, security_guard_allow_all):
        """Test that queries with aliases in aggregations are validated."""
        query = """
            SELECT 
                users.username AS customer,
                COUNT(orders.id) AS total_orders,
                SUM(orders.amount) AS total_spent
            FROM users
            WHERE users.created_at > '2024-01-01'
            GROUP BY users.username
        """
        assert security_guard_allow_all.validate_query(query)

    def test_denied_column_with_alias(self, security_deny_only_email_column):
        """Test that denied columns are caught even when aliased."""
        query = """
            SELECT 
                users.email AS contact_info
            FROM users
            WHERE users.created_at > '2024-01-01'
        """
        with pytest.raises(ColumnAccessError):
            security_deny_only_email_column.validate_query(query)

    def test_nonexistent_column_with_alias(self, security_guard_deny_all):
        """Test that nonexistent columns are caught even when aliased."""
        query = """
            SELECT 
                users.nonexistent_column AS some_alias
            FROM users
            WHERE users.created_at > '2024-01-01'
        """
        with pytest.raises(ColumnAccessError):
            security_guard_deny_all.validate_query(query)
