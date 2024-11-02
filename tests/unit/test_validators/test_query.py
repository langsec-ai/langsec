import pytest
from langsec.exceptions.errors import (
    TableAccessError,
    ColumnAccessError,
    JoinViolationError,
    QueryComplexityError
)

class TestBasicQueries:
    def test_simple_select(self, security_guard):
        """Test basic SELECT query validation."""
        query = "SELECT id, username FROM users WHERE created_at > '2024-01-01'"
        assert security_guard.validate_query(query)

    def test_denied_column(self, security_guard):
        """Test that denied columns are caught."""
        query = "SELECT email FROM users WHERE created_at > '2024-01-01'"
        with pytest.raises(ColumnAccessError):
            security_guard.validate_query(query)

    def test_missing_where_clause(self, security_guard):
        """Test that missing WHERE clause is caught."""
        query = "SELECT id, username FROM users"
        with pytest.raises(QueryComplexityError):
            security_guard.validate_query(query)

    def test_invalid_table(self, security_guard):
        """Test that invalid tables are caught."""
        query = "SELECT * FROM nonexistent_table"
        with pytest.raises(TableAccessError):
            security_guard.validate_query(query)

class TestJoins:
    def test_allowed_join(self, security_guard):
        """Test allowed JOIN operations."""
        query = """
            SELECT users.username, orders.amount 
            FROM users 
            INNER JOIN orders ON users.id = orders.user_id
            WHERE users.created_at > '2024-01-01'
        """
        assert security_guard.validate_query(query)

    def test_invalid_join_type(self, security_guard):
        """Test that invalid join types are caught."""
        query = """
            SELECT users.username, orders.amount 
            FROM users 
            RIGHT JOIN orders ON users.id = orders.user_id
            WHERE users.created_at > '2024-01-01'
        """
        with pytest.raises(JoinViolationError):
            security_guard.validate_query(query)

    def test_too_many_joins(self, security_guard):
        """Test join limit enforcement."""
        query = """
            SELECT u.username, o.amount, p.name 
            FROM users u
            JOIN orders o ON u.id = o.user_id
            JOIN products p ON o.product_id = p.id
            JOIN categories c ON p.category_id = c.id
            WHERE u.created_at > '2024-01-01'
        """
        with pytest.raises(JoinViolationError):
            security_guard.validate_query(query)

class TestAggregations:
    def test_allowed_aggregation(self, security_guard):
        """Test allowed aggregation functions."""
        query = """
            SELECT users.username, SUM(orders.amount) as total_amount
            FROM users 
            JOIN orders ON users.id = orders.user_id
            WHERE users.created_at > '2024-01-01'
            GROUP BY users.username
        """
        assert security_guard.validate_query(query)

    def test_invalid_aggregation(self, security_guard):
        """Test that invalid aggregations are caught."""
        query = """
            SELECT users.username, MIN(orders.amount) as min_amount
            FROM users 
            JOIN orders ON users.id = orders.user_id
            WHERE users.created_at > '2024-01-01'
            GROUP BY users.username
        """
        with pytest.raises(QueryComplexityError):
            security_guard.validate_query(query)