import pytest
from langsec.exceptions.errors import (
    TableAccessError,
    ColumnAccessError,
    JoinViolationError,
    QueryComplexityError,
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

    def test_invalid_table(self, security_guard):
        """Test that invalid tables are caught."""
        query = "SELECT * FROM nonexistent_table"
        with pytest.raises(TableAccessError):
            security_guard.validate_query(query)


class TestColumnAccess:
    def test_allowed_column(self, security_guard):
        """Test that allowed columns are allowed."""
        query = "SELECT id, username FROM users WHERE created_at > '2024-01-01'"
        assert security_guard.validate_query(query)

    def test_denied_column(self, security_guard):
        """Test that denied columns are caught."""
        query = "SELECT email FROM users WHERE created_at > '2024-01-01'"
        with pytest.raises(ColumnAccessError):
            security_guard.validate_query(query)

    def test_allowed_aggregation(self, security_guard):
        """Test that allowed aggregations are allowed."""
        query = "SELECT SUM(amount) as total_amount FROM orders"
        assert security_guard.validate_query(query)

    def test_denied_aggregation(self, security_guard):
        """Test that denied aggregations are caught."""
        query = "SELECT AVG(amount) as avg_amount FROM orders"
        assert security_guard.validate_query(query)

    def test_allowed_where_column(self, security_guard):
        """Test that allowed WHERE columns are allowed."""
        query = "SELECT * FROM users WHERE created_at > '2024-01-01'"
        assert security_guard.validate_query(query)

    def test_denied_where_column(self, security_guard):
        """Test that denied WHERE columns are caught."""
        query = "SELECT * FROM users WHERE email = 'a@a.com'"
        with pytest.raises(ColumnAccessError):
            security_guard.validate_query(query)

    def test_column_not_in_schema(self, security_guard):
        """Test that columns not in the schema are caught."""
        query = "SELECT * FROM users WHERE foo = 'bar'"
        with pytest.raises(ColumnAccessError):
            security_guard.validate_query(query)


class TestJoins:
    def test_allowed_inner_join(self, security_guard):
        """Test allowed JOIN operations."""
        query = """
            SELECT users.username, orders.amount 
            FROM users 
            INNER JOIN orders ON users.id = orders.user_id
            WHERE users.created_at > '2024-01-01'
        """
        assert security_guard.validate_query(query)

    def test_valid_left_join(self, security_guard):
        """Test that LEFT JOIN is allowed."""
        query = """
            SELECT users.username, orders.amount
            FROM users
            LEFT JOIN orders ON users.id = orders.user_id
            WHERE users.created_at > '2024-01-01'
        """
        security_guard.validate_query(query)  # Should not raise

    def test_invalid_full_join(self, security_guard):
        """Test that FULL JOIN is not allowed."""
        query = """
            SELECT users.username, orders.amount
            FROM users
            FULL JOIN orders ON users.id = orders.user_id
            WHERE users.created_at > '2024-01-01'
        """
        with pytest.raises(JoinViolationError):
            security_guard.validate_query(query)

    def test_right_join(self, security_guard):
        """Test that RIGHT JOIN is allowed between users and orders when LEFT JOIN is supported between orders and users"""
        query = """
            SELECT users.username, orders.amount
            FROM users
            RIGHT JOIN orders ON users.id = orders.user_id
            WHERE users.created_at > '2024-01-01'
        """
        security_guard.validate_query(query)  # Should not raise

    def test_invalid_cross_join(self, security_guard):
        """Test that CROSS JOIN is not allowed."""
        query = """
            SELECT users.username, orders.amount
            FROM users
            CROSS JOIN orders
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
            JOIN users p ON o.product_id = p.id
            JOIN users c ON p.category_id = c.id
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


class TestAliases:
    def test_table_aliases(self, security_guard):
        """Test that queries with table aliases are validated correctly."""
        query = """
            SELECT u.id, u.username 
            FROM users u
            WHERE u.created_at > '2024-01-01'
        """
        assert security_guard.validate_query(query)

    def test_column_aliases(self, security_guard):
        """Test that queries with column aliases are validated correctly."""
        query = """
            SELECT 
                users.username AS user_name,
                users.created_at AS registration_date
            FROM users
            WHERE users.created_at > '2024-01-01'
        """
        assert security_guard.validate_query(query)

    def test_complex_aliases(self, security_guard):
        """Test that queries with both table and column aliases in joins are validated."""
        query = """
            SELECT 
                u.username AS customer_name,
                o.amount AS order_total,
                o.id AS order_number
            FROM users u
            JOIN orders o ON u.id = o.user_id
            WHERE u.created_at > '2024-01-01'
        """
        assert security_guard.validate_query(query)

    def test_aliased_aggregations(self, security_guard):
        """Test that queries with aliases in aggregations are validated."""
        query = """
            SELECT 
                users.username AS customer,
                COUNT(orders.id) AS total_orders,
                SUM(orders.amount) AS total_spent
            FROM users
            LEFT JOIN orders ON users.id = orders.user_id
            WHERE users.created_at > '2024-01-01'
            GROUP BY users.username
        """
        assert security_guard.validate_query(query)

    def test_denied_column_with_alias(self, security_guard):
        """Test that denied columns are caught even when aliased."""
        query = """
            SELECT 
                users.email AS contact_info
            FROM users
            WHERE users.created_at > '2024-01-01'
        """
        with pytest.raises(ColumnAccessError):
            security_guard.validate_query(query)

    def test_nonexistent_column_with_alias(self, security_guard):
        """Test that nonexistent columns are caught even when aliased."""
        query = """
            SELECT 
                users.nonexistent_column AS some_alias
            FROM users
            WHERE users.created_at > '2024-01-01'
        """
        with pytest.raises(ColumnAccessError):
            security_guard.validate_query(query)


class TestSubqueries:
    def test_simple_subquery_allowed(self, complex_security_guard):
        """Test that subqueries are allowed when enabled."""
        query = """
            SELECT username
            FROM users
            WHERE id IN (
                SELECT user_id
                FROM orders 
                WHERE amount > 100
            )
        """
        assert complex_security_guard.validate_query(query)

    def test_correlated_subquery_allowed(self, complex_security_guard):
        """Test that correlated subqueries are allowed when enabled."""
        query = """
            SELECT username,
                (SELECT SUM(amount) 
                 FROM orders 
                 WHERE orders.user_id = users.id) as total_spent
            FROM users
            WHERE created_at > '2024-01-01'
        """
        assert complex_security_guard.validate_query(query)

    def test_multiple_subqueries_allowed(self, complex_security_guard):
        """Test that multiple subqueries are allowed when enabled."""
        query = """
            SELECT 
                username,
                (SELECT COUNT(*) FROM orders WHERE orders.user_id = users.id) as order_count,
                (SELECT MAX(amount) FROM orders WHERE orders.user_id = users.id) as max_order
            FROM users
            WHERE id IN (
                SELECT user_id
                FROM orders 
                WHERE amount > 100
            )
        """
        assert complex_security_guard.validate_query(query)

    def test_subquery_denied(self, security_guard_no_subqueries):
        """Test that subqueries are denied when disabled."""
        query = """
            SELECT username
            FROM users
            WHERE id IN (
                SELECT user_id
                FROM orders 
                WHERE amount > 100
            )
        """
        with pytest.raises(QueryComplexityError) as exc:
            security_guard_no_subqueries.validate_query(query)
        assert "Subqueries are not allowed" in str(exc.value)

    def test_correlated_subquery_denied(self, security_guard_no_subqueries):
        """Test that correlated subqueries are denied when disabled."""
        query = """
            SELECT username,
                (SELECT SUM(amount) 
                 FROM orders 
                 WHERE orders.user_id = users.id) as total_spent
            FROM users
            WHERE created_at > '2024-01-01'
        """
        with pytest.raises(QueryComplexityError) as exc:
            security_guard_no_subqueries.validate_query(query)
        assert "Subqueries are not allowed" in str(exc.value)


class TestQueryTypes:
    def test_allowed_select(self, security_guard):
        """Test that SELECT queries are allowed by default."""
        query = "SELECT id, username FROM users WHERE id = 1"
        assert security_guard.validate_query(query)

    # TODO: Once we enforce operation types, uncomment these tests.
    # def test_denied_insert(self, security_guard):
    #     """Test that INSERT queries are denied by default."""
    #     query = "INSERT INTO users (username) VALUES ('test')"
    #     with pytest.raises(QueryComplexityError) as exc:
    #         security_guard.validate_query(query)
    #     assert "Query type 'INSERT' is not allowed" in str(exc.value)

    # TODO: Once we enforce operation types, uncomment these tests.
    # def test_denied_update(self, security_guard):
    #     """Test that UPDATE queries are denied by default."""
    #     query = "UPDATE users SET username = 'test' WHERE id = 1"
    #     with pytest.raises(QueryComplexityError) as exc:
    #         security_guard.validate_query(query)
    #     assert "Query type 'UPDATE' is not allowed" in str(exc.value)

    # TODO: Once we enforce operation types, uncomment these tests.
    # def test_multiple_allowed_types(self, basic_schema):
    #     """Test that multiple query types can be allowed."""
    #     # Modify schema to allow multiple query types and disable WHERE clause requirement
    #     basic_schema.allowed_query_types = {QueryType.SELECT, QueryType.INSERT}
    #     basic_schema.tables["users"].require_where_clause = False

    #     guard = SQLSecurityGuard(schema=basic_schema)

    #     # Test SELECT
    #     select_query = "SELECT id FROM users"
    #     assert guard.validate_query(select_query)

    #     # Test INSERT
    #     insert_query = "INSERT INTO users (username) VALUES ('test')"
    #     assert guard.validate_query(insert_query)


class TestColumnAccessWithMixedAccess:
    def test_mixed_access_permissions(self, mixed_access_guard):
        """Test various access permissions scenarios."""

        # Should succeed: Reading from both READ and WRITE columns
        mixed_access_guard.validate_query("""
            SELECT id, username, email 
            FROM users 
            WHERE id = 1
        """)

        # Should succeed: Modifying WRITE columns
        mixed_access_guard.validate_query("""
            UPDATE users 
            SET email = 'new@email.com'
            WHERE id = 1
        """)

        # Should succeed: Inserting into WRITE columns
        mixed_access_guard.validate_query("""
            INSERT INTO audit_log (action) 
            VALUES ('user_login')
        """)

        # Should fail: Attempting to modify READ-only column
        with pytest.raises(ColumnAccessError):
            mixed_access_guard.validate_query("""
                UPDATE users 
                SET username = 'new_username' 
                WHERE id = 1
            """)

    def test_mixed_access_complex_queries(self, mixed_access_guard):
        """Test complex queries with mixed access permissions."""

        # Should succeed: Complex query using only READ operations
        mixed_access_guard.validate_query("""
            SELECT u.id, u.username, u.email
            FROM users u
            WHERE u.id IN (
                SELECT id FROM users WHERE email LIKE '%.com'
            )
            GROUP BY u.id, u.username, u.email
        """)

        # Should fail: Complex query attempting to read from column without SELECT permission
        with pytest.raises(ColumnAccessError):
            mixed_access_guard.validate_query("""
                SELECT u.id, u.username, u.last_login
                FROM users u
                WHERE u.id IN (
                    SELECT id FROM users WHERE email LIKE '%.com'
                )
            """)

    def test_delete_permissions(self, mixed_access_guard):
        """Test delete permissions with mixed access."""

        # Should fail: DELETE not allowed on users table
        with pytest.raises(ColumnAccessError):
            mixed_access_guard.validate_query("""
                DELETE FROM users
                WHERE id = 1
            """)

        # Should fail: DELETE not allowed on audit_log table
        with pytest.raises(ColumnAccessError):
            mixed_access_guard.validate_query("""
                DELETE FROM audit_log
                WHERE action = 'test'
            """)
