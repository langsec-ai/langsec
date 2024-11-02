import pytest
from langsec.exceptions.errors import QueryComplexityError, ColumnAccessError


class TestComplexQueries:
    def test_nested_queries(self, complex_security_guard):
        """Test nested query validation."""
        query = """
            SELECT 
                u.username,
                (SELECT COUNT(*) FROM orders o WHERE o.user_id = u.id) as order_count
            FROM users u
            WHERE u.created_at > '2024-01-01'
        """
        assert complex_security_guard.validate_query(query)

    def test_complex_joins_and_aggregations(self, complex_security_guard):
        """Test complex joins with aggregations."""
        query = """
            SELECT 
                u.username,
                COUNT(o.id) as order_count,
                AVG(o.amount) as avg_amount,
                MAX(p.price) as max_product_price
            FROM users u
            LEFT JOIN orders o ON u.id = o.user_id
            LEFT JOIN products p ON o.product_id = p.id
            WHERE u.created_at > '2024-01-01'
            GROUP BY u.username
            HAVING COUNT(o.id) > 5
        """
        assert complex_security_guard.validate_query(query)

    def test_complex_group_by(self, complex_security_guard):
        """Test complex GROUP BY scenarios."""
        query = """
            SELECT 
                p.category,
                COUNT(*) as product_count,
                AVG(p.price) as avg_price,
                SUM(o.amount) as total_sales
            FROM products p
            LEFT JOIN orders o ON p.id = o.product_id
            GROUP BY p.category
            HAVING AVG(p.price) > 100
        """
        assert complex_security_guard.validate_query(query)


class TestEdgeCases:
    def test_query_with_aliases(self, complex_security_guard):
        """Test queries using table and column aliases."""
        query = """
            SELECT 
                u.username as user,
                COALESCE(SUM(o.amount), 0) as total_spent
            FROM users u
            LEFT JOIN orders o ON u.id = o.user_id
            WHERE u.created_at > '2024-01-01'
            GROUP BY u.username
        """
        assert complex_security_guard.validate_query(query)

    def test_query_with_case_statements(self, complex_security_guard):
        """Test queries using CASE statements."""
        query = """
            SELECT 
                u.username,
                CASE 
                    WHEN COUNT(o.id) > 10 THEN 'High'
                    WHEN COUNT(o.id) > 5 THEN 'Medium'
                    ELSE 'Low'
                END as order_frequency
            FROM users u
            LEFT JOIN orders o ON u.id = o.user_id
            WHERE u.created_at > '2024-01-01'
            GROUP BY u.username
        """
        assert complex_security_guard.validate_query(query)


class TestErrorScenarios:
    def test_exceed_query_length(self, complex_security_guard):
        """Test query length limit."""
        long_query = "SELECT * FROM users WHERE " + " AND ".join(
            [f"column_{i} = {i}" for i in range(1000)]
        )
        with pytest.raises(QueryComplexityError):
            complex_security_guard.validate_query(long_query)

    def test_invalid_column_combinations(self, complex_security_guard):
        """Test invalid column combination scenarios."""
        query = """
            SELECT 
                users.email,
                SUM(orders.amount) as total
            FROM users
            JOIN orders ON users.id = orders.user_id
            WHERE users.created_at > '2024-01-01'
            GROUP BY users.email
        """
        with pytest.raises(ColumnAccessError):
            complex_security_guard.validate_query(query)
