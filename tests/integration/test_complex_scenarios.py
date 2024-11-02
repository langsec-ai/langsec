import pytest
from langsec.exceptions.errors import QueryComplexityError, ColumnAccessError


class TestComplexQueries:
    def test_nested_queries(self, complex_security_guard):
        """Test nested query validation."""
        query = """
            SELECT 
                users.username,
                (SELECT COUNT(*) FROM orders WHERE orders.user_id = users.id) as order_count
            FROM users
            WHERE users.created_at > '2024-01-01'
        """
        assert complex_security_guard.validate_query(query)

    def test_complex_joins_and_aggregations(self, complex_security_guard):
        """Test complex joins with aggregations."""
        query = """
            SELECT 
                users.username,
                COUNT(orders.id) as order_count,
                AVG(orders.amount) as avg_amount,
                MAX(products.price) as max_product_price
            FROM users
            LEFT JOIN orders ON users.id = orders.user_id
            LEFT JOIN products ON orders.product_id = products.id
            WHERE users.created_at > '2024-01-01'
            GROUP BY users.username
            HAVING COUNT(orders.id) > 5
        """
        assert complex_security_guard.validate_query(query)

    def test_complex_group_by(self, complex_security_guard):
        """Test complex GROUP BY scenarios."""
        query = """
            SELECT 
                products.category,
                COUNT(*) as product_count,
                AVG(products.price) as avg_price,
                SUM(orders.amount) as total_sales
            FROM products
            LEFT JOIN orders ON products.id = orders.product_id
            GROUP BY products.category
            HAVING AVG(products.price) > 100
        """
        assert complex_security_guard.validate_query(query)


class TestEdgeCases:
    def test_query_with_aliases(self, complex_security_guard):
        """Test queries using column aliases."""
        query = """
                SELECT 
                    users.username as user,
                    COALESCE(SUM(orders.amount), 0) as total_spent
                FROM users
                LEFT JOIN orders ON users.id = orders.user_id
                WHERE users.created_at > '2024-01-01'
                GROUP BY users.username
            """
        assert complex_security_guard.validate_query(query)

    def test_query_with_case_statements(self, complex_security_guard):
        """Test queries using CASE statements."""
        query = """
            SELECT 
                users.username,
                CASE 
                    WHEN COUNT(orders.id) > 10 THEN 'High'
                    WHEN COUNT(orders.id) > 5 THEN 'Medium'
                    ELSE 'Low'
                END as order_frequency
            FROM users
            LEFT JOIN orders ON users.id = orders.user_id
            WHERE users.created_at > '2024-01-01'
            GROUP BY users.username
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
