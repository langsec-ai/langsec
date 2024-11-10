import pytest
from langsec import SQLSecurityGuard
from langsec.schema import (
    SecuritySchema,
    TableSchema,
    ColumnSchema,
)
from langsec.schema.sql import (
    JoinRule,
    QueryType,
    JoinType, 
    AggregationType
)

from langsec.schema import ColumnAccess


@pytest.fixture
def basic_schema():
    """Provides a basic security schema for testing."""
    return SecuritySchema(
        tables={
            "users": TableSchema(
                columns={
                    "id": ColumnSchema(access=ColumnAccess.READ),
                    "username": ColumnSchema(access=ColumnAccess.READ),
                    "email": ColumnSchema(access=ColumnAccess.DENIED),
                    "created_at": ColumnSchema(access=ColumnAccess.READ),
                    "column_1": ColumnSchema(
                        access=ColumnAccess.READ
                    ),  # Added for length test
                },
                max_rows=1000,
                require_where_clause=True,
                allowed_joins={
                    "orders": JoinRule(allowed_types={JoinType.INNER, JoinType.LEFT})
                },
            ),
            "orders": TableSchema(
                columns={
                    "id": ColumnSchema(access=ColumnAccess.READ),
                    "user_id": ColumnSchema(access=ColumnAccess.READ),
                    "amount": ColumnSchema(
                        access=ColumnAccess.READ,
                        allowed_aggregations={AggregationType.SUM, AggregationType.AVG},
                    ),
                },
                allowed_joins={
                    "users": JoinRule(allowed_types={JoinType.INNER, JoinType.LEFT})
                },
            ),
        },
        max_joins=2,
        max_query_length=500,
    )


@pytest.fixture
def complex_schema():
    """Provides a complex security schema for testing."""
    return SecuritySchema(
        tables={
            "users": TableSchema(
                columns={
                    "id": ColumnSchema(access=ColumnAccess.READ),
                    "username": ColumnSchema(access=ColumnAccess.READ),
                    "email": ColumnSchema(access=ColumnAccess.DENIED),
                    "created_at": ColumnSchema(access=ColumnAccess.READ),
                    # Add case statement columns
                    "order_frequency": ColumnSchema(access=ColumnAccess.READ),
                },
                max_rows=1000,
                require_where_clause=True,
                allowed_joins={
                    "orders": JoinRule(allowed_types={JoinType.INNER, JoinType.LEFT})
                },
            ),
            "orders": TableSchema(
                columns={
                    "id": ColumnSchema(access=ColumnAccess.READ),
                    "user_id": ColumnSchema(access=ColumnAccess.READ),
                    "amount": ColumnSchema(
                        access=ColumnAccess.READ,
                        allowed_aggregations={
                            AggregationType.SUM,
                            AggregationType.AVG,
                            AggregationType.COUNT,
                        },
                    ),
                    "product_id": ColumnSchema(access=ColumnAccess.READ),
                    "total_spent": ColumnSchema(
                        access=ColumnAccess.READ
                    ),  # Added for alias test
                    "order_count": ColumnSchema(
                        access=ColumnAccess.READ
                    ),  # Added for subquery
                },
                allowed_joins={
                    "users": JoinRule(allowed_types={JoinType.INNER, JoinType.LEFT}),
                    "products": JoinRule(allowed_types={JoinType.INNER, JoinType.LEFT}),
                },
            ),
            "products": TableSchema(
                columns={
                    "id": ColumnSchema(access=ColumnAccess.READ),
                    "name": ColumnSchema(access=ColumnAccess.READ),
                    "price": ColumnSchema(
                        access=ColumnAccess.READ,
                        allowed_aggregations={
                            AggregationType.AVG,
                            AggregationType.MIN,
                            AggregationType.MAX,
                        },
                    ),
                    "category": ColumnSchema(
                        access=ColumnAccess.READ,
                        allowed_aggregations={AggregationType.COUNT},
                    ),
                    "product_count": ColumnSchema(
                        access=ColumnAccess.READ
                    ),  # Added for aggregation
                    "avg_price": ColumnSchema(
                        access=ColumnAccess.READ
                    ),  # Added for aggregation
                    "total_sales": ColumnSchema(
                        access=ColumnAccess.READ
                    ),  # Added for aggregation
                    "max_product_price": ColumnSchema(
                        access=ColumnAccess.READ
                    ),  # Added for complex joins test
                },
                allowed_joins={
                    "orders": JoinRule(allowed_types={JoinType.INNER, JoinType.LEFT})
                },
                allow_group_by=True,
                allowed_group_by_columns={"category"},
            ),
        },
        max_joins=3,
        allow_subqueries=True,
        allow_unions=False,
        max_query_length=500,
        forbidden_keywords={
            "DROP",
            "DELETE",
            "TRUNCATE",
            "ALTER",
            "GRANT",
            "REVOKE",
            "EXECUTE",
            "EXEC",
        },
    )


@pytest.fixture
def security_guard(basic_schema):
    """Provides a configured SQLSecurityGuard instance."""
    return SQLSecurityGuard(schema=basic_schema)


@pytest.fixture
def complex_security_guard(complex_schema):
    """Provides a SQLSecurityGuard instance with complex configuration."""
    return SQLSecurityGuard(schema=complex_schema)


@pytest.fixture
def security_guard_no_subqueries(basic_schema):
    """Create a security guard with subqueries disabled."""
    basic_schema.allow_subqueries = False
    return SQLSecurityGuard(schema=basic_schema)


@pytest.fixture
def security_guard_multiple_types(basic_schema):
    """Create a security guard that allows multiple query types."""
    basic_schema.allowed_query_types = {QueryType.SELECT, QueryType.INSERT}
    return SQLSecurityGuard(schema=basic_schema)
