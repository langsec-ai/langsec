import pytest
from langsec import SQLSecurityGuard
from langsec.schema.security_schema import (
    SecuritySchema,
    TableSchema,
    ColumnSchema,
)
from langsec.schema.sql.enums import (
    JoinType, 
    AggregationType,
    Access
)

@pytest.fixture
def security_schema_allow_all():
    """Provides a security schema that allows most operations."""
    default_table_schema = TableSchema(
        default_allowed_join={
            JoinType.CROSS, 
            JoinType.INNER, 
            JoinType.RIGHT, 
            JoinType.LEFT
        }
    )
    
    default_column_schema = ColumnSchema(
        access=Access.READ,
        allowed_aggregations={AggregationType.SUM, AggregationType.COUNT}
    )
    
    return SecuritySchema(
        default_table_security_schema=default_table_schema,
        default_column_security_schema=default_column_schema
    )

@pytest.fixture
def security_guard_allow_all(security_schema_allow_all):
    """Provides a security guard with default table and column security schemas."""
    return SQLSecurityGuard(security_schema_allow_all)

@pytest.fixture
def security_guard_deny_AVG():
    """Provides a security guard that denies AVG aggregations."""
    default_table_schema = TableSchema(
        allowed_joins={},
        default_allowed_join=None
    )
    
    default_column_schema = ColumnSchema(
        access=Access.READ,
        allowed_aggregations={AggregationType.SUM}
    )
    
    security_schema = SecuritySchema(
        default_table_security_schema=default_table_schema,
        default_column_security_schema=default_column_schema
    )
    
    return SQLSecurityGuard(security_schema)

@pytest.fixture
def security_guard_deny_all():
    """Provides a security guard that denies most operations."""
    default_table_schema = TableSchema(
        allowed_joins={},
        default_allowed_join=None
    )
    
    default_column_schema = ColumnSchema(
        access=Access.DENIED,
        allowed_aggregations=set()
    )
    
    security_schema = SecuritySchema(
        default_table_security_schema=default_table_schema,
        default_column_security_schema=default_column_schema
    )
    
    return SQLSecurityGuard(security_schema)

@pytest.fixture
def security_guard_require_where_clause_all():
    """Provides a security guard that requires WHERE clauses."""
    default_table_schema = TableSchema(
        allowed_joins={},
        default_allowed_join=None
    )
    
    default_column_schema = ColumnSchema(
        access=Access.READ,
        allowed_aggregations=set()
    )
    
    security_schema = SecuritySchema(
        default_table_security_schema=default_table_schema,
        default_column_security_schema=default_column_schema
    )
    
    return SQLSecurityGuard(security_schema)

@pytest.fixture
def basic_schema():
    """Provides a basic security schema for testing."""
    return SecuritySchema(
        tables={
            "users": TableSchema(
                columns={
                    "id": ColumnSchema(access=Access.READ),
                    "username": ColumnSchema(access=Access.READ),
                    "created_at": ColumnSchema(access=Access.READ),
                    "column_1": ColumnSchema(access=Access.READ),
                },
                allowed_joins={
                    "orders": {JoinType.INNER, JoinType.LEFT}
                },
                default_allowed_join=None
            ),
            "orders": TableSchema(
                columns={
                    "id": ColumnSchema(access=Access.READ),
                    "user_id": ColumnSchema(access=Access.READ),
                    "amount": ColumnSchema(
                        access=Access.READ,
                        allowed_aggregations={AggregationType.SUM, AggregationType.AVG},
                    ),
                },
                allowed_joins={
                    "users": {JoinType.INNER, JoinType.LEFT}
                },
                default_allowed_join=None
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
                    "id": ColumnSchema(access=Access.READ),
                    "username": ColumnSchema(access=Access.READ),
                    "created_at": ColumnSchema(access=Access.READ),
                    "order_frequency": ColumnSchema(access=Access.READ),
                },
                allowed_joins={
                    "orders": {JoinType.INNER, JoinType.LEFT},
                    "products": {JoinType.INNER, JoinType.LEFT}
                },
                default_allowed_join=None
            ),
            "orders": TableSchema(
                columns={
                    "id": ColumnSchema(access=Access.READ),
                    "user_id": ColumnSchema(access=Access.READ),
                    "amount": ColumnSchema(
                        access=Access.READ,
                        allowed_aggregations={
                            AggregationType.MAX,
                            AggregationType.SUM,
                            AggregationType.AVG,
                            AggregationType.COUNT,
                        },
                    ),
                    "product_id": ColumnSchema(access=Access.READ),
                    "total_spent": ColumnSchema(access=Access.READ),
                    "order_count": ColumnSchema(access=Access.READ),
                },
                allowed_joins={
                    "users": {JoinType.INNER, JoinType.LEFT},
                    "products": {JoinType.INNER, JoinType.LEFT},
                },
                default_allowed_join=None
            ),
            "products": TableSchema(
                columns={
                    "id": ColumnSchema(access=Access.READ),
                    "name": ColumnSchema(access=Access.READ),
                    "price": ColumnSchema(
                        access=Access.READ,
                        allowed_aggregations={
                            AggregationType.AVG,
                            AggregationType.MIN,
                            AggregationType.MAX,
                        },
                    ),
                    "category": ColumnSchema(
                        access=Access.READ,
                        allowed_aggregations={AggregationType.COUNT},
                    ),
                    "product_count": ColumnSchema(access=Access.READ),
                    "avg_price": ColumnSchema(access=Access.READ),
                    "total_sales": ColumnSchema(access=Access.READ),
                    "max_product_price": ColumnSchema(access=Access.READ),
                },
                allowed_joins={
                    "orders": {JoinType.INNER, JoinType.LEFT}
                },
                default_allowed_join=None
            ),
        },
        max_joins=3,
        allow_subqueries=True,
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
def security_deny_only_email_column(security_schema_allow_all: SecuritySchema):
    """Creates a security guard that denies access only to the email column."""
    security_schema_allow_all.tables = {
        "users": TableSchema(
            columns={
                "email": ColumnSchema(access=Access.DENIED),
            },
            default_allowed_join=None
        )
    }

    return SQLSecurityGuard(security_schema_allow_all)

@pytest.fixture
def mixed_access_schema():
    """
    Provides a security schema with mixed read/write access:
    - users table:
        - id: read-only (SELECT only)
        - username: read-only (SELECT only)
        - email: write (SELECT, UPDATE)
        - last_login: write (UPDATE, INSERT only - no SELECT)
    - audit_log table:
        - id: read-only (SELECT only)
        - action: write (SELECT, INSERT only)
        - timestamp: write (INSERT only)
    """
    return SecuritySchema(
        tables={
            "users": TableSchema(
                columns={
                    "id": ColumnSchema(
                        access=Access.READ,
                        allowed_operations={"SELECT"}
                    ),
                    "username": ColumnSchema(
                        access=Access.READ,
                        allowed_operations={"SELECT"}
                    ),
                    "email": ColumnSchema(
                        access=Access.WRITE,
                        allowed_operations={"SELECT", "UPDATE"}
                    ),
                    "last_login": ColumnSchema(
                        access=Access.WRITE,
                        allowed_operations={"UPDATE", "INSERT"}  # No SELECT permission
                    )
                }
            ),
            "audit_log": TableSchema(
                columns={
                    "id": ColumnSchema(
                        access=Access.READ,
                        allowed_operations={"SELECT"}
                    ),
                    "action": ColumnSchema(
                        access=Access.WRITE,
                        allowed_operations={"SELECT", "INSERT"}  # Can read and insert
                    ),
                    "timestamp": ColumnSchema(
                        access=Access.WRITE,
                        allowed_operations={"INSERT"}  # Insert only
                    )
                }
            )
        },
        max_joins=1,
        allow_subqueries=True,
        forbidden_keywords=set()
    )

@pytest.fixture
def mixed_access_guard(mixed_access_schema):
    """Provides a security guard with mixed read/write access configuration."""
    return SQLSecurityGuard(mixed_access_schema)
