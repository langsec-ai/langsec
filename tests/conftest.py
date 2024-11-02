import pytest
from langsec import SQLSecurityGuard
from langsec.models.schema import (
    SecuritySchema,
    TableSchema,
    ColumnRule,
    JoinRule
)
from langsec.models.enums import (
    ColumnAccess,
    JoinType,
    AggregationType,
    TimeWindow
)

@pytest.fixture
def basic_schema():
    """Provides a basic security schema for testing."""
    return SecuritySchema(
        tables={
            "users": TableSchema(
                columns={
                    "id": ColumnRule(access=ColumnAccess.READ),
                    "username": ColumnRule(access=ColumnAccess.READ),
                    "email": ColumnRule(
                        access=ColumnAccess.DENIED,
                        sensitive_data=True
                    ),
                    "created_at": ColumnRule(access=ColumnAccess.READ)
                },
                max_rows=1000,
                require_where_clause=True,
                allowed_joins={
                    "orders": JoinRule(
                        allowed_types={JoinType.INNER, JoinType.LEFT}
                    )
                }
            ),
            "orders": TableSchema(
                columns={
                    "id": ColumnRule(access=ColumnAccess.READ),
                    "user_id": ColumnRule(access=ColumnAccess.READ),
                    "amount": ColumnRule(
                        access=ColumnAccess.READ,
                        allowed_aggregations={
                            AggregationType.SUM,
                            AggregationType.AVG
                        }
                    )
                },
                allowed_joins={
                    "users": JoinRule(
                        allowed_types={JoinType.INNER, JoinType.LEFT}
                    )
                }
            )
        },
        max_joins=2,
        forbidden_keywords={"DROP", "DELETE", "TRUNCATE", "--", "/*", "*/", "UNION"}
    )

@pytest.fixture
def complex_schema(basic_schema):
    """Provides a complex security schema for testing."""
    schema_dict = basic_schema.model_dump()
    schema_dict["tables"]["products"] = TableSchema(
        columns={
            "id": ColumnRule(access=ColumnAccess.READ),
            "name": ColumnRule(access=ColumnAccess.READ),
            "price": ColumnRule(
                access=ColumnAccess.READ,
                allowed_aggregations={
                    AggregationType.AVG,
                    AggregationType.MIN,
                    AggregationType.MAX
                }
            ),
            "category": ColumnRule(
                access=ColumnAccess.READ
            )
        },
        allowed_joins={
            "orders": JoinRule(
                allowed_types={JoinType.INNER, JoinType.LEFT}
            )
        }
    )
    return SecuritySchema(**schema_dict)

@pytest.fixture
def security_guard(basic_schema):
    """Provides a configured SQLSecurityGuard instance."""
    return SQLSecurityGuard(schema=basic_schema)

@pytest.fixture
def complex_security_guard(complex_schema):
    """Provides a SQLSecurityGuard instance with complex configuration."""
    return SQLSecurityGuard(schema=complex_schema)