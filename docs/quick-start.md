# LangSec: SQL Query Security Framework

LangSec is a robust Python framework designed to enforce security policies on SQL queries. It's particularly valuable when working with LLMs (Large Language Models) or handling user-generated queries where query validation and security enforcement are critical.

## Core Concepts

### Security Guard

The `SQLSecurityGuard` is the main entry point for query validation:

```python
from langsec import SQLSecurityGuard
from langsec.schema.security_schema import SecuritySchema
from langsec.config import LangSecConfig

# Basic initialization
guard = SQLSecurityGuard(schema=schema)

# With custom configuration
config = LangSecConfig(
    log_queries=True,
    log_path="/path/to/logs/queries.log",
    raise_on_violation=True
)
guard = SQLSecurityGuard(schema=schema, config=config)
```

### Configuration Options

The `LangSecConfig` class provides several options to customize LangSec's behavior:

```python
class LangSecConfig:
    log_queries: bool = False        # Enable/disable query logging
    log_path: Optional[str] = None   # Path for log file
    raise_on_violation: bool = True  # Raise exceptions vs return False
```

### Security Schema Structure

The security schema is the cornerstone of LangSec's security model. It defines what operations are allowed on your database at multiple levels:

#### 1. Column Level Security
```python
from langsec.schema.sql.enums import Access, AggregationType

# Basic read-only column
column = ColumnSchema(
    access=Access.READ,
    allowed_operations={"SELECT"}
)

# Column with aggregation permissions
metrics_column = ColumnSchema(
    access=Access.READ,
    allowed_operations={"SELECT"},
    allowed_aggregations={
        AggregationType.SUM,
        AggregationType.AVG,
        AggregationType.COUNT
    }
)

# Write-only audit column
audit_column = ColumnSchema(
    access=Access.WRITE,
    allowed_operations={"INSERT"}
)
```

#### 2. Table Level Security
```python
from langsec.schema.sql.enums import JoinType

table = TableSchema(
    columns={
        "id": ColumnSchema(access=Access.READ),
        "username": ColumnSchema(access=Access.READ),
        "email": ColumnSchema(access=Access.DENIED)
    },
    allowed_joins={
        "orders": {JoinType.INNER, JoinType.LEFT},
        "products": {JoinType.INNER}
    },
    default_allowed_join=None  # Default join policy for unlisted tables
)
```

#### 3. Database Level Security
```python
schema = SecuritySchema(
    tables={
        "users": users_table_schema,
        "orders": orders_table_schema,
        "products": products_table_schema
    },
    max_joins=2,                    # Maximum number of joins allowed
    allow_subqueries=True,          # Enable/disable subqueries
    max_query_length=1000,          # Maximum query length
    sql_injection_protection=True,   # Enable basic SQL injection protection
    forbidden_keywords={            # SQL keywords to block
        "DROP", "DELETE", "TRUNCATE",
        "ALTER", "GRANT", "REVOKE",
        "EXECUTE", "EXEC",
        "SYSADMIN", "DBADMIN"
    },
    # Default schemas for tables/columns not explicitly defined
    default_table_security_schema=TableSchema(...),
    default_column_security_schema=ColumnSchema(...)
)
```

## Query Validation

The validation process checks multiple aspects of the query:

1. **Access Control**: Verifies that the query only accesses allowed tables and columns
2. **Join Validation**: Ensures joins are allowed and don't exceed complexity limits
3. **Aggregation Control**: Validates that aggregation functions are permitted
4. **Query Complexity**: Checks query length and subquery usage
5. **SQL Injection Protection**: Basic SQL injection prevention

```python
try:
    guard.validate_query("""
        SELECT 
            users.username,
            SUM(orders.amount) as total_spent
        FROM users
        LEFT JOIN orders ON users.id = orders.user_id
        WHERE users.created_at > '2024-01-01'
        GROUP BY users.username
    """)
except Exception as e:
    print(f"Query validation failed: {e}")
```

## Access Control Patterns

### Pattern 1: Read-Only Analytics
```python
analytics_schema = SecuritySchema(
    tables={
        "users": TableSchema(
            columns={
                "id": ColumnSchema(access=Access.READ),
                "signup_date": ColumnSchema(access=Access.READ),
                "country": ColumnSchema(access=Access.READ)
            },
            allowed_joins={"orders": {JoinType.LEFT, JoinType.INNER}}
        ),
        "orders": TableSchema(
            columns={
                "user_id": ColumnSchema(access=Access.READ),
                "amount": ColumnSchema(
                    access=Access.READ,
                    allowed_aggregations={
                        AggregationType.SUM,
                        AggregationType.AVG,
                        AggregationType.COUNT
                    }
                ),
                "order_date": ColumnSchema(access=Access.READ)
            }
        )
    },
    max_joins=2,
    allow_subqueries=True
)
```

### Pattern 2: Audit Logging System
```python
audit_schema = SecuritySchema(
    tables={
        "users": TableSchema(
            columns={
                "id": ColumnSchema(access=Access.READ),
                "username": ColumnSchema(access=Access.READ),
                "last_login": ColumnSchema(
                    access=Access.WRITE,
                    allowed_operations={"UPDATE", "SELECT"}
                )
            }
        ),
        "audit_log": TableSchema(
            columns={
                "user_id": ColumnSchema(access=Access.WRITE),
                "action": ColumnSchema(access=Access.WRITE),
                "timestamp": ColumnSchema(access=Access.WRITE),
                "details": ColumnSchema(access=Access.WRITE)
            },
            # No joins allowed on audit log
            allowed_joins={},
            default_allowed_join=None
        )
    },
    # Strict settings for audit system
    max_joins=0,
    allow_subqueries=False,
    sql_injection_protection=True
)
```

### Pattern 3: Mixed Access Control
```python
mixed_schema = SecuritySchema(
    tables={
        "users": TableSchema(
            columns={
                "id": ColumnSchema(
                    access=Access.READ,
                    allowed_operations={"SELECT"}
                ),
                "email": ColumnSchema(
                    access=Access.WRITE,
                    allowed_operations={"SELECT", "UPDATE"}
                ),
                "password_hash": ColumnSchema(access=Access.DENIED),
                "last_login": ColumnSchema(
                    access=Access.WRITE,
                    allowed_operations={"UPDATE"}
                )
            }
        )
    }
)
```

## Error Handling and Logging

LangSec provides detailed error reporting and optional logging:

```python
from langsec.exceptions.errors import (
    TableAccessError,
    ColumnAccessError,
    JoinViolationError,
    QueryComplexityError
)

# Setup with logging
config = LangSecConfig(
    log_queries=True,
    log_path="/var/log/langsec/queries.log",
    raise_on_violation=True
)

guard = SQLSecurityGuard(schema=schema, config=config)

try:
    guard.validate_query(query)
except TableAccessError as e:
    print(f"Invalid table access: {e}")
except ColumnAccessError as e:
    print(f"Invalid column access: {e}")
except JoinViolationError as e:
    print(f"Join violation: {e}")
except QueryComplexityError as e:
    print(f"Query too complex: {e}")
```

The logging system captures:
- Query validation attempts
- Validation results
- Detailed error information
- Timestamp and context

## Integration with LLMs

Example using LangSec with OpenAI:

```python
from openai import OpenAI
from langsec import SQLSecurityGuard

client = OpenAI()
guard = SQLSecurityGuard(schema=your_schema)

def get_safe_sql(prompt: str) -> str:
    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": "You are a SQL query generator."},
            {"role": "user", "content": prompt}
        ]
    )
    
    query = response.choices[0].message.content
    
    # Validate query before execution
    try:
        guard.validate_query(query)
        return query
    except Exception as e:
        raise ValueError(f"Generated query is not safe: {e}")
```
