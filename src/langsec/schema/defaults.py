from .sql.enums import AggregationType
from .security_schema import TableSchema, ColumnSchema, SecuritySchema


low_security_config = SecuritySchema(
    default_table_security_schema=TableSchema(
        max_rows=None,
        require_where_clause=False,
        allow_group_by=True
    ),
    default_column_security_schema=ColumnSchema(
        access=None,
        max_rows=None,
        allowed_operations=set(),
        allowed_aggregations=set()
    )
)

medium_security_config = SecuritySchema(
    default_table_security_schema=TableSchema(
        max_rows=1000,
        require_where_clause=True,
        allow_group_by=True
    ),
    default_column_security_schema=ColumnSchema(
        access=None,
        max_rows=1000,
        allowed_operations={"SELECT", "INSERT"},
        allowed_aggregations={AggregationType.SUM, AggregationType.AVG}
    )
)

high_security_config = SecuritySchema(
    default_table_security_schema=TableSchema(
        max_rows=100,
        require_where_clause=True,
        allow_group_by=False
    ),
    default_column_security_schema=ColumnSchema(
        access=None,
        max_rows=100,
        allowed_operations={"SELECT"},
        allowed_aggregations=set()
    )
)
