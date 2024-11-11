from .sql.enums import AggregationType
from .security_schema import TableSchema, ColumnSchema, SecuritySchema, ColumnAccess

low_security_config = SecuritySchema(
    allow_subqueries=True,
    allow_unions=False,
    allow_temp_tables=False,
    max_query_length=1000,
    default_table_security_schema=TableSchema(
        require_where_clause=False,
        allow_group_by=True,
    ),
    default_column_security_schema=ColumnSchema(
        access=ColumnAccess.READ,
        allowed_operations={"SELECT"},
        allowed_aggregations={AggregationType.SUM, AggregationType.AVG, AggregationType.COUNT, AggregationType.MAX, AggregationType.MIN}
    )
)

medium_security_config = SecuritySchema(
    allow_subqueries=False,
    allow_unions=False,
    allow_temp_tables=False,
    max_query_length=500,
    default_table_security_schema=TableSchema(
        require_where_clause=True,
        allow_group_by=True,
    ),
    default_column_security_schema=ColumnSchema(
        access=ColumnAccess.READ,
        allowed_operations={"SELECT"},
        allowed_aggregations={AggregationType.SUM, AggregationType.AVG}
    )
)

high_security_config = SecuritySchema(
    allow_subqueries=False,
    allow_unions=False,
    allow_temp_tables=False,
    max_query_length=200,
    default_table_security_schema=TableSchema(
        require_where_clause=True,
        allow_group_by=False,
    ),
    default_column_security_schema=ColumnSchema(
        access=ColumnAccess.DENIED,
        allowed_operations=set(),
        allowed_aggregations=set()
    )
)
