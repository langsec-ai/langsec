from .sql.operations import JoinRule
from .sql.enums import AggregationType, JoinType
from .security_schema import TableSchema, ColumnSchema, SecuritySchema, ColumnAccess

low_security_config = SecuritySchema(
    allow_subqueries=True,
    allow_unions=True,
    allow_temp_tables=True,
    max_query_length=1000,
    # Table access parameters
    require_where_clause=False,
    allow_group_by=True,
    # Column access parameters
    access=ColumnAccess.READ,
    allowed_operations={"SELECT", "JOIN", "GROUP BY", "INSERT", "UPDATE", "DELETE"},
    default_allowed_join=JoinRule(allowed_types={JoinType.CROSS, JoinType.INNER, JoinType.RIGHT, JoinType.LEFT}),
    allowed_aggregations={AggregationType.SUM, AggregationType.AVG, AggregationType.COUNT, AggregationType.MAX, AggregationType.MIN}
)

medium_security_config = SecuritySchema(
    allow_subqueries=False,
    allow_unions=False,
    allow_temp_tables=False,
    max_query_length=500,
    # Table access parameters
    require_where_clause=True,
    allow_group_by=True,
    # Column access parameters
    access=ColumnAccess.READ,
    allowed_operations={"SELECT", "JOIN"},
    default_allowed_join=JoinRule(allowed_types={JoinType.RIGHT, JoinType.LEFT}),
    allowed_aggregations={AggregationType.SUM, AggregationType.AVG}
)

high_security_config = SecuritySchema(
    allow_subqueries=False,
    allow_unions=False,
    allow_temp_tables=False,
    max_query_length=200,
    # Table access parameters
    require_where_clause=True,
    allow_group_by=False,
    # Column access parameters
    access=ColumnAccess.READ,
    allowed_operations={"SELECT"},
    default_allowed_join=JoinRule(allowed_types={JoinType.LEFT}),
    allowed_aggregations=set()
)
