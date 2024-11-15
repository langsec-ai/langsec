from .sql.enums import AggregationType, QueryType, JoinType
from .security_schema import SecuritySchema, Access

low_security_config = SecuritySchema(
    allow_subqueries=True,
    allow_temp_tables=False,
    max_query_length=1000,
    # Table access parameters
    require_where_clause=False,
    allow_group_by=True,
    # Column access parameters
    access=Access.READ,
    allowed_operations={QueryType.SELECT, QueryType.JOIN, QueryType.GROUPBY, QueryType.INSERT, QueryType.UPDATE, QueryType.DELETE},
    default_allowed_join={JoinType.CROSS, JoinType.INNER, JoinType.RIGHT, JoinType.LEFT},
    allowed_aggregations={AggregationType.SUM, AggregationType.AVG, AggregationType.COUNT, AggregationType.MAX, AggregationType.MIN}
)

medium_security_config = SecuritySchema(
    allow_subqueries=False,
    allow_temp_tables=False,
    max_query_length=500,
    # Table access parameters
    require_where_clause=True,
    allow_group_by=True,
    # Column access parameters
    access=Access.READ,
    allowed_operations={QueryType.SELECT, QueryType.JOIN},
    default_allowed_join={JoinType.RIGHT, JoinType.LEFT},
    allowed_aggregations={AggregationType.SUM, AggregationType.AVG}
)

high_security_config = SecuritySchema(
    allow_subqueries=False,
    allow_temp_tables=False,
    max_query_length=200,
    # Table access parameters
    require_where_clause=True,
    allow_group_by=False,
    # Column access parameters
    access=Access.READ,
    allowed_operations={QueryType.SELECT},
    default_allowed_join={JoinType.LEFT},
    allowed_aggregations=set()
)
