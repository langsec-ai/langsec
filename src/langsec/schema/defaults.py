from .sql.enums import AggregationType, Operation, JoinType
from .security_schema import SecuritySchema, Access

low_security_config = SecuritySchema(
    allow_subqueries=True,
    allow_temp_tables=False,
    max_query_length=1000,
    # Column access parameters
    access=Access.READ,
    allowed_operations={
        Operation.SELECT,
        Operation.JOIN,
        Operation.GROUPBY,
        Operation.INSERT,
        Operation.UPDATE,
        Operation.DELETE,
    },
    default_allowed_join={
        JoinType.CROSS,
        JoinType.INNER,
        JoinType.RIGHT,
        JoinType.LEFT,
    },
    allowed_aggregations={
        AggregationType.SUM,
        AggregationType.AVG,
        AggregationType.COUNT,
        AggregationType.MAX,
        AggregationType.MIN,
    },
)

medium_security_config = SecuritySchema(
    allow_subqueries=False,
    allow_temp_tables=False,
    max_query_length=500,
    # Column access parameters
    access=Access.READ,
    allowed_operations={Operation.SELECT, Operation.JOIN},
    default_allowed_join={JoinType.RIGHT, JoinType.LEFT},
    allowed_aggregations={AggregationType.SUM, AggregationType.AVG},
)

high_security_config = SecuritySchema(
    allow_subqueries=False,
    allow_temp_tables=False,
    max_query_length=200,
    # Column access parameters
    access=Access.READ,
    allowed_operations={Operation.SELECT},
    default_allowed_join={JoinType.LEFT},
    allowed_aggregations=set(),
)
