from .sql.enums import AggregationType
from .security_schema import SecuritySchema, Access

low_security_config = SecuritySchema(
    allow_subqueries=True,
    allow_temp_tables=False,
    max_query_length=1000,
    access=Access.READ,
    allowed_operations={"SELECT", "JOIN", "GROUP BY", "INSERT", "UPDATE", "DELETE"},
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
    # Column parameters
    access=Access.READ,
    allowed_operations={"SELECT", "JOIN"},
    allowed_aggregations={AggregationType.SUM, AggregationType.AVG},
)

high_security_config = SecuritySchema(
    allow_subqueries=False,
    allow_temp_tables=False,
    max_query_length=200,
    access=Access.READ,
    allowed_operations={"SELECT"},
    allowed_aggregations=set(),
)
