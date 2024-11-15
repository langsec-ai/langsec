from enum import Enum


class AggregationType(str, Enum):
    COUNT = "count"
    SUM = "sum"
    AVG = "avg"
    MIN = "min"
    MAX = "max"


class JoinType(str, Enum):
    INNER = "inner"
    LEFT = "left"
    RIGHT = "right"
    FULL = "full"
    CROSS = "cross"


class Access(str, Enum):
    READ = "read"
    WRITE = "write"
    DENIED = "denied"


class QueryType(str, Enum):
    SELECT = "SELECT"
    JOIN = "JOIN"
    GROUPBY = "GROUPBY"
    INSERT = "INSERT"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    CREATE = "CREATE"
    DROP = "DROP"
    ALTER = "ALTER"
    TRUNCATE = "TRUNCATE"
