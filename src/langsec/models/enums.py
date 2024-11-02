from enum import Enum


class ColumnAccess(str, Enum):
    READ = "read"
    WRITE = "write"
    DENIED = "denied"


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


class TimeWindow(str, Enum):
    MINUTE = "minute"
    HOUR = "hour"
    DAY = "day"
    WEEK = "week"
    MONTH = "month"
    YEAR = "year"
