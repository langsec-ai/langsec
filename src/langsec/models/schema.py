from typing import Dict, List, Optional, Set, Union
from pydantic import BaseModel, Field, validator

from .enums import AggregationType, ColumnAccess, JoinType, TimeWindow


class ColumnRule(BaseModel):
    access: Optional[ColumnAccess] = None
    max_rows: Optional[int] = None
    allowed_operations: Optional[Set[str]] = Field(default_factory=set)
    allowed_aggregations: Optional[Set[AggregationType]] = Field(default_factory=set)
    sensitive_data: bool = False
    mask_pattern: Optional[str] = None
    validation_regex: Optional[str] = None
    min_value: Optional[Union[int, float]] = None
    max_value: Optional[Union[int, float]] = None


class JoinRule(BaseModel):
    allowed_types: Set[JoinType] = Field(
        default_factory=lambda: {JoinType.INNER, JoinType.LEFT}
    )
    conditions: List[str] = Field(default_factory=list)
    max_rows_after_join: Optional[int] = None


class TableSchema(BaseModel):
    columns: Dict[str, ColumnRule] = Field(default_factory=dict)
    max_rows: Optional[int] = None
    allowed_joins: Dict[str, JoinRule] = Field(default_factory=dict)
    require_where_clause: bool = False
    allowed_where_columns: Set[str] = Field(default_factory=set)
    time_window_restriction: Optional[TimeWindow] = None
    time_column: Optional[str] = None
    allow_group_by: bool = True
    allowed_group_by_columns: Set[str] = Field(default_factory=set)

    class Config:
        validate_assignment = True
        arbitrary_types_allowed = True

    @validator("allowed_joins", pre=True)
    def ensure_join_rules(cls, v):
        """Ensures join rules are properly instantiated."""
        if isinstance(v, dict):
            return {
                k: v[k] if isinstance(v[k], JoinRule) else JoinRule(**v[k]) for k in v
            }
        return v


class SecuritySchema(BaseModel):
    tables: Dict[str, TableSchema] = Field(default_factory=dict)
    max_joins: int = 3
    allow_subqueries: bool = True
    allow_unions: bool = False
    allow_temp_tables: bool = False
    max_query_length: Optional[int] = None
    forbidden_keywords: Set[str] = Field(
        default_factory=lambda: {
            "TRUNCATE",
            "DROP",
            "ALTER",
            "GRANT",
            "REVOKE",
            "EXECUTE",
            "EXEC",
            "SYSADMIN",
            "DBADMIN",
        }
    )

    class Config:
        validate_assignment = True
        arbitrary_types_allowed = True

    @validator("tables", pre=True)
    def ensure_table_schemas(cls, v):
        """Ensures table schemas are properly instantiated."""
        if isinstance(v, dict):
            return {
                k: v[k] if isinstance(v[k], TableSchema) else TableSchema(**v[k])
                for k in v
            }
        return v
