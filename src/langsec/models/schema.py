from typing import Dict, Optional, Set
from pydantic import BaseModel, Field, field_validator, ConfigDict

from .enums import AggregationType, ColumnAccess, JoinType


class ColumnRule(BaseModel):
    access: Optional[ColumnAccess] = None
    max_rows: Optional[int] = None
    allowed_operations: Optional[Set[str]] = Field(default_factory=set)
    allowed_aggregations: Optional[Set[AggregationType]] = Field(default_factory=set)

    model_config = ConfigDict(validate_assignment=True, arbitrary_types_allowed=True)


class JoinRule(BaseModel):
    allowed_types: Set[JoinType] = Field(
        default_factory=lambda: {JoinType.INNER, JoinType.LEFT}
    )

    model_config = ConfigDict(validate_assignment=True, arbitrary_types_allowed=True)


class TableSchema(BaseModel):
    columns: Dict[str, ColumnRule] = Field(default_factory=dict)
    max_rows: Optional[int] = None  # TODO: implement.
    allowed_joins: Dict[str, JoinRule] = Field(default_factory=dict)
    require_where_clause: bool = False
    allowed_where_columns: Set[str] = Field(default_factory=set)
    allow_group_by: bool = True
    allowed_group_by_columns: Set[str] = Field(default_factory=set)

    model_config = ConfigDict(validate_assignment=True, arbitrary_types_allowed=True)

    @field_validator("allowed_joins", mode="before")
    @classmethod
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
    sql_injection_protection: bool = True
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

    model_config = ConfigDict(validate_assignment=True, arbitrary_types_allowed=True)

    @field_validator("tables", mode="before")
    @classmethod
    def ensure_table_schemas(cls, v):
        """Ensures table schemas are properly instantiated."""
        if isinstance(v, dict):
            return {
                k: v[k] if isinstance(v[k], TableSchema) else TableSchema(**v[k])
                for k in v
            }
        return v
