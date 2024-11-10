from enum import Enum
from typing import Dict, Optional, Set
from pydantic import BaseModel, Field, field_validator, ConfigDict

from .sql import JoinRule

from .sql.enums import AggregationType, QueryType


class ColumnAccess(str, Enum):
    READ = "read"
    WRITE = "write"
    DENIED = "denied"

# TODO: Move to SQL
class ColumnSchema(BaseModel):
    access: Optional[ColumnAccess] = None
    max_rows: Optional[int] = None
    allowed_operations: Optional[Set[str]] = Field(default_factory=set)
    allowed_aggregations: Optional[Set[AggregationType]] = Field(default_factory=set)

    model_config = ConfigDict(validate_assignment=True, arbitrary_types_allowed=True)


# TODO: Move to SQL
class TableSchema(BaseModel):
    columns: Dict[str, ColumnSchema] = Field(default_factory=dict)
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
    allowed_query_types: Set[QueryType] = Field(
        default_factory=lambda: {
            QueryType.SELECT
        }  # Default to only allowing SELECT queries
    )
    
    # Declare default values for unspecified tables and columns
    default_table_security_schema: Optional[TableSchema] = None
    default_column_security_schema: Optional[ColumnSchema] = None

    model_config = ConfigDict(validate_assignment=True, arbitrary_types_allowed=True)

    def get_table_schema(self, table_name: str) -> TableSchema:
        """Returns the table schema, or the default if not found."""
        return self.tables.get(table_name, self.default_table_security_schema)

    def get_column_schema(self, table_name: str, column_name: str) -> ColumnSchema:
        """Returns the column schema, or the default if not found."""
        table_schema = self.get_table_schema(table_name)
        if table_schema:
            return table_schema.columns.get(column_name, self.default_column_security_schema)
        return self.default_column_security_schema

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

    @field_validator("allowed_query_types", mode="before")
    @classmethod
    def ensure_query_types(cls, v):
        """Ensures query types are properly instantiated."""
        if isinstance(v, set):
            return {QueryType(qt) if isinstance(qt, str) else qt for qt in v}
        return v
