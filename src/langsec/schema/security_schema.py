from enum import Enum
from typing import Dict, Optional, Set, Union
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
    allowed_operations: Optional[Set[str]] = Field(default_factory=set)
    allowed_aggregations: Optional[Set[AggregationType]] = Field(default_factory=set)

    model_config = ConfigDict(validate_assignment=True, arbitrary_types_allowed=True)


# TODO: Move to SQL
class TableSchema(BaseModel):
    columns: Dict[str, ColumnSchema] = Field(default_factory=dict)
    
    allowed_joins: Dict[str, JoinRule] = Field(default_factory=dict)
    default_allowed_join: Optional[JoinRule] = Field(default_factory=JoinRule)
    
    require_where_clause: bool = False
    allowed_where_columns: Set[str] = Field(default_factory=set)
    
    allow_group_by: bool = True
    allowed_group_by_columns: Set[str] = Field(default_factory=set)

    model_config = ConfigDict(validate_assignment=True, arbitrary_types_allowed=True)

    def get_table_allowed_joins(self, column: str) -> Union[JoinRule, None]:
        if column in self.allowed_joins:
            return self.allowed_joins[column]
        return self.default_allowed_join

    @field_validator("allowed_joins", mode="before")
    @classmethod
    def ensure_join_rules(cls, v):
        """Ensures join rules are properly instantiated."""
        if isinstance(v, dict):
            return {
                k: v[k] if isinstance(v[k], JoinRule) else JoinRule(**v[k]) for k in v
            }
        return v


def instantiate_class_with_kwargs(cls, kwargs):
        class_args = {key: kwargs.get(key) for key in cls.__annotations__.keys() if kwargs.get(key) is not None}
        return cls(**class_args) if class_args else None


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
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Initialize default_column_security_schema only if needed.
        # Only if any of the kwargs are needed.
        if self.default_column_security_schema is None:
            self.default_column_security_schema = instantiate_class_with_kwargs(ColumnSchema, kwargs)
            
        if self.default_table_security_schema is None:
            self.default_table_security_schema = instantiate_class_with_kwargs(TableSchema, kwargs)

    def get_prompt(self) -> str:
        prompt = "Generate an SQL query adhering to the following constraints:\n"
        prompt += f"- Maximum joins allowed: {self.max_joins}\n"
        prompt += f"- Subqueries allowed: {'Yes' if self.allow_subqueries else 'No'}\n"
        prompt += f"- Unions allowed: {'Yes' if self.allow_unions else 'No'}\n"
        prompt += f"- Temporary tables allowed: {'Yes' if self.allow_temp_tables else 'No'}\n"
        prompt += f"- Maximum query length: {self.max_query_length if self.max_query_length else 'Unlimited'}\n"
        prompt += f"- SQL Injection Protection: {'Enabled' if self.sql_injection_protection else 'Disabled'}\n"
        prompt += f"- Forbidden keywords: {', '.join(self.forbidden_keywords)}\n"
        prompt += f"- Allowed query types: {', '.join(qt.value for qt in self.allowed_query_types)}\n"
        return prompt

    def get_table_schema(self, table_name: str) -> TableSchema:
        """Returns the table schema, or the default if not found."""
        if self.tables is None:
            return self.default_table_security_schema
        return self.tables.get(table_name, self.default_table_security_schema)

    def get_column_schema(self, table_name: str, column_name: str) -> ColumnSchema:
        """Returns the column schema, or the default if not found."""
        table_schema = self.get_table_schema(table_name)
        if not table_schema:
            return self.default_column_security_schema
        return table_schema.columns.get(column_name, self.default_column_security_schema)

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