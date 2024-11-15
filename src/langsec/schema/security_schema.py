from enum import Enum
from typing import Dict, Optional, Set, Union
from pydantic import BaseModel, Field, field_validator, ConfigDict, model_validator

from .sql import JoinRule
from .sql.enums import AggregationType, Access


class ColumnSchema(BaseModel):
    """Schema defining security rules for a database column."""
    access: Access = Field(default=Access.DENIED)
    allowed_operations: Set[str] = Field(default_factory=set)
    allowed_aggregations: Set[AggregationType] = Field(default_factory=set)

    model_config = ConfigDict(validate_assignment=True, arbitrary_types_allowed=True)

    @classmethod
    def create_default(cls, **kwargs) -> 'ColumnSchema':
        """Create a default column schema with optional overrides."""
        valid_fields = {
            k: v for k, v in kwargs.items() 
            if k in cls.model_fields
        }
        return cls(**valid_fields)


class TableSchema(BaseModel):
    """Schema defining security rules for a database table."""
    columns: Dict[str, ColumnSchema] = Field(default_factory=dict)
    allowed_joins: Dict[str, JoinRule] = Field(default_factory=dict)
    default_allowed_join: Optional[JoinRule] = Field(default_factory=JoinRule)

    model_config = ConfigDict(validate_assignment=True, arbitrary_types_allowed=True)

    def get_table_allowed_joins(self, column: str) -> JoinRule:
        """Get join rules for a column, returning default JoinRule if none specified."""
        return self.allowed_joins.get(column, self.default_allowed_join or JoinRule())
    
    @field_validator("allowed_joins", mode="before")
    @classmethod
    def ensure_join_rules(cls, v: Optional[Dict]) -> Dict[str, JoinRule]:
        """Ensures join rules are properly instantiated."""
        if not isinstance(v, dict):
            return {}
            
        return {
            k: v[k] if isinstance(v[k], JoinRule) else JoinRule(**(v[k] or {}))
            for k in v
        }

    @field_validator("default_allowed_join", mode="before")
    @classmethod
    def ensure_default_join_rule(cls, v: Optional[Union[Dict, JoinRule]]) -> Optional[JoinRule]:
        """Ensures default join rule is properly instantiated."""
        if v is None:
            return None
        if isinstance(v, JoinRule):
            return v
        return JoinRule(**(v or {}))

    @classmethod
    def create_default(cls, **kwargs) -> 'TableSchema':
        """Create a default table schema with optional overrides."""
        valid_fields = {
            k: v for k, v in kwargs.items() 
            if k in cls.model_fields
        }
        return cls(**valid_fields)

class SecuritySchema(BaseModel):
    """Schema defining overall security rules for database access."""
    tables: Dict[str, TableSchema] = Field(default_factory=dict)
    max_joins: int = Field(default=3, ge=0)
    allow_subqueries: bool = True
    allow_temp_tables: bool = False
    max_query_length: Optional[int] = Field(default=None, ge=0)
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
    # Add these fields to match the configuration use case
    access: Optional[Access] = Field(default=None)
    allowed_operations: Optional[Set[str]] = Field(default=None)
    allowed_aggregations: Optional[Set[AggregationType]] = Field(default=None)
    
    # Default schemas with proper typing
    default_table_security_schema: TableSchema = Field(default_factory=TableSchema)
    default_column_security_schema: ColumnSchema = Field(default_factory=ColumnSchema)

    model_config = ConfigDict(validate_assignment=True, arbitrary_types_allowed=True)
    
    @model_validator(mode='after')
    def initialize_default_schemas(self) -> 'SecuritySchema':
        """Initialize default schemas with any relevant fields from the main config."""
        # Extract fields that could apply to column schema
        column_fields = {
            'access': self.access,
            'allowed_operations': self.allowed_operations,
            'allowed_aggregations': self.allowed_aggregations
        }
        # Only include non-None values
        column_fields = {k: v for k, v in column_fields.items() if v is not None}
        self.default_column_security_schema = ColumnSchema.create_default(**column_fields)

        # Extract fields that could apply to table schema
        table_fields = {
            'columns': {},  # Empty default columns
            'allowed_joins': {},  # Empty default joins
            'default_allowed_join': JoinRule() if self.allowed_operations and "JOIN" in self.allowed_operations else None
        }
        self.default_table_security_schema = TableSchema.create_default(**table_fields)
        
        return self

    def get_prompt(self) -> str:
        """Generate a prompt describing the security constraints."""
        prompt = "Generate an SQL query adhering to the following constraints:\n"
        prompt += f"- Maximum joins allowed: {self.max_joins}\n"
        prompt += f"- Subqueries allowed: {'Yes' if self.allow_subqueries else 'No'}\n"
        prompt += f"- Temporary tables allowed: {'Yes' if self.allow_temp_tables else 'No'}\n"
        prompt += f"- Maximum query length: {self.max_query_length if self.max_query_length else 'Unlimited'}\n"
        prompt += f"- SQL Injection Protection: {'Enabled' if self.sql_injection_protection else 'Disabled'}\n"
        prompt += f"- Forbidden keywords: {', '.join(sorted(self.forbidden_keywords))}\n"
        if self.allowed_operations:
            prompt += f"- Allowed operations: {', '.join(sorted(self.allowed_operations))}\n"
        if self.allowed_aggregations:
            prompt += f"- Allowed aggregations: {', '.join(sorted(agg.name for agg in self.allowed_aggregations))}\n"
        if self.access:
            prompt += f"- Default access level: {self.access.name}\n"
        return prompt

    def get_table_schema(self, table_name: str) -> TableSchema:
        """Returns the table schema, or the default if not found."""
        return self.tables.get(table_name, self.default_table_security_schema)

    def get_column_schema(self, table_name: str, column_name: str) -> ColumnSchema:
        """Returns the column schema, or the default if not found."""
        table_schema = self.get_table_schema(table_name)
        return table_schema.columns.get(column_name, self.default_column_security_schema)

    @field_validator("tables", mode="before")
    @classmethod
    def ensure_table_schemas(cls, v: Union[Dict, None]) -> Dict[str, TableSchema]:
        """Ensures table schemas are properly instantiated."""
        if not isinstance(v, dict):
            return {}
            
        return {
            k: v[k] if isinstance(v[k], TableSchema) else TableSchema(**(v[k] or {}))
            for k in v
        }