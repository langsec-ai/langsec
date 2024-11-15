from enum import Enum
from typing import Dict, Optional, Set
from pydantic import BaseModel, Field, field_validator, ConfigDict

from .sql import JoinRule

from .sql.enums import AggregationType, Access


# TODO: Move to SQL
class ColumnSchema(BaseModel):
    access: Optional[Access] = Access.DENIED
    allowed_operations: Optional[Set[str]] = Field(default_factory=set) # TODO: Implement.
    allowed_aggregations: Optional[Set[AggregationType]] = Field(default_factory=set)

    model_config = ConfigDict(validate_assignment=True, arbitrary_types_allowed=True)


# TODO: Move to SQL
class TableSchema(BaseModel):
    columns: Dict[str, ColumnSchema] = Field(default_factory=dict)
    allowed_joins: Dict[str, JoinRule] = Field(default_factory=dict)

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
    access: Optional[Access] = None # TODO: implement.
    
    # Declare default values for unspecified tables and columns
    default_table_security_schema: TableSchema = TableSchema()
    default_column_security_schema: ColumnSchema = ColumnSchema()

    model_config = ConfigDict(validate_assignment=True, arbitrary_types_allowed=True)

    def get_prompt(self) -> str:
        prompt = "Generate an SQL query adhering to the following constraints:\n"
        prompt += f"- Maximum joins allowed: {self.max_joins}\n"
        prompt += f"- Subqueries allowed: {'Yes' if self.allow_subqueries else 'No'}\n"
        prompt += f"- Temporary tables allowed: {'Yes' if self.allow_temp_tables else 'No'}\n"
        prompt += f"- Maximum query length: {self.max_query_length if self.max_query_length else 'Unlimited'}\n"
        prompt += f"- SQL Injection Protection: {'Enabled' if self.sql_injection_protection else 'Disabled'}\n"
        prompt += f"- Forbidden keywords: {', '.join(self.forbidden_keywords)}\n"
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
