from typing import List, Optional, Set, Any, Tuple
from sqlglot import parse_one, exp
from ..models.schema import SecuritySchema
from ..models.config import LangSecConfig
from ..exceptions.errors import (
    TableAccessError,
    ColumnAccessError,
    JoinViolationError,
    QueryComplexityError,
    SQLInjectionError
)
from ..models.enums import ColumnAccess, JoinType, AggregationType
from .table import TableValidator
from .column import ColumnValidator
from .join import JoinValidator
from .aggregation import AggregationValidator
from .group_by import GroupByValidator
from .where import WhereValidator

class QueryValidator:
    def __init__(self, schema: Optional[SecuritySchema] = None, config: Optional[LangSecConfig] = None):
        self.schema = schema or SecuritySchema()
        self.config = config or LangSecConfig()
        
        # Initialize all validators
        self.table_validator = TableValidator(schema)
        self.join_validator = JoinValidator(schema)
        self.column_validator = ColumnValidator(schema)
        self.where_validator = WhereValidator(schema)
        self.aggregation_validator = AggregationValidator(schema)
        self.group_by_validator = GroupByValidator(schema)

    def validate(self, query: str) -> bool:
        """Validates a query against all configured rules."""
        self._validate_query_length(query)
        self._validate_forbidden_keywords(query)

        if not self.schema.tables:
            return True
            
        parsed = parse_one(query)
        
        # Run all validators
        self.table_validator.validate(parsed)
        self.join_validator.validate(parsed)
        self.column_validator.validate(parsed)
        self.where_validator.validate(parsed)
        self.aggregation_validator.validate(parsed)
        self.group_by_validator.validate(parsed)
        
        return True

    def _validate_query_length(self, query: str) -> None:
        if (
            self.schema.max_query_length and 
            len(query) > self.schema.max_query_length
        ):
            raise QueryComplexityError(
                f"Query length exceeds maximum allowed "
                f"({len(query)} > {self.schema.max_query_length})"
            )

    def _validate_forbidden_keywords(self, query: str) -> None:
        if not self.schema.forbidden_keywords:
            return
            
        query_upper = query.upper()
        for keyword in self.schema.forbidden_keywords:
            if keyword.upper() in query_upper:
                raise QueryComplexityError(f"Forbidden keyword found: {keyword}")