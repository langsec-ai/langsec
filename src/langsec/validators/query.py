from typing import Optional
from sqlglot import parse_one

from ..schema.security_schema import SecuritySchema
from ..config import LangSecConfig
from ..exceptions.errors import (
    QueryComplexityError,
)
from .table import TableValidator
from .column import ColumnValidator
from .join import JoinValidator
from .aggregation import AggregationValidator
from .subquery import SubqueryValidator
from .injection import SQLInjectionValidator


class QueryValidator:
    def __init__(
        self,
        schema: Optional[SecuritySchema] = None,
        config: Optional[LangSecConfig] = None,
    ):
        self.schema = schema or SecuritySchema()
        self.config = config or LangSecConfig()

        # Initialize all validators
        self.table_validator = TableValidator(schema)
        self.column_validator = ColumnValidator(schema)
        self.join_validator = JoinValidator(schema)
        self.aggregation_validator = AggregationValidator(schema)
        self.subqueries_validator = SubqueryValidator(schema)

        if self.schema.sql_injection_protection:
            self.sql_injection_validator = SQLInjectionValidator()

    def validate(self, query: str) -> bool:
        """Validates a query against all configured rules."""
        self._validate_query_length(query)
        self._validate_forbidden_keywords(query)

        parsed = parse_one(query)

        # Run all validators
        self.table_validator.validate(parsed)
        self.join_validator.validate(parsed)
        self.column_validator.validate(parsed)
        self.aggregation_validator.validate(parsed)
        self.subqueries_validator.validate(parsed)

        if self.schema.sql_injection_protection:
            self.sql_injection_validator.validate(parsed)

        return True

    def _validate_query_length(self, query: str) -> None:
        if self.schema.max_query_length and len(query) > self.schema.max_query_length:
            raise QueryComplexityError(
                f"Query length exceeds maximum allowed " f"({len(query)} > {self.schema.max_query_length})"
            )

    def _validate_forbidden_keywords(self, query: str) -> None:
        if not self.schema.forbidden_keywords:
            return

        query_upper = query.upper()
        for keyword in self.schema.forbidden_keywords:
            if keyword.upper() in query_upper:
                raise QueryComplexityError(f"Forbidden keyword found: {keyword}")
