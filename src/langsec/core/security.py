import logging
from typing import Optional
from ..models.schema import SecuritySchema
from ..models.config import LangSecConfig
from ..validators.query import QueryValidator
from ..validators.injection import SQLInjectionValidator
from ..validators.syntax import SyntaxValidator


class SQLSecurityGuard:
    """Main entry point for SQL query security validation."""

    def __init__(
        self,
        schema: Optional[SecuritySchema] = None,
        config: Optional[LangSecConfig] = None,
    ):
        self.schema = schema or SecuritySchema()
        self.config = config or LangSecConfig()

        self.query_validator = QueryValidator(schema, config)
        self.injection_validator = SQLInjectionValidator()
        self.syntax_validator = SyntaxValidator()

        if self.config.log_queries:
            self._setup_logging()

    def _setup_logging(self) -> None:
        """Sets up logging if enabled in config."""
        logging.basicConfig(
            filename=self.config.log_path,
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )
        self.logger = logging.getLogger("langsec")

    def validate_query(self, query: str) -> bool:
        """
        Performs comprehensive validation of an SQL query.
        Returns True if valid, raises appropriate exception if invalid.
        """
        try:
            if self.config.log_queries:
                self.logger.info(f"Validating query: {query}")

            # Always validate syntax
            self.syntax_validator.validate(query)

            # Only validate injection if we have forbidden keywords
            if self.schema.forbidden_keywords:
                self.injection_validator.validate(query)

            # Validate against schema if provided
            if self.schema.tables:
                self.query_validator.validate(query)

            if self.config.log_queries:
                self.logger.info("Query validation successful")

            return True

        except Exception as e:
            if self.config.log_queries:
                self.logger.error(f"Query validation failed: {str(e)}")

            if self.config.raise_on_violation:
                raise
            return False
