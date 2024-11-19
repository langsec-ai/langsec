from sqlglot import exp
from sqlglot.expressions import AggFunc
from .base import BaseQueryValidator
from ..schema.sql.enums import AggregationType
from ..exceptions.errors import QueryComplexityError


class AggregationValidator(BaseQueryValidator):
    def validate(self, parsed: exp.Expression) -> None:
        """Validates aggregation functions against schema rules."""
        all_aggregations = AggFunc.__subclasses__()
        for agg in parsed.find_all(*all_aggregations):
            for column in agg.find_all(exp.Column):
                table_name = column.table or self._get_default_table(agg, column)
                if not table_name:
                    continue

                column_rule = self.schema.get_column_schema(table_name, column.name)
                if column_rule and column_rule.allowed_aggregations:
                    agg_type = self._get_aggregation_type(agg)
                    if agg_type not in column_rule.allowed_aggregations:
                        raise QueryComplexityError(f"Aggregation {agg_type} not allowed for column {column.name}")

    def _get_aggregation_type(self, agg: exp.Expression) -> AggregationType:
        """Maps sqlglot aggregation to AggregationType."""
        agg_map = {
            exp.Sum: AggregationType.SUM,
            exp.Avg: AggregationType.AVG,
            exp.Min: AggregationType.MIN,
            exp.Max: AggregationType.MAX,
            exp.Count: AggregationType.COUNT,
        }
        return agg_map.get(type(agg))  # type: ignore
