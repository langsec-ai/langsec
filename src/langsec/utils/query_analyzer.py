from typing import Dict, Set, Optional
from sqlglot import parse_one, exp

class QueryAnalyzer:
    """Utility class for analyzing SQL queries."""
    
    @staticmethod
    def estimate_row_count(query: str) -> int:
        """
        Estimates the number of rows that might be returned by a query.
        This is a simple estimation based on query structure.
        """
        parsed = parse_one(query)
        base_rows = 1000  # Default assumption
        
        # Adjust based on LIMIT
        limit = QueryAnalyzer._find_limit(parsed)
        if limit is not None:
            base_rows = min(base_rows, limit)
            
        # Adjust based on joins
        join_multiplier = len(list(parsed.find_all(exp.Join))) + 1
        
        # Adjust based on aggregations
        if QueryAnalyzer._has_aggregation(parsed):
            base_rows = base_rows // 10
            
        return base_rows * join_multiplier

    @staticmethod
    def _find_limit(parsed: exp.Expression) -> Optional[int]:
        """Finds LIMIT clause value if present."""
        for limit in parsed.find_all(exp.Limit):
            if isinstance(limit.value, (int, str)):
                try:
                    return int(limit.value)
                except ValueError:
                    continue
        return None

    @staticmethod
    def _has_aggregation(parsed: exp.Expression) -> bool:
        """Checks if query contains aggregation functions."""
        return any(parsed.find_all(exp.Aggregate))

    @staticmethod
    def extract_table_dependencies(query: str) -> Dict[str, Set[str]]:
        """
        Extracts table dependencies from a query.
        Returns a dict of table -> set of dependent tables.
        """
        parsed = parse_one(query)
        dependencies: Dict[str, Set[str]] = {}
        
        # Handle FROM clause
        for select in parsed.find_all(exp.Select):
            current_table = None
            for table in select.find_all(exp.Table):
                if current_table:
                    dependencies.setdefault(current_table, set()).add(table.name)
                current_table = table.name
                
        # Handle JOINs
        for join in parsed.find_all(exp.Join):
            left_table = QueryAnalyzer._extract_table_name(join.left)
            right_table = QueryAnalyzer._extract_table_name(join.right)
            if left_table and right_table:
                dependencies.setdefault(left_table, set()).add(right_table)
                
        return dependencies

    @staticmethod
    def _extract_table_name(expr: exp.Expression) -> Optional[str]:
        """Extracts table name from an expression."""
        if isinstance(expr, exp.Table):
            return expr.name
        for table in expr.find_all(exp.Table):
            return table.name
        return None