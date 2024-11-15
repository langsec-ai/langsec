from typing import Dict, Optional
from sqlglot import exp
from .base import BaseQueryValidator
from ..schema.sql.enums import Access
from ..exceptions.errors import ColumnAccessError


class ColumnValidator(BaseQueryValidator):
    def _resolve_table_name(
        self, parsed: exp.Expression, table_alias: str
    ) -> Optional[str]:
        """Resolve table alias to actual table name."""
        for table in parsed.find_all(exp.Table):
            if table.alias and table.alias.lower() == table_alias.lower():
                return table.name.lower()
        return None

    def _get_table_aliases(self, parsed: exp.Expression) -> Dict[str, str]:
        """Get mapping of aliases to actual table names."""
        aliases = {}
        for table in parsed.find_all(exp.Table):
            if table.alias:
                aliases[table.alias.lower()] = table.name.lower()
        return aliases

    def validate(self, parsed: exp.Expression) -> None:
        aliases = self._get_table_aliases(parsed)
        column_access = self._get_columns_to_access(parsed)

        for column in parsed.find_all(exp.Column):
            table_name = None
            if column.table:
                # If column has a table reference, try to resolve alias
                table_name = aliases.get(column.table.lower()) or column.table.lower()
            else:
                table_name = self._get_default_table(parsed, column)

            if not table_name:
                continue

            column_name = str(column.name).lower()
            column_rule = self.schema.get_column_schema(table_name, column_name)

            # Check if column exists in schema
            if column_rule.access == Access.DENIED:
                raise ColumnAccessError(
                    f"Column '{column_name}' not found in table '{table_name}' schema"
                )

            # Check column access (read/write)
            col_id = f"{table_name}.{column_name}"
            required_access = column_access.get(col_id)
            
            if required_access is None:
                continue
                
            if not column_rule.access:
                continue
                
            # If write access is required but column only has read access
            if required_access == Access.WRITE and column_rule.access == Access.READ:
                raise ColumnAccessError(
                    f"Write access denied for column '{column_name}' in table '{table_name}'. "
                    f"Column only has read access."
                )
            
            
    def _get_columns_to_access(self, parsed: exp.Expression) -> Dict[str, Access]:
        """
        Parse the query recursively to find all columns to access and figure out the access type.
        
        Args:
            parsed: The parsed SQL expression
            
        Returns:
            Dictionary mapping column identifiers to their access types
        """
        access_map: Dict[str, Access] = {}
        
        def add_column_access(column: exp.Column, access: Access) -> None:
            """Helper to add column access to the map."""
            # Create a unique identifier for the column
            col_id = f"{column.table}.{column.name}" if column.table else column.name
            
            # Only upgrade to WRITE if it's currently READ
            if col_id not in access_map or access_map[col_id] == Access.READ:
                access_map[col_id] = access

        def process_node(node: exp.Expression) -> None:
            """Recursively process nodes to determine column access."""
            
            # Handle INSERT statements
            if isinstance(node, exp.Insert):
                # Columns being inserted into have WRITE access
                for col in node.args.get('expressions', []):
                    if isinstance(col, exp.Column):
                        add_column_access(col, Access.WRITE)
                
                # Process values for any column references
                if node.expression:
                    process_node(node.expression)

            # Handle UPDATE statements
            elif isinstance(node, exp.Update):
                # Columns being updated have WRITE access
                for assignment in node.expressions:
                    if isinstance(assignment, exp.EQ):
                        if isinstance(assignment.left, exp.Column):
                            add_column_access(assignment.left, Access.WRITE)
                        if isinstance(assignment.right, exp.Column):
                            add_column_access(assignment.right, Access.READ)
                
                # Process WHERE clause
                if node.this:
                    process_node(node.this)

            # Handle DELETE statements
            elif isinstance(node, exp.Delete):
                # Mark all columns from the target table as WRITE
                table_name = node.this.name if isinstance(node.this, exp.Table) else None
                if table_name:
                    # Mark primary key or identifying columns as WRITE
                    # In a DELETE operation, we're effectively writing to all columns
                    for column in parsed.find_all(exp.Column):
                        if column.table and column.table.lower() == table_name.lower():
                            add_column_access(column, Access.WRITE)
                        
                # Process WHERE clause columns as READ
                if node.expression:
                    process_node(node.expression)

            # Handle SELECT statements
            elif isinstance(node, exp.Select):
                # Process selected columns
                for expr in node.expressions:
                    if isinstance(expr, exp.Column):
                        add_column_access(expr, Access.READ)
                    elif isinstance(expr, exp.Alias):
                        if isinstance(expr.this, exp.Column):
                            add_column_access(expr.this, Access.READ)
                
                # Process WHERE clause
                if node.this:
                    process_node(node.this)
                
                # Process GROUP BY
                for group_expr in node.find_all(exp.Group):
                    for expr in group_expr.expressions:
                        if isinstance(expr, exp.Column):
                            add_column_access(expr, Access.READ)
                
                # Process HAVING
                for having_expr in node.find_all(exp.Having):
                    process_conditions(having_expr.this)
                
                # Process ORDER BY
                for order_expr in node.find_all(exp.Order):
                    for expr in order_expr.expressions:
                        if isinstance(expr, exp.Column):
                            add_column_access(expr, Access.READ)

            # Handle WHERE conditions
            elif isinstance(node, exp.Where):
                process_conditions(node.this)

        def process_conditions(condition: exp.Expression) -> None:
            """Process WHERE/HAVING conditions to track column access."""
            if isinstance(condition, exp.Binary):
                if isinstance(condition.left, exp.Column):
                    add_column_access(condition.left, Access.READ)
                elif isinstance(condition.left, exp.Expression):
                    process_conditions(condition.left)
                    
                if isinstance(condition.right, exp.Column):
                    add_column_access(condition.right, Access.READ)
                elif isinstance(condition.right, exp.Expression):
                    process_conditions(condition.right)

            elif isinstance(condition, exp.In):
                if isinstance(condition.this, exp.Column):
                    add_column_access(condition.this, Access.READ)
                if hasattr(condition, 'expressions'):
                    for expr in condition.expressions:
                        if isinstance(expr, exp.Column):
                            add_column_access(expr, Access.READ)

            elif isinstance(condition, exp.Between):
                if isinstance(condition.this, exp.Column):
                    add_column_access(condition.this, Access.READ)

            elif isinstance(condition, (exp.And, exp.Or)):
                process_conditions(condition.left)
                process_conditions(condition.right)
                
            elif isinstance(condition, exp.Column):
                add_column_access(condition, Access.READ)

        # Start processing from the root node
        process_node(parsed)
        
        return access_map
    
            
