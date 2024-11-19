from typing import Dict, Optional, Set
from sqlglot import exp
from .base import BaseQueryValidator
from ..schema.sql.enums import Access, Operation
from ..exceptions.errors import ColumnAccessError


class ColumnValidator(BaseQueryValidator):
    def _resolve_table_name(self, parsed: exp.Expression, table_alias: str) -> Optional[str]:
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

    def _get_column_operations(self, column: exp.Column, parsed: exp.Expression) -> Set[Operation]:
        """
        Determine all operations being performed on a column, including in nested queries.
        Returns a set of operations (SELECT, UPDATE, INSERT, DELETE).
        """
        operations = set()
        current_node = column

        # First, check if we're in a DELETE context
        delete_node = parsed.find(exp.Delete)
        if delete_node:
            # For DELETE queries, we need both DELETE and SELECT permissions
            operations.add(Operation.DELETE)
            operations.add(Operation.SELECT)  # For WHERE clause evaluation

        # Traverse up the tree to find all relevant operations
        while current_node:
            if isinstance(current_node, (exp.Select, exp.Subquery)):
                operations.add(Operation.SELECT)
            elif isinstance(current_node, exp.Update):
                if hasattr(current_node, "expressions"):
                    for expr in current_node.expressions:
                        if (
                            isinstance(expr, exp.EQ)
                            and isinstance(expr.left, exp.Column)
                            and expr.left.name.lower() == column.name.lower()
                        ):
                            operations.add(Operation.UPDATE)
                            break
                operations.add(Operation.SELECT)
            elif isinstance(current_node, exp.Insert):
                if hasattr(current_node, "expressions"):
                    for col in current_node.expressions:
                        if isinstance(col, exp.Column) and col.name.lower() == column.name.lower():
                            operations.add(Operation.INSERT)
                            break
                if current_node.find(exp.Select):
                    operations.add(Operation.SELECT)

            current_node = current_node.parent

        return operations

    def validate(self, parsed: exp.Expression) -> None:
        aliases = self._get_table_aliases(parsed)
        write_columns = self._get_write_columns(parsed, aliases)

        # Special handling for DELETE operations
        if parsed.find(exp.Delete):
            table_name = None
            delete_node = parsed.find(exp.Delete)
            if hasattr(delete_node, "this") and isinstance(delete_node.this, exp.Table):  # type: ignore
                table_name = delete_node.this.name.lower()  # type: ignore

                # Check if any column in the table has DELETE permission
                table_schema = self.schema.tables.get(table_name)
                if table_schema:
                    has_delete_permission = False
                    for _, col_schema in table_schema.columns.items():
                        if Operation.DELETE in col_schema.allowed_operations:
                            has_delete_permission = True
                            break
                    if not has_delete_permission:
                        raise ColumnAccessError(f"DELETE operation not allowed on table '{table_name}'")

        for column in parsed.find_all(exp.Column):
            table_name = None
            if column.table:
                table_name = aliases.get(column.table.lower()) or column.table.lower()
            else:
                table_name = self._get_default_table(parsed, column)

            if not table_name:
                continue

            column_name = str(column.name).lower()
            column_rule = self.schema.get_column_schema(table_name, column_name)

            # Check if column exists and has access
            if column_rule.access == Access.DENIED:
                raise ColumnAccessError(f"Access denied for column '{column_name}' in table '{table_name}'")

            # Get all operations being performed on this column
            column_operations = self._get_column_operations(column, parsed)

            # Check if all operations are allowed for this column
            for operation in column_operations:
                if operation not in column_rule.allowed_operations:
                    raise ColumnAccessError(
                        f"Operation {operation} not allowed for column '{column_name}' in table '{table_name}'. "
                        f"Allowed operations: {', '.join(column_rule.allowed_operations)}"
                    )

            # Check if column is being written to and only has READ access
            col_id = f"{table_name}.{column_name}"
            if col_id in write_columns and column_rule.access == Access.READ:
                raise ColumnAccessError(
                    f"Write access denied for column '{column_name}' in table '{table_name}'. "
                    f"Column only has read access."
                )

    def _get_write_columns(self, parsed: exp.Expression, aliases: Dict[str, str]) -> Set[str]:
        """Get set of columns that are being written to."""
        write_columns = set()

        def add_write_column(column: exp.Column, table_context: Optional[str] = None) -> None:
            """Helper to add column to write set."""
            table_name = None
            if column.table:
                table_name = aliases.get(column.table.lower()) or column.table.lower()
            elif table_context:
                table_name = table_context
            else:
                table_name = self._get_default_table(parsed, column)

            if table_name:
                col_id = f"{table_name}.{column.name.lower()}"
                write_columns.add(col_id)

        # Handle UPDATE SET clause
        for update in parsed.find_all(exp.Update):
            table_context = update.this.name if isinstance(update.this, exp.Table) else None
            if hasattr(update, "expressions"):
                for expr in update.expressions:
                    if isinstance(expr, exp.EQ) and isinstance(expr.left, exp.Column):
                        add_write_column(expr.left, table_context)

        # Handle INSERT columns
        for insert in parsed.find_all(exp.Insert):
            table_context = insert.this.name if isinstance(insert.this, exp.Table) else None
            if hasattr(insert, "expressions"):
                for col in insert.expressions:
                    if isinstance(col, exp.Column):
                        add_write_column(col, table_context)

        # Handle DELETE - gets all columns from the target table used in the query
        for delete in parsed.find_all(exp.Delete):
            table_context = delete.this.name if isinstance(delete.this, exp.Table) else None
            if table_context:
                for column in delete.find_all(exp.Column):
                    if not column.table or column.table.lower() == table_context.lower():
                        add_write_column(column, table_context)

        return write_columns
