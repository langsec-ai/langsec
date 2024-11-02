from typing import Optional
from pydantic import BaseModel


class LangSecConfig(BaseModel):
    """Optional configuration for LangSec behavior."""

    log_queries: bool = False
    log_path: Optional[str] = None
    raise_on_violation: bool = True
    dry_run_mode: bool = False # TODO: implement.
