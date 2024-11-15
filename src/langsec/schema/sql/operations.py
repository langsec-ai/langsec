from typing import Set
from pydantic import BaseModel, ConfigDict, Field

from .enums import JoinType


class JoinRule(BaseModel):
    allowed_types: Set[JoinType] = Field(
        default_factory=lambda: {JoinType.INNER, JoinType.LEFT}
    )

    model_config = ConfigDict(validate_assignment=True, arbitrary_types_allowed=True)
