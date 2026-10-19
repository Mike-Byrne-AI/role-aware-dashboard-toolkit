"""Bounded request contracts. Extra fields cannot smuggle roles or ownership."""

from datetime import datetime, timedelta, timezone
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StringConstraints, field_validator, model_validator

Short = Annotated[str, StringConstraints(strict=True, strip_whitespace=True, min_length=1, max_length=120)]
Notes = Annotated[str, StringConstraints(strict=True, strip_whitespace=True, max_length=4000)]
Body = Annotated[str, StringConstraints(strict=True, strip_whitespace=True, min_length=1, max_length=4000)]
Revision = Annotated[StrictInt, Field(ge=0)]


class RequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Login(RequestModel):
    username: Annotated[str, StringConstraints(strict=True, strip_whitespace=True, min_length=1, max_length=64)]
    password: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=128)]
    otp: Annotated[str, StringConstraints(strict=True, pattern=r"^[0-9]{6}$")] | None = None


class PasswordChange(RequestModel):
    current_password: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=128)]
    new_password: Annotated[str, StringConstraints(strict=True, min_length=12, max_length=128)]


class Empty(RequestModel):
    pass


class Schedule(RequestModel):
    title: Short
    starts_at: str
    ends_at: str
    location: Annotated[str, StringConstraints(strict=True, strip_whitespace=True, max_length=160)] = ""
    notes: Notes = ""
    employee_ids: Annotated[list[Short], Field(min_length=1, max_length=5)]

    @field_validator("starts_at", "ends_at")
    @classmethod
    def timestamp(cls, value):
        if len(value) > 40:
            raise ValueError("Use an ISO timestamp with a timezone.")
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("A timezone is required.")
        try:
            return parsed.astimezone(timezone.utc).isoformat(timespec="seconds")
        except OverflowError:
            raise ValueError("The timestamp is outside the supported range.") from None

    @model_validator(mode="after")
    def range_and_assignment(self):
        start, end = datetime.fromisoformat(self.starts_at), datetime.fromisoformat(self.ends_at)
        if end <= start or end - start > timedelta(days=7) or end <= datetime.now(timezone.utc):
            raise ValueError("The event must end in the future, after its start, within seven days.")
        if len(set(self.employee_ids)) != len(self.employee_ids):
            raise ValueError("Choose each employee once.")
        return self


class ScheduleUpdate(Schedule):
    revision: Revision


class RevisionRequest(RequestModel):
    revision: Revision


class Message(RequestModel):
    body: Body


class Submission(RequestModel):
    title: Short
    body: Body
    rules_version: Short
    accept_rules: StrictBool
    turnstile_token: Annotated[str, StringConstraints(strict=True, max_length=2048)] | None = None


class SubmissionReview(RevisionRequest):
    decision: Literal["approve", "reject"]


class Contact(RequestModel):
    name: Short
    company: Short
    email: Annotated[str, StringConstraints(strict=True, strip_whitespace=True, min_length=3, max_length=254, pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$")]
    stage: Literal["New", "Contacted", "Proposal", "Won"]
    value: Annotated[float, Field(ge=0, le=100_000_000, allow_inf_nan=False, strict=True)]
    notes: Notes = ""


class ContactUpdate(Contact):
    revision: Revision


class Post(RequestModel):
    title: Short
    body: Body
    category: Annotated[str, StringConstraints(strict=True, strip_whitespace=True, min_length=1, max_length=40)]
    published: StrictBool


class PostUpdate(Post):
    revision: Revision


class Freeze(RevisionRequest):
    frozen: StrictBool


class UserUpdate(RevisionRequest):
    active: StrictBool
