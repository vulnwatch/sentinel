"""CNAAuditEvent model — audit trail for the auto-ignore policy of a CNA.

See `docs/data-model.md` (CNAAuditEvent) and `docs/features/tickets/cna.md`
(CNA Audit Log) for the full specification. This model implements the
persistence root; `CNAAuditLog.log_event()` (in `app.services.cna_service`)
handles validation and write.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.mixins import AuditEventMixin

if TYPE_CHECKING:
    from app.models.cna import CNA
    from app.models.user import User


class CNAAuditEvent(Base, AuditEventMixin):
    """Audit trail for administrative changes of `CNA.auto_ignore`.

    Inherits `id`, `created_at`, and the actor `user_id` from
    `AuditEventMixin`. Every CNA audit event has a human actor, enforced by
    `CNAAuditLog.log_event()` at the service layer (the `user_id` column
    remains nullable at the database level, consistent with every other
    audit event table). `old_value` and `new_value` are `NULL` for the
    current event types; `detail` carries the event-time display name of
    the CNA.
    """

    __tablename__ = "cna_audit_event"
    __table_args__ = (Index("ix_cna_audit_event_cna_id", "cna_id"),)

    cna_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cna.id", ondelete="RESTRICT"),
        nullable=False,
    )
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    old_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    new_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    detail: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)

    cna: Mapped[CNA] = relationship("CNA", back_populates="audit_events")
    # Read-only convenience relationship for API consumers. Deliberately
    # unidirectional and NOT back-populated: User gets no reverse
    # collection, mirroring SettingAuditEvent.actor and
    # FetcherAuditEvent.actor. `viewonly=True` because this model is
    # append-only and this relationship must never be used to persist
    # changes through ORM cascade.
    actor: Mapped[User | None] = relationship(
        "User", foreign_keys="CNAAuditEvent.user_id", viewonly=True
    )
