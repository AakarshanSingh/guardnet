from datetime import datetime
import uuid
from sqlalchemy import Column, String, Text, DateTime, func, UUID
from sqlalchemy.orm import relationship

from app.database.base import Base


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, index=True, default=uuid.uuid4)
    name = Column(String(255))
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    websites = relationship(
        "Website", back_populates="user", cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<User(id={self.id}, name={self.name}, email={self.email})>"
