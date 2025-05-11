from datetime import datetime
import uuid
from sqlalchemy import Column, String, Text, DateTime, ForeignKey, UUID
from sqlalchemy.orm import relationship

from app.database.base import Base


class Website(Base):
    __tablename__ = "websites"

    id = Column(UUID(as_uuid=True), primary_key=True, index=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    url = Column(Text, nullable=False)
    cookies = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="websites")
    website_urls = relationship(
        "WebsiteUrl", back_populates="website", cascade="all, delete-orphan"
    )
    scans = relationship("Scan", back_populates="website", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Website(id={self.id}, url={self.url})>"


class WebsiteUrl(Base):
    __tablename__ = "website_urls"

    id = Column(UUID(as_uuid=True), primary_key=True, index=True, default=uuid.uuid4)
    website_id = Column(UUID(as_uuid=True), ForeignKey("websites.id"), nullable=False)
    url = Column(Text, nullable=False)
    status = Column(String(20), default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)

    website = relationship("Website", back_populates="website_urls")
    xss_results = relationship(
        "XSSResult", back_populates="website_url", cascade="all, delete-orphan"
    )
    sqli_results = relationship(
        "SQLiResult", back_populates="website_url", cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<WebsiteUrl(id={self.id}, url={self.url}, status={self.status})>"
