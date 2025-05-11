from datetime import datetime
import uuid
from sqlalchemy import Column, String, Text, DateTime, ForeignKey, JSON, UUID
from sqlalchemy.orm import relationship

from app.database.base import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, index=True, default=uuid.uuid4)
    website_id = Column(UUID(as_uuid=True), ForeignKey("websites.id"), nullable=False)
    status = Column(String(20), default="pending")
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    website = relationship("Website", back_populates="scans")
    wpscan_result = relationship(
        "WPScanResult",
        back_populates="scan",
        uselist=False,
        cascade="all, delete-orphan",
    )
    lfi_result = relationship(
        "LFIResult", back_populates="scan", uselist=False, cascade="all, delete-orphan"
    )
    cmd_injection_result = relationship(
        "CommandInjectionResult",
        back_populates="scan",
        uselist=False,
        cascade="all, delete-orphan",
    )
    ssl_result = relationship(
        "SSLResult", back_populates="scan", uselist=False, cascade="all, delete-orphan"
    )
    dns_result = relationship(
        "DNSResult", back_populates="scan", uselist=False, cascade="all, delete-orphan"
    )
    open_ports_result = relationship(
        "OpenPortsResult",
        back_populates="scan",
        uselist=False,
        cascade="all, delete-orphan",
    )
    zone_transfer_result = relationship(
        "ZoneTransferResult",
        back_populates="scan",
        uselist=False,
        cascade="all, delete-orphan",
    )
    directory_scanning_result = relationship(
        "DirectoryScanningResult",
        back_populates="scan",
        uselist=False,
        cascade="all, delete-orphan",
    )

    def __repr__(self):
        return (
            f"<Scan(id={self.id}, website_id={self.website_id}, status={self.status})>"
        )


class WPScanResult(Base):
    __tablename__ = "wpscan_results"

    id = Column(UUID(as_uuid=True), primary_key=True, index=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    vulnerabilities_found = Column(JSON, nullable=True)
    plugins_found = Column(JSON, nullable=True)
    themes_found = Column(JSON, nullable=True)
    version_info = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="wpscan_result")

    def __repr__(self):
        return f"<WPScanResult(id={self.id}, scan_id={self.scan_id})>"


class XSSResult(Base):
    __tablename__ = "xss_results"

    id = Column(UUID(as_uuid=True), primary_key=True, index=True, default=uuid.uuid4)
    website_url_id = Column(
        UUID(as_uuid=True), ForeignKey("website_urls.id"), nullable=False
    )
    vulnerable_endpoints = Column(JSON, nullable=True)
    payloads_used = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    website_url = relationship("WebsiteUrl", back_populates="xss_results")

    def __repr__(self):
        return f"<XSSResult(id={self.id}, website_url_id={self.website_url_id})>"


class SQLiResult(Base):
    __tablename__ = "sqli_results"

    id = Column(UUID(as_uuid=True), primary_key=True, index=True, default=uuid.uuid4)
    website_url_id = Column(
        UUID(as_uuid=True), ForeignKey("website_urls.id"), nullable=False
    )
    vulnerable_params = Column(JSON, nullable=True)
    dbms_info = Column(Text, nullable=True)
    payloads_used = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    website_url = relationship("WebsiteUrl", back_populates="sqli_results")

    def __repr__(self):
        return f"<SQLiResult(id={self.id}, website_url_id={self.website_url_id})>"


class LFIResult(Base):
    __tablename__ = "lfi_results"

    id = Column(UUID(as_uuid=True), primary_key=True, index=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    vulnerable_endpoints = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="lfi_result")

    def __repr__(self):
        return f"<LFIResult(id={self.id}, scan_id={self.scan_id})>"


class CommandInjectionResult(Base):
    __tablename__ = "command_injection_results"

    id = Column(UUID(as_uuid=True), primary_key=True, index=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    vulnerable_endpoints = Column(JSON, nullable=True)
    commands_executed = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="cmd_injection_result")

    def __repr__(self):
        return f"<CommandInjectionResult(id={self.id}, scan_id={self.scan_id})>"


class SSLResult(Base):
    __tablename__ = "ssl_results"

    id = Column(UUID(as_uuid=True), primary_key=True, index=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    ssl_grade = Column(Text, nullable=True)
    issues_found = Column(JSON, nullable=True)
    certificate_details = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="ssl_result")

    def __repr__(self):
        return f"<SSLResult(id={self.id}, scan_id={self.scan_id})>"


class DNSResult(Base):
    __tablename__ = "dns_results"

    id = Column(UUID(as_uuid=True), primary_key=True, index=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    records = Column(JSON, nullable=True)
    misconfigurations = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="dns_result")

    def __repr__(self):
        return f"<DNSResult(id={self.id}, scan_id={self.scan_id})>"


class OpenPortsResult(Base):
    __tablename__ = "open_ports_results"

    id = Column(UUID(as_uuid=True), primary_key=True, index=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    open_ports = Column(JSON, nullable=True)
    services_detected = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="open_ports_result")

    def __repr__(self):
        return f"<OpenPortsResult(id={self.id}, scan_id={self.scan_id})>"


class ZoneTransferResult(Base):
    __tablename__ = "zone_transfer_results"

    id = Column(UUID(as_uuid=True), primary_key=True, index=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    transferable_domains = Column(JSON, nullable=True)
    issues_found = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="zone_transfer_result")

    def __repr__(self):
        return f"<ZoneTransferResult(id={self.id}, scan_id={self.scan_id})>"


class DirectoryScanningResult(Base):
    __tablename__ = "directory_scanning_results"

    id = Column(UUID(as_uuid=True), primary_key=True, index=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    directories_found = Column(JSON, nullable=True)
    sensitive_files_found = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="directory_scanning_result")

    def __repr__(self):
        return f"<DirectoryScanningResult(id={self.id}, scan_id={self.scan_id})>"
