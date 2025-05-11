from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID
from pydantic import BaseModel, Field


class WebsiteUrlBase(BaseModel):
    """Base schema for website URLs"""

    url: str


class WebsiteUrlCreate(WebsiteUrlBase):
    """Schema for creating website URLs"""

    pass


class WebsiteUrlResponse(WebsiteUrlBase):
    """Schema for website URL responses"""

    id: int
    website_id: int
    status: str
    created_at: datetime

    model_config = {"from_attributes": True}


class WebsiteBase(BaseModel):
    """Base schema for websites"""

    url: str
    cookies: Optional[str] = None


class WebsiteCreate(WebsiteBase):
    """Schema for creating websites"""

    urls: Optional[List[WebsiteUrlCreate]] = []
    exclude_patterns: Optional[List[str]] = []


class WebsiteResponse(WebsiteBase):
    """Schema for website responses"""

    id: int
    user_id: int
    created_at: datetime
    website_urls: List[WebsiteUrlResponse] = []

    model_config = {"from_attributes": True}


class ScanBase(BaseModel):
    """Base schema for scans"""

    website_id: int

    class Config:
        json_encoders = {UUID: str}


class ScanCreate(ScanBase):
    """Schema for creating scans"""

    scan_types: Optional[List[str]] = Field(
        default=[
            "wordpress",
            "xss",
            "sqli",
            "lfi",
            "command_injection",
            "ssl",
            "dns",
            "open_ports",
            "zone_transfer",
            "directory_scanning",
        ]
    )


class ScanResponse(ScanBase):
    """Schema for scan responses"""

    id: int
    status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanStatusResponse(BaseModel):
    """Schema for scan status responses"""

    id: int
    status: str
    progress: Optional[float] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    current_scanner: Optional[str] = None

    model_config = {"from_attributes": True}


class ScanResultBase(BaseModel):
    """Base schema for scan results"""

    scan_id: int


class WPScanResultResponse(ScanResultBase):
    """Schema for WP scan result responses"""

    vulnerabilities_found: Optional[List[Dict[str, Any]]] = []
    plugins_found: Optional[List[Dict[str, Any]]] = []
    themes_found: Optional[List[Dict[str, Any]]] = []
    version_info: Optional[str] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class XSSResultResponse(BaseModel):
    """Schema for XSS scan result responses"""

    website_url_id: int
    vulnerable_endpoints: Optional[List[Dict[str, Any]]] = []
    payloads_used: Optional[List[str]] = []
    created_at: datetime

    model_config = {"from_attributes": True}


class SQLiResultResponse(BaseModel):
    """Schema for SQLi scan result responses"""

    website_url_id: int
    vulnerable_params: Optional[List[Dict[str, Any]]] = []
    dbms_info: Optional[str] = None
    payloads_used: Optional[List[str]] = []
    created_at: datetime

    model_config = {"from_attributes": True}


class LFIResultResponse(ScanResultBase):
    """Schema for LFI scan result responses"""

    vulnerable_endpoints: Optional[List[Dict[str, Any]]] = []
    created_at: datetime

    model_config = {"from_attributes": True}


class CommandInjectionResultResponse(ScanResultBase):
    """Schema for Command Injection scan result responses"""

    vulnerable_endpoints: Optional[List[Dict[str, Any]]] = []
    commands_executed: Optional[List[str]] = []
    created_at: datetime

    model_config = {"from_attributes": True}


class SSLResultResponse(ScanResultBase):
    """Schema for SSL scan result responses"""

    ssl_grade: Optional[str] = None
    issues_found: Optional[List[Dict[str, Any]]] = []
    certificate_details: Optional[Dict[str, Any]] = {}
    created_at: datetime

    model_config = {"from_attributes": True}


class DNSResultResponse(ScanResultBase):
    """Schema for DNS scan result responses"""

    records: Optional[Dict[str, List[str]]] = {}
    misconfigurations: Optional[List[Dict[str, Any]]] = []
    created_at: datetime

    model_config = {"from_attributes": True}


class OpenPortsResultResponse(ScanResultBase):
    """Schema for Open Ports scan result responses"""

    open_ports: Optional[List[int]] = []
    services_detected: Optional[Dict[str, str]] = {}
    created_at: datetime

    model_config = {"from_attributes": True}


class ZoneTransferResultResponse(ScanResultBase):
    """Schema for Zone Transfer scan result responses"""

    transferable_domains: Optional[List[str]] = []
    issues_found: Optional[List[Dict[str, Any]]] = []
    created_at: datetime

    model_config = {"from_attributes": True}


class DirectoryScanningResultResponse(ScanResultBase):
    """Schema for Directory Scanning result responses"""

    directories_found: Optional[List[str]] = []
    sensitive_files_found: Optional[List[Dict[str, Any]]] = []
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanResultResponse(BaseModel):
    """Combined schema for all scan results"""

    scan: ScanResponse
    wpscan_result: Optional[WPScanResultResponse] = None
    xss_results: Optional[List[XSSResultResponse]] = []
    sqli_results: Optional[List[SQLiResultResponse]] = []
    lfi_result: Optional[LFIResultResponse] = None
    command_injection_result: Optional[CommandInjectionResultResponse] = None
    ssl_result: Optional[SSLResultResponse] = None
    dns_result: Optional[DNSResultResponse] = None
    open_ports_result: Optional[OpenPortsResultResponse] = None
    zone_transfer_result: Optional[ZoneTransferResultResponse] = None
    directory_scanning_result: Optional[DirectoryScanningResultResponse] = None

    model_config = {"from_attributes": True}


class PaginatedResponse(BaseModel):
    """Base schema for paginated responses"""

    total: int
    page: int
    page_size: int
    pages: int


class ScanListResponse(PaginatedResponse):
    """Schema for paginated scan list responses"""

    items: List[ScanResponse]

    model_config = {"from_attributes": True}


class DirectScanCreate(BaseModel):
    """Schema for creating a scan directly with URL"""

    url: str
    cookies: Optional[str] = None
    scan_types: Optional[List[str]] = None

    class Config:
        json_encoders = {UUID: str}
