from typing import Any, List, Dict, Optional
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    status,
    BackgroundTasks,
    Body,
    Request,
)
from sqlalchemy.orm import Session
from pydantic import ValidationError
from uuid import UUID
import json
import requests
from app.auth.deps import get_current_active_user
from app.database.base import get_db
from app.models.user import User
from app.models.website import Website, WebsiteUrl
from app.models.scan import (
    Scan,
    SSLResult,
    DNSResult,
    OpenPortsResult,
    ZoneTransferResult,
    DirectoryScanningResult,
)
from app.api import schemas
from app.api.services import ScanService
from app.core.config import settings
from app.utils.api.responses import success_response, error_response, not_found_response

router = APIRouter()


@router.post("/scan", response_model=None)
async def create_scan(
    *,
    db: Session = Depends(get_db),
    scan_data: schemas.DirectScanCreate = Body(...),
    current_user: User = Depends(get_current_active_user),
    background_tasks: BackgroundTasks,
) -> Any:
    """
    Create new scan for a website using URL directly.
    Accepts URL, cookies, and scan types.
    """
    try:

        scan = await ScanService.create_scan_record(
            db=db,
            url=scan_data.url,
            cookies=scan_data.cookies,
            user_id=current_user.id,
        )

        background_tasks.add_task(
            ScanService.run_scan,
            db=db,
            scan_id=scan.id,
            scan_types=scan_data.scan_types,
        )

        scan_dict = {
            "scan_id": str(scan.id),
            "website_id": str(scan.website_id),
            "status": scan.status,
            "started_at": scan.started_at,
            "completed_at": scan.completed_at,
            "created_at": scan.created_at,
        }

        return success_response(
            data=scan_dict,
            message="Scan created successfully and will run in background",
            status_code=status.HTTP_201_CREATED,
        )
    except ValidationError as e:
        return error_response(
            message=f"Invalid request data: {str(e)}",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    except Exception as e:
        return error_response(
            message=f"Error creating scan: {str(e)}",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/scan/status", response_model=None)
def get_scan_status(
    *,
    db: Session = Depends(get_db),
    id: str = Query(..., description="ID of the scan (UUID format)"),
    current_user: User = Depends(get_current_active_user),
) -> Any:
    """
    Get the status of a specific scan.
    """

    try:
        scan_id = UUID(id)
    except ValueError:
        return error_response(
            message=f"Invalid scan ID format: {id}. Must be a valid UUID.",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    scan = (
        db.query(Website.user_id)
        .join(Website.scans)
        .filter(Scan.id == scan_id, Website.user_id == current_user.id)
        .first()
    )

    if not scan:
        return not_found_response(
            resource_type="Scan",
            message=f"Scan with ID {id} not found or does not belong to you",
        )

    try:
        result = ScanService.get_scan_status(db=db, scan_id=scan_id)

        if "id" in result and isinstance(result["id"], UUID):
            result["id"] = str(result["id"])
        if "website_id" in result and isinstance(result["website_id"], UUID):
            result["website_id"] = str(result["website_id"])

        return success_response(
            data=result,
            message="Scan status retrieved successfully",
        )
    except Exception as e:
        return error_response(
            message=f"Error getting scan status: {str(e)}",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/scan/result", response_model=None)
def get_scan_result(
    *,
    db: Session = Depends(get_db),
    id: str = Query(..., description="ID of the scan (UUID format)"),
    current_user: User = Depends(get_current_active_user),
) -> Any:
    """
    Get the detailed results of a specific scan including all scan types.
    Returns comprehensive data from:
    1. WordPress Scan
    2. XSS Scan
    3. SQLi Scan
    4. LFI Scan
    5. Command Injection Scan
    6. SSL Scan
    7. DNS Scan
    8. Open Ports Scan
    9. Zone Transfer Scan
    10. Directory Scanning
    """

    try:
        scan_id = UUID(id)
    except ValueError:
        return error_response(
            message=f"Invalid scan ID format: {id}. Must be a valid UUID.",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    scan = (
        db.query(Scan, Website)
        .join(Website, Scan.website_id == Website.id)
        .filter(Scan.id == scan_id, Website.user_id == current_user.id)
        .first()
    )

    if not scan:
        return not_found_response(
            resource_type="Scan",
            message=f"Scan with ID {id} not found or does not belong to you",
        )

    try:

        result = ScanService.get_scan_result(db=db, scan_id=scan_id)
        import logging

        logger = logging.getLogger(__name__)

        website = db.query(Website).filter(Website.id == scan[0].website_id).first()
        all_urls = (
            db.query(WebsiteUrl).filter(WebsiteUrl.website_id == website.id).all()
        )

        urls_data = []
        for url_obj in all_urls:

            url_data = {
                "id": str(url_obj.id),
                "url": url_obj.url,
                "status": url_obj.status,
            }

            if hasattr(url_obj, "is_main"):
                url_data["is_main"] = url_obj.is_main

            urls_data.append(url_data)

        result["website_data"] = {
            "url": website.url,
            "cookies": website.cookies,
            "all_urls": urls_data,
        }

        scan_types = [
            "wordpress",
            "xss",
            "sqli",
            "lfi",
            "command_injection",
            "ssl",
            "dns",
            "ports",
            "zone_transfer",
            "directories",
        ]

        for scan_type in scan_types:
            if scan_type not in result:
                if scan_type == "wordpress":
                    result[scan_type] = {"is_wordpress": False}
                elif scan_type in ["xss", "sqli"]:
                    result[scan_type] = []
                elif scan_type == "ports":
                    result[scan_type] = {"open_ports": [], "services_detected": {}}
                elif scan_type == "directories":
                    result[scan_type] = {
                        "directories_found": [],
                        "sensitive_files_found": [],
                    }
                elif scan_type == "zone_transfer":
                    result[scan_type] = {"transferable_domains": [], "issues_found": []}
                elif scan_type == "dns":
                    result[scan_type] = {"records": {}, "misconfigurations": []}
                elif scan_type == "ssl":
                    result[scan_type] = {
                        "ssl_grade": None,
                        "issues_found": [],
                        "certificate_details": {},
                    }
                elif scan_type == "lfi":
                    result[scan_type] = {"vulnerable_endpoints": []}
                elif scan_type == "command_injection":
                    result[scan_type] = {
                        "vulnerable_endpoints": [],
                        "commands_executed": [],
                    }

        result["summary"] = {
            "scan_completed": scan[0].status == "completed",
            "scan_status": scan[0].status,
            "scan_started_at": scan[0].started_at,
            "scan_completed_at": scan[0].completed_at,
            "total_issues_found": _count_vulnerabilities_for_scan(db, scan_id),
            "high_severity_issues": _count_vulnerabilities_by_severity(
                db, scan_id, "high"
            ),
            "medium_severity_issues": _count_vulnerabilities_by_severity(
                db, scan_id, "medium"
            ),
            "low_severity_issues": _count_vulnerabilities_by_severity(
                db, scan_id, "low"
            ),
        }

        return success_response(
            data=result,
            message="Scan results retrieved successfully",
        )
    except Exception as e:
        logger.error(f"Error getting scan result: {str(e)}", exc_info=True)
        return error_response(
            message=f"Error getting scan result: {str(e)}",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/scan/report", response_model=None)
def get_scan_report(
    *,
    db: Session = Depends(get_db),
    id: str = Query(..., description="ID of the scan (UUID format)"),
    format: str = Query("json", description="Report format (json, excel, pdf)"),
    current_user: User = Depends(get_current_active_user),
    request: Request,
) -> Any:
    """
    Generate and download a report for a scan.
    """

    try:
        scan_id = UUID(id)
    except ValueError:
        return error_response(
            message=f"Invalid scan ID format: {id}. Must be a valid UUID.",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    scan = (
        db.query(Website.user_id)
        .join(Website.scans)
        .filter(Scan.id == scan_id, Website.user_id == current_user.id)
        .first()
    )

    if not scan:
        return not_found_response(
            resource_type="Scan",
            message=f"Scan with ID {id} not found or does not belong to you",
        )

    try:
        report = ScanService.generate_report(
            db=db, scan_id=scan_id, report_format=format
        )

        if isinstance(report, dict):
            return success_response(
                data=report,
                message=f"Report generated in {format} format",
            )
        else:

            origin = request.headers.get("origin")

            if origin and origin in settings.BACKEND_CORS_ORIGINS:
                headers = dict(report.headers)
                headers["Access-Control-Allow-Origin"] = origin
                headers["Access-Control-Allow-Credentials"] = "true"
                headers["Access-Control-Allow-Methods"] = (
                    "GET, POST, PUT, DELETE, OPTIONS"
                )
                headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
                headers["Access-Control-Expose-Headers"] = "Content-Disposition"

                from fastapi.responses import Response

                return Response(
                    content=report.body,
                    status_code=report.status_code,
                    headers=headers,
                    media_type=report.media_type,
                )

            return report
    except ValueError as e:
        return error_response(
            message=str(e),
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    except Exception as e:
        return error_response(
            message=f"Error generating report: {str(e)}",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/dashboard/scans", response_model=None)
def list_scans(
    request: Request,
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(10, ge=1, le=100, description="Items per page"),
    limit: int = Query(
        None, description="Alias for page_size for backwards compatibility"
    ),
    current_user: User = Depends(get_current_active_user),
) -> Any:
    """
    List all scans for the current user with pagination.
    """
    try:

        print(f"Fetching scans for user_id: {current_user.id}")

        if limit is not None:
            page_size = limit

        result = ScanService.list_scans(
            db=db, user_id=current_user.id, page=page, page_size=page_size
        )

        print(
            f"Found {len(result.get('items', []))} scans for user_id: {current_user.id}"
        )

        serialized_items = []
        for scan in result.get("items", []):
            scan_dict = {
                "id": str(scan.id),
                "website_id": str(scan.website_id),
                "status": scan.status,
                "started_at": scan.started_at,
                "completed_at": scan.completed_at,
                "created_at": scan.created_at,
                "url": scan.website.url if scan.website else None,
                "vulnerabilities_summary": {
                    "total": _count_vulnerabilities_for_scan(db, scan.id),
                    "high": _count_vulnerabilities_by_severity(db, scan.id, "high"),
                    "medium": _count_vulnerabilities_by_severity(db, scan.id, "medium"),
                    "low": _count_vulnerabilities_by_severity(db, scan.id, "low"),
                },
            }
            serialized_items.append(scan_dict)

        result["items"] = serialized_items

        return success_response(
            data=result,
            message="Scans retrieved successfully",
        )
    except Exception as e:
        print(f"Error listing scans: {str(e)}")
        return error_response(
            message=f"Error listing scans: {str(e)}",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


def _count_vulnerabilities_for_scan(db: Session, scan_id: UUID) -> int:
    """Count total vulnerabilities across all scan results"""
    total = 0

    ssl_result = db.query(SSLResult).filter(SSLResult.scan_id == scan_id).first()
    if ssl_result and ssl_result.issues_found:
        total += len(json.loads(ssl_result.issues_found))

    dns_result = db.query(DNSResult).filter(DNSResult.scan_id == scan_id).first()
    if dns_result and dns_result.misconfigurations:
        total += len(json.loads(dns_result.misconfigurations))

    return total


def _count_vulnerabilities_by_severity(
    db: Session, scan_id: UUID, severity: str
) -> int:
    """Count vulnerabilities of a specific severity"""
    count = 0

    ssl_result = db.query(SSLResult).filter(SSLResult.scan_id == scan_id).first()
    if ssl_result and ssl_result.issues_found:
        issues = json.loads(ssl_result.issues_found)
        count += sum(1 for issue in issues if issue.get("severity") == severity)

    dns_result = db.query(DNSResult).filter(DNSResult.scan_id == scan_id).first()
    if dns_result and dns_result.misconfigurations:
        issues = json.loads(dns_result.misconfigurations)
        count += sum(1 for issue in issues if issue.get("severity") == severity)

    return count
