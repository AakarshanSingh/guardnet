import logging
import traceback
import os
import uvicorn

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from sqlalchemy.exc import SQLAlchemyError
from app.api.endpoints import router as api_router
from app.api.auth import router as auth_router
from app.core.config import settings
from app.database.base import Base, engine
from app.utils.api.responses import error_response, validation_error_response
from app.utils.browser_manager import browser_manager
from app.utils.api.json_encoder import CustomJSONEncoder
from urllib3.exceptions import NewConnectionError, MaxRetryError


logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url="/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc",
    json_encoder=CustomJSONEncoder,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],
)

try:
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created successfully")
except SQLAlchemyError as e:
    logger.error(f"Error creating database tables: {str(e)}")
    raise

app.include_router(auth_router, prefix=settings.API_V1_STR, tags=["auth"])
app.include_router(api_router, prefix=settings.API_V1_STR, tags=["scan"])


@app.get("/")
def root():
    """Root endpoint for API health check"""
    return {
        "message": "Welcome to GuardNet Security Scanner API",
        "status": "OK",
        "success": True,
    }


@app.get("/health")
def health_check():
    """Health check endpoint"""
    return {"status": "OK", "success": True}


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle validation errors with clear messages"""
    errors = []
    for error in exc.errors():
        error_msg = {
            "loc": error.get("loc", []),
            "msg": error.get("msg", ""),
            "type": error.get("type", ""),
        }
        errors.append(error_msg)

    return validation_error_response(errors=errors)


@app.exception_handler(SQLAlchemyError)
async def sqlalchemy_exception_handler(request: Request, exc: SQLAlchemyError):
    """Handle database errors safely"""
    logger.error(f"Database error: {str(exc)}\n{traceback.format_exc()}")
    return error_response(message="Database error occurred", status_code=500)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions"""
    return error_response(
        message=exc.detail,
        status_code=exc.status_code,
        errors=[{"type": "http_error", "detail": exc.detail}],
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle all other exceptions"""
    logger.error(f"Unhandled exception: {str(exc)}\n{traceback.format_exc()}")
    return error_response(message="Internal server error", status_code=500)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all incoming requests"""
    method = request.method
    path = request.url.path
    logger.debug(f"Request: {method} {path}")

    try:
        response = await call_next(request)
        return response
    except Exception as e:
        logger.error(f"Request error: {method} {path} - {str(e)}")
        raise


@app.on_event("shutdown")
def shutdown_event():
    """Clean up resources on shutdown"""
    try:
        browser_manager.close_browser()
        logger.info("Application shutdown: Browser instance closed successfully")
    except (NewConnectionError, ConnectionError, MaxRetryError) as e:
        logger.warning(
            f"Connection error during browser shutdown (expected behavior): {str(e)}"
        )
        if os.name == "nt":
            try:
                os.system("taskkill /f /im chromedriver.exe")
                logger.info("Force-killed chromedriver processes during shutdown")
            except Exception as kill_error:
                logger.error(
                    f"Failed to force kill browser processes: {str(kill_error)}"
                )
    except Exception as e:
        logger.error(f"Error during shutdown: {str(e)}")

    logger.info("Application shutdown complete")


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
