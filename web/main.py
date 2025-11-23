"""FastAPI application factory"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
import os

from web.database import engine, Base
from web.config import settings
from web.auth.router import router as auth_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle"""
    # Startup
    Base.metadata.create_all(bind=engine)

    # Create admin user if not exists
    from web.database import SessionLocal
    from web.models.user import User, UserRole
    from web.auth.security import get_password_hash

    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.email == settings.ADMIN_EMAIL).first()
        if not admin:
            admin = User(
                email=settings.ADMIN_EMAIL,
                password_hash=get_password_hash(settings.ADMIN_PASSWORD),
                role=UserRole.ADMIN
            )
            db.add(admin)
            db.commit()
            print(f"✅ Created admin user: {settings.ADMIN_EMAIL}")
    finally:
        db.close()

    yield
    # Shutdown
    pass


def create_app() -> FastAPI:
    """Create FastAPI application"""

    app = FastAPI(
        title="Knock Knock Web",
        description="Network Security Scanner Web Interface",
        version="1.0.0",
        lifespan=lifespan
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Include routers
    app.include_router(auth_router, prefix="/api/auth", tags=["auth"])

    # Import and include other routers
    try:
        from web.api import health, targets, target_lists, schedules, scans, reports, analytics
        app.include_router(health.router, prefix="/api", tags=["health"])
        app.include_router(targets.router, prefix="/api/targets", tags=["targets"])
        app.include_router(target_lists.router, prefix="/api/target-lists", tags=["target_lists"])
        app.include_router(schedules.router, prefix="/api/schedules", tags=["schedules"])
        app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
        app.include_router(reports.router, prefix="/api/reports", tags=["reports"])
        app.include_router(analytics.router, prefix="/api/analytics", tags=["analytics"])
    except ImportError as e:
        print(f"⚠️  Some API routers not yet implemented: {e}")

    # Serve static files if they exist
    if os.path.exists("web/ui/static"):
        app.mount("/static", StaticFiles(directory="web/ui/static"), name="static")

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
