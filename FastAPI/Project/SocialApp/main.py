from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from App.core.database import get_db
import uvicorn
from contextlib import asynccontextmanager
from App.core.database import Base, engine
from App.user.models import User  # noqa: F401  # Import to register model with SQLAlchemy 
from App.user import router as user_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ─── Startup ─── (runs once when server starts)
    print("Application startup...")

    # Create tables (only creates missing ones — safe)
    Base.metadata.create_all(bind=engine)
    print("Tables created (learning mode)")

    # You can also run other startup tasks here, e.g.:
    # await some_async_init()
    # test_db_connection()

    yield  # ← hand over control to the app (requests can now be handled)

    # ─── Shutdown ─── (runs once when server stops — Ctrl+C, docker stop, etc.)
    print("Application shutdown...")
    # Optional: close things if needed
    # await engine.dispose()   # usually not necessary with connection pool


app = FastAPI(lifespan=lifespan)

app.include_router(user_router.router)


@app.get("/health")
def db_health_check(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "details": str(e)}


if __name__ == "__main__":
    uvicorn.run(app="main:app", host="localhost", port=8000, reload=True)
