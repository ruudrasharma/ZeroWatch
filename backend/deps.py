"""
ZeroWatch — SQLAlchemy session dependency for FastAPI.

Authors:
    Bhavishyata Yadav (24CSU036)
    Bhavya Jain (24CSU037)
    Rudra Kumar Sharma (24CSU175)
B.Tech CSE (Cybersecurity), The NorthCap University.
"""

from typing import Generator

from sqlalchemy.orm import Session, sessionmaker

from database import engine

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency: yields a SQLAlchemy session, closes it on exit."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
