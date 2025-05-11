from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from uuid import UUID

from app.core.config import settings

engine = create_engine(
    settings.DATABASE_URL,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base:
    """
    Base SQLAlchemy model class with additional functionality
    """

    def to_dict(self):
        """
        Convert model to dictionary with serializable values
        """
        result = {}
        for column in self.__table__.columns:
            value = getattr(self, column.name)
            if isinstance(value, UUID):
                # Convert UUID to string
                value = str(value)
            result[column.name] = value
        return result


Base = declarative_base(cls=Base)


# Helper function to get a database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
