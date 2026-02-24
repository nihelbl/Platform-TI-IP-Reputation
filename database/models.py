from sqlalchemy import Column, Integer, String, JSON, DateTime
from sqlalchemy.sql import func
from database.database import Base

class IPReputation(Base):
    __tablename__ = "ip_reputation"
    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String, index=True)  # ❌ enlever unique=True
    final_verdict = Column(String)
    country = Column(String)
    data = Column(JSON)

    created_at = Column(DateTime(timezone=True), server_default=func.now())