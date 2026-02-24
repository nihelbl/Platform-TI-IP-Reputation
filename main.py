from fastapi import FastAPI
from routers.ip_router import router as ip_router
from database.database import engine, Base
from database.database import init_db

Base.metadata.create_all(bind=engine)

app = FastAPI()
init_db()

@app.get("/")
def home():
    return {"message": "Threat Intelligence Platform is running"}

app.include_router(ip_router)
