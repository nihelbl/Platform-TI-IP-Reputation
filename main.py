from fastapi import FastAPI
from routers.ip_router import router as ip_router

app = FastAPI()

@app.get("/")
def home():
    return {"message": "Threat Intelligence Platform is running"}

app.include_router(ip_router)
