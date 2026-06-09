from fastapi import FastAPI
from dotenv import load_dotenv
from webhook import router as webhook_router

load_dotenv()

app = FastAPI(title="Intelligent CI/CD")

app.include_router(webhook_router)

@app.get("/")
def root():
    return {"status": "running"}
