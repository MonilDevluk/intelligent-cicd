from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from webhook import router as webhook_router
from api import router as api_router

load_dotenv()

app = FastAPI(title="Intelligent CI/CD")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

app.include_router(webhook_router)
app.include_router(api_router)

@app.get("/")
def root():
    return {"status": "running"}
