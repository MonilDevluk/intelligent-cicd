from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from webhook import router as webhook_router
from api import router as api_router

load_dotenv()

app = FastAPI(title="Intelligent CI/CD")

origins = [
    "http://localhost:3000",
    # add allowed origins as needed
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "Authorization"]
)

app.include_router(webhook_router)
app.include_router(api_router)

@app.get("/")
def root():
    return {"status": "running"}