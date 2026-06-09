from fastapi import FastAPI
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="Intelligent CI/CD")

@app.get("/")
def root():
    return {"status": "running"}
