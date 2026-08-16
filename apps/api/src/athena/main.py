from fastapi import FastAPI

app = FastAPI(
    title="Athena API",
    description="Continuous authorization provenance and identity-governance evidence.",
    version="0.1.0",
)


@app.get("/health", tags=["operations"])
def health() -> dict[str, str]:
    """Report whether the API process is available."""
    return {"status": "ok", "service": "athena-api"}
