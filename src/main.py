import hashlib
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl

import ssl
import socket
from urllib.parse import urlparse


class Site(BaseModel):
    url: HttpUrl


class Cert(BaseModel):
    fingerprint: str


app = FastAPI()


@app.get("/")
async def get_root():
    return "OK"


@app.post("/")
async def post_root(site: Site) -> Cert:
    parsed_url = urlparse(str(site.url))
    hostname = parsed_url.hostname
    port = 443
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                raw_fingerprint = hashlib.sha256(cert).digest()
                formatted = ":".join(f"{b:02X}" for b in raw_fingerprint)
                return {"fingerprint": formatted}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
