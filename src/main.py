from fastapi import FastAPI
from pydantic import BaseModel, HttpUrl

import ssl
import socket
from urllib.parse import urlparse


class Site(BaseModel):
    url: HttpUrl


class Cert(BaseModel):
    cert: str


app = FastAPI()


@app.get("/")
async def get_root():
    return "OK"


@app.post("/")
async def post_root(site: Site) -> Cert:
    parsed_url = urlparse(str(site.url))
    hostname = parsed_url.hostname
    port = int(parsed_url.port or 443)
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    sock = context.wrap_socket(conn, server_hostname=hostname)
    sock.connect((hostname, port))

    return {"cert": ssl.DER_cert_to_PEM_cert(sock.getpeercert(True))}
