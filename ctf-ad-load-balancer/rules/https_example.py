"""Example HTTPS rule: TLS terminated here, forwarded to the backend as plain HTTP.

Needs certs/cert.pem + certs/key.pem (./gen-cert.sh makes a self-signed pair).
"""
from balancer import HTTPSHandler, Route


class SecureExample(HTTPSHandler):
    PORT = 31338
    CERT = "/certs/cert.pem"
    KEY = "/certs/key.pem"

    async def handle(self, req):
        # tls=False: the backend speaks plain HTTP. Use tls=True if it serves
        # HTTPS itself (its certificate is not verified unless verify=True).
        return Route("svc-patched", 31337, tls=False)
