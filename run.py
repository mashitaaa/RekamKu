import argparse
import os

from werkzeug.serving import WSGIRequestHandler


class QuietHandler(WSGIRequestHandler):
    def version_string(self):
        return "RekamKu"


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--https", action="store_true", help="enable TLS (Secure cookie + HSTS)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int)
    args = ap.parse_args()
    if args.https:
        os.environ["REKAMKU_HTTPS"] = "1"

    from app import create_app

    app = create_app()
    app.run(host=args.host, port=args.port or (5443 if args.https else 5000), debug=False, threaded=True,
            ssl_context="adhoc" if args.https else None, request_handler=QuietHandler)
