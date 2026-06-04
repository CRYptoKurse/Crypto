import sys
from flask import Flask, request, abort, send_file, Response
import os
from pathlib import Path
from .database import get_certificate_by_serial
from .logger import setup_logging

app = Flask(__name__)

def start_repo_server(host, port, db_path, cert_dir, log_file=None):
    logger = setup_logging(log_file)
    app.config['DB_PATH'] = db_path
    app.config['CERT_DIR'] = cert_dir
    app.config['LOGGER'] = logger

    @app.before_request
    def log_request():
        logger.info(f"[HTTP] {request.method} {request.path} from {request.remote_addr}")

    @app.route('/certificate/<serial>')
    def get_certificate(serial):
        if not all(c in '0123456789ABCDEFabcdef' for c in serial):
            abort(400, description="Invalid serial: must be hexadecimal")
        cert_pem = get_certificate_by_serial(db_path, serial.upper())
        if cert_pem is None:
            abort(404)
        return Response(cert_pem, mimetype='application/x-pem-file')

    @app.route('/ca/<level>')
    def get_ca(level):
        if level not in ('root', 'intermediate'):
            abort(400, description="Level must be 'root' or 'intermediate'")
        filename = 'ca.cert.pem' if level == 'root' else 'intermediate.cert.pem'
        filepath = Path(cert_dir) / filename
        if not filepath.exists():
            abort(404)
        return send_file(filepath, mimetype='application/x-pem-file')

    @app.route('/crl')
    def get_crl():
        return Response("CRL generation not yet implemented", status=501, mimetype='text/plain')

    app.run(host=host, port=port, threaded=True)