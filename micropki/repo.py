import sys
from pathlib import Path
from flask import Flask, request, abort, send_file, Response
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
        cert_pem = get_certificate_by_serial(app.config['DB_PATH'], serial.upper())
        if cert_pem is None:
            abort(404)
        return Response(cert_pem, mimetype='application/x-pem-file')

    @app.route('/ca/<level>')
    def get_ca(level):
        if level not in ('root', 'intermediate'):
            abort(400, description="Level must be 'root' or 'intermediate'")
        filename = 'ca.cert.pem' if level == 'root' else 'intermediate.cert.pem'
        filepath = Path(app.config['CERT_DIR']) / filename
        if not filepath.exists():
            abort(404)
        return send_file(filepath, mimetype='application/x-pem-file')

    @app.route('/crl')
    def get_crl():
        ca_param = request.args.get('ca')
        # Для обратной совместимости со Sprint 3: без параметра возвращаем 501
        if ca_param is None:
            return Response("CRL generation not yet implemented", status=501, mimetype='text/plain')
        if ca_param not in ('root', 'intermediate'):
            abort(400, description="ca must be 'root' or 'intermediate'")
        crl_dir = Path(app.config['CERT_DIR']).parent / 'crl'
        filename = f"{ca_param}.crl.pem"
        crl_path = crl_dir / filename
        if not crl_path.exists():
            abort(404)
        return send_file(crl_path, mimetype='application/pkix-crl')

    @app.route('/crl/root.crl')
    def get_root_crl_static():
        crl_dir = Path(app.config['CERT_DIR']).parent / 'crl'
        crl_path = crl_dir / 'root.crl.pem'
        if not crl_path.exists():
            abort(404)
        return send_file(crl_path, mimetype='application/pkix-crl')

    @app.route('/crl/intermediate.crl')
    def get_intermediate_crl_static():
        crl_dir = Path(app.config['CERT_DIR']).parent / 'crl'
        crl_path = crl_dir / 'intermediate.crl.pem'
        if not crl_path.exists():
            abort(404)
        return send_file(crl_path, mimetype='application/pkix-crl')

    app.run(host=host, port=port, threaded=True)