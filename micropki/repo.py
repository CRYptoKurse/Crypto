import sys
import os
import tempfile
from pathlib import Path
from flask import Flask, request, abort, send_file, Response
from argparse import Namespace
from .database import get_certificate_by_serial
from .logger import setup_logging

app = Flask(__name__)

def start_repo_server(host, port, db_path, cert_dir, log_file=None, rate_limit=0, rate_burst=10):
    logger = setup_logging(log_file)

    cert_dir = os.path.abspath(cert_dir)
    db_path = os.path.abspath(db_path)

    logger.info(f"Starting repository server with cert_dir={cert_dir}, db={db_path}")

    app.config['DB_PATH'] = db_path
    app.config['CERT_DIR'] = cert_dir
    app.config['LOGGER'] = logger

    # Rate limiting
    if rate_limit > 0:
        from .ratelimit import rate_limit_middleware
        rate_limit_middleware(app, rate_limit, rate_burst)

    pki_root = Path(cert_dir).parent
    intermediate_cert = pki_root / 'certs' / 'intermediate.cert.pem'
    intermediate_key = pki_root / 'private' / 'intermediate.key.pem'
    intermediate_pass_file = pki_root / 'inter.pass'
    if not intermediate_pass_file.exists():
        pass_files = list(pki_root.glob('*.pass'))
        if pass_files:
            intermediate_pass_file = pass_files[0]
            logger.warning(f"Using passphrase file: {intermediate_pass_file}")
        else:
            logger.error("No passphrase file found in PKI root")
            intermediate_pass_file = None

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
        if ca_param is None:
            return Response("CRL generation not yet implemented", status=501, mimetype='text/plain')
        if ca_param not in ('root', 'intermediate'):
            abort(400, description="ca must be 'root' or 'intermediate'")
        crl_dir = Path(app.config['CERT_DIR']).parent / 'crl'
        filename = f"{ca_param}.crl.pem"
        crl_path = crl_dir / filename
        if not crl_path.exists():
            logger.error(f"CRL file not found: {crl_path}")
            abort(404)
        return send_file(crl_path, mimetype='application/pkix-crl')

    @app.route('/request-cert', methods=['POST'])
    def request_cert():
        from .ca import issue_cert
        template = request.args.get('template')
        if template not in ('server', 'client', 'code_signing'):
            abort(400, description="Invalid or missing template parameter")

        csr_pem = request.get_data()
        if not csr_pem:
            abort(400, description="No CSR provided")

        with tempfile.NamedTemporaryFile(mode='wb', suffix='.csr', delete=False) as f:
            f.write(csr_pem)
            csr_path = f.name

        args = Namespace()
        args.ca_cert = str(intermediate_cert)
        args.ca_key = str(intermediate_key)
        args.ca_pass_file = str(intermediate_pass_file) if intermediate_pass_file and intermediate_pass_file.exists() else None
        if not args.ca_pass_file:
            logger.error("CA passphrase file not configured")
            abort(500, description="CA passphrase file not configured")
        args.template = template
        args.subject = None
        args.san = None
        args.out_dir = app.config['CERT_DIR']
        args.validity_days = 365
        args.log_file = None
        args.db_path = app.config['DB_PATH']
        args.csr = csr_path
        args.cert_name = None
        args.force = False

        try:
            issue_cert(args)
            certs_dir = Path(app.config['CERT_DIR'])
            newest_cert = None
            for f in certs_dir.glob('*.cert.pem'):
                if f.name not in ('ca.cert.pem', 'intermediate.cert.pem', 'ocsp.cert.pem'):
                    if newest_cert is None or f.stat().st_mtime > newest_cert.stat().st_mtime:
                        newest_cert = f
            if not newest_cert:
                raise Exception("No certificate file generated")
            with open(newest_cert, 'rb') as f:
                cert_pem = f.read()
            return Response(cert_pem, status=201, mimetype='application/x-pem-file')
        except SystemExit as e:
            logger.error(f"Certificate issuance failed: {e}")
            abort(500, description=str(e))
        except Exception as e:
            logger.error(f"Certificate issuance failed: {e}")
            abort(500, description=str(e))
        finally:
            try:
                os.unlink(csr_path)
            except OSError:
                pass

    app.run(host=host, port=port, threaded=True, use_reloader=False)