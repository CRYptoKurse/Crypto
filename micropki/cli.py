import argparse
import sys
import os
from pathlib import Path
from .ca import init_ca, issue_intermediate, issue_cert
from .database import init_db, list_certificates, get_certificate_by_serial
from .repo import start_repo_server
from .ocsp import issue_ocsp_cert
from .ocsp_responder import start_ocsp_server
from .client import gen_csr, request_cert, validate_cert, check_status

def main():
    parser = argparse.ArgumentParser(prog='micropki')
    subparsers = parser.add_subparsers(dest='command', required=True)

    # ---------- db ----------
    db_parser = subparsers.add_parser('db', help='Database operations')
    db_subparsers = db_parser.add_subparsers(dest='db_command', required=True)
    db_init = db_subparsers.add_parser('init', help='Initialize database')
    db_init.add_argument('--db-path', default='./pki/micropki.db')

    # ---------- ca ----------
    ca_parser = subparsers.add_parser('ca', help='CA operations')
    ca_subparsers = ca_parser.add_subparsers(dest='ca_command', required=True)

    # ca init
    init_parser = ca_subparsers.add_parser('init', help='Initialize Root CA')
    init_parser.add_argument('--subject', required=True)
    init_parser.add_argument('--key-type', choices=['rsa','ecc'], default='rsa')
    init_parser.add_argument('--key-size', type=int, default=4096)
    init_parser.add_argument('--passphrase-file', required=True)
    init_parser.add_argument('--out-dir', default='./pki')
    init_parser.add_argument('--validity-days', type=int, default=3650)
    init_parser.add_argument('--log-file')
    init_parser.add_argument('--force', action='store_true')
    init_parser.add_argument('--db-path', default='./pki/micropki.db')

    # ca issue-intermediate
    inter_parser = ca_subparsers.add_parser('issue-intermediate', help='Create Intermediate CA')
    inter_parser.add_argument('--root-cert', required=True)
    inter_parser.add_argument('--root-key', required=True)
    inter_parser.add_argument('--root-pass-file', required=True)
    inter_parser.add_argument('--subject', required=True)
    inter_parser.add_argument('--key-type', choices=['rsa','ecc'], default='rsa')
    inter_parser.add_argument('--key-size', type=int, default=4096)
    inter_parser.add_argument('--passphrase-file', required=True)
    inter_parser.add_argument('--out-dir', default='./pki')
    inter_parser.add_argument('--validity-days', type=int, default=1825)
    inter_parser.add_argument('--pathlen', type=int, default=0)
    inter_parser.add_argument('--log-file')
    inter_parser.add_argument('--db-path', default='./pki/micropki.db')

    # ca issue-cert (with optional --csr)
    cert_parser = ca_subparsers.add_parser('issue-cert', help='Issue end-entity certificate')
    cert_parser.add_argument('--ca-cert', required=True)
    cert_parser.add_argument('--ca-key', required=True)
    cert_parser.add_argument('--ca-pass-file', required=True)
    cert_parser.add_argument('--template', required=True, choices=['server','client','code_signing'])
    cert_parser.add_argument('--subject')
    cert_parser.add_argument('--san', action='append')
    cert_parser.add_argument('--out-dir', default='./pki/certs')
    cert_parser.add_argument('--validity-days', type=int, default=365)
    cert_parser.add_argument('--log-file')
    cert_parser.add_argument('--db-path', default='./pki/micropki.db')
    cert_parser.add_argument('--csr', help='Path to CSR (PEM) to sign instead of generating new key')

    # ca list-certs
    list_parser = ca_subparsers.add_parser('list-certs', help='List certificates from database')
    list_parser.add_argument('--status', choices=['valid', 'revoked', 'expired'])
    list_parser.add_argument('--format', choices=['table', 'json', 'csv'], default='table')
    list_parser.add_argument('--db-path', default='./pki/micropki.db')

    # ca show-cert
    show_parser = ca_subparsers.add_parser('show-cert', help='Show certificate by serial')
    show_parser.add_argument('serial')
    show_parser.add_argument('--db-path', default='./pki/micropki.db')

    # ca revoke
    revoke_parser = ca_subparsers.add_parser('revoke', help='Revoke a certificate')
    revoke_parser.add_argument('serial')
    revoke_parser.add_argument('--reason', default='unspecified',
                               choices=['unspecified','keyCompromise','cACompromise','affiliationChanged',
                                        'superseded','cessationOfOperation','certificateHold','removeFromCRL',
                                        'privilegeWithdrawn','aACompromise'])
    revoke_parser.add_argument('--force', action='store_true')
    revoke_parser.add_argument('--db-path', default='./pki/micropki.db')
    revoke_parser.add_argument('--log-file')

    # ca gen-crl
    crl_parser = ca_subparsers.add_parser('gen-crl', help='Generate CRL')
    crl_parser.add_argument('--ca', required=True, choices=['root','intermediate'])
    crl_parser.add_argument('--next-update', type=int, default=7)
    crl_parser.add_argument('--out-file')
    crl_parser.add_argument('--passphrase-file', required=True)
    crl_parser.add_argument('--out-dir', default='./pki')
    crl_parser.add_argument('--db-path', default='./pki/micropki.db')
    crl_parser.add_argument('--log-file')

    # ca issue-ocsp-cert
    ocsp_cert_parser = ca_subparsers.add_parser('issue-ocsp-cert', help='Issue OCSP responder certificate')
    ocsp_cert_parser.add_argument('--ca-cert', required=True)
    ocsp_cert_parser.add_argument('--ca-key', required=True)
    ocsp_cert_parser.add_argument('--ca-pass-file', required=True)
    ocsp_cert_parser.add_argument('--subject', required=True)
    ocsp_cert_parser.add_argument('--key-type', choices=['rsa','ecc'], default='rsa')
    ocsp_cert_parser.add_argument('--key-size', type=int, default=2048)
    ocsp_cert_parser.add_argument('--san', action='append')
    ocsp_cert_parser.add_argument('--out-dir', default='./pki/certs')
    ocsp_cert_parser.add_argument('--validity-days', type=int, default=365)
    ocsp_cert_parser.add_argument('--log-file')

    # ca audit-query
    audit_query_parser = ca_subparsers.add_parser('audit-query', help='Query audit log')
    audit_query_parser.add_argument('--from', dest='from_ts')
    audit_query_parser.add_argument('--to')
    audit_query_parser.add_argument('--level')
    audit_query_parser.add_argument('--operation')
    audit_query_parser.add_argument('--serial')
    audit_query_parser.add_argument('--format', choices=['table','json','csv'], default='table')
    audit_query_parser.add_argument('--audit-log', default='./pki/audit/audit.log')

    # ca audit-verify
    audit_verify_parser = ca_subparsers.add_parser('audit-verify', help='Verify audit log integrity')
    audit_verify_parser.add_argument('--audit-log', default='./pki/audit/audit.log')
    audit_verify_parser.add_argument('--chain-file', default='./pki/audit/chain.dat')

    # ca compromise
    compromise_parser = ca_subparsers.add_parser('compromise', help='Simulate private key compromise')
    compromise_parser.add_argument('--cert', required=True)
    compromise_parser.add_argument('--reason', default='keyCompromise')
    compromise_parser.add_argument('--force', action='store_true')
    compromise_parser.add_argument('--db-path', default='./pki/micropki.db')

    # ---------- repo ----------
    repo_parser = subparsers.add_parser('repo', help='Repository server')
    repo_subparsers = repo_parser.add_subparsers(dest='repo_command', required=True)
    serve_parser = repo_subparsers.add_parser('serve', help='Start HTTP repository server')
    serve_parser.add_argument('--host', default='127.0.0.1')
    serve_parser.add_argument('--port', type=int, default=8080)
    serve_parser.add_argument('--db-path', default='./pki/micropki.db')
    serve_parser.add_argument('--cert-dir', default='./pki/certs')
    serve_parser.add_argument('--log-file')
    serve_parser.add_argument('--rate-limit', type=float, default=0, help='Requests per second per client IP (0=disabled)')
    serve_parser.add_argument('--rate-burst', type=int, default=10, help='Burst allowance')

    # ---------- ocsp ----------
    ocsp_parser = subparsers.add_parser('ocsp', help='OCSP responder')
    ocsp_subparsers = ocsp_parser.add_subparsers(dest='ocsp_command', required=True)
    serve_ocsp_parser = ocsp_subparsers.add_parser('serve', help='Start OCSP responder')
    serve_ocsp_parser.add_argument('--host', default='127.0.0.1')
    serve_ocsp_parser.add_argument('--port', type=int, default=8081)
    serve_ocsp_parser.add_argument('--db-path', default='./pki/micropki.db')
    serve_ocsp_parser.add_argument('--responder-cert', required=True)
    serve_ocsp_parser.add_argument('--responder-key', required=True)
    serve_ocsp_parser.add_argument('--ca-cert', required=True)
    serve_ocsp_parser.add_argument('--cache-ttl', type=int, default=60)
    serve_ocsp_parser.add_argument('--log-file')
    serve_ocsp_parser.add_argument('--rate-limit', type=float, default=0, help='Requests per second per client IP (0=disabled)')
    serve_ocsp_parser.add_argument('--rate-burst', type=int, default=10, help='Burst allowance')

    # ---------- client ----------
    client_parser = subparsers.add_parser('client', help='Client tools')
    client_subparsers = client_parser.add_subparsers(dest='client_command', required=True)

    # client gen-csr
    gen_csr_parser = client_subparsers.add_parser('gen-csr')
    gen_csr_parser.add_argument('--subject', required=True)
    gen_csr_parser.add_argument('--key-type', choices=['rsa','ecc'], default='rsa')
    gen_csr_parser.add_argument('--key-size', type=int, default=2048)
    gen_csr_parser.add_argument('--san', action='append')
    gen_csr_parser.add_argument('--out-key', default='./key.pem')
    gen_csr_parser.add_argument('--out-csr', default='./request.csr.pem')
    gen_csr_parser.add_argument('--log-file')

    # client request-cert
    req_parser = client_subparsers.add_parser('request-cert')
    req_parser.add_argument('--csr', required=True)
    req_parser.add_argument('--template', required=True, choices=['server','client','code_signing'])
    req_parser.add_argument('--ca-url', required=True)
    req_parser.add_argument('--api-key', help='API key for repository authentication')
    req_parser.add_argument('--out-cert', default='./cert.pem')
    req_parser.add_argument('--log-file')

    # client validate
    val_parser = client_subparsers.add_parser('validate')
    val_parser.add_argument('--cert', required=True)
    val_parser.add_argument('--untrusted', action='append')
    val_parser.add_argument('--trusted', default='./pki/certs/ca.cert.pem')
    val_parser.add_argument('--crl', action='append')
    val_parser.add_argument('--ocsp', help='OCSP responder URL (optional)')
    val_parser.add_argument('--mode', choices=['chain', 'full'], default='full')
    val_parser.add_argument('--validation-time', help='Validation time in ISO format')
    val_parser.add_argument('--log-file')

    # client check-status
    status_parser = client_subparsers.add_parser('check-status')
    status_parser.add_argument('--cert', required=True)
    status_parser.add_argument('--ca-cert', required=True)
    status_parser.add_argument('--crl', action='append')
    status_parser.add_argument('--ocsp-url')
    status_parser.add_argument('--log-file')

    args = parser.parse_args()

    # ---------- Обработка ----------
    if args.command == 'db' and args.db_command == 'init':
        Path(args.db_path).parent.mkdir(parents=True, exist_ok=True)
        init_db(args.db_path)
        print(f"Database initialised at {args.db_path}")
        return

    if args.command == 'ca':
        if args.ca_command == 'init':
            if args.key_type == 'rsa' and args.key_size != 4096:
                sys.exit("RSA key size must be 4096")
            if args.key_type == 'ecc' and args.key_size != 384:
                sys.exit("ECC key size must be 384")
            if args.validity_days <= 0:
                sys.exit("Validity days must be positive")
            if not os.path.isfile(args.passphrase_file):
                sys.exit(f"Passphrase file {args.passphrase_file} not found")
            init_ca(args)
        elif args.ca_command == 'issue-intermediate':
            if args.key_type == 'rsa' and args.key_size != 4096:
                sys.exit("RSA key size must be 4096")
            if args.key_type == 'ecc' and args.key_size != 384:
                sys.exit("ECC key size must be 384")
            if args.validity_days <= 0:
                sys.exit("Validity days must be positive")
            for f in [args.root_cert, args.root_key, args.root_pass_file, args.passphrase_file]:
                if not os.path.isfile(f):
                    sys.exit(f"File not found: {f}")
            issue_intermediate(args)
        elif args.ca_command == 'issue-cert':
            if args.validity_days <= 0:
                sys.exit("Validity days must be positive")
            for f in [args.ca_cert, args.ca_key, args.ca_pass_file]:
                if not os.path.isfile(f):
                    sys.exit(f"File not found: {f}")
            if not args.csr:
                if not args.subject:
                    sys.exit("--subject required when --csr is not provided")
                if args.template == 'server' and not args.san:
                    sys.exit("Server certificate requires at least one --san entry")
            issue_cert(args)
        elif args.ca_command == 'list-certs':
            rows = list_certificates(args.db_path, args.status)
            if args.format == 'table':
                print(f"{'Serial':<20} {'Subject':<40} {'Expires':<25} {'Status':<10}")
                for row in rows:
                    print(f"{row[0]:<20} {row[1][:40]:<40} {row[3][:25]:<25} {row[4]:<10}")
            elif args.format == 'json':
                import json
                data = [{'serial':r[0],'subject':r[1],'not_before':r[2],'not_after':r[3],'status':r[4]} for r in rows]
                print(json.dumps(data, indent=2))
            elif args.format == 'csv':
                import csv
                writer = csv.writer(sys.stdout)
                writer.writerow(['serial','subject','not_before','not_after','status'])
                writer.writerows(rows)
        elif args.ca_command == 'show-cert':
            pem = get_certificate_by_serial(args.db_path, args.serial)
            if pem:
                print(pem)
            else:
                print(f"Certificate with serial {args.serial} not found.", file=sys.stderr)
                sys.exit(1)
        elif args.ca_command == 'revoke':
            from .revocation import revoke_certificate
            revoke_certificate(args.db_path, args.serial, args.reason, args.force, args.log_file,
                                   audit_log_path="./pki/audit/audit.log")
            revoke_certificate(args.db_path, args.serial, args.reason, args.force, args.log_file)
        elif args.ca_command == 'gen-crl':
            from .crl import generate_crl
            generate_crl(args)
        elif args.ca_command == 'issue-ocsp-cert':
            issue_ocsp_cert(args)
        elif args.ca_command == 'audit-query':
            from .audit import AuditLogger
            audit = AuditLogger(args.audit_log)
            results = audit.query(
                start_time=getattr(args, 'from_ts', None),
                end_time=args.to,
                level=args.level,
                operation=args.operation,
                serial=args.serial
            )
            if args.format == 'table':
                for r in results:
                    print(f"{r['timestamp']} [{r['level']}] {r['operation']} {r['status']}: {r['message']}")
            elif args.format == 'json':
                import json; print(json.dumps(results, indent=2))
            elif args.format == 'csv':
                import csv; writer = csv.DictWriter(sys.stdout, fieldnames=['timestamp','level','operation','status','message'])
                writer.writeheader(); writer.writerows(results)
        elif args.ca_command == 'audit-verify':
            from .audit import AuditLogger
            audit = AuditLogger(args.audit_log, args.chain_file)
            ok, err = audit.verify()
            if ok:
                print("Audit log integrity verified")
                sys.exit(0)
            else:
                print(f"INTEGRITY VIOLATION: {err}")
                sys.exit(1)
        elif args.ca_command == 'compromise':
            from .compromise import compromise_certificate
            from .audit import AuditLogger
            from cryptography import x509
            with open(args.cert, 'rb') as f:
                cert = x509.load_pem_x509_certificate(f.read())
            serial_hex = format(cert.serial_number, 'x').upper()
            audit = AuditLogger('./pki/audit/audit.log')
            compromise_certificate(args.db_path, serial_hex, args.reason, audit)
            print(f"Certificate {serial_hex} compromised and revoked.")
        else:
            parser.print_help()

    elif args.command == 'repo' and args.repo_command == 'serve':
        start_repo_server(args.host, args.port, args.db_path, args.cert_dir, args.log_file,
                          rate_limit=args.rate_limit, rate_burst=args.rate_burst)

    elif args.command == 'ocsp' and args.ocsp_command == 'serve':
        start_ocsp_server(args.host, args.port, args.db_path, args.responder_cert,
                          args.responder_key, args.ca_cert, args.cache_ttl, args.log_file,
                          rate_limit=args.rate_limit, rate_burst=args.rate_burst)

    elif args.command == 'client':
        if args.client_command == 'gen-csr':
            gen_csr(args)
        elif args.client_command == 'request-cert':
            request_cert(args)
        elif args.client_command == 'validate':
            validate_cert(args)
        elif args.client_command == 'check-status':
            check_status(args)
        else:
            parser.print_help()

    else:
        parser.print_help()
        sys.exit(1)

if __name__ == '__main__':
    main()