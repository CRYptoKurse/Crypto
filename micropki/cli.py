import argparse
import sys
import os
from pathlib import Path
from .ca import init_ca, issue_intermediate, issue_cert
from .database import init_db, list_certificates, get_certificate_by_serial
from .repo import start_repo_server

def main():
    parser = argparse.ArgumentParser(prog='micropki')
    subparsers = parser.add_subparsers(dest='command', required=True)

    # ---------- db ----------
    db_parser = subparsers.add_parser('db', help='Database operations')
    db_subparsers = db_parser.add_subparsers(dest='db_command', required=True)
    db_init = db_subparsers.add_parser('init', help='Initialize database')
    db_init.add_argument('--db-path', default='./pki/micropki.db', help='SQLite database path')

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
    init_parser.add_argument('--db-path', default='./pki/micropki.db', help='Database path')

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
    inter_parser.add_argument('--db-path', default='./pki/micropki.db', help='Database path')

    # ca issue-cert
    cert_parser = ca_subparsers.add_parser('issue-cert', help='Issue end-entity certificate')
    cert_parser.add_argument('--ca-cert', required=True)
    cert_parser.add_argument('--ca-key', required=True)
    cert_parser.add_argument('--ca-pass-file', required=True)
    cert_parser.add_argument('--template', required=True, choices=['server','client','code_signing'])
    cert_parser.add_argument('--subject', required=True)
    cert_parser.add_argument('--san', action='append', help='SAN (e.g., dns:example.com)')
    cert_parser.add_argument('--out-dir', default='./pki/certs')
    cert_parser.add_argument('--validity-days', type=int, default=365)
    cert_parser.add_argument('--log-file')
    cert_parser.add_argument('--db-path', default='./pki/micropki.db', help='Database path')

    # ca list-certs
    list_parser = ca_subparsers.add_parser('list-certs', help='List certificates from database')
    list_parser.add_argument('--status', choices=['valid', 'revoked', 'expired'])
    list_parser.add_argument('--format', choices=['table', 'json', 'csv'], default='table')
    list_parser.add_argument('--db-path', default='./pki/micropki.db')

    # ca show-cert
    show_parser = ca_subparsers.add_parser('show-cert', help='Show certificate by serial')
    show_parser.add_argument('serial', help='Serial number in hex')
    show_parser.add_argument('--db-path', default='./pki/micropki.db')

    # ca revoke (Sprint 4)
    revoke_parser = ca_subparsers.add_parser('revoke', help='Revoke a certificate')
    revoke_parser.add_argument('serial', help='Serial number in hex')
    revoke_parser.add_argument('--reason', default='unspecified',
                               choices=['unspecified', 'keyCompromise', 'cACompromise', 'affiliationChanged',
                                        'superseded', 'cessationOfOperation', 'certificateHold', 'removeFromCRL',
                                        'privilegeWithdrawn', 'aACompromise'],
                               help='Revocation reason')
    revoke_parser.add_argument('--force', action='store_true', help='Skip confirmation')
    revoke_parser.add_argument('--db-path', default='./pki/micropki.db')
    revoke_parser.add_argument('--log-file')

    # ca gen-crl (Sprint 4)
    crl_parser = ca_subparsers.add_parser('gen-crl', help='Generate CRL')
    crl_parser.add_argument('--ca', required=True, choices=['root', 'intermediate'])
    crl_parser.add_argument('--next-update', type=int, default=7, help='Days until next CRL update')
    crl_parser.add_argument('--out-file', help='Output file path (default: ./pki/crl/<ca>.crl.pem)')
    crl_parser.add_argument('--passphrase-file', required=True, help='Passphrase for CA private key')
    crl_parser.add_argument('--out-dir', default='./pki', help='Output directory (for certs/private)')
    crl_parser.add_argument('--db-path', default='./pki/micropki.db')
    crl_parser.add_argument('--log-file')

    # ---------- repo ----------
    repo_parser = subparsers.add_parser('repo', help='Repository server')
    repo_subparsers = repo_parser.add_subparsers(dest='repo_command', required=True)
    serve_parser = repo_subparsers.add_parser('serve', help='Start HTTP repository server')
    serve_parser.add_argument('--host', default='127.0.0.1')
    serve_parser.add_argument('--port', type=int, default=8080)
    serve_parser.add_argument('--db-path', default='./pki/micropki.db')
    serve_parser.add_argument('--cert-dir', default='./pki/certs')
    serve_parser.add_argument('--log-file')

    args = parser.parse_args()

    # ---------- Обработка команд ----------
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
                data = [{'serial':r[0], 'subject':r[1], 'not_before':r[2], 'not_after':r[3], 'status':r[4]} for r in rows]
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
            revoke_certificate(args.db_path, args.serial, args.reason, args.force, args.log_file)
        elif args.ca_command == 'gen-crl':
            from .crl import generate_crl
            generate_crl(args)
        else:
            parser.print_help()
    elif args.command == 'repo' and args.repo_command == 'serve':
        start_repo_server(args.host, args.port, args.db_path, args.cert_dir, args.log_file)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == '__main__':
    main()