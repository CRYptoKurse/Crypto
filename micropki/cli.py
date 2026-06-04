import argparse
import sys
import os
from .ca import init_ca, issue_intermediate, issue_cert

def main():
    parser = argparse.ArgumentParser(prog='micropki', description='MicroPKI - Minimal PKI tool')
    subparsers = parser.add_subparsers(dest='command', required=True)

    ca_parser = subparsers.add_parser('ca', help='CA operations')
    ca_subparsers = ca_parser.add_subparsers(dest='ca_command', required=True)

    # ca init (Sprint 1)
    init_parser = ca_subparsers.add_parser('init', help='Initialize Root CA')
    init_parser.add_argument('--subject', required=True)
    init_parser.add_argument('--key-type', choices=['rsa','ecc'], default='rsa')
    init_parser.add_argument('--key-size', type=int, default=4096)
    init_parser.add_argument('--passphrase-file', required=True)
    init_parser.add_argument('--out-dir', default='./pki')
    init_parser.add_argument('--validity-days', type=int, default=3650)
    init_parser.add_argument('--log-file')
    init_parser.add_argument('--force', action='store_true')

    # ca issue-intermediate (Sprint 2)
    inter_parser = ca_subparsers.add_parser('issue-intermediate', help='Create an Intermediate CA')
    inter_parser.add_argument('--root-cert', required=True, help='Root CA certificate PEM')
    inter_parser.add_argument('--root-key', required=True, help='Root CA encrypted private key')
    inter_parser.add_argument('--root-pass-file', required=True, help='Passphrase for root key')
    inter_parser.add_argument('--subject', required=True)
    inter_parser.add_argument('--key-type', choices=['rsa','ecc'], default='rsa')
    inter_parser.add_argument('--key-size', type=int, default=4096)
    inter_parser.add_argument('--passphrase-file', required=True, help='Passphrase for intermediate key')
    inter_parser.add_argument('--out-dir', default='./pki')
    inter_parser.add_argument('--validity-days', type=int, default=1825)
    inter_parser.add_argument('--pathlen', type=int, default=0, help='Path length constraint')
    inter_parser.add_argument('--log-file')

    # ca issue-cert (Sprint 2)
    cert_parser = ca_subparsers.add_parser('issue-cert', help='Issue an end-entity certificate')
    cert_parser.add_argument('--ca-cert', required=True, help='CA certificate (Intermediate)')
    cert_parser.add_argument('--ca-key', required=True, help='CA encrypted private key')
    cert_parser.add_argument('--ca-pass-file', required=True, help='Passphrase for CA key')
    cert_parser.add_argument('--template', required=True, choices=['server','client','code_signing'])
    cert_parser.add_argument('--subject', required=True)
    cert_parser.add_argument('--san', action='append', help='SAN (e.g., dns:example.com)')
    cert_parser.add_argument('--out-dir', default='./pki/certs')
    cert_parser.add_argument('--validity-days', type=int, default=365)
    cert_parser.add_argument('--log-file')

    args = parser.parse_args()

    if args.command == 'ca':
        if args.ca_command == 'init':
            # валидации Sprint 1 (уже есть)
            if not args.subject.strip():
                sys.exit("Error: --subject cannot be empty")
            if args.key_type == 'rsa' and args.key_size != 4096:
                sys.exit("Error: RSA key size must be 4096")
            if args.key_type == 'ecc' and args.key_size != 384:
                sys.exit("Error: ECC key size must be 384")
            if args.validity_days <= 0:
                sys.exit("Error: --validity-days must be positive")
            if not os.path.isfile(args.passphrase_file):
                sys.exit(f"Error: Passphrase file '{args.passphrase_file}' does not exist")
            init_ca(args)
        elif args.ca_command == 'issue-intermediate':
            # валидации
            if args.key_type == 'rsa' and args.key_size != 4096:
                sys.exit("Error: RSA key size must be 4096")
            if args.key_type == 'ecc' and args.key_size != 384:
                sys.exit("Error: ECC key size must be 384")
            if args.validity_days <= 0:
                sys.exit("Error: --validity-days must be positive")
            for f in [args.root_cert, args.root_key, args.root_pass_file, args.passphrase_file]:
                if not os.path.isfile(f):
                    sys.exit(f"Error: File not found: {f}")
            issue_intermediate(args)
        elif args.ca_command == 'issue-cert':
            # валидации
            if args.validity_days <= 0:
                sys.exit("Error: --validity-days must be positive")
            for f in [args.ca_cert, args.ca_key, args.ca_pass_file]:
                if not os.path.isfile(f):
                    sys.exit(f"Error: File not found: {f}")
            # Доп. проверка: server требует SAN
            if args.template == 'server' and not args.san:
                sys.exit("Error: Server certificate requires at least one --san entry")
            issue_cert(args)

if __name__ == '__main__':
    main()