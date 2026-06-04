import argparse
import sys
import os
from .ca import init_ca

def main():
    parser = argparse.ArgumentParser(prog='micropki', description='MicroPKI - Minimal PKI tool')
    subparsers = parser.add_subparsers(dest='command', required=True, help='Commands')

    # подкоманда 'ca'
    ca_parser = subparsers.add_parser('ca', help='CA operations')
    ca_subparsers = ca_parser.add_subparsers(dest='ca_command', required=True, help='CA subcommands')

    # подкоманда 'ca init'
    init_parser = ca_subparsers.add_parser('init', help='Initialize Root CA')
    init_parser.add_argument('--subject', required=True, help='Distinguished Name (e.g. "/CN=Root CA" or "CN=Root CA,O=Demo")')
    init_parser.add_argument('--key-type', choices=['rsa', 'ecc'], default='rsa', help='Key type')
    init_parser.add_argument('--key-size', type=int, default=4096, help='Key size (RSA:4096, ECC:384)')
    init_parser.add_argument('--passphrase-file', required=True, help='File containing passphrase')
    init_parser.add_argument('--out-dir', default='./pki', help='Output directory')
    init_parser.add_argument('--validity-days', type=int, default=3650, help='Validity in days')
    init_parser.add_argument('--log-file', help='Log file path (default: stderr)')
    init_parser.add_argument('--force', action='store_true', help='Overwrite existing files')

    args = parser.parse_args()

    # Валидации
    if args.command == 'ca' and args.ca_command == 'init':
        if not args.subject.strip():
            sys.exit("Error: --subject cannot be empty")
        if args.key_type == 'rsa' and args.key_size != 4096:
            sys.exit("Error: RSA key size must be 4096")
        if args.key_type == 'ecc' and args.key_size != 384:
            sys.exit("Error: ECC key size must be 384")
        if args.validity_days <= 0:
            sys.exit("Error: --validity-days must be positive")
        if not os.path.isfile(args.passphrase_file):
            sys.exit(f"Error: Passphrase file '{args.passphrase_file}' does not exist or is not readable")
        init_ca(args)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == '__main__':
    main()