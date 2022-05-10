import os
from typing import Any
from PyQt5.QtWidgets import QApplication
from argparse import ArgumentParser, SUPPRESS
from ui import UI
from crypto import *

def parse_arguments() -> ArgumentParser:
    parser = ArgumentParser(add_help=False, description='Program do generowania kluczy asymetrycznych oraz szyfrowania i deszyfrowania plików')
    parser.add_argument('-h', '--help', action='help', default=SUPPRESS, help='Wyświetl pomoc i zakończ.')
    subparser = parser.add_subparsers(help='sub-command help', dest='command')

    g_parser: ArgumentParser = subparser.add_parser('generate-keys', help='Generuje klucze asymetryczne')
    g_parser.add_argument('length', type=int, choices=[1024, 2048, 4096, 8192], help='Długosc klucza w bitach')
    g_parser.add_argument('-o', '--output', type=str, metavar='name', help='Zapisuje klucze do plików public/public_{name}.key i private/private_{name}.key')
    g_parser.add_argument('-p', '--password', type=str, help='Hasło do zaszyfrowania klucza prywatnego')

    e_parser: ArgumentParser = subparser.add_parser('encrypt', help='Zaszyfruj plik/tekst')
    group = e_parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-s', '--string', type=str, help='Tekst do zaszyfrowania')
    group.add_argument('-f', '--file', type=str, help='Plik do zaszyfrowania')
    e_parser.add_argument('-k', '--key', type=str, required=True, help='Ścieżka do pliku z kluczem publicznym')
    e_parser.add_argument('-o', '--output', type=str, help='Ścieżka do pliku wyjściowego')

    d_parser: ArgumentParser = subparser.add_parser('decrypt', help='Odszyfruj plik')
    d_parser.add_argument('-f', '--file', type=str, required=True, help='Plik do odszyfrowania')
    d_parser.add_argument('-k', '--key', type=str, required=True, help='Ścieżka do pliku z kluczem prywatnym')
    d_parser.add_argument('-p', '--password', type=str, help='Hasło do odszyfrowania klucza prywatnego')
    d_parser.add_argument('-o', '--output', type=str, help='Ścieżka do pliku wyjściowego')

    return parser

def test():
    public, private = generate_keys(2048)
    text = b'Testowy test tekst abcde!@#$$321'
    encrypted_text = encrypt(text, public)
    encrypted_text = encrypted_text[0] + encrypted_text[1]
    decrypted_text = decrypt(encrypted_text, private)
    print(f'text = {text}\n')
    print(f'encrypted = {encrypted_text}\n')
    print(f'decrypted = {decrypted_text}')
    

def main(args: dict[str, Any]):
    if args['command'] is None:
        app = QApplication([])
        _ = UI()
        app.exec()
    elif args['command'] == 'generate-keys':
        public, private = generate_keys(args['length'])
        if args['output'] is not None:
            saveKey(public, args['output'])
            saveKey(private, args['output'], args['password'])
        else:
            print(public)
            print(private)
    elif args['command'] == 'encrypt':
        public_key = loadPublicKeyFromFile(args['key'])
        data: bytes = None
        if args['string'] is None:
            with open(args['file'], 'r', encoding='utf-8') as file:
                data = file.read().encode('utf-8')
        else:
            data = args['string'].encode('utf-8')
        encrypted_data = encrypt(data, public_key)
        encrypted_data = encrypted_data[0] + encrypted_data[1]
        if args['output'] is None:
            print(encrypted_data)
        else:
            with open(args['output'], 'wb') as output:
                output.write(encrypted_data)
    elif args['command'] == 'decrypt':
        encrypted_data: bytes = None
        private_key = loadPrivateKeyFromFile(args['key'], args['password'])
        with open(args['file'], 'rb') as file:
            encrypted_data = file.read()
        decrypted_data = decrypt(encrypted_data, private_key)
        if args['output'] is None:
            print(decrypted_data)
        else:
            with open(args['output'], 'wb') as output:
                output.write(decrypted_data)

if __name__ == "__main__":
    parser = parse_arguments()
    args = vars(parser.parse_args())
    #print(args) # debug

    main(args)
