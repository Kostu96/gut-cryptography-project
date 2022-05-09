import os
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

    return parser

if __name__ == "__main__":
    parser = parse_arguments()
    args = vars(parser.parse_args())
    print(args) # debug

    os.makedirs('public', exist_ok=True)
    os.makedirs('private', exist_ok=True)
    if args['command'] is None:
        app = QApplication([])
        mainWindow = UI()
        app.exec()
    elif args['command'] == 'generate-keys':
        public, private = generate_keys(args['length'])
        if args['output'] is not None:
            name = args['output']
            with open(f'public/public_{name}.key', 'w') as public_file, open(f'private/private_{name}.key', 'w') as private_file:
                print(public, file=public_file)
                print(private, file=private_file)
        else:
            print(public)
            print(private)
