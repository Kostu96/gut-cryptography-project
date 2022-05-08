from PyQt5.QtWidgets import QApplication
from argparse import ArgumentParser
from ui import UI
from crypto import *

def parseArgs() -> ArgumentParser:
    parser = ArgumentParser(description='Program do generowania kluczy asymetrycznych oraz szyfrowania i deszyfrowania plików')
    subparser = parser.add_subparsers(help='sub-command help', dest='command')

    g_parser: ArgumentParser = subparser.add_parser('generate-keys', help='Generuj klucze asymetryczne')
    g_parser.add_argument('length', type=int, choices=[1024, 2048, 4096, 8192], help='Dlugosc klucza w bitach')

    return parser

if __name__ == "__main__":
    parser = parseArgs()
    args = vars(parser.parse_args())
    #print(args) # debug

    if args['command'] is None:
        app = QApplication([])
        mainWindow = UI()
        app.exec()
    elif args['command'] == 'generate-keys':
        public, private = generate_keys(args['length'])
