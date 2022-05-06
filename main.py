<<<<<<< HEAD
from PyQt5.QtWidgets import QApplication
from ui import UI


if __name__ == '__main__':
    app = QApplication([])
    mainWindow = UI()
    app.exec()
=======
from gui import CryptoGUI
from wdc_crypto import *
from argparse import ArgumentParser

def parseArgs() -> ArgumentParser:
    parser = ArgumentParser(description='Program do generowania kluczy asymetrycznych oraz szyfrowania i deszyfrowania plików')
    subparser = parser.add_subparsers(help='sub-command help', dest='command')

    g_parser: ArgumentParser = subparser.add_parser('generate-keys', help='Generuj klucze asymetryczne')
    g_parser.add_argument('type', choices=AssymetricKeyType._member_names_, help='Typ algorytmu')
    g_parser.add_argument('length', type=int, choices=[16,32,64,128,256,512,1024], help='Dlugosc klucza')

    return parser

if __name__ == "__main__":
    parser = parseArgs()
    args = vars(parser.parse_args())
    print(args)

    if args['command'] is None:
        app = CryptoGUI()
        app.run()
    elif args['command'] == 'generate-keys':
        private, public = generateKeys(AssymetricKeyType[args['type']], args['length'])
        print('Private key:'.ljust(12), private.key)
        print('Public key:'.ljust(12), public.key)
>>>>>>> 64ba188 (example of possible code)
