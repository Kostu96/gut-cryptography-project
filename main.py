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
    g_parser.add_argument('-a', '--asymmetric', required=True, type=str, choices=['RSA', 'SECP256K1'], help='Rodzaj kluczy asymetrycznych')
    g_parser.add_argument('-l', '--length', type=int, default=2048, const=2048, nargs='?', choices=[1024, 2048, 4096, 8192], help='Tylko dla RSA. Długosc klucza w bitach. Domyślnie 2048')
    g_parser.add_argument('-o', '--output', type=str, metavar='name', help='Zapisuje klucze do plików public/public_<name>.key i private/private_<name>.key')
    g_parser.add_argument('-p', '--password', type=str, help='Hasło do zaszyfrowania klucza prywatnego')

    e_parser: ArgumentParser = subparser.add_parser('encrypt', help='Zaszyfruj plik/tekst')
    alg_subparser = e_parser.add_subparsers(help='sub-command help', dest='algorithm', required=True)
    for symmetric in SymmetricAlgorithm:
        help = 'Rodzaj algorytmu symetrycznego' if symmetric != SymmetricAlgorithm.NONE else 'Szyfrowanie asymetryczne, tylko z RSA'
        sym_parser = alg_subparser.add_parser(symmetric.name, help=help)
        if len(KEY_LENGTHS[symmetric]) > 1:
            sym_parser.add_argument('-l', '--length', required=True, type=int, choices=KEY_LENGTHS[symmetric], help='Długość klucza symetrycznego')
        group = sym_parser.add_mutually_exclusive_group(required=True)
        group.add_argument('-s', '--string', type=str, help='Tekst do zaszyfrowania')
        group.add_argument('-f', '--file', type=str, help='Plik do zaszyfrowania')
        group_key = sym_parser.add_mutually_exclusive_group(required=True)
        group_key.add_argument('-i', '--input-key', type=str, help='Ścieżka do pliku z kluczem publicznym')
        group_key.add_argument('-n', '--name-key', type=str, help='Nazwa klucza publicznego znajdującego się w folderze public: public/public_<nazwa>.key')
        sym_parser.add_argument('-o', '--output', type=str, help='Ścieżka do pliku wyjściowego')

    d_parser: ArgumentParser = subparser.add_parser('decrypt', help='Odszyfruj plik')
    d_parser.add_argument('-f', '--file', type=str, required=True, help='Plik do odszyfrowania')
    group_key = d_parser.add_mutually_exclusive_group(required=True)
    group_key.add_argument('-i', '--input-key', type=str, help='Ścieżka do pliku z kluczem prywatnym')
    group_key.add_argument('-n', '--name-key', type=str, help='Nazwa klucza prywatnego znajdującego się w folderze private: private/private_<nazwa>.key')
    d_parser.add_argument('-p', '--password', type=str, help='Hasło do odszyfrowania klucza prywatnego')
    d_parser.add_argument('-o', '--output', type=str, help='Ścieżka do pliku wyjściowego')

    return parser


def test():
    """ encrypts text with every symmetric algorithm with every key size and then decrypts """
    public, private = generate_keys()
    public_ECC, private_ECC = generate_keys(AsymmetricAlgorithm.ECC_SECP256K1)
    encrypted_list: list[tuple[str, str, bytes]] = []
    for algorithm in SymmetricAlgorithm:
        if len(KEY_LENGTHS[algorithm]) == 0:
            encrypted_list.append(('RSA', f'RSA_{algorithm.name}(-)', encrypt(b'12345', public, algorithm).encrypted_file))
        else:
            for key_size in KEY_LENGTHS[algorithm]:
                encrypted_list.append(('RSA', f'RSA_{algorithm.name}({key_size})', encrypt(b'12345', public, algorithm, key_size).encrypted_file))
                encrypted_list.append(('ECC', f'ECC_{algorithm.name}({key_size})', encrypt(b'12345', public_ECC, algorithm, key_size).encrypted_file))

    for asymmetric_alg, text, encrypted_file in encrypted_list:
        if asymmetric_alg == 'RSA':
            print(f'{text} = {decrypt(encrypted_file, private)}')
        else:
            print(f'{text} = {decrypt(encrypted_file, private_ECC)}')


def main(args: dict[str, Any]):
    #test()
    if args['command'] is None:
        app = QApplication([])
        _ = UI()
        app.exec()
    elif args['command'] == 'generate-keys':
        type = AsymmetricAlgorithm.RSA if args['asymmetric'] == 'RSA' else AsymmetricAlgorithm.ECC_SECP256K1
        public, private = generate_keys(type, args['length'])
        if args['output'] is not None:
            saveKey(public, args['output'])
            saveKey(private, args['output'], args['password'])
        else:
            print(public)
            print(private.toString(password=args['password']))
    elif args['command'] == 'encrypt':
        path = args['input_key'] if args['input_key'] is not None else f'public/public_{args["name_key"]}.key'
        public_key = loadPublicKeyFromFile(path)
        data: bytes = None
        if args['string'] is None:
            with open(args['file'], 'r', encoding='utf-8') as file:
                data = file.read().encode('utf-8')
        else:
            data = args['string'].encode('utf-8')
        encrypted_data = encrypt(data, public_key, SymmetricAlgorithm[args['algorithm']], args.get('length'))
        if args['output'] is None:
            print(encrypted_data.getPrintableFile())
        else:
            with open(args['output'], 'wb') as output:
                output.write(encrypted_data.encrypted_file)
    elif args['command'] == 'decrypt':
        encrypted_data = None
        path = args['input_key'] if args['input_key'] is not None else f'private/private_{args["name_key"]}.key'
        private_key = loadPrivateKeyFromFile(path, args['password'])
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
