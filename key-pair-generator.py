import sys, argparse
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import snowflake.connector

# Process the command line arguments
def processArgs():

    parser = argparse.ArgumentParser()
    parser.add_argument('--a', dest='account')
    parser.add_argument('--u', dest='user')
    parser.add_argument('--p', dest='password')
    parser.add_argument('--pk', dest='pk_file')
    parser.add_argument('--f', dest='filename')
    parser.add_argument('--pp', dest='passphrase')
    args = parser.parse_args()

    if args.account == None or args.user == None or args.password == None:
        print("Usage: python key-pair-generator.py options\n"
            "--a account        - Snowflake account name\n"
            "--u user           - Snowflake user, to conect and assign the key pair\n"
            "--p password       - Snowflake password, when connecting with basic authentication\n"
            "--pk pk_file       - path to an existing private key file, when connecting to Snowflake with a key pair\n"
            "--pp passphrase    - optional pass phrase to encrypt the private key with (by default no encryption)\n"
            "--f filename       - optional name of the generated files (by default 'rsa_key')\n")
        sys.exit(2)

    # byte-encode the passphrase, if any
    if (args.passphrase != None):
        print(f"Remember your passphrase: '{args.passphrase}'")
        args.passphrase = args.passphrase.encode()

    # never override existing RSA files
    if args.filename == None:
        args.filename = "rsa_key"
    filename = f"{str(Path.home())}\.ssh\{args.filename}"
    suffix = 1
    while (Path(f"{filename}_{suffix}.pub").is_file()
        or Path(f"{filename}_{suffix}.p8").is_file()):
        suffix = suffix + 1
    args.filename = f"{filename}_{suffix}"

    return args

# Generate and save a new 'rsa_key.p8' private key
def genPrivateKey(args):

    key = rsa.generate_private_key(
        backend = default_backend(),
        public_exponent = 65537,
        key_size = 2048
    )

    encryption_type = serialization.NoEncryption()
    if (args.passphrase != None):
        encryption_type = serialization.BestAvailableEncryption(args.passphrase)

    private_key = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        encryption_type
    )
    private_key_file = f"{args.filename}.p8"
    with open(private_key_file, 'wb') as f:
        f.write(private_key)
    print(f"Saved private key in '{private_key_file}'.")

    return key

# Generate and save a new 'rsa_key.pub' public key
def genPublicKey(args, key):

    public_key = key.public_key().public_bytes(
        serialization.Encoding.PEM,                           # not OpenSSH!
        serialization.PublicFormat.SubjectPublicKeyInfo       # not OpenSSH!
    )

    public_key_file = f"{args.filename}.pub"
    with open(public_key_file, 'wb') as f:
        f.write(public_key)
    print(f"Saved public key in '{public_key_file}'.")

    return public_key

# Alter the Snowflake user to use the generated public key
def assocUserWithPublicKey(args, public_key):

    # extract public key from the file content
    lines = public_key.decode().splitlines()[1:-1]
    inner_public_key = "".join(line.rstrip("\n") for line in lines)

    if args.pk_file == None:
        # associate user with the public key value through basic authentication
        con = connect(args.account, args.user, args.password)
        con.cursor().execute(f"alter user {args.user} set rsa_public_key = '{inner_public_key}'")
        con.close()
    else:
        # for key pair rotation, RSA_PUBLIC_KEY_2 or RSA_PUBLIC_KEY must be empty
        params = getRsaParams(args, args.pk_file, args.password.encode())
        rsa_public_key = "RSA_PUBLIC_KEY_2"
        if (params["RSA_PUBLIC_KEY_2"] != "null"):
            rsa_public_key = "RSA_PUBLIC_KEY"
            if (params["RSA_PUBLIC_KEY"] != "null"):
                print(f"??? Cannot alter user: both RSA_PUBLIC_KEY_2 and RSA_PUBLIC_KEY are set for '{args.user}'!")
                sys.exit(2)

        # associate user with the public key value through key pair authentication
        con = connectKeyPair(args.account, args.user, args.pk_file, args.password.encode())
        con.cursor().execute(f"alter user {args.user} set {rsa_public_key} = '{inner_public_key}'")
        con.close()

    print(f"RSA Public Key set in Snowflake for user '{args.user}'.")
    return inner_public_key

# Connect with a key pair to Snowflake and collects the RSA_PUBLIC_KEY parameters
def getRsaParams(args, private_key_file, passphrase):

    params = {}
    con = connectKeyPair(args.account, args.user, private_key_file, passphrase)
    results = con.cursor().execute(f"desc user {args.user}").fetchall()
    for row in results:
        if str(row[0]).startswith("RSA_PUBLIC_KEY"):
            params[str(row[0])] = str(row[1])
    con.close()
    return params

# Connect to Snowflake with basic authentication
def connect(account, user, password):

    return snowflake.connector.connect(
        account = account,
        # role = "ACCOUNTADMIN",
        user = user,
        password = password
    )
    
# Connect to Snowflake with a key pair
def connectKeyPair(account, user, private_key_file, passphrase):

    with open(private_key_file, "rb") as pk_file:
        p_key = serialization.load_pem_private_key(
            pk_file.read(),
            password = passphrase,
            backend = default_backend()
        )

    private_key = p_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())

    return snowflake.connector.connect(
        account = account,
        # role = "ACCOUNTADMIN",
        user = user,
        private_key = private_key
    )

# Main entry point of the application
def main():

    args = processArgs()                                                    # process the command line arguments
    key = genPrivateKey(args)                                               # generate a private key
    public_key = genPublicKey(args, key)                                    # generate a public key
    assocUserWithPublicKey(args, public_key)                                # associate user with the public key

    print("Connecting to Snowflake with your new RSA Public Key:")
    params = getRsaParams(args, f"{args.filename}.p8", args.passphrase)     # connect with the new key pair
    for name in params:
        print(f"   {name} = {params[name]}")

if __name__ == "__main__":
    main()
