Snowflake Key Pair Generator
============================

Practical Python script that automates the creation of a [key pair for authentication to Snowflake](https://docs.snowflake.com/en/user-guide/key-pair-auth.html). 

We'll automatically generate an encrypted or unencrypted private key file, and a public key file. We'll associate the public key value with a Snowflake user, and we'll reconnect to Snowflake through the new key pair, making sure it works. 

We also provide support for the key pair rotation, setting a second key when the initial connection was not done through basic authentication.

# CLI Executable File

You can invoke the tool directly from a Terminal window in Visual Source Code, as it follows:

**<code>python key-pair-generator.py options</code>**  

Calling with no options will show you what commands are available:

Usage: python key-pair-generator.py options
* --a account        - Snowflake account name  
* --u user           - Snowflake user, to conect and assign the key pair  
* --p password       - Snowflake password, when connecting with basic authentication  
* --pk pk_file       - path to an existing private key file, when connecting to Snowflake with a key pair  
* --pp passphrase    - optional pass phrase to encrypt the private key with (by default no encryption)  
* --f filename       - optional name of the generated files (by default 'rsa_key')  

To compile into a CLI executable:

**<code>pip install pyinstaller</code>**  
**<code>pyinstaller --onefile key-pair-generator.py</code>**  
**<code>dist/key-pair-generator options</code>**  

# Example Usage

**<code>python key-pair-generator.py --a www55555 --u MyUsername --p MyPassword123_</code>**

This will generate a **.ssh\rsa_key_1.p8** unencrypted private key file and a **.ssh\rsa_key_1.pub** public key file in your home user folder. A _2, _3, _4 etc suffix will be used instead if files with the same names exist (i.e. existing files are never overwritten).

The public key content is also extracted and associated with the Snowflake user MyUsername. The connection to Snowflake is though basic authentication, using the account, username and password passed in the command line.

**<code>python key-pair-generator.py --a www55555 --u MyUsername --p MyPassword123_ --f my_key_file</code>**

Same as before, except the generated files will be **.ssh\my_key_file_1.p8** and **.ssh\my_key_file_1.pub**.

**<code>python key-pair-generator.py --a www55555 --u MyUsername --p MyPassword123_ --pp "This is the way"</code>**

Same as the first example, except the private key will be encrypted with a "This is the way" pass-phrase.

**<code>python key-pair-generator.py --a www55555 --u MyUsername --pk C:\Users\myname\.ssh\rsa_key_1.p8 --p "This is the way" --pp "And this is another way"</code>**

If you run this after the previous example, the first connection to Snowflake will be through the key pair you already assigned to that user. The **--pk** option will have a valid path to your private key file, and the **--p** option will have the pass-phrase to decrypt it, in this case. Last **--pp** parameter will establish a pass-phrase for the newly generated keys.

The code will set the public key value into either RSA_PUBLIC_KEY_2 or RSA_PUBLIC_KEY user parameters. If both are set, we do nothing. The app will always dump on screen the content of the four user parameters associated with a key pair: RSA_PUBLIC_KEY, RSA_PUBLIC_KEY_FP, RSA_PUBLIC_KEY_2, RSA_PUBLIC_KEY_2_FP.

This last use case allows for a key pair rotation: you may connect with one key pair, set another one in RSA_PUBLIC_KEY_2, reconnect with this one and eventually remove the one that you had in RSA_PUBLIC_KEY.
