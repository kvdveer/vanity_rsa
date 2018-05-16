This tool generates valid RSA keypairs which contain some piece of text. The 
details are discussed in the accompanying 
[blog post](https://ondergetekende.nl/vanity-rsa-public-key.html).

Use
---

Simplest usage: `python3 vanity_rsa.py "MyVanityText"`


```
usage: vanity_rsa.py [-h] [--key-length KEY_LENGTH] [--key-format {PEM,SSH}]
                     [--output-file OUTPUT_FILE]
                     [--output-file-public OUTPUT_FILE_PUBLIC]
                     vanity

Generate an RSA key containing arbitrary text in the public key.

positional arguments:
  vanity                The text to inject

optional arguments:
  -h, --help            show this help message and exit
  --key-length KEY_LENGTH
                        The length of the key in bits
  --key-format {PEM,SSH}
                        The format of the key
  --output-file OUTPUT_FILE
                        Where to save the private key
  --output-file-public OUTPUT_FILE_PUBLIC
                        Where to save the public key
```

Dependencies
---

The code depends on [cryptography package](https://pypi.org/project/cryptography/). 
While not strictly necessary, you may want to install 
[gmpy2](https://pypi.org/project/gmpy2/) for a factor 10 speedup. You can 
install both of these using `pip install cryptography gmpy2`.