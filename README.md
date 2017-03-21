# Fernet Haskell Implementation

[![Build Status](https://travis-ci.org/rvl/fernet-hs.svg?branch=master)](https://travis-ci.org/rvl/fernet-hs) [![Hackage](https://img.shields.io/hackage/v/fernet.svg)](http://hackage.haskell.org/package/fernet)

*Fernet* generates and verifies HMAC-based authentication tokens.

Originally designed for use within OpenStack clusters, it was intended
to be fast and light-weight, with non-persistent tokens. Integrity and
confidentiality of the token contents are implemented with HMAC SHA256
and AES128 CBC.

See the [Fernet Spec][spec] for a little more information.

[spec]: https://github.com/fernet/spec/blob/master/Spec.md

## Usage

To encrypt a token:

    >>> import Network.Fernet
    >>> k <- generateKey
    >>> keyToBase64 k
    "JQAeL3iFN9wIW_hMKiIzA1EiG_EZNivnMPBOOJn2wZc="
    >>> token <- encrypt k "secret text"
    >>> print token
    "gAAAAABY0H9kx7ihkcj6ZF_bQ73Lvc7aG-ZlEtjx24io-DQy5tCjLbq1JvVY27uAe6BuwG8css-4LDIywOJRyY_zetq7aLPPag=="

The resulting token can be distributed to clients. To check and
decrypt the token, use the same key:

    >>> decrypt k 60 token
    Right "secret text"

Do read the [Network.Fernet module][haddock] documentation for further
information.

[haddock]: http://hackage.haskell.org/package/fernet/docs/Network-Fernet.html


## Command-line tool

This package also includes a command-line tool for encrypting and
decrypting tokens.

    Fernet Utility

    Usage: fernet (((-k|--key STRING) | --key-file FILENAME) ([-e|--encrypt] |
                  [-d|--decrypt]) [--ttl SECONDS] | (-g|--gen-key))
      Encrypts/decrypts Fernet tokens. One token written to stdout for each line
      read from stdin. Use --gen-key to make a key.

    Available options:
      -h,--help                Show this help text
      -k,--key STRING          Base64-urlsafe-encoded 32 byte encryption key
      --key-file FILENAME      File containing the encryption key
      -e,--encrypt             Encryption mode (default: autodetect)
      -d,--decrypt             Decryption mode (default: autodetect)
      --ttl SECONDS            Token lifetime in seconds (default: 1 minute)
      -g,--gen-key             Generate a key from the password on standard input

## Development

### Building with Stack

```
stack build
```

### Building with Nix

```
nix-shell -p cabal2nix --command "cabal2nix --shell . > default.nix"
nix-shell --command "cabal configure"
cabal build
```

## Better & Cooler Stuff

You might also be interested in [hsoz](https://github.com/rvl/hsoz).
