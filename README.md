# gep: Good Enough Privacy

This program encrypts files with AEAD_XChaCha20_Poly1305, a variant
of rfc8439.
It is mostly an adaptation of the excellent
[`enchive`](http://nullprogram.com/enchive/) tool by Chris Wellons
to a single key encryption algorithm.

See the included man page for option details.

## Installation

Clone this repository, then:

    $ make PREFIX=/usr/local install

This will install both the compiled binary and a manual page under `PREFIX`.

## Usage

The first thing to do is generate an encryption key using `keygen`.
You will be prompted for the passphrase to protect the key.

    $ gep keygen

By default, this will create a file in `$XDG_CONFIG_HOME/gep`
(or `$HOME/.config/gep`): `gep.key`.

To encrypt a file:

    $ gep encrypt private.txt

It will ask for the protection password, encrypt `private.txt`
and replace it by `private.txt.gep`.

For authentification, you can specify your own AAD (Additional
Authentificated Data) with the `--aad` option:

    $ gep encrypt --aad "Ripeness is all" private.txt

To decrypt a file:

    $ gep decrypt --aad "Ripeness is all" private.txt.gep

It will ask for the protection password, decrypt and authenticate
`private.txt.gep`, and replace it by `private.txt`.

With no filenames, `encrypt` and `decrypt` operate on standard input
and output.

## Key management

Like its sibling Enchive, Gep can derive an encryption key from a passphrase.
This means you can store your key in your brain! To access this feature, use
the `--derive` (`-d`) option with the `keygen` command.

    $ gep keygen --derive

If you want to change your protection passphrase, use the `--edit`
option with `keygen`. It will load the key as if it were going
to encrypt a file, then write it back out with the new option.

Gep has a built-in protection key agent that keeps the protection key in
memory for a configurable period of time (default: 15 minutes) after a
protection passphrase has been read. This allows many files to be
encrypted and decrypted with only a single passphrase prompt. Use the
`--agent` (`-a`) global option to enable it.

    $ gep --agent encrypt private.txt

Unlike gpg-agent and ssh-agent, this agent need not be started ahead
of time. It is started on demand, shuts down on timeout, and does not
coordinate with environment variables. One agent is created per unique
encryption key file.

## Key derivation algorithm

The key derivation algorithm is reproduced from
[`enchive`](http://nullprogram.com/enchive/).

Derivation is controlled by a single difficulty exponent *D*. Encryption
key derivation requires 512MB of memory (D=29) by default. The salt for
the secret key is all zeros.

1. Allocate a `(1 << D) + 32` byte buffer, *M*.
2. Compute `HMAC_SHA256(salt, passphrase)` and write this 32-byte
   result to the beginning of *M*.
3. For each uninitialized 32-byte chunk in *M*, compute the SHA-256
   hash of the previous 32-byte chunk.
4. Initialize a byte pointer *P* to the last 32-byte chunk of *M*.
5. Compute the SHA-256 hash, *H*, of the 32 bytes at *P*.
6. Overwrite the memory at *P* with *H*.
7. Take the first *D* bits of *H* and use this value to set a new
    *P* pointing into *M*.
8. Repeat from step 5 `1 << (D - 5)` times.
9. *P* points to the result.

## Test of conformance to AEAD_XChaCha20_Poly1305

You can buil a test program to check the algorithms used by gep against
some of the test vectors given in rfc8439 and xchacha20 specifications:

    $ make test
    $ ./rfc8439

This will output test results of chacha20, poly1305 and xchacha20
algorithms.


