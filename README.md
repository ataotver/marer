# marer

A command-line file encryptor written in C using libsodium, with a minimal interactive mode for those less familiar with the command line. It encrypts files with a password using authenticated, streaming encryption.

## How it works

- **Key derivation:** passwords are run through the **Argon2id** algorithm, which is deliberately slow (~0.5s) to resist brute-force attacks.
- **Encryption:** **XChaCha20-Poly1305** provides *authenticated* encryption, it not only hides the data but detects if the file has been tampered with.
- **Streaming:** files are processed in chunks, so any file size can be encrypted without loading the whole thing into RAM.

The encrypted file has the following structure:

```
[magic bytes] [salt] [header] [encrypted chunks...]
```

## Building

marer depends on [libsodium](https://libsodium.org) and a C compiler.

**Windows (MSYS2 / UCRT64)** — how this was developed:

```bash
# Install MSYS2, open the MSYS2 UCRT64 terminal, then install libsodium + compiler:
pacman -S mingw-w64-ucrt-x86_64-libsodium mingw-w64-ucrt-x86_64-gcc

# Compile a standalone .exe (no DLL dependency):
gcc marer.c -o marer.exe -static -lsodium
```

**Linux (Debian/Ubuntu):**

```bash
sudo apt install libsodium-dev gcc
gcc marer.c -o marer -lsodium
```

**macOS (Homebrew):**

```bash
brew install libsodium
gcc marer.c -o marer -lsodium
```

## Usage

```bash
# Encrypt a file
./marer encrypt secret.txt secret.enc

# Decrypt it
./marer decrypt secret.enc recovered.txt
```

Or run it with no arguments (or double-click on Windows) to be prompted interactively.

## Status & limitations

This is at the **MVP stage**, built primarily as a learning project. You're welcome to use it, but be mindful:

- It hasn't been audited — don't use it to protect genuinely sensitive data yet.
- The password is echoed to the screen as you type (no hidden input yet).
- The "delete original" option only unlinks the file — the data remains on disk and is recoverable with forensic tools (especially on SSDs).
- Same-file protection compares the paths you type as text, so it won't catch aliases like `file.txt` vs `./file.txt`.
- Decryption requires this same tool and the same password, so there's no key exchange.
- The derived key and password sit in normal memory (not locked or zeroed after use).

This project was developed and tested on Windows/MSYS2. So you shouldn't encounter much bugs.

Feedback and suggestions welcome. Hope this was helpful!
