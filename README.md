# go-nacl

This is a high level wrapper around Go's implementation of [NaCl](http://nacl.cr.yp.to/) symetric encryption

# secretbox
--
    import "github.com/chinkley/go-nacl/secretbox"


## Usage

```go
const KeySize = 32
```
keySize

```go
const NonceSize = 24
```
NonceSize

```go
const SaltSize = 16
```
SaltSize

#### func  Decrypt

```go
func Decrypt(key *[KeySize]byte, nonce *[NonceSize]byte, ciphertext []byte) ([]byte, error)
```
Decrypt returns plaintext from ciphertext

#### func  DecryptWithSecret

```go
func DecryptWithSecret(secret string, ciphertext []byte) ([]byte, error)
```
DecryptWithSecret Decrypt ciphertext into plaintext using supplied secret

#### func  Encrypt

```go
func Encrypt(key *[KeySize]byte, nonce *[NonceSize]byte, plaintext []byte) ([]byte, error)
```
Encrypt returns ciphertext from plaintext

#### func  EncryptWithSecret

```go
func EncryptWithSecret(secret string, plaintext []byte) ([]byte, error)
```
EncryptWithSecret Encrypt plaintext into ciphertext using supplied secret

#### func  GenerateSalt

```go
func GenerateSalt() (*[SaltSize]byte, error)
```
GenerateSalt generates a random salt

#### func  KeyFromPassphrase

```go
func KeyFromPassphrase(passphrase string) (*[KeySize]byte, *[SaltSize]byte, error)
```
KeyFromPassphrase generates a random salt and derives key material from
passphrase

## Example

    package main

    import (
      "fmt"

      "github.com/hink/go-nacl/secretbox"
    )

    func main() {
      /*
      NACL SECRETBOX SYMETRIC ENCRYPTION
      */

      // Message to Encrypt
      message := "This is a super top secret message."

      // Encrypt
      ciphertext, err := secretbox.EncryptWithSecret(secret, []byte(message))
      if err != nil {
        panic(err)
      }

      // Decrypt
      plaintext, err := secretbox.DecryptWithSecret(key, ciphertext)
      if err != nil {
        panic(err)
      }

      // Output Encrypted and Decrypted text
      fmt.Print("\n")
      fmt.Printf("             Message: %v\n\n", message)
      fmt.Printf("Encrypted Ciphertext: %v\n\n", string(ciphertext))
      fmt.Printf(" Decrypted Plaintext: %v\n\n", string(plaintext))
    }
