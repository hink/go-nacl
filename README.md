# go-nacl

This is a high level wrapper around Go's implementation of [NaCl](http://nacl.cr.yp.to/) symetric encryption

## Example

    package main

    import (
      "fmt"

      "github.firehost.co/chinkley/go-nacl/secretbox"
    )

    func main() {
      /*
      NACL SECRETBOX SYMETRIC ENCRYPTION
      */

      // Message to Encrypt
      message := "This is a super top secret message."

      // Create encryption key from passphrase
      secret := "This is a secret phrase"
      key, _ := secretbox.KeyFromPassphrase(secret)

      // Encrypt
      ciphertext, err := secretbox.Encrypt(key, []byte(message))
      if err != nil {
        panic(err)
      }

      // Decrypt
      plaintext, err := secretbox.Decrypt(key, ciphertext)
      if err != nil {
        panic(err)
      }

      // Output Encrypted and Decrypted text
      fmt.Print("\n")
      fmt.Printf("             Message: %v\n\n", message)
      fmt.Printf("Encrypted Ciphertext: %v\n\n", string(ciphertext))
      fmt.Printf(" Decrypted Plaintext: %v\n\n", string(plaintext))
    }
