```markdown
# AES Encryption and Decryption Library

This library provides a simple implementation of Advanced Encryption Standard (AES) encryption and decryption in Delphi. AES is a widely used symmetric encryption algorithm for securing data. This readme will guide you on how to use this library in your Delphi projects.

## Features

- AES encryption and decryption.
- Password-based key derivation using PBKDF2.
- Hexadecimal encoding and decoding.
- Key generation and management.

## Getting Started

To use this library in your Delphi project, follow these steps:

1. **Include the Unit:** Include the `MEncryptDecryptAES` unit in your project's `uses` clause.

2. **Encryption and Decryption:**

   - Use the `EncryptPassword` function to encrypt a password.
   - Use the `DecryptPassword` function to decrypt an encrypted password.

   Example:
   ```delphi
   var
     EncryptedPassword, DecryptedPassword: string;
   begin
     EncryptedPassword := EncryptPassword('MySecretPassword', 'MyEncryptionKey');
     DecryptedPassword := DecryptPassword(EncryptedPassword, 'MyEncryptionKey');
   end;
   ```

3. **Hashing:**

   - Use the `CalculateHash` function to calculate a hash for password storage.
   - Use the `verifyHash` function to verify a stored hash.

   Example:
   ```delphi
   var
     Hash, StoredSalt, StoredHash: string;
     IsPasswordValid: Boolean;
   begin
     StoredSalt := GenerateSalt(16);
     Hash := CalculateHash('MySecretPassword', StoredSalt);
     // Store 'Hash' and 'StoredSalt' securely.
     
     // Later, when verifying a password:
     IsPasswordValid := verifyHash('MySecretPassword', StoredSalt, StoredHash);
   end;
   ```

4. **Key Generation:**

   - Use the `GenerateRandomKey` function to generate a random encryption key.
   
   Example:
   ```delphi
   var
     RandomKey: string;
   begin
     RandomKey := GenerateRandomKey(32); // Generate a 32-byte key (256 bits).
   end;
   ```

## Usage Notes

- Ensure that you handle encryption keys securely, as they are critical for both encryption and decryption.
- Always store and manage salts and hashes securely when handling passwords.

## License

This project is licensed under the MIT License. You are free to use and modify it for your own purposes.

## Acknowledgments

This library is based on the AES encryption algorithm and PBKDF2 key derivation.

For more details on the implementation and the algorithm used, please refer to the source code in `MEncryptDecryptAES.pas`.

## Contributing

If you want to contribute to this project, please feel free to create a pull request or open an issue.

---

Enjoy using this AES encryption and decryption library in your Delphi projects!
```

