# SwiftSoft.Shield

Encrypts and signs the data exchanged by an ASP.NET Core API, so that it stays
unreadable and tamper-proof, even in logs, proxies or debugging tools.

## Features
- **Encryption**: encrypts data with symmetric authenticated encryption
  (AES-256-CBC + HMAC-SHA256). A random IV is generated for each message and
  sent along with the encrypted data; the keys never leave the server.
- **Decryption**: verifies the integrity of the encrypted data, then decrypts it
  using the keys stored in the application configuration.
- **Key generator**: generates a cryptographically secure random 32-byte key.

## Installation
    dotnet add package SwiftSoft.Shield

## Configuration

- appsettings.json

       {
           ...,
           "PayloadSecurity": {
               "AesKey": "<32 bytes in Base64>",
               "HmacKey": "<32 bytes or more in Base64>"
           },
           ...
       }

- Program.cs

       builder.Services.AddSwiftSoftSecurity(builder.Configuration);

## Usage
 - Generate key

       var aesKey = SecurityHelper.KeyGenerate();
       var hmacKey = SecurityHelper.KeyGenerate();

 - Use service

       var contract = SecurityService<MyData>.Instance.Encrypt(myData);
       var data     = SecurityService<MyData>.Instance.Decrypt(contract);

## Security
- Keys stored in appsettings.json must only be used for local testing.
  In other environments, use user-secrets, environment variables or a secret
  vault (Azure Key Vault, AWS Secrets Manager, etc.).
- Use different keys for each environment.

> **NOTE: This library complements HTTPS; it does not replace it.**