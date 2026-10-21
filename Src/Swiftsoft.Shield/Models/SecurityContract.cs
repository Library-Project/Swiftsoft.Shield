namespace Swiftsoft.Shield.Models;

/// <summary>
/// An encrypted and authenticated message exchanged between the client and the API.
/// </summary>
/// <remarks>
/// The contract transmits data protected by AES-256-CBC (confidentiality)
/// and HMAC-SHA256 (integrity), using the “Encrypt-then-MAC” scheme.
/// </remarks>
public sealed class SecurityContract
{
    /// <summary>
    /// Version of the encryption protocol used to generate this contract.
    /// </summary>
    /// <remarks>
    /// Current value : <c>1</c> (AES-256-CBC + HMAC-SHA256).
    /// Allows the algorithm or keys to be updated without breaking existing contracts.
    /// This value is not covered by <see cref="Integrity"/>.
    /// </remarks>
    public int Velocity { get; set; }

    /// <summary>
    /// Size, in bytes, of the plaintext data before encryption.
    /// </summary>
    /// <remarks>
    /// For informational purposes only; not used for decryption 
    /// and not covered by <see cref="Integrity"/>.
    /// </remarks>
    public int Graduation { get; set; }

    /// <summary>
    /// HMAC-SHA256 signature of <see cref="Payload"/>, Base64-encoded.
    /// </summary>
    /// <remarks>
    /// A 44-character string (32 bytes). It is verified before any decryption:
    /// any change to <see cref="Payload"/> causes the verification to fail.
    /// </remarks>
    public string Integrity { get; set; }

    /// <summary>
    /// Encrypted data, Base64-encoded.
    /// </summary>
    /// <remarks>
    /// Contains the initialization vector (first 16 bytes) followed by the data
    /// encrypted with AES-256-CBC.
    /// </remarks>
    public string Payload { get; set; }

    /// <summary>
    /// Constructor : Initializes a contract with the specified values.
    /// </summary>
    /// <param name="velocity">Version of the encryption protocol.</param>
    /// <param name="graduation">Size in bytes of the plaintext data before encryption.</param>
    /// <param name="integrity">HMAC-SHA256 signature of the payload, Base64-encoded.</param>
    /// <param name="payload">Initialization vector and encrypted data, Base64-encoded.</param>
    public SecurityContract(int velocity, int graduation, string integrity, string payload)
    {
        Velocity = velocity;
        Graduation = graduation;
        Integrity = integrity;
        Payload = payload;
    }
}