namespace Swiftsoft.Shield.Models;

/// <summary>
/// Secret keys used to encrypt and authenticate payloads.
/// </summary>
/// <remarks>
/// Values are read from the application configuration
/// (appsettings.json, environment variables, user secrets or a secret vault).
/// Both keys are Base64-encoded, must be randomly generated,
/// and must never be stored in source code or committed to Git.
/// </remarks>
/// <example>
/// Example section in appsettings.json:
/// <code>
/// "PayloadSecurity": {
///   "AesKey": "&lt;32 random bytes in Base64&gt;",
///   "HmacKey": "&lt;32 or more random bytes in Base64&gt;"
/// }
/// </code>
/// </example>
public partial class PayloadSecuritySettings
{
    /// <summary>
    /// AES = Advanced Encryption Standard
    /// AES-256 encryption key, Base64-encoded.
    /// </summary>
    /// <remarks>
    /// Must decode to exactly 32 bytes (44 Base64 characters).
    /// Used to encrypt and decrypt the payload (symmetric encryption).
    /// Must be different from <see cref="HmacKey"/>.
    /// Changing it makes all contracts produced with the previous key unreadable.
    /// </remarks>
    public string AesKey { get; set; } = string.Empty;

    /// <summary>
    /// HMAC = Hash-based Message Authentication Code
    /// Secret key for the HMAC-SHA256 integrity signature, Base64-encoded.
    /// </summary>
    /// <remarks>
    /// Must decode to at least 32 bytes (44 or more Base64 characters).
    /// Used to sign the encrypted payload and to verify that it has not been modified.
    /// Must be different from <see cref="AesKey"/>.
    /// Changing it causes verification to fail for all existing contracts.
    /// </remarks>
    public string HmacKey { get; set; } = string.Empty;
}