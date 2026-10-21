using System.Security.Cryptography;

namespace Swiftsoft.Shield.Services.SecurePayload.Utilities;

public static class SecurityHelper
{
    /// <summary>
    /// Generates a new random 32-byte (256-bit) key, Base64-encoded.
    /// </summary>
    /// <remarks>
    /// Uses a cryptographically secure random number generator (<see cref="RandomNumberGenerator"/>).
    /// The generated key is suitable for both <c>AesKey</c> (AES-256) and <c>HmacKey</c>
    /// (HMAC-SHA256). Call the method once per key: <c>AesKey</c> and <c>HmacKey</c>
    /// must be different.
    /// </remarks>
    /// <returns>A 44-character Base64 string.</returns>
    /// <example>
    /// <code>
    /// var aesKey = SecurityHelper.KeyGenerate();
    /// var hmacKey = SecurityHelper.KeyGenerate();
    /// </code>
    /// </example>
    public static string KeyGenerate()
        => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).ToString();

    /// <summary>
    /// Decodes a Base64 string into bytes.
    /// </summary>
    /// <remarks>
    /// Useful for validating a configuration key before using it,
    /// for example to check that <c>AesKey</c> represents exactly 32 bytes.
    /// </remarks>
    /// <param name="value">Base64-encoded string.</param>
    /// <returns>
    /// The decoded bytes, or <c>null</c> if <paramref name="value"/> is <c>null</c>,
    /// empty, or not a valid Base64 string.
    /// </returns>
    public static byte[]? Base64ToByte(string value)
    {
        try { return Convert.FromBase64String(value); }
        catch (FormatException) { return null; }
    }
}