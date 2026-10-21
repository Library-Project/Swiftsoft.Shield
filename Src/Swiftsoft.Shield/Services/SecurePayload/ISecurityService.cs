using Swiftsoft.Shield.Models;

namespace Swiftsoft.Shield.Services.SecurePayload;

/// <summary>
/// Payload encryption and decryption service.
/// </summary>
/// <remarks>
/// <list type="bullet">
///   <item><description>Encryption: AES-256-CBC (confidentiality).</description></item>
///   <item><description>Integrity: HMAC-SHA256 (detection of any modification).</description></item>
/// </list>
/// </remarks>
/// <typeparam name="TResult">Type of the data to encrypt or decrypt.</typeparam>
public interface ISecurityService<TResult>
    where TResult: class
{
    /// <summary>
    /// Encrypts an object and returns a SecurityContract.
    /// Flow: object -> canonical JSON -> {Integrity, Data} envelope -> AES -> Base64 -> HMAC.
    /// </summary>
    /// <param name="data">Represents the encoded data</param>
    /// <returns>The data encoded using the model <see cref="SecurityContract"/>.</returns>
    SecurityContract Encrypt(TResult data);

    /// <summary>
    /// Decrypts a SecurityContract and returns the plaintext data.
    /// Flow: outer HMAC -> IV/ciphertext split -> AES -> envelope parsing -> inner HMAC -> result.
    /// </summary>
    /// <param name="contract">The data has been decoded</param>
    /// <returns>The decoded data of type <c>TResult</c> </returns>
    TResult Decrypt(SecurityContract contract);
}