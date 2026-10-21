using System.Security;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
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
public sealed  class SecurityService<TResult> : ISecurityService<TResult>
    where TResult: class
{
    #region Properties (Private)

    /// <summary>
    /// One instance per <c>TResult</c>, created lazily on first access (thread-safe).
    /// It reads the shared configuration from <see cref="SecuritySettingsConfig"/>.
    /// </summary>
    private static readonly Lazy<SecurityService<TResult>> _instance =
        new(() => new SecurityService<TResult>(SecuritySettingsConfig.Settings));

    /// <summary>
    /// 32-byte (256-bit) AES key.
    /// Used to both encrypt AND decrypt (symmetric encryption).
    /// </summary>
    private readonly byte[] _aesKey;

    /// <summary>
    /// Secret HMAC key, used to compute the integrity "signature".
    /// Different from AES key: the same key is never reused for two purposes.
    /// </summary>
    private readonly byte[] _hmacKey;

    /// <summary>
    /// Settings applied when Newtonsoft builds a JToken from JSON text; 
    /// Identical for encoding and decoding.
    /// </summary>
    private static readonly JsonLoadSettings LoadSettings = new()
    {
        CommentHandling = CommentHandling.Ignore
    };

    /// <summary>
    /// Settings applied when deserializing to a concrete type.
    /// </summary>
    private static readonly JsonSerializerSettings ReadSettings = new()
    {
        DateParseHandling = DateParseHandling.None,
        FloatParseHandling = FloatParseHandling.Decimal
    };

    #endregion

    #region Properties (Public)

    /// <summary>
    /// Instance that can be used without dependency injection.
    /// </summary>
    public static ISecurityService<TResult> Instance => _instance.Value;

    #endregion

    #region Constructors (Public)

    /// <summary>
    /// Initializes the service with keys from the application configuration,
    /// provided through dependency injection.
    /// </summary>
    /// <param name="appPayloadSettings">
    /// The "PayloadSecurity" section of appsettings.json, bound to <see cref="PayloadSecuritySettings"/>.
    /// </param>
    private SecurityService(PayloadSecuritySettings appPayloadSettings)
    {
        _aesKey = Convert.FromBase64String(appPayloadSettings.AesKey);
        _hmacKey = Convert.FromBase64String(appPayloadSettings.HmacKey);
    }

    #endregion

    #region Methods (Public)

    /// <summary>
    /// Encrypts an object and returns a SecurityContract.
    /// Flow: object -> canonical JSON -> {Integrity, Data} envelope -> AES -> Base64 -> HMAC.
    /// </summary>
    /// <param name="data">Represents the encoded data</param>
    /// <returns>The data encoded using the model <see cref="SecurityContract"/>.</returns>
    public SecurityContract Encrypt(TResult data)
    {
        var dataJson = Canonicalize(JsonConvert.SerializeObject(data));
        var envelope = new JObject
        {
            ["Integrity"] = ComputeIntegrity(dataJson),
            ["Data"] = ParseToken(dataJson)
        };
        var json = envelope.ToString(Formatting.None);
        using var aes = Aes.Create();

        aes.Key = _aesKey;
        aes.GenerateIV();
        
        using var encryptor = aes.CreateEncryptor();
        var plainBytes = Encoding.UTF8.GetBytes(json);
        var cipherBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
        var payload = Convert.ToBase64String(aes.IV.Concat(cipherBytes).ToArray());

        return new SecurityContract(
            velocity: 1,                             // numéro de version du protocole (champ libre)
            graduation: plainBytes.Length,           // taille du texte clair avant chiffrement (information)
            integrity: ComputeIntegrity(payload),    // HMAC du payload CHIFFRÉ (couche externe)
            payload: payload);                       // IV + données chiffrées, en Base64
    }

    /// <summary>
    /// Decrypts a SecurityContract and returns the plaintext data.
    /// Flow: outer HMAC -> IV/ciphertext split -> AES -> envelope parsing -> inner HMAC -> result.
    /// </summary>
    /// <param name="contract">The data has been decoded</param>
    /// <returns>The decoded data of type <c>TResult</c> </returns>
    public TResult Decrypt(SecurityContract contract)
    {
        var expected = Convert.FromBase64String(ComputeIntegrity(contract.Payload));
        var received = Convert.FromBase64String(contract.Integrity);
        
        if (!CryptographicOperations.FixedTimeEquals(expected, received))
            throw new SecurityException("Intégrité du payload compromise.");

        var fullBytes = Convert.FromBase64String(contract.Payload);
        var iv = fullBytes[..16];
        var cipherBytes = fullBytes[16..];
        using var aes = Aes.Create();

        aes.Key = _aesKey;
        aes.IV = iv;

        using var decryptor = aes.CreateDecryptor();
        var plainBytes = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
        var root = ParseToken(Encoding.UTF8.GetString(plainBytes)) as JObject
                   ?? throw new SecurityException("Payload illisible.");

        var dataToken = root["Data"] ?? throw new SecurityException("Payload illisible.");
        var innerIntegrity = root["Integrity"]?.Value<string>();

        var dataJson = dataToken.ToString(Formatting.None);

        if (ComputeIntegrity(dataJson) != innerIntegrity)
            throw new SecurityException("Données altérées.");

        if (typeof(TResult) == typeof(object) || typeof(JToken).IsAssignableFrom(typeof(TResult)))
            return (TResult)(object)dataToken;

        return JsonConvert.DeserializeObject<TResult>(dataJson, ReadSettings)
               ?? throw new SecurityException("Payload illisible.");
    }

    #endregion

    #region Methods (Private)

    /// <summary>
    /// Parses JSON text into a JToken using fixed settings (the same everywhere).
    /// </summary>
    private static JToken ParseToken(string json)
    {
        using var stringReader = new StringReader(json);
        using var reader = new JsonTextReader(stringReader)
        {
            DateParseHandling = DateParseHandling.None,
            FloatParseHandling = FloatParseHandling.Decimal
        };
        
        return JToken.Load(reader, LoadSettings);
    }

    /// <summary>
    /// JSON -> tree (JToken) -> compact JSON: the same content always produces exactly the same text.
    /// </summary>
    private static string Canonicalize(string json)
        => ParseToken(json).ToString(Formatting.None);

    /// <summary>
    /// Computes the HMAC-SHA256 signature of a string and returns it Base64-encoded.
    /// </summary>
    private string ComputeIntegrity(string data)
    {
        using var hmac = new HMACSHA256(_hmacKey);
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));

        return Convert.ToBase64String(hash);
    }

    #endregion
}