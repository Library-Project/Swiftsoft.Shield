namespace Swiftsoft.Shield.Models;

/// <summary>
/// Application-wide security configuration,
/// used when encryption is called without dependency injection.
/// </summary>
/// <remarks>
/// This class is populated once at startup by
/// <c>services.AddSwiftSoftSecurity(configuration)</c>.
/// <para>
/// It is intentionally non-generic: a single configuration is shared
/// by all instances of <c>SecurityService&lt;TResult&gt;</c>, regardless of <c>TResult</c>.
/// </para>
/// </remarks>
public static class SecuritySettingsConfig
{
    private static PayloadSecuritySettings? _setting;

    /// <summary>
    /// Encryption and integrity keys used by static calls.
    /// </summary>
    /// <remarks>
    /// Set at startup by <c>AddSwiftSoftSecurity</c>.
    /// Any later change only applies to <c>SecurityService&lt;TResult&gt;</c>
    /// instances created after the change: existing instances keep the keys
    /// they read when they were created.
    /// </remarks>
    /// <exception cref="InvalidOperationException">
    /// The property is read before security has been configured at startup.
    /// </exception>
    public static PayloadSecuritySettings Settings
    {
        get => _setting ?? throw new InvalidOperationException(
            "Payload security settings are not configured.");
        internal set => _setting = value;
    }
}