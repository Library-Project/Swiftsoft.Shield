using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Swiftsoft.Shield.Models;
using Swiftsoft.Shield.Services.SecurePayload;
using Swiftsoft.Shield.Services.SecurePayload.Helpers;

namespace Swiftsoft.Shield.Extensions;

public static class DependencyInjection
{
    public static IServiceCollection AddSwiftSoftSecurity(
        this IServiceCollection services,
        IConfiguration configuration,
        string sectionName = "PayloadSecurity")
    {
        var section = configuration.GetSection(sectionName);

        SecuritySettingsConfig.Settings = section.Get<PayloadSecuritySettings>()
                                  ?? throw new InvalidOperationException($"Section '{sectionName}' not found.");

        services.Configure<PayloadSecuritySettings>(section)
            .AddOptions<PayloadSecuritySettings>()
            .Bind(section)
            .Validate(s => SecurityHelper.Base64ToByte(s.AesKey)?.Length == 32, "AesKey must be 32 bytes in Base64.")
            .Validate(s => SecurityHelper.Base64ToByte(s.HmacKey)?.Length >= 32, "macKey must be at least 32 bytes in Base64.")
            .Validate(s => s.AesKey != s.HmacKey, "AesKey and HmacKey must be different.")
            .ValidateOnStart();

        services.AddSingleton(typeof(ISecurityService<>), typeof(SecurityService<>));

        return services;
    }
}