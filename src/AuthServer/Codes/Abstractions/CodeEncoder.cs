using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace AuthServer.Codes.Abstractions;

internal class CodeEncoder<T> : ICodeEncoder<T> where T : class
{
    private readonly IDataProtector _dataProtector;
    private readonly ILogger _logger;

    public CodeEncoder(
        IDataProtectionProvider dataProtectionProvider,
        ILogger logger)
    {
        _dataProtector = dataProtectionProvider.CreateProtector(typeof(T).Name);
        _logger = logger;
    }
    
    /// <inheritdoc/>
    public string Encode(T code)
    {
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms, Encoding.UTF8, false);
        writer.Write(JsonSerializer.Serialize(code));
        var protectedBytes = _dataProtector.Protect(ms.ToArray());
        return Base64UrlEncoder.Encode(protectedBytes);
    }

    /// <inheritdoc/>
    public T? Decode(string? code)
    {
        if (string.IsNullOrEmpty(code))
        {
            return null;
        }

        try
        {
            var decoded = Base64UrlEncoder.DecodeBytes(code);
            var unProtectedBytes = _dataProtector.Unprotect(decoded);
            using var ms = new MemoryStream(unProtectedBytes);
            using var reader = new BinaryReader(ms, Encoding.UTF8, false);
            var deserializedCode = JsonSerializer.Deserialize<T>(reader.ReadString());
            return deserializedCode;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Decoding failed");
            return null;
        }
    }
}