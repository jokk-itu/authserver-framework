using Microsoft.Extensions.Options;

namespace AuthServer.Options;
internal class ValidateJwksDocument : IValidateOptions<JwksDocument>
{
    public ValidateOptionsResult Validate(string? name, JwksDocument options)
    {
        var hasSigningKeys = options.SigningKeys.Count > 0;
        if (!hasSigningKeys)
        {
            ValidateOptionsResult.Fail("Missing signing keys");
        }

        var hasSigningKeyInvalidKeyId = options.SigningKeys.Any(x => string.IsNullOrEmpty(x.Key.KeyId));
        if (hasSigningKeyInvalidKeyId)
        {
            ValidateOptionsResult.Fail("SigningKey has empty KeyId");
        }

        var hasEncryptionKeys = options.EncryptionKeys.Count > 0;
        if (!hasEncryptionKeys)
        {
            ValidateOptionsResult.Fail("Missing encryption keys");
        }

        var hasEncryptionKeyInvalidKeyId = options.EncryptionKeys.Any(x => string.IsNullOrEmpty(x.Key.KeyId));
        if (hasEncryptionKeyInvalidKeyId)
        {
            ValidateOptionsResult.Fail("EncryptionKey has empty KeyId");
        }

        return ValidateOptionsResult.Success;
    }
}
