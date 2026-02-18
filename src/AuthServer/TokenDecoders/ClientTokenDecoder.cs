using System.Diagnostics;
using System.Runtime.CompilerServices;
using AuthServer.Authentication.Abstractions;
using AuthServer.Constants;
using AuthServer.Endpoints.Abstractions;
using AuthServer.Helpers;
using AuthServer.Metrics;
using AuthServer.Metrics.Abstractions;
using AuthServer.Options;
using AuthServer.TokenDecoders.Abstractions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace AuthServer.TokenDecoders;
internal class ClientTokenDecoder : IClientTokenDecoder
{
    private readonly ILogger<ClientTokenDecoder> _logger;
    private readonly ITokenReplayCache _tokenReplayCache;
    private readonly IClientJwkService _clientJwkService;
    private readonly IMetricService _metricService;
    private readonly IOptionsSnapshot<JwksDocument> _jwkDocumentOptions;
    private readonly IOptionsSnapshot<TokenValidationOptions> _tokenValidationOptions;
    private readonly IEndpointResolver _endpointResolver;

    public ClientTokenDecoder(
        IOptionsSnapshot<JwksDocument> jwkDocumentOptions,
        IOptionsSnapshot<TokenValidationOptions> tokenValidationOptions,
        IEndpointResolver endpointResolver,
        ILogger<ClientTokenDecoder> logger,
        ITokenReplayCache tokenReplayCache,
        IClientJwkService clientJwkService,
        IMetricService metricService)
    {
        _jwkDocumentOptions = jwkDocumentOptions;
        _tokenValidationOptions = tokenValidationOptions;
        _endpointResolver = endpointResolver;
        _logger = logger;
        _tokenReplayCache = tokenReplayCache;
        _clientJwkService = clientJwkService;
        _metricService = metricService;
    }

    public async Task<JsonWebToken> Read(string token)
    {
        var handler = new JsonWebTokenHandler();
        if (TokenHelper.IsJws(token))
        {
            return handler.ReadJsonWebToken(token);
        }

        if (TokenHelper.IsJwe(token))
        {
            var parameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateLifetime = false,
                ValidateTokenReplay = false,
                TokenDecryptionKeys = _jwkDocumentOptions.Value.EncryptionKeys.Select(x => x.Key),
                SignatureValidator = (x, _) => new JsonWebToken(x)
            };

            var tokenValidationResult = await handler.ValidateTokenAsync(token, parameters);
            return (tokenValidationResult.SecurityToken as JsonWebToken)!;
        }

        throw new ArgumentException("Not a valid JWT", nameof(token));
    }

    public async Task<JsonWebToken?> Validate(string token, ClientTokenDecodeArguments arguments, CancellationToken cancellationToken)
    {
        var stopWatch = Stopwatch.StartNew();
        IEnumerable<JsonWebKey> issuerSigningKeys;
        if (arguments.UseJwkHeaderSignatureValidation)
        {
            var jwk = await GetJwkHeaderValue(token);
            if (jwk is null)
            {
                return null;
            }

            issuerSigningKeys = new List<JsonWebKey>
            {
                jwk
            };
        }
        else
        {
            issuerSigningKeys = await _clientJwkService.GetSigningKeys(arguments.ClientId, cancellationToken);
        }

        var jsonWebToken = await Validate(token, arguments, issuerSigningKeys);
        stopWatch.Stop();

        TokenTypeTag? tokenTypeTag = jsonWebToken is null
            ? null
            : TokenHelper.MapTokenTypHeaderToTokenTypeTag(arguments.TokenType);

        _metricService.AddValidateClientToken(stopWatch.ElapsedMilliseconds, tokenTypeTag);

        return jsonWebToken;
    }

    private async Task<JsonWebToken?> Validate(string token, ClientTokenDecodeArguments arguments,
        IEnumerable<JsonWebKey> issuerSigningKeys)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            ClockSkew = _tokenValidationOptions.Value.ClockSkew,
            ValidTypes = [arguments.TokenType],
            ValidIssuer = arguments.ClientId,
            ValidAudiences = [GetAudience(arguments.Audience)],
            ValidAlgorithms = arguments.Algorithms,
            IssuerSigningKeys = issuerSigningKeys,
            TokenDecryptionKeys = _jwkDocumentOptions.Value.EncryptionKeys.Select(x => x.Key),
            TokenReplayCache = _tokenReplayCache,
            ValidateTokenReplay = true,
            ValidateLifetime = arguments.ValidateLifetime,
            ValidateAudience = true,
            ValidateIssuer = true
        };

        var handler = new JsonWebTokenHandler();
        var validationResult = await handler.ValidateTokenAsync(token, tokenValidationParameters);

        if (!validationResult.IsValid)
        {
            _logger.LogWarning(validationResult.Exception, "Token validation failed");
            return null;
        }

        var jsonWebToken = (validationResult.SecurityToken as JsonWebToken)!;

        var isSubjectValidationRequired = !string.IsNullOrWhiteSpace(arguments.SubjectId);
        var isSubjectValid = arguments.SubjectId == jsonWebToken.Subject;
        if (isSubjectValidationRequired && !isSubjectValid)
        {
            _logger.LogWarning("Subject {ActualSubject} mismatch. Expected {ExpectedSubject}", jsonWebToken.Subject, arguments.SubjectId);
            return null;
        }

        if (!AreLifetimeClaimsValid(jsonWebToken))
        {
            return null;
        }

        return jsonWebToken;
    }

    private bool AreLifetimeClaimsValid(JsonWebToken jsonWebToken)
    {
        if (jsonWebToken.IssuedAt > DateTime.UtcNow)
        {
            _logger.LogWarning("Token iat claim {IssuedAt} is in the future", jsonWebToken.IssuedAt);
            return false;
        }

        var expires = jsonWebToken.ValidTo;
        if (expires > DateTime.UtcNow.Add(_tokenValidationOptions.Value.ClientTokenLifetimeWindow))
        {
            _logger.LogWarning("Token exp claim {Expires} is too far in the future", expires);
            return false;
        }

        var notBefore = jsonWebToken.ValidFrom;
        if (notBefore < DateTime.UtcNow.Subtract(_tokenValidationOptions.Value.ClientTokenLifetimeWindow))
        {
            _logger.LogWarning("Token nbf claim {NotBefore} is too far in the past", notBefore);
            return false;
        }

        return true;
    }

    private async Task<JsonWebKey?> GetJwkHeaderValue(string token)
    {
        try
        {
            var jsonWebToken = await Read(token);
            var jwkHeaderValue = jsonWebToken.GetHeaderValue<string>(ClaimNameConstants.Jwk);
            var jsonWebKey = new JsonWebKey(jwkHeaderValue);
            if (jsonWebKey.HasPrivateKey)
            {
                throw new SecurityTokenValidationException("jwk header contains private key");
            }

            return jsonWebKey;
        }
        catch (ArgumentException e)
        {
            _logger.LogInformation(e, "Token does not contain a valid jwk header");
            return null;
        }
        catch (SecurityTokenValidationException e)
        {
            _logger.LogInformation(e, "Jwk header validation failed");
            return null;
        }
    }

    private string GetAudience(ClientTokenAudience audience)
    {
        return audience switch
        {
            ClientTokenAudience.TokenEndpoint => _endpointResolver.TokenEndpoint,
            ClientTokenAudience.AuthorizationEndpoint => _endpointResolver.AuthorizationEndpoint,
            ClientTokenAudience.IntrospectionEndpoint => _endpointResolver.IntrospectionEndpoint,
            ClientTokenAudience.RevocationEndpoint => _endpointResolver.RevocationEndpoint,
            ClientTokenAudience.PushedAuthorizationEndpoint => _endpointResolver.PushedAuthorizationEndpoint,
            ClientTokenAudience.DeviceAuthorizationEndpoint => _endpointResolver.DeviceAuthorizationEndpoint,
            _ => throw new SwitchExpressionException(audience)
        };
    }
}