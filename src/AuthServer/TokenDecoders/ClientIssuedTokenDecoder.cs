using AuthServer.Authentication.Abstractions;
using AuthServer.Endpoints.Abstractions;
using AuthServer.Helpers;
using AuthServer.Options;
using AuthServer.TokenDecoders.Abstractions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace AuthServer.TokenDecoders;
internal class ClientIssuedTokenDecoder : ITokenDecoder<ClientIssuedTokenDecodeArguments>
{
    private readonly ILogger<ClientIssuedTokenDecoder> _logger;
    private readonly ITokenReplayCache _tokenReplayCache;
    private readonly IClientJwkService _clientJwkService;
    private readonly IOptionsSnapshot<JwksDocument> _jwkDocumentOptions;
    private readonly IEndpointResolver _endpointResolver;

    public ClientIssuedTokenDecoder(
        IOptionsSnapshot<JwksDocument> jwkDocumentOptions,
        IEndpointResolver endpointResolver,
        ILogger<ClientIssuedTokenDecoder> logger,
        ITokenReplayCache tokenReplayCache,
        IClientJwkService clientJwkService)
    {
        _jwkDocumentOptions = jwkDocumentOptions;
        _endpointResolver = endpointResolver;
        _logger = logger;
        _tokenReplayCache = tokenReplayCache;
        _clientJwkService = clientJwkService;
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

    public async Task<JsonWebToken?> Validate(string token, ClientIssuedTokenDecodeArguments arguments, CancellationToken cancellationToken)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            ClockSkew = new TimeSpan(0),
            ValidTypes = [arguments.TokenType],
            ValidIssuer = arguments.ClientId,
            ValidAudiences = [ GetAudience(arguments.Audience) ],
            ValidAlgorithms = arguments.Algorithms,
            IssuerSigningKeys = await _clientJwkService.GetSigningKeys(arguments.ClientId, cancellationToken),
            TokenDecryptionKeys = _jwkDocumentOptions.Value.EncryptionKeys.Select(x => x.Key),
            TokenReplayCache = _tokenReplayCache,
            ValidateTokenReplay = true,
            ValidateLifetime = arguments.ValidateLifetime,
            ValidateAudience = true,
            ValidateIssuer = true,
        };

        var handler = new JsonWebTokenHandler();
        var validationResult = await handler.ValidateTokenAsync(token, tokenValidationParameters);

        if (!validationResult.IsValid)
        {
            _logger.LogInformation(validationResult.Exception, "Token validation failed");
            return null;
        }

        var jsonWebToken = (validationResult.SecurityToken as JsonWebToken)!;

        var isSubjectValidationRequired = !string.IsNullOrWhiteSpace(arguments.SubjectId);
        var isSubjectValid = arguments.SubjectId == jsonWebToken.Subject;
        if (isSubjectValidationRequired && !isSubjectValid)
        {
            _logger.LogInformation("Subject {ActualSubject} mismatch. Expected {ExpectedSubject}", jsonWebToken.Subject, arguments.SubjectId);
            return null;
        }

        return jsonWebToken;
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
            _ => throw new ArgumentOutOfRangeException(nameof(audience), audience, "does not map to a valid enum")
        };
    }
}