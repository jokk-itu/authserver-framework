using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Entities;
using AuthServer.Extensions;
using AuthServer.Helpers;
using AuthServer.Metrics;
using AuthServer.Metrics.Abstractions;
using AuthServer.Options;
using AuthServer.TokenDecoders.Abstractions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Diagnostics;

namespace AuthServer.TokenDecoders;

internal class ServerTokenDecoder : IServerTokenDecoder
{
    private readonly ILogger<ServerTokenDecoder> _logger;
    private readonly IOptionsSnapshot<JwksDocument> _jwkDocumentOptions;
    private readonly IOptionsSnapshot<TokenValidationOptions> _tokenValidationOptions;
    private readonly IOptionsSnapshot<DiscoveryDocument> _discoveryDocumentOptions;
    private readonly IMetricService _metricService;
    private readonly AuthorizationDbContext _authorizationDbContext;

    public ServerTokenDecoder(
        ILogger<ServerTokenDecoder> logger,
        IOptionsSnapshot<JwksDocument> jwkDocumentOptions,
        IOptionsSnapshot<TokenValidationOptions> tokenValidationOptions,
        IOptionsSnapshot<DiscoveryDocument> discoveryDocumentOptions,
        IMetricService metricService,
        AuthorizationDbContext authorizationDbContext)
    {
        _logger = logger;
        _jwkDocumentOptions = jwkDocumentOptions;
        _tokenValidationOptions = tokenValidationOptions;
        _discoveryDocumentOptions = discoveryDocumentOptions;
        _metricService = metricService;
        _authorizationDbContext = authorizationDbContext;
    }

    /// <inheritdoc/>
    public async Task<TokenResult> Read(string token, CancellationToken cancellationToken)
    {
        var handler = new JsonWebTokenHandler();
        if (TokenHelper.IsJws(token))
        {
            var jsonWebToken = handler.ReadJsonWebToken(token);
            return MapFromJsonWebToken(jsonWebToken);
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
            var jsonWebToken = (tokenValidationResult.SecurityToken as JsonWebToken)!;
            return MapFromJsonWebToken(jsonWebToken);
        }

        var tokenQuery = (await GetTokenQuery(token, cancellationToken))!;
        return MapFromTokenQuery(tokenQuery);
    }

    /// <inheritdoc/>
    public async Task<TokenResult?> Validate(string token, ServerTokenDecodeArguments arguments, CancellationToken cancellationToken)
    {
        var stopWatch = Stopwatch.StartNew();
        if (TokenHelper.IsJsonWebToken(token))
        {
            var jwtResult = await ValidateJsonWebToken(token, arguments, stopWatch);
            if (jwtResult?.Typ != TokenTypeHeaderConstants.RefreshToken)
            {
                return jwtResult;
            }

            // If the token is a refresh token, we also try to validate its reference
            token = jwtResult.Jti;
        }

        return await ValidateReferenceToken(token, arguments, stopWatch, cancellationToken);
    }

    private async Task<TokenResult?> ValidateJsonWebToken(string token, ServerTokenDecodeArguments arguments,
        Stopwatch stopWatch)
    {
        var jsonWebTokenTokenResult = await ValidateJsonWebToken(token, arguments);
        stopWatch.Stop();

        TokenTypeTag? tokenTypeTag = jsonWebTokenTokenResult is null
            ? null
            : TokenHelper.MapTokenTypHeaderToTokenTypeTag(jsonWebTokenTokenResult.Typ);

        _metricService.AddValidateServerToken(
            stopWatch.ElapsedMilliseconds,
            tokenTypeTag,
            TokenStructureTag.Jwt);

        return jsonWebTokenTokenResult;
    }

    private async Task<TokenResult?> ValidateReferenceToken(string token, ServerTokenDecodeArguments arguments,
        Stopwatch stopWatch, CancellationToken cancellationToken)
    {
        var referenceTokenResult = await ValidateReferenceToken(token, arguments, cancellationToken);
        stopWatch.Stop();

        TokenTypeTag? tokenTypeTag = referenceTokenResult is null
            ? null
            : TokenHelper.MapTokenTypHeaderToTokenTypeTag(referenceTokenResult.Typ);

        _metricService.AddValidateServerToken(
            stopWatch.ElapsedMilliseconds,
            tokenTypeTag,
            TokenStructureTag.Reference);

        return referenceTokenResult;
    }

    private async Task<TokenResult?> ValidateJsonWebToken(string token, ServerTokenDecodeArguments arguments)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            ClockSkew = _tokenValidationOptions.Value.ClockSkew,
            ValidTypes = arguments.TokenTypes,
            ValidIssuer = _discoveryDocumentOptions.Value.Issuer,
            ValidAudiences = arguments.Audiences,
            IssuerSigningKeys = _jwkDocumentOptions.Value.SigningKeys.Select(x => x.Key),
            TokenDecryptionKeys = _jwkDocumentOptions.Value.EncryptionKeys.Select(x => x.Key),
            ValidateLifetime = arguments.ValidateLifetime,
            ValidateAudience = arguments.Audiences.Count != 0,
            ValidateIssuer = true,
            NameClaimType = ClaimNameConstants.Name,
            RoleClaimType = ClaimNameConstants.Roles
        };

        var handler = new JsonWebTokenHandler();
        var validationResult = await handler.ValidateTokenAsync(token, tokenValidationParameters);

        if (!validationResult.IsValid)
        {
            _logger.LogInformation(validationResult.Exception, "Token validation failed");
            return null;
        }

        var jsonWebToken = (validationResult.SecurityToken as JsonWebToken)!;
        return MapFromJsonWebToken(jsonWebToken);
    }

    private async Task<TokenResult?> ValidateReferenceToken(string token, ServerTokenDecodeArguments arguments, CancellationToken cancellationToken)
    {
        var tokenQuery = await GetTokenQuery(token, cancellationToken);
        if (tokenQuery is null)
        {
            _logger.LogInformation("Token {ReferenceToken} is not a valid reference token", token);
            return null;
        }

        if (arguments.ValidateLifetime && !tokenQuery.Token.IsActive(_tokenValidationOptions.Value.ClockSkew))
        {
            _logger.LogInformation("Token {ReferenceToken} is inactive", token);
            return null;
        }

        if (arguments.Audiences.Count != 0 && tokenQuery.Token.Audience.Split(' ').IsDisjoint(arguments.Audiences))
        {
            _logger.LogInformation("Token {ReferenceToken} is unauthorized for audience {@Audiences}", token, arguments.Audiences);
            return null;
        }

        if (!arguments.TokenTypes.Contains(TokenHelper.MapToTokenTypHeader(tokenQuery.Token.TokenType)))
        {
            _logger.LogInformation("Token {ReferenceToken} is unauthorized for type {@TokenTypes}", token, arguments.TokenTypes);
            return null;
        }

        return MapFromTokenQuery(tokenQuery);
    }

    private async Task<TokenQuery?> GetTokenQuery(string token, CancellationToken cancellationToken)
    {
        return await _authorizationDbContext
            .Set<Token>()
            .Where(x => x.Reference == token)
            .Select(x => new TokenQuery
            {
                Token = x,
                ClientIdFromClientToken = (x as ClientToken)!.Client.Id,
                ClientIdFromGrantToken = (x as GrantToken)!.AuthorizationGrant.Client.Id,
                GrantId = (x as GrantToken)!.AuthorizationGrant.Id,
                SessionId = (x as GrantToken)!.AuthorizationGrant.Session.Id,
                Subject = (x as GrantToken)!.AuthorizationGrant.Subject,
                SubjectActor = x.SubjectActor,
                SubjectMayAct = x.SubjectMayAct
            })
            .SingleOrDefaultAsync(cancellationToken);
    }

    private static TokenResult MapFromTokenQuery(TokenQuery tokenQuery)
    {
        return new TokenResult
        {
            ClientId = tokenQuery.ClientIdFromClientToken ?? tokenQuery.ClientIdFromGrantToken!,
            Sub = tokenQuery.Subject ?? tokenQuery.ClientIdFromClientToken!,
            Jti = tokenQuery.Token.Id.ToString(),
            Typ = TokenHelper.MapToTokenTypHeader(tokenQuery.Token.TokenType),
            Scope = tokenQuery.Token.Scope!.Split(' '),
            GrantId = tokenQuery.GrantId,
            Jkt = tokenQuery.Token.Jkt,
            Sid = tokenQuery.SessionId,
            Act = tokenQuery.SubjectActor is not null
                ? new ActDto
                {
                    Sub = tokenQuery.SubjectActor
                }
                : null,
            MayAct = tokenQuery.SubjectMayAct is not null
                ? new ActDto
                {
                    Sub = tokenQuery.SubjectMayAct
                }
                : null
        };
    }

    private static TokenResult MapFromJsonWebToken(JsonWebToken jsonWebToken)
    {
        jsonWebToken.TryGetPayloadValue<string>(ClaimNameConstants.Sid, out var sid);
        jsonWebToken.TryGetPayloadValue<string>(ClaimNameConstants.GrantId, out var grantId);
        jsonWebToken.TryGetPayloadValue<string>(ClaimNameConstants.Scope, out var scope);

        jsonWebToken.TryGetPayloadValue<Dictionary<string, object>>(ClaimNameConstants.Act, out var act);
        object? subjectActor = null;
        act?.TryGetValue(ClaimNameConstants.Sub, out subjectActor);

        jsonWebToken.TryGetPayloadValue<Dictionary<string, object>>(ClaimNameConstants.MayAct, out var mayAct);
        object? subjectMayAct = null;
        mayAct?.TryGetValue(ClaimNameConstants.Sub, out subjectMayAct);

        jsonWebToken.TryGetPayloadValue<Dictionary<string, object>>(ClaimNameConstants.Cnf, out var cnf);
        object? jkt = null;
        cnf?.TryGetValue(ClaimNameConstants.Jkt, out jkt);

        return new TokenResult
        {
            ClientId = jsonWebToken.GetPayloadValue<string>(ClaimNameConstants.ClientId),
            Jti = jsonWebToken.GetPayloadValue<string>(ClaimNameConstants.Jti),
            Sub = jsonWebToken.GetPayloadValue<string>(ClaimNameConstants.Sub),
            Typ = jsonWebToken.GetHeaderValue<string>(JwtHeaderParameterNames.Typ),
            Scope = scope?.Split(' ') ?? [],
            GrantId = grantId,
            Jkt = jkt?.ToString(),
            Sid = sid,
            Act = subjectActor is not null
                ? new ActDto
                {
                    Sub = subjectActor.ToString()!
                }
                : null,
            MayAct = subjectMayAct is not null
                ? new ActDto
                {
                    Sub = subjectMayAct.ToString()!
                }
                : null
        };
    }

    private class TokenQuery
    {
        public string? ClientIdFromClientToken { get; init; }
        public string? ClientIdFromGrantToken { get; init; }
        public string? Subject { get; init; }
        public string? SessionId { get; init; }
        public string? GrantId { get; init; }
        public required Token Token { get; init; }
        public string? SubjectActor { get; init; }
        public string? SubjectMayAct { get; init; }
    };
}