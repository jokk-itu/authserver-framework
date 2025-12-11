using AuthServer.Authentication.Abstractions;
using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Extensions;
using AuthServer.Metrics;
using AuthServer.Metrics.Abstractions;
using AuthServer.Options;
using AuthServer.Repositories.Abstractions;
using AuthServer.TokenBuilders.Abstractions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Diagnostics;
using System.Text.Json;

namespace AuthServer.TokenBuilders;

internal class IdTokenBuilder : ITokenBuilder<IdTokenArguments>
{
    private readonly AuthorizationDbContext _identityContext;
    private readonly IOptionsSnapshot<DiscoveryDocument> _discoveryDocumentOptions;
    private readonly IOptionsSnapshot<JwksDocument> _jwksDocumentOptions;
    private readonly ITokenSecurityService _tokenSecurityService;
    private readonly IUserClaimService _userClaimService;
    private readonly IMetricService _metricService;
    private readonly IConsentRepository _consentGrantRepository;
    private readonly IClientRepository _clientRepository;

    public IdTokenBuilder(
        AuthorizationDbContext identityContext,
        IOptionsSnapshot<DiscoveryDocument> discoveryDocumentOptions,
        IOptionsSnapshot<JwksDocument> jwksDocumentOptions,
        ITokenSecurityService tokenSecurityService,
        IUserClaimService userClaimService,
        IMetricService metricService,
        IConsentRepository consentGrantRepository,
        IClientRepository clientRepository)
    {
        _identityContext = identityContext;
        _discoveryDocumentOptions = discoveryDocumentOptions;
        _jwksDocumentOptions = jwksDocumentOptions;
        _tokenSecurityService = tokenSecurityService;
        _userClaimService = userClaimService;
        _metricService = metricService;
        _consentGrantRepository = consentGrantRepository;
        _clientRepository = clientRepository;
    }

    public async Task<string> BuildToken(IdTokenArguments arguments, CancellationToken cancellationToken)
    {
        var stopWatch = Stopwatch.StartNew();
        var query = await _identityContext
            .Set<AuthorizationGrant>()
            .Where(x => x.Id == arguments.AuthorizationGrantId)
            .Select(x => new IdTokenBuildEntity
            {
                AuthTime = x.UpdatedAuthTime,
                ClientId = x.Client.Id,
                RequireConsent = x.Client.RequireConsent,
                RequireIdTokenClaims = x.Client.RequireIdTokenClaims,
                IdTokenExpiration = x.Client.IdTokenExpiration!.Value,
                SessionId = x.Session.Id,
                SubjectIdentifier = x.Session.SubjectIdentifier.Id,
                GrantSubject = x.Subject,
                SigningAlg = x.Client.IdTokenSignedResponseAlg,
                EncryptionAlg = x.Client.IdTokenEncryptedResponseAlg,
                EncryptionEnc = x.Client.IdTokenEncryptedResponseEnc,
                Nonce = x.Nonces.OrderByDescending(y => y.IssuedAt).First(),
                AuthenticationMethodReferences = x.AuthenticationMethodReferences.Select(amr => amr.Name).ToList(),
                AuthenticationContextReference = x.AuthenticationContextReference.Name
            })
            .SingleAsync(cancellationToken);

        var claims = new Dictionary<string, object>
        {
            { ClaimNameConstants.Sub, query.GrantSubject },
            { ClaimNameConstants.Aud, query.ClientId },
            { ClaimNameConstants.Sid, query.SessionId },
            { ClaimNameConstants.Jti, Guid.NewGuid() },
            { ClaimNameConstants.GrantId, arguments.AuthorizationGrantId },
            { ClaimNameConstants.Nonce, query.Nonce.Value },
            { ClaimNameConstants.ClientId, query.ClientId },
            { ClaimNameConstants.Azp, query.ClientId },
            { ClaimNameConstants.AuthTime, query.AuthTime.ToUnixTimeSeconds() },
            { ClaimNameConstants.Amr, JsonSerializer.SerializeToElement(query.AuthenticationMethodReferences) },
            { ClaimNameConstants.Acr, query.AuthenticationContextReference }
        };

        if (!string.IsNullOrEmpty(arguments.SubjectActor))
        {
            claims.Add(ClaimNameConstants.Act, new Dictionary<string, object>
            {
                { ClaimNameConstants.Sub, arguments.SubjectActor }
            });
        }

        var userClaims = query.RequireIdTokenClaims
            ? await _userClaimService.GetClaims(query.SubjectIdentifier, cancellationToken)
            : [];

        var authorizedClaims = await GetAuthorizedClaims(arguments, query, cancellationToken);
        foreach (var userClaim in userClaims.Where(x => authorizedClaims.Contains(x.Type)))
        {
            claims.Add(userClaim.Type, userClaim.Value);
        }

        var now = DateTime.UtcNow;
        var signingKey = _jwksDocumentOptions.Value.GetSigningKey(query.SigningAlg!.Value);
        var signingCredentials = new SigningCredentials(signingKey, query.SigningAlg.GetDescription());

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            IssuedAt = now,
            Expires = now.AddSeconds(query.IdTokenExpiration),
            NotBefore = now,
            Issuer = _discoveryDocumentOptions.Value.Issuer,
            SigningCredentials = signingCredentials,
            EncryptingCredentials = await GetEncryptingCredentials(arguments, query, cancellationToken),
            TokenType = TokenTypeHeaderConstants.IdToken,
            Claims = claims
        };

        var tokenHandler = new JsonWebTokenHandler();
        var jwt = tokenHandler.CreateToken(tokenDescriptor);
        stopWatch.Stop();
        _metricService.AddBuiltToken(stopWatch.ElapsedMilliseconds, TokenTypeTag.IdToken, TokenStructureTag.Jwt);
        return jwt;
    }

    private async Task<EncryptingCredentials?> GetEncryptingCredentials(IdTokenArguments idTokenArguments, IdTokenBuildEntity idTokenBuildEntity, CancellationToken cancellationToken)
    {
        var clientId = idTokenBuildEntity.ClientId;
        var encryptionAlg = idTokenBuildEntity.EncryptionAlg;
        var encryptionEnc = idTokenBuildEntity.EncryptionEnc;

        if (idTokenArguments.EncyptorClientId is not null)
        {
            var encryptorClient = (await _identityContext
                .Set<Client>()
                .FindAsync([idTokenArguments.EncyptorClientId], cancellationToken))!;

            encryptionAlg = encryptorClient.IdTokenEncryptedResponseAlg;
            encryptionEnc = encryptorClient.IdTokenEncryptedResponseEnc;
            clientId = encryptorClient.Id;
        }

        if (encryptionAlg is not null && encryptionEnc is not null)
        {
            return await _tokenSecurityService.GetEncryptingCredentials(
                clientId,
                encryptionAlg.Value,
                encryptionEnc.Value,
                cancellationToken);
        }

        return null;
    }

    private async Task<IReadOnlyCollection<string>> GetAuthorizedClaims(IdTokenArguments idTokenArguments, IdTokenBuildEntity idTokenBuildEntity, CancellationToken cancellationToken)
    {
        if (!idTokenBuildEntity.RequireIdTokenClaims)
        {
            return [];
        }

        if (idTokenBuildEntity.RequireConsent)
        {
            return await _consentGrantRepository.GetGrantConsentedClaims(idTokenArguments.AuthorizationGrantId, cancellationToken);
        }

        return await _clientRepository.GetAuthorizedClaims(idTokenBuildEntity.ClientId, cancellationToken);
    }

    private sealed class IdTokenBuildEntity
    {
        public required DateTime AuthTime { get; init; }
        public required string ClientId { get; init; }
        public required bool RequireConsent { get; init; }
        public required bool RequireIdTokenClaims { get; init; }
        public required int IdTokenExpiration { get; init; }
        public required string SessionId { get; init; }
        public required string SubjectIdentifier { get; init; }
        public required string GrantSubject { get; init; }
        public SigningAlg? SigningAlg { get; init; }
        public EncryptionAlg? EncryptionAlg { get; init; }
        public EncryptionEnc? EncryptionEnc { get; init; }
        public required AuthorizationGrantNonce Nonce { get; init; }
        public required IEnumerable<string> AuthenticationMethodReferences { get; init; }
        public required string AuthenticationContextReference { get; init; }
    }
}