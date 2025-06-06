﻿using System.Diagnostics;
using System.Text.Json;
using AuthServer.Authentication.Abstractions;
using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Entities;
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
            .Select(x => new
            {
                AuthTime = x.UpdatedAuthTime,
                ClientId = x.Client.Id,
                x.Client.RequireConsent,
                x.Client.RequireIdTokenClaims,
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

        var userClaims = query.RequireIdTokenClaims
            ? await _userClaimService.GetClaims(query.SubjectIdentifier, cancellationToken)
            : [];

        IReadOnlyCollection<string> authorizedClaims;
        if (!query.RequireIdTokenClaims)
        {
            authorizedClaims = [];
        }
        else if (query.RequireConsent)
        {
            authorizedClaims = await _consentGrantRepository.GetGrantConsentedClaims(arguments.AuthorizationGrantId, cancellationToken);
        }
        else
        {
            authorizedClaims = await _clientRepository.GetAuthorizedClaims(query.ClientId, cancellationToken);
        }

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
            Expires = now.AddHours(1),
            NotBefore = now,
            Issuer = _discoveryDocumentOptions.Value.Issuer,
            SigningCredentials = signingCredentials,
            TokenType = TokenTypeHeaderConstants.IdToken,
            Claims = claims
        };

        if (query.EncryptionAlg is not null &&
            query.EncryptionEnc is not null)
        {
            tokenDescriptor.EncryptingCredentials = await _tokenSecurityService.GetEncryptingCredentials(
                query.ClientId,
                query.EncryptionAlg.Value,
                query.EncryptionEnc.Value,
                cancellationToken);
        }

        var tokenHandler = new JsonWebTokenHandler();
        var jwt = tokenHandler.CreateToken(tokenDescriptor);
        stopWatch.Stop();
        _metricService.AddBuiltToken(stopWatch.ElapsedMilliseconds, TokenTypeTag.IdToken, TokenStructureTag.Jwt);
        return jwt;
    }
}