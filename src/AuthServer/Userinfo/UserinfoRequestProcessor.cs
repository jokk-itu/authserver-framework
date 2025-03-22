using AuthServer.Core;
using AuthServer.Entities;
using AuthServer.TokenBuilders;
using AuthServer.TokenBuilders.Abstractions;
using Microsoft.EntityFrameworkCore;
using System.Text.Json;
using AuthServer.Repositories.Abstractions;
using AuthServer.Authentication.Abstractions;
using AuthServer.Core.Abstractions;

namespace AuthServer.Userinfo;
internal class UserinfoRequestProcessor : IRequestProcessor<UserinfoValidatedRequest, string>
{
    private readonly AuthorizationDbContext _identityContext;
    private readonly ITokenBuilder<UserinfoTokenArguments> _userinfoTokenBuilder;
    private readonly IUserClaimService _userClaimService;
    private readonly IConsentRepository _consentGrantRepository;
    private readonly IClientRepository _clientRepository;

    public UserinfoRequestProcessor(
        AuthorizationDbContext identityContext,
        ITokenBuilder<UserinfoTokenArguments> userinfoTokenBuilder,
        IUserClaimService userClaimService,
        IConsentRepository consentGrantRepository,
        IClientRepository clientRepository)
    {
        _identityContext = identityContext;
        _userinfoTokenBuilder = userinfoTokenBuilder;
        _userClaimService = userClaimService;
        _consentGrantRepository = consentGrantRepository;
        _clientRepository = clientRepository;
    }

    public async Task<string> Process(UserinfoValidatedRequest request, CancellationToken cancellationToken)
    {
        var query = await _identityContext
            .Set<AuthorizationGrant>()
            .Where(x => x.Id == request.AuthorizationGrantId)
            .Include(x => x.Nonces)
            .Select(x => new
            {
                ClientId = x.Client.Id,
                RequiresConsent = x.Client.RequireConsent,
                SubjectIdentifier = x.Session.SubjectIdentifier.Id,
                GrantSubjectId = x.Subject,
                SigningAlg = x.Client.UserinfoSignedResponseAlg,
                EncryptionAlg = x.Client.UserinfoEncryptedResponseAlg,
                EncryptionEnc = x.Client.UserinfoEncryptedResponseEnc
            })
            .SingleAsync(cancellationToken);

        var claims = new Dictionary<string, object>
        {
            { Parameter.Subject, query.GrantSubjectId }
        };

        var userClaims = await _userClaimService.GetClaims(query.SubjectIdentifier, cancellationToken);
        IReadOnlyCollection<string> authorizedClaims;
        if (query.RequiresConsent)
        {
            authorizedClaims = await _consentGrantRepository.GetGrantConsentedClaims(request.AuthorizationGrantId, cancellationToken);
        }
        else
        {
            authorizedClaims = await _clientRepository.GetAuthorizedClaims(query.ClientId, cancellationToken);
        }

        foreach (var userClaim in userClaims.Where(x => authorizedClaims.Contains(x.Type)))
        {
            claims.Add(userClaim.Type, userClaim.Value);
        }

        var clientExpectsJwt = query.SigningAlg != null;
        
        if (clientExpectsJwt)
        {
            return await _userinfoTokenBuilder.BuildToken(new UserinfoTokenArguments
            {
                ClientId = query.ClientId,
                SigningAlg = query.SigningAlg!.Value,
                EncryptionAlg = query.EncryptionAlg,
                EncryptionEnc = query.EncryptionEnc,
                EndUserClaims = claims
            }, cancellationToken);
        }

        return JsonSerializer.Serialize(claims);
    }
}