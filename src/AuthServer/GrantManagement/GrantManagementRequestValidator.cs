using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.Entities;
using AuthServer.Helpers;
using AuthServer.TokenDecoders;
using AuthServer.TokenDecoders.Abstractions;
using Microsoft.EntityFrameworkCore;

namespace AuthServer.GrantManagement;

internal class GrantManagementRequestValidator : IRequestValidator<GrantManagementRequest, GrantManagementValidatedRequest>
{
    private readonly AuthorizationDbContext _authorizationDbContext;
    private readonly ITokenDecoder<ServerIssuedTokenDecodeArguments> _tokenDecoder;

    public GrantManagementRequestValidator(
        AuthorizationDbContext authorizationDbContext,
        ITokenDecoder<ServerIssuedTokenDecodeArguments> tokenDecoder)
    {
        _authorizationDbContext = authorizationDbContext;
        _tokenDecoder = tokenDecoder;
    }
    
    public async Task<ProcessResult<GrantManagementValidatedRequest, ProcessError>> Validate(GrantManagementRequest request, CancellationToken cancellationToken)
    {
        if (request.GrantId is null)
        {
            return GrantManagementError.InvalidGrantId;
        }

        var clientIdFromGrant = await _authorizationDbContext
            .Set<AuthorizationGrant>()
            .Where(x => x.Id == request.GrantId)
            .Select(x => x.Client.Id)
            .SingleOrDefaultAsync(cancellationToken);

        if (clientIdFromGrant is null)
        {
            return GrantManagementError.NotFoundGrantId;
        }

        string clientIdFromToken;
        if (TokenHelper.IsJsonWebToken(request.AccessToken))
        {
            // only read because the token has already been validated
            var token = await _tokenDecoder.Read(request.AccessToken);
            clientIdFromToken = token.GetClaim(ClaimNameConstants.ClientId).Value;
        }
        else
        {
            clientIdFromToken = await _authorizationDbContext
                .Set<GrantAccessToken>()
                .Where(x => x.Reference == request.AccessToken)
                .Select(x => x.AuthorizationGrant.Client.Id)
                .SingleAsync(cancellationToken);
        }

        if (clientIdFromGrant != clientIdFromToken)
        {
            return GrantManagementError.InvalidGrant;
        }
        
        return new GrantManagementValidatedRequest
        { 
            GrantId = request.GrantId!
        };
    }
}