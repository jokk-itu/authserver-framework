using AuthServer.Codes;
using AuthServer.Codes.Abstractions;
using AuthServer.Constants;
using AuthServer.Core.Abstractions;
using AuthServer.Entities;
using AuthServer.Helpers;
using AuthServer.Repositories.Abstractions;

namespace AuthServer.Authorize;

internal class AuthorizeRequestProcessor : IRequestProcessor<AuthorizeValidatedRequest, AuthorizeResponse>
{
    private readonly ICodeEncoder<EncodedAuthorizationCode> _authorizationCodeEncoder;
    private readonly IAuthorizationGrantRepository _authorizationGrantRepository;
    private readonly IClientRepository _clientRepository;
    private readonly IConsentRepository _consentGrantRepository;

    public AuthorizeRequestProcessor(
        ICodeEncoder<EncodedAuthorizationCode> authorizationCodeEncoder,
        IAuthorizationGrantRepository authorizationGrantRepository,
        IClientRepository clientRepository,
        IConsentRepository consentGrantRepository)
    {
        _authorizationCodeEncoder = authorizationCodeEncoder;
        _authorizationGrantRepository = authorizationGrantRepository;
        _clientRepository = clientRepository;
        _consentGrantRepository = consentGrantRepository;
    }

    public async Task<AuthorizeResponse> Process(AuthorizeValidatedRequest request, CancellationToken cancellationToken)
    {
        if (request.RequestUri is not null)
        {
            var isPushedRequest = request.RequestUri.StartsWith(RequestUriConstants.RequestUriPrefix);
            if (isPushedRequest)
            {
                var reference = request.RequestUri[RequestUriConstants.RequestUriPrefix.Length..];
                await _clientRepository.RedeemAuthorizeMessage(reference, cancellationToken);
            }
        }

        var authorizationCodeGrant =
            (await _authorizationGrantRepository.GetActiveAuthorizationCodeGrant(request.AuthorizationGrantId,
                cancellationToken))!;

        if (string.IsNullOrEmpty(request.GrantManagementAction) ||
            request.GrantManagementAction == GrantManagementActionConstants.Create)
        {
            await _consentGrantRepository.CreateGrantConsent(request.AuthorizationGrantId, request.Scope,
                request.Resource, cancellationToken);
        }
        else if (request.GrantManagementAction == GrantManagementActionConstants.Merge)
        {
            await _consentGrantRepository.MergeGrantConsent(request.AuthorizationGrantId, request.Scope,
                request.Resource, cancellationToken);
        }
        else if (request.GrantManagementAction == GrantManagementActionConstants.Replace)
        {
            await _consentGrantRepository.ReplaceGrantConsent(request.AuthorizationGrantId, request.Scope,
                request.Resource, cancellationToken);
        }


        if (request.ResponseType == ResponseTypeConstants.Code)
        {
            return new AuthorizeResponse
            {
                AuthorizationCode = GetAuthorizationCode(request, authorizationCodeGrant)
            };
        }

        return new AuthorizeResponse();
    }

    private string GetAuthorizationCode(AuthorizeValidatedRequest request,
        AuthorizationCodeGrant authorizationCodeGrant)
    {
        var authorizationCode = new AuthorizationCode(authorizationCodeGrant,
            authorizationCodeGrant.Client.AuthorizationCodeExpiration!.Value);
        var nonce = new AuthorizationGrantNonce(request.Nonce!, request.Nonce!.Sha256(), authorizationCodeGrant);

        authorizationCodeGrant.AuthorizationCodes.Add(authorizationCode);
        authorizationCodeGrant.Nonces.Add(nonce);

        var encodedAuthorizationCode = _authorizationCodeEncoder.Encode(
            new EncodedAuthorizationCode
            {
                AuthorizationGrantId = authorizationCodeGrant.Id,
                AuthorizationCodeId = authorizationCode.Id,
                Scope = request.Scope,
                Resource = request.Resource,
                RedirectUri = request.RedirectUri,
                DPoPJkt = request.DPoPJkt,
                CodeChallenge = request.CodeChallenge!,
                CodeChallengeMethod = request.CodeChallengeMethod!
            });

        authorizationCode.SetRawValue(encodedAuthorizationCode);

        return encodedAuthorizationCode;
    }
}