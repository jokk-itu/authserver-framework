﻿using AuthServer.Codes;
using AuthServer.Codes.Abstractions;
using AuthServer.Constants;
using AuthServer.Core.Abstractions;
using AuthServer.Entities;
using AuthServer.Helpers;
using AuthServer.Repositories.Abstractions;

namespace AuthServer.Authorize;

internal class AuthorizeRequestProcessor : IRequestProcessor<AuthorizeValidatedRequest, string>
{
    private readonly IAuthorizationCodeEncoder _authorizationCodeEncoder;
    private readonly IAuthorizationGrantRepository _authorizationGrantRepository;
    private readonly IClientRepository _clientRepository;
    private readonly IConsentRepository _consentGrantRepository;

    public AuthorizeRequestProcessor(
        IAuthorizationCodeEncoder authorizationCodeEncoder,
        IAuthorizationGrantRepository authorizationGrantRepository,
        IClientRepository clientRepository,
        IConsentRepository consentGrantRepository)
    {
        _authorizationCodeEncoder = authorizationCodeEncoder;
        _authorizationGrantRepository = authorizationGrantRepository;
        _clientRepository = clientRepository;
        _consentGrantRepository = consentGrantRepository;
    }

    public async Task<string> Process(AuthorizeValidatedRequest request, CancellationToken cancellationToken)
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

        var authorizationGrant = (await _authorizationGrantRepository.GetActiveAuthorizationGrant(request.AuthorizationGrantId, cancellationToken))!;

        var authorizationCode = new AuthorizationCode(authorizationGrant, authorizationGrant.Client.AuthorizationCodeExpiration!.Value);
        var nonce = new Nonce(request.Nonce, request.Nonce.Sha256(), authorizationGrant);

        authorizationGrant.AuthorizationCodes.Add(authorizationCode);
        authorizationGrant.Nonces.Add(nonce);

        var encodedAuthorizationCode = _authorizationCodeEncoder.EncodeAuthorizationCode(
            new EncodedAuthorizationCode
            {
                AuthorizationGrantId = authorizationGrant.Id,
                AuthorizationCodeId = authorizationCode.Id,
                Scope = request.Scope,
                RedirectUri = request.RedirectUri,
                CodeChallenge = request.CodeChallenge
            });

        authorizationCode.SetValue(encodedAuthorizationCode);

        if (authorizationGrant.Client.RequireConsent)
        {
            if (request.GrantManagementAction is null
                || request.GrantManagementAction == GrantManagementActionConstants.Create)
            {
                await _consentGrantRepository.CreateGrantConsent(request.AuthorizationGrantId, request.Scope, cancellationToken);
            }
            else if (request.GrantManagementAction == GrantManagementActionConstants.Merge)
            {
                await _consentGrantRepository.MergeGrantConsent(request.AuthorizationGrantId, request.Scope, cancellationToken);
            }
            else if (request.GrantManagementAction == GrantManagementActionConstants.Replace)
            {
                await _consentGrantRepository.ReplaceGrantConsent(request.AuthorizationGrantId, request.Scope, cancellationToken);
            }
        }

        return encodedAuthorizationCode;
    }
}