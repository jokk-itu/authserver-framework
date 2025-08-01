using AuthServer.Authorization.Models;
using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Core.Abstractions;
using AuthServer.Extensions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.FeatureManagement;

namespace AuthServer.TokenByGrant;
internal class TokenEndpointHandler : IEndpointHandler
{
    private readonly IRequestAccessor<TokenRequest> _requestAccessor;
    private readonly IFeatureManagerSnapshot _featureManagerSnapshot;
    private readonly IServiceProvider _serviceProvider;

    public TokenEndpointHandler(
        IRequestAccessor<TokenRequest> requestAccessor,
        IFeatureManagerSnapshot featureManagerSnapshot,
        IServiceProvider serviceProvider)
    {
        _requestAccessor = requestAccessor;
        _featureManagerSnapshot = featureManagerSnapshot;
        _serviceProvider = serviceProvider;
    }

    public async Task<IResult> Handle(HttpContext httpContext, CancellationToken cancellationToken)
    {
        var request = await _requestAccessor.GetRequest(httpContext.Request);

        if (!GrantTypeConstants.GrantTypes.Contains(request.GrantType))
        {
            return Results.Extensions.OAuthBadRequest(TokenError.UnsupportedGrantType);
        }
        
        switch (request.GrantType)
        {
            case GrantTypeConstants.AuthorizationCode when
                !await _featureManagerSnapshot.IsEnabledAsync(FeatureFlags.AuthorizationCode):
            case GrantTypeConstants.RefreshToken when
                !await _featureManagerSnapshot.IsEnabledAsync(FeatureFlags.RefreshToken):
            case GrantTypeConstants.ClientCredentials when
                !await _featureManagerSnapshot.IsEnabledAsync(FeatureFlags.ClientCredentials):
            case GrantTypeConstants.DeviceCode when
                !await _featureManagerSnapshot.IsEnabledAsync(FeatureFlags.DeviceCode):
            case GrantTypeConstants.TokenExchange when
                !await _featureManagerSnapshot.IsEnabledAsync(FeatureFlags.TokenExchange):
                return Results.Extensions.OAuthBadRequest(TokenError.UnsupportedGrantType);
        }

        var requestHandler = _serviceProvider.GetRequiredKeyedService<IRequestHandler<TokenRequest, TokenResponse>>(request.GrantType);
        var result = await requestHandler.Handle(request, cancellationToken);

        return result.Match(
            response => Results.Ok(new PostTokenResponse
            {
                AccessToken = response.AccessToken,
                Scope = response.Scope,
                ExpiresIn = response.ExpiresIn,
                IdToken = response.IdToken,
                RefreshToken = response.RefreshToken,
                GrantId = response.GrantId,
                TokenType = response.TokenType,
                IssuedTokenType = response.IssuedTokenType
            }),
            error =>
            {
                if (error is DPoPNonceProcessError dPoPNonceProcessError)
                {
                    httpContext.Response.Headers[Parameter.DPoPNonce] = dPoPNonceProcessError.DPoPNonce;
                }

                return Results.Extensions.OAuthBadRequest(error);
            });
    }
}
