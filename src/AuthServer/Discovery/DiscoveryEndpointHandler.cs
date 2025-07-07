using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Core.Abstractions;
using AuthServer.Endpoints.Abstractions;
using AuthServer.Options;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.FeatureManagement;

namespace AuthServer.Discovery;

internal class DiscoveryEndpointHandler : IEndpointHandler
{
    private readonly IOptionsSnapshot<DiscoveryDocument> _discoveryDocumentOptions;
    private readonly IFeatureManagerSnapshot _featureManagerSnapshot;
    private readonly IEndpointResolver _endpointResolver;

    public DiscoveryEndpointHandler(
        IOptionsSnapshot<DiscoveryDocument> discoveryDocumentOptions,
        IFeatureManagerSnapshot featureManagerSnapshot,
        IEndpointResolver endpointResolver)
    {
        _discoveryDocumentOptions = discoveryDocumentOptions;
        _featureManagerSnapshot = featureManagerSnapshot;
        _endpointResolver = endpointResolver;
    }

    private DiscoveryDocument DiscoveryDocument => _discoveryDocumentOptions.Value;

    public async Task<IResult> Handle(HttpContext httpContext, CancellationToken cancellationToken)
    {
        var response = new GetDiscoveryResponse
        {
            Issuer = DiscoveryDocument.Issuer,
            ServiceDocumentation = DiscoveryDocument.ServiceDocumentation,
            OpPolicyUri = DiscoveryDocument.OpPolicyUri,
            OpTosUri = DiscoveryDocument.OpTosUri,
            AuthorizationEndpoint = await Filter(_endpointResolver.AuthorizationEndpoint, FeatureFlags.Authorize),
            TokenEndpoint = await Filter(_endpointResolver.TokenEndpoint, FeatureFlags.AuthorizationCode, FeatureFlags.RefreshToken, FeatureFlags.ClientCredentials),
            UserinfoEndpoint = await Filter(_endpointResolver.UserinfoEndpoint, FeatureFlags.Userinfo),
            JwksUri = await Filter(_endpointResolver.JwksEndpoint, FeatureFlags.Jwks),
            RegistrationEndpoint = await Filter(_endpointResolver.RegistrationEndpoint, FeatureFlags.RegisterGet, FeatureFlags.RegisterDelete, FeatureFlags.RegisterPost, FeatureFlags.RegisterPut),
            EndSessionEndpoint = await Filter(_endpointResolver.EndSessionEndpoint, FeatureFlags.EndSession),
            IntrospectionEndpoint = await Filter(_endpointResolver.IntrospectionEndpoint, FeatureFlags.TokenIntrospection),
            RevocationEndpoint = await Filter(_endpointResolver.RevocationEndpoint, FeatureFlags.TokenRevocation),
            PushedAuthorizationRequestEndpoint = await Filter(_endpointResolver.PushedAuthorizationEndpoint, FeatureFlags.PushedAuthorization),
            GrantManagementEndpoint = await Filter(_endpointResolver.GrantManagementEndpoint, FeatureFlags.GrantManagementRevoke, FeatureFlags.GrantManagementQuery),
            ProtectedResources = DiscoveryDocument.ProtectedResources,
            ClaimsSupported = DiscoveryDocument.ClaimsSupported,
            ScopesSupported = DiscoveryDocument.ScopesSupported,
            AcrValuesSupported = DiscoveryDocument.AcrValuesSupported,
            ClaimTypesSupported = ClaimTypeConstants.ClaimTypes,
            PromptValuesSupported = PromptConstants.Prompts,
            DisplayValuesSupported = DisplayConstants.DisplayValues,
            SubjectTypesSupported = SubjectTypeConstants.SubjectTypes,
            GrantTypesSupported = GrantTypeConstants.GrantTypes,
            ChallengeMethodsSupported = CodeChallengeMethodConstants.CodeChallengeMethods,
            ResponseTypesSupported = ResponseTypeConstants.ResponseTypes,
            ResponseModesSupported = ResponseModeConstants.ResponseModes,
            IntrospectionEndpointAuthMethodsSupported = TokenEndpointAuthMethodConstants.SecureAuthMethods,
            RevocationEndpointAuthMethodsSupported = TokenEndpointAuthMethodConstants.SecureAuthMethods,
            TokenEndpointAuthMethodsSupported = TokenEndpointAuthMethodConstants.AuthMethods,
            GrantManagementActionsSupported = GrantManagementActionConstants.GrantManagementActions,
            IdTokenSigningAlgValuesSupported = DiscoveryDocument.IdTokenSigningAlgValuesSupported,
            IdTokenEncryptionAlgValuesSupported = DiscoveryDocument.IdTokenEncryptionAlgValuesSupported,
            IdTokenEncryptionEncValuesSupported = DiscoveryDocument.IdTokenEncryptionEncValuesSupported,
            UserinfoSigningAlgValuesSupported = DiscoveryDocument.UserinfoSigningAlgValuesSupported,
            UserinfoEncryptionAlgValuesSupported = DiscoveryDocument.UserinfoEncryptionAlgValuesSupported,
            UserinfoEncryptionEncValuesSupported = DiscoveryDocument.UserinfoEncryptionEncValuesSupported,
            RequestObjectSigningAlgValuesSupported = DiscoveryDocument.RequestObjectSigningAlgValuesSupported,
            RequestObjectEncryptionAlgValuesSupported = DiscoveryDocument.RequestObjectEncryptionAlgValuesSupported,
            RequestObjectEncryptionEncValuesSupported = DiscoveryDocument.RequestObjectEncryptionEncValuesSupported,
            TokenEndpointAuthSigningAlgValuesSupported = DiscoveryDocument.TokenEndpointAuthSigningAlgValuesSupported,
            TokenEndpointAuthEncryptionAlgValuesSupported = DiscoveryDocument.TokenEndpointAuthEncryptionAlgValuesSupported,
            TokenEndpointAuthEncryptionEncValuesSupported = DiscoveryDocument.TokenEndpointAuthEncryptionEncValuesSupported,
            IntrospectionEndpointAuthSigningAlgValuesSupported = DiscoveryDocument.IntrospectionEndpointAuthSigningAlgValuesSupported,
            RevocationEndpointAuthSigningAlgValuesSupported = DiscoveryDocument.RevocationEndpointAuthSigningAlgValuesSupported,
            DPoPSigningAlgValuesSupported = DiscoveryDocument.DPoPSigningAlgValuesSupported,
            AuthorizationResponseIssParameterSupported = true,
            BackchannelLogoutSupported = true,
            RequireRequestUriRegistration = true,
            ClaimsParameterSupported = false,
            RequestParameterSupported = true,
            RequestUriParameterSupported = true,
            RequireSignedRequestObject = DiscoveryDocument.RequireSignedRequestObject,
            RequirePushedAuthorizationRequests = DiscoveryDocument.RequirePushedAuthorizationRequests,
            GrantManagementActionRequired = DiscoveryDocument.GrantManagementActionRequired
        };

        return Results.Ok(response);
    }

    private async Task<T?> Filter<T>(T value, params string[] featureFlags)
    {
        foreach (var featureFlag in featureFlags)
        {
            if (await _featureManagerSnapshot.IsEnabledAsync(featureFlag))
            {
                return value;
            }
        }

        return default;
    }
}