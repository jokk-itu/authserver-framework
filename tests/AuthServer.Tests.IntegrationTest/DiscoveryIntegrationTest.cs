using System.Text.Json;
using AuthServer.Constants;
using AuthServer.Discovery;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit.Abstractions;

namespace AuthServer.Tests.IntegrationTest;

public class DiscoveryIntegrationTest : BaseIntegrationTest
{
    public DiscoveryIntegrationTest(WebApplicationFactory<Program> factory, ITestOutputHelper testOutputHelper)
        : base(factory, testOutputHelper)
    {
    }

    [Fact]
    public async Task GetDiscovery_ExpectGetDiscoveryResponse()
    {
        // Arrange
        var httpClient = GetHttpClient();

        // Act
        var response = await httpClient.GetAsync(EndpointResolver.DiscoveryEndpoint);
        var content = await response.Content.ReadAsStringAsync();
        var getDiscoveryResponse = JsonSerializer.Deserialize<GetDiscoveryResponse>(content);

        // Assert
        Assert.NotNull(getDiscoveryResponse);
        Assert.Equal(DiscoveryDocument.Issuer, getDiscoveryResponse.Issuer);
        Assert.Equal(DiscoveryDocument.ServiceDocumentation, getDiscoveryResponse.ServiceDocumentation);
        Assert.Equal(DiscoveryDocument.OpPolicyUri, getDiscoveryResponse.OpPolicyUri);
        Assert.Equal(DiscoveryDocument.OpTosUri, getDiscoveryResponse.OpTosUri);

        Assert.Equal(EndpointResolver.AuthorizationEndpoint, getDiscoveryResponse.AuthorizationEndpoint);
        Assert.Equal(EndpointResolver.TokenEndpoint, getDiscoveryResponse.TokenEndpoint);
        Assert.Equal(EndpointResolver.UserinfoEndpoint, getDiscoveryResponse.UserinfoEndpoint);
        Assert.Equal(EndpointResolver.JwksEndpoint, getDiscoveryResponse.JwksUri);
        Assert.Equal(EndpointResolver.RegistrationEndpoint, getDiscoveryResponse.RegistrationEndpoint);
        Assert.Equal(EndpointResolver.EndSessionEndpoint, getDiscoveryResponse.EndSessionEndpoint);
        Assert.Equal(EndpointResolver.IntrospectionEndpoint, getDiscoveryResponse.IntrospectionEndpoint);
        Assert.Equal(EndpointResolver.RevocationEndpoint, getDiscoveryResponse.RevocationEndpoint);
        Assert.Equal(EndpointResolver.PushedAuthorizationEndpoint, getDiscoveryResponse.PushedAuthorizationRequestEndpoint);
        Assert.Equal(EndpointResolver.GrantManagementEndpoint, getDiscoveryResponse.GrantManagementEndpoint);
        Assert.Equal(EndpointResolver.DeviceAuthorizationEndpoint, getDiscoveryResponse.DeviceAuthorizationEndpoint);

        Assert.Equal(DiscoveryDocument.ProtectedResources, getDiscoveryResponse.ProtectedResources);
        Assert.Equal(DiscoveryDocument.ClaimsSupported, getDiscoveryResponse.ClaimsSupported);
        Assert.Equal(DiscoveryDocument.ScopesSupported, getDiscoveryResponse.ScopesSupported);
        Assert.Equal(DiscoveryDocument.AcrValuesSupported, getDiscoveryResponse.AcrValuesSupported);

        Assert.Equal(ClaimTypeConstants.ClaimTypes, getDiscoveryResponse.ClaimTypesSupported);
        Assert.Equal(PromptConstants.Prompts, getDiscoveryResponse.PromptValuesSupported);
        Assert.Equal(DisplayConstants.DisplayValues, getDiscoveryResponse.DisplayValuesSupported);
        Assert.Equal(SubjectTypeConstants.SubjectTypes, getDiscoveryResponse.SubjectTypesSupported);
        Assert.Equal(GrantTypeConstants.GrantTypes, getDiscoveryResponse.GrantTypesSupported);
        Assert.Equal(CodeChallengeMethodConstants.CodeChallengeMethods, getDiscoveryResponse.ChallengeMethodsSupported);
        Assert.Equal(ResponseTypeConstants.ResponseTypes, getDiscoveryResponse.ResponseTypesSupported);
        Assert.Equal(ResponseModeConstants.ResponseModes, getDiscoveryResponse.ResponseModesSupported);
        Assert.Equal(TokenEndpointAuthMethodConstants.SecureAuthMethods, getDiscoveryResponse.IntrospectionEndpointAuthMethodsSupported);
        Assert.Equal(TokenEndpointAuthMethodConstants.SecureAuthMethods, getDiscoveryResponse.RevocationEndpointAuthMethodsSupported);
        Assert.Equal(TokenEndpointAuthMethodConstants.AuthMethods, getDiscoveryResponse.TokenEndpointAuthMethodsSupported);
        Assert.Equal(GrantManagementActionConstants.GrantManagementActions, getDiscoveryResponse.GrantManagementActionsSupported);

        Assert.Equal(DiscoveryDocument.IdTokenSigningAlgValuesSupported, getDiscoveryResponse.IdTokenSigningAlgValuesSupported);
        Assert.Equal(DiscoveryDocument.IdTokenEncryptionAlgValuesSupported, getDiscoveryResponse.IdTokenEncryptionAlgValuesSupported);
        Assert.Equal(DiscoveryDocument.IdTokenEncryptionEncValuesSupported, getDiscoveryResponse.IdTokenEncryptionEncValuesSupported);

        Assert.Equal(DiscoveryDocument.UserinfoSigningAlgValuesSupported, getDiscoveryResponse.UserinfoSigningAlgValuesSupported);
        Assert.Equal(DiscoveryDocument.UserinfoEncryptionAlgValuesSupported, getDiscoveryResponse.UserinfoEncryptionAlgValuesSupported);
        Assert.Equal(DiscoveryDocument.UserinfoEncryptionEncValuesSupported, getDiscoveryResponse.UserinfoEncryptionEncValuesSupported);

        Assert.Equal(DiscoveryDocument.RequestObjectSigningAlgValuesSupported, getDiscoveryResponse.RequestObjectSigningAlgValuesSupported);
        Assert.Equal(DiscoveryDocument.RequestObjectEncryptionAlgValuesSupported, getDiscoveryResponse.RequestObjectEncryptionAlgValuesSupported);
        Assert.Equal(DiscoveryDocument.RequestObjectEncryptionEncValuesSupported, getDiscoveryResponse.RequestObjectEncryptionEncValuesSupported);

        Assert.Equal(DiscoveryDocument.TokenEndpointAuthSigningAlgValuesSupported, getDiscoveryResponse.TokenEndpointAuthSigningAlgValuesSupported);
        Assert.Equal(DiscoveryDocument.TokenEndpointAuthEncryptionAlgValuesSupported, getDiscoveryResponse.TokenEndpointAuthEncryptionAlgValuesSupported);
        Assert.Equal(DiscoveryDocument.TokenEndpointAuthEncryptionEncValuesSupported, getDiscoveryResponse.TokenEndpointAuthEncryptionEncValuesSupported);

        Assert.Equal(DiscoveryDocument.IntrospectionEndpointAuthSigningAlgValuesSupported, getDiscoveryResponse.IntrospectionEndpointAuthSigningAlgValuesSupported);

        Assert.Equal(DiscoveryDocument.RevocationEndpointAuthSigningAlgValuesSupported, getDiscoveryResponse.RevocationEndpointAuthSigningAlgValuesSupported);

        Assert.Equal(DiscoveryDocument.DPoPSigningAlgValuesSupported, getDiscoveryResponse.DPoPSigningAlgValuesSupported);

        Assert.True(getDiscoveryResponse.AuthorizationResponseIssParameterSupported);
        Assert.True(getDiscoveryResponse.BackchannelLogoutSupported);
        Assert.True(getDiscoveryResponse.RequireRequestUriRegistration);
        Assert.False(getDiscoveryResponse.ClaimsParameterSupported);
        Assert.True(getDiscoveryResponse.RequestParameterSupported);
        Assert.True(getDiscoveryResponse.RequestUriParameterSupported);
        Assert.Equal(DiscoveryDocument.RequireSignedRequestObject, getDiscoveryResponse.RequireSignedRequestObject);
        Assert.Equal(DiscoveryDocument.RequirePushedAuthorizationRequests, getDiscoveryResponse.RequirePushedAuthorizationRequests);
        Assert.Equal(DiscoveryDocument.GrantManagementActionRequired, getDiscoveryResponse.GrantManagementActionRequired);
    }
}