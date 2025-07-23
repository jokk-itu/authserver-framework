using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Enums;
using AuthServer.Helpers;
using AuthServer.Tests.Core;
using Microsoft.AspNetCore.Mvc.Testing;
using System.Net;
using Xunit.Abstractions;

namespace AuthServer.Tests.IntegrationTest;
public class DeviceCodeIntegrationTest : BaseIntegrationTest
{
    public DeviceCodeIntegrationTest(WebApplicationFactory<Program> factory, ITestOutputHelper testOutputHelper)
        : base(factory, testOutputHelper)
    {
    }

    [Fact]
    public async Task DeviceCode_DPoPRequestWithoutNonce_ExpectUseDPoPNonce()
    {
        // Arrange
        var weatherReadScope = await AddWeatherReadScope();
        var weatherClientSecret = CryptographyHelper.GetRandomString(16);
        var weatherClient = await AddWeatherClient(weatherClientSecret);

        var registerResponse = await RegisterEndpointBuilder
            .WithClientName("tv-app")
            .WithGrantTypes([GrantTypeConstants.DeviceCode])
            .WithTokenEndpointAuthMethod(TokenEndpointAuthMethod.None)
            .WithApplicationType(ApplicationTypeConstants.Native)
            .WithSubjectType(SubjectType.Public)
            .WithScope([weatherReadScope, ScopeConstants.OpenId])
            .Post();

        var dPoPNonce = await GetDPoPNonce(registerResponse.ClientId);
        var jwks = ClientJwkBuilder.GetClientJwks();
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var nonce = CryptographyHelper.GetRandomString(16);
        var deviceAuthorizationResponse = await DeviceAuthorizationEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithScope(registerResponse.Scope)
            .WithCodeChallenge(proofKey.CodeChallenge)
            .WithCodeChallengeMethod(proofKey.CodeChallengeMethod)
            .WithResource([weatherClient.ClientUri!])
            .WithDPoP(dPoPNonce)
            .WithNonce(nonce)
            .WithClientJwks(jwks)
            .WithTokenEndpointAuthMethod(TokenEndpointAuthMethod.None)
            .Post();

        await AddUser();
        await AddAuthenticationContextReferences();
        var grantId = await CreateDeviceCodeGrant(registerResponse.ClientId, [AuthenticationMethodReferenceConstants.Password], deviceAuthorizationResponse.Response!.UserCode, nonce);
        await Consent(UserConstants.SubjectIdentifier, registerResponse.ClientId, registerResponse.Scope, []);
        await GrantConsent(grantId, registerResponse.Scope, [weatherClient.ClientUri!]);
        await RedeemUserCode(deviceAuthorizationResponse.Response!.UserCode);

        await ExpireDPoPNonce(dPoPNonce);

        await Task.Delay(TimeSpan.FromSeconds(deviceAuthorizationResponse.Response!.Interval));

        // Act
        var tokenResponse = await TokenEndpointBuilder
            .WithGrantType(GrantTypeConstants.DeviceCode)
            .WithTokenEndpointAuthMethod(TokenEndpointAuthMethod.None)
            .WithDeviceCode(deviceAuthorizationResponse.Response!.DeviceCode)
            .WithCodeVerifier(proofKey.CodeVerifier)
            .WithDPoP(null)
            .WithClientJwks(jwks)
            .WithClientId(registerResponse.ClientId)
            .WithScope(registerResponse.Scope)
            .WithResource([weatherClient.ClientUri!])
            .Post();

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, tokenResponse.StatusCode);
        Assert.NotNull(tokenResponse.Error);
        Assert.Equal(ErrorCode.UseDPoPNonce, tokenResponse.Error.Error);
        Assert.Null(tokenResponse.Response);
        Assert.NotNull(tokenResponse.DPoPNonce);
    }

    [Fact]
    public async Task DeviceCode_DeviceCodeGrant_ExpectTokens()
    {
        // Arrange
        var weatherReadScope = await AddWeatherReadScope();
        var weatherClientSecret = CryptographyHelper.GetRandomString(16);
        var weatherClient = await AddWeatherClient(weatherClientSecret);

        var registerResponse = await RegisterEndpointBuilder
            .WithClientName("tv-app")
            .WithGrantTypes([GrantTypeConstants.DeviceCode])
            .WithTokenEndpointAuthMethod(TokenEndpointAuthMethod.None)
            .WithApplicationType(ApplicationTypeConstants.Native)
            .WithIdTokenSigningAlg(SigningAlg.RsaSha256)
            .WithSubjectType(SubjectType.Public)
            .WithScope([weatherReadScope, ScopeConstants.OpenId])
            .Post();

        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var nonce = CryptographyHelper.GetRandomString(16);
        var deviceAuthorizationResponse = await DeviceAuthorizationEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithScope(registerResponse.Scope)
            .WithCodeChallenge(proofKey.CodeChallenge)
            .WithCodeChallengeMethod(proofKey.CodeChallengeMethod)
            .WithResource([weatherClient.ClientUri!])
            .WithNonce(nonce)
            .WithTokenEndpointAuthMethod(TokenEndpointAuthMethod.None)
            .Post();

        await AddUser();
        await AddAuthenticationContextReferences();
        var grantId = await CreateDeviceCodeGrant(registerResponse.ClientId, [AuthenticationMethodReferenceConstants.Password], deviceAuthorizationResponse.Response!.UserCode, nonce);
        await Consent(UserConstants.SubjectIdentifier, registerResponse.ClientId, registerResponse.Scope, []);
        await GrantConsent(grantId, registerResponse.Scope, [weatherClient.ClientUri!]);
        await RedeemUserCode(deviceAuthorizationResponse.Response!.UserCode);

        await Task.Delay(TimeSpan.FromSeconds(deviceAuthorizationResponse.Response!.Interval));

        // Act
        var tokenResponse = await TokenEndpointBuilder
            .WithGrantType(GrantTypeConstants.DeviceCode)
            .WithTokenEndpointAuthMethod(TokenEndpointAuthMethod.None)
            .WithDeviceCode(deviceAuthorizationResponse.Response!.DeviceCode)
            .WithCodeVerifier(proofKey.CodeVerifier)
            .WithClientId(registerResponse.ClientId)
            .WithScope(registerResponse.Scope)
            .WithResource([weatherClient.ClientUri!])
            .Post();

        // Assert
        Assert.Equal(HttpStatusCode.OK, tokenResponse.StatusCode);
        Assert.Equal(string.Join(' ', registerResponse.Scope), tokenResponse.Response!.Scope);
        Assert.Equal(TokenTypeSchemaConstants.Bearer, tokenResponse.Response!.TokenType);
        Assert.Null(tokenResponse.Response!.RefreshToken);
        Assert.NotNull(tokenResponse.Response!.IdToken);
        Assert.NotNull(tokenResponse.Response!.AccessToken);
        Assert.Equal(registerResponse.AccessTokenExpiration, tokenResponse.Response!.ExpiresIn);
    }
}
