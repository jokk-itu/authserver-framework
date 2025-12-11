using AuthServer.Authentication.Abstractions;
using AuthServer.Constants;
using AuthServer.Core.Abstractions;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Extensions;
using AuthServer.Helpers;
using AuthServer.Tests.Core;
using AuthServer.TokenBuilders.Abstractions;
using AuthServer.TokenByGrant;
using AuthServer.TokenByGrant.TokenExchangeGrant;
using AuthServer.TokenDecoders;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.TokenByGrant.TokenExchangeGrant;

public class TokenExchangeRequestProcessorTest : BaseUnitTest
{
    public TokenExchangeRequestProcessorTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Theory]
    [InlineData(TokenTypeSchemaConstants.Bearer, null)]
    [InlineData(TokenTypeSchemaConstants.DPoP, "jkt")]
    public async Task Process_RequestImpersonatedClientAccessToken_ExpectTokenResponse(string tokenType, string? jkt)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var processor = serviceProvider
            .GetRequiredService<IRequestProcessor<TokenExchangeValidatedRequest, TokenResponse>>();

        var subjectTokenClient = await GetSubjectTokenClient();
        var resourceClient = await GetResourceClient();

        var validatedRequest = new TokenExchangeValidatedRequest
        {
            RequestedTokenType = TokenTypeIdentifier.AccessToken,
            SubjectToken = new TokenResult
            {
                Sub = subjectTokenClient.Id,
                ClientId = subjectTokenClient.Id,
                Jti = Guid.NewGuid().ToString(),
                Typ = TokenTypeHeaderConstants.AccessToken,
                Scope = [ScopeConstants.OpenId]
            },
            Scope = [ScopeConstants.OpenId],
            Resource = [resourceClient.ClientUri!],
            Jkt = jkt
        };

        // Act
        var tokenResponse = await processor.Process(validatedRequest, CancellationToken.None);

        // Assert
        Assert.NotNull(tokenResponse.AccessToken);
        Assert.Equal(subjectTokenClient.AccessTokenExpiration, tokenResponse.ExpiresIn);
        Assert.Equal(tokenType, tokenResponse.TokenType);
        Assert.Equal(validatedRequest.RequestedTokenType, tokenResponse.IssuedTokenType);
        Assert.Null(tokenResponse.GrantId);
        Assert.Equal(string.Join(' ', validatedRequest.Scope), tokenResponse.Scope);
    }

    [Fact]
    public async Task Process_RequestDelegatedClientAccessToken_ExpectTokenResponse()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var processor = serviceProvider
            .GetRequiredService<IRequestProcessor<TokenExchangeValidatedRequest, TokenResponse>>();

        var subjectTokenClient = await GetSubjectTokenClient();
        var resourceClient = await GetResourceClient();
        var actorTokenClient = await GetActorTokenClient();

        var validatedRequest = new TokenExchangeValidatedRequest
        {
            RequestedTokenType = TokenTypeIdentifier.AccessToken,
            SubjectToken = new TokenResult
            {
                Sub = subjectTokenClient.Id,
                ClientId = subjectTokenClient.Id,
                Jti = Guid.NewGuid().ToString(),
                Typ = TokenTypeHeaderConstants.AccessToken,
                Scope = [ScopeConstants.OpenId]
            },
            ActorToken = new TokenResult
            {
                Sub = actorTokenClient.Id,
                ClientId = actorTokenClient.Id,
                Jti = Guid.NewGuid().ToString(),
                Typ = TokenTypeHeaderConstants.AccessToken,
                Scope = [ScopeConstants.OpenId]
            },
            Scope = [ScopeConstants.OpenId],
            Resource = [resourceClient.ClientUri!]
        };

        // Act
        var tokenResponse = await processor.Process(validatedRequest, CancellationToken.None);

        // Assert
        Assert.NotNull(tokenResponse.AccessToken);
        Assert.Equal(subjectTokenClient.AccessTokenExpiration, tokenResponse.ExpiresIn);
        Assert.Equal(TokenTypeSchemaConstants.Bearer, tokenResponse.TokenType);
        Assert.Equal(validatedRequest.RequestedTokenType, tokenResponse.IssuedTokenType);
        Assert.Null(tokenResponse.GrantId);
        Assert.Equal(string.Join(' ', validatedRequest.Scope), tokenResponse.Scope);
    }

    [Theory]
    [InlineData(TokenTypeSchemaConstants.Bearer, null)]
    [InlineData(TokenTypeSchemaConstants.DPoP, "jkt")]
    public async Task Process_RequestImpersonatedGrantAccessToken_ExpectTokenResponse(string tokenType, string? jkt)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var processor = serviceProvider
            .GetRequiredService<IRequestProcessor<TokenExchangeValidatedRequest, TokenResponse>>();

        var subjectTokenGrant = await GetSubjectTokenAuthorizationCodeGrant();
        var resourceClient = await GetResourceClient();

        var validatedRequest = new TokenExchangeValidatedRequest
        {
            RequestedTokenType = TokenTypeIdentifier.AccessToken,
            SubjectToken = new TokenResult
            {
                Sub = subjectTokenGrant.Subject,
                ClientId = subjectTokenGrant.Client.Id,
                Jti = Guid.NewGuid().ToString(),
                Typ = TokenTypeHeaderConstants.AccessToken,
                Scope = [ScopeConstants.OpenId],
                Sid = subjectTokenGrant.Session.Id,
                GrantId = subjectTokenGrant.Id
            },
            Scope = [ScopeConstants.OpenId],
            Resource = [resourceClient.ClientUri!],
            Jkt = jkt
        };

        // Act
        var tokenResponse = await processor.Process(validatedRequest, CancellationToken.None);

        // Assert
        Assert.NotNull(tokenResponse.AccessToken);
        Assert.Equal(subjectTokenGrant.Client.AccessTokenExpiration, tokenResponse.ExpiresIn);
        Assert.Equal(tokenType, tokenResponse.TokenType);
        Assert.Equal(validatedRequest.RequestedTokenType, tokenResponse.IssuedTokenType);
        Assert.Equal(subjectTokenGrant.Id, tokenResponse.GrantId);
        Assert.Equal(string.Join(' ', validatedRequest.Scope), tokenResponse.Scope);
    }

    [Fact]
    public async Task Process_RequestDelegatedGrantAccessToken_ExpectTokenResponse()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var processor = serviceProvider
            .GetRequiredService<IRequestProcessor<TokenExchangeValidatedRequest, TokenResponse>>();

        var subjectTokenGrant = await GetSubjectTokenAuthorizationCodeGrant();
        var resourceClient = await GetResourceClient();
        var actorTokenClient = await GetActorTokenClient();

        var validatedRequest = new TokenExchangeValidatedRequest
        {
            RequestedTokenType = TokenTypeIdentifier.AccessToken,
            SubjectToken = new TokenResult
            {
                Sub = subjectTokenGrant.Subject,
                ClientId = subjectTokenGrant.Client.Id,
                Jti = Guid.NewGuid().ToString(),
                Typ = TokenTypeHeaderConstants.AccessToken,
                Scope = [ScopeConstants.OpenId],
                Sid = subjectTokenGrant.Session.Id,
                GrantId = subjectTokenGrant.Id
            },
            ActorToken = new TokenResult
            {
                Sub = actorTokenClient.Id,
                ClientId = actorTokenClient.Id,
                Jti = Guid.NewGuid().ToString(),
                Typ = TokenTypeHeaderConstants.AccessToken,
                Scope = [ScopeConstants.OpenId]
            },
            Scope = [ScopeConstants.OpenId],
            Resource = [resourceClient.ClientUri!]
        };

        // Act
        var tokenResponse = await processor.Process(validatedRequest, CancellationToken.None);

        // Assert
        Assert.NotNull(tokenResponse.AccessToken);
        Assert.Equal(subjectTokenGrant.Client.AccessTokenExpiration, tokenResponse.ExpiresIn);
        Assert.Equal(TokenTypeSchemaConstants.Bearer, tokenResponse.TokenType);
        Assert.Equal(validatedRequest.RequestedTokenType, tokenResponse.IssuedTokenType);
        Assert.Equal(subjectTokenGrant.Id, tokenResponse.GrantId);
        Assert.Equal(string.Join(' ', validatedRequest.Scope), tokenResponse.Scope);
    }

    [Fact]
    public async Task Process_RequestImpersonatedIdToken_ExpectTokenResponse()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var processor = serviceProvider
            .GetRequiredService<IRequestProcessor<TokenExchangeValidatedRequest, TokenResponse>>();

        var subjectTokenGrant = await GetSubjectTokenAuthorizationCodeGrant();
        var resourceClient = await GetResourceClient();

        var validatedRequest = new TokenExchangeValidatedRequest
        {
            RequestedTokenType = TokenTypeIdentifier.IdToken,
            SubjectToken = new TokenResult
            {
                Sub = subjectTokenGrant.Subject,
                ClientId = subjectTokenGrant.Client.Id,
                Jti = Guid.NewGuid().ToString(),
                Typ = TokenTypeHeaderConstants.AccessToken,
                Scope = [ScopeConstants.OpenId],
                Sid = subjectTokenGrant.Session.Id,
                GrantId = subjectTokenGrant.Id
            },
            Scope = [ScopeConstants.OpenId],
            Resource = [resourceClient.ClientUri!]
        };

        // Act
        var tokenResponse = await processor.Process(validatedRequest, CancellationToken.None);

        // Assert
        Assert.NotNull(tokenResponse.AccessToken);
        Assert.Equal(subjectTokenGrant.Client.IdTokenExpiration!.Value, tokenResponse.ExpiresIn);
        Assert.Equal(TokenTypeSchemaConstants.Bearer, tokenResponse.TokenType);
        Assert.Equal(validatedRequest.RequestedTokenType, tokenResponse.IssuedTokenType);
        Assert.Equal(subjectTokenGrant.Id, tokenResponse.GrantId);
        Assert.Equal(string.Join(' ', validatedRequest.Scope), tokenResponse.Scope);
    }

    [Fact]
    public async Task Process_RequestDelegatedIdToken_ExpectTokenResponse()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var processor = serviceProvider
            .GetRequiredService<IRequestProcessor<TokenExchangeValidatedRequest, TokenResponse>>();

        var subjectTokenGrant = await GetSubjectTokenAuthorizationCodeGrant();
        var resourceClient = await GetResourceClient();
        var actorTokenClient = await GetActorTokenClient();
        actorTokenClient.IdTokenSignedResponseAlg = SigningAlg.EcdsaSha256;
        actorTokenClient.IdTokenEncryptedResponseAlg = EncryptionAlg.EcdhEsA128KW;
        actorTokenClient.IdTokenEncryptedResponseEnc = EncryptionEnc.Aes128CbcHmacSha256;
        actorTokenClient.Jwks = ClientJwkBuilder.GetClientJwks(
            actorTokenClient.IdTokenSignedResponseAlg.Value,
            actorTokenClient.IdTokenEncryptedResponseAlg.Value).PublicJwks;

        await SaveChangesAsync();

        var validatedRequest = new TokenExchangeValidatedRequest
        {
            RequestedTokenType = TokenTypeIdentifier.IdToken,
            SubjectToken = new TokenResult
            {
                Sub = subjectTokenGrant.Subject,
                ClientId = subjectTokenGrant.Client.Id,
                Jti = Guid.NewGuid().ToString(),
                Typ = TokenTypeHeaderConstants.AccessToken,
                Scope = [ScopeConstants.OpenId],
                Sid = subjectTokenGrant.Session.Id,
                GrantId = subjectTokenGrant.Id
            },
            ActorToken = new TokenResult
            {
                Sub = actorTokenClient.Id,
                ClientId = actorTokenClient.Id,
                Jti = Guid.NewGuid().ToString(),
                Typ = TokenTypeHeaderConstants.AccessToken,
                Scope = [ScopeConstants.OpenId]
            },
            Scope = [ScopeConstants.OpenId],
            Resource = [resourceClient.ClientUri!]
        };

        // Act
        var tokenResponse = await processor.Process(validatedRequest, CancellationToken.None);

        // Assert
        Assert.NotNull(tokenResponse.AccessToken);
        Assert.Equal(3600, tokenResponse.ExpiresIn);
        Assert.Equal(TokenTypeSchemaConstants.Bearer, tokenResponse.TokenType);
        Assert.Equal(validatedRequest.RequestedTokenType, tokenResponse.IssuedTokenType);
        Assert.Equal(subjectTokenGrant.Id, tokenResponse.GrantId);
        Assert.Equal(string.Join(' ', validatedRequest.Scope), tokenResponse.Scope);
        Assert.True(TokenHelper.IsJwe(tokenResponse.AccessToken));
    }

    private async Task<Client> GetSubjectTokenClient()
    {
        var client = new Client("subject-web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        await AddEntity(client);
        return client;
    }

    private async Task<AuthorizationCodeGrant> GetSubjectTokenAuthorizationCodeGrant()
    {
        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("subject-web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            IdTokenSignedResponseAlg = SigningAlg.RsaSha256,
            IdTokenExpiration = 3600
        };
        var levelOfAssurance = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationCodeGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, levelOfAssurance);

        var passwordAuthenticationMethodReference = await GetAuthenticationMethodReference(AuthenticationMethodReferenceConstants.Password);
        authorizationCodeGrant.AuthenticationMethodReferences.Add(passwordAuthenticationMethodReference);

        var nonceValue = CryptographyHelper.GetRandomString(32);
        var nonce = new AuthorizationGrantNonce(nonceValue, nonceValue.Sha256(), authorizationCodeGrant);
        authorizationCodeGrant.Nonces.Add(nonce);

        await AddEntity(authorizationCodeGrant);
        return authorizationCodeGrant;
    }

    private async Task<Client> GetActorTokenClient()
    {
        var client = new Client("actor-web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        await AddEntity(client);
        return client;
    }

    private async Task<Client> GetResourceClient()
    {
        var client = new Client("web-api", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            ClientUri = "https://localhost:5000/api"
        };
        await AddEntity(client);
        return client;
    }
}