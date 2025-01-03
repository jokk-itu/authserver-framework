using AuthServer.Constants;
using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Helpers;
using AuthServer.Register;
using AuthServer.Tests.Core;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.Register;

public class RegisterRequestProcessorTest : BaseUnitTest
{
    public RegisterRequestProcessorTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Fact]
    public async Task Process_PostRegister_ExpectRegisterResponse()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var processor = serviceProvider
            .GetRequiredService<IRequestProcessor<RegisterValidatedRequest, ProcessResult<RegisterResponse, Unit>>>();
        var unitOfWork = serviceProvider.GetRequiredService<IUnitOfWork>();

        var jwks = ClientJwkBuilder.GetClientJwks();

        var request = new RegisterValidatedRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            GrantTypes = [GrantTypeConstants.AuthorizationCode],
            ApplicationType = ApplicationType.Web,
            TokenEndpointAuthMethod = TokenEndpointAuthMethod.PrivateKeyJwt,
            SubjectType = SubjectType.Pairwise,
            RedirectUris = ["https://webapp.authserver.dk/callback"],
            Contacts = ["info@authserver.dk"],
            RequestUris = ["https://webapp.authserver.dk/request"],
            ResponseTypes = [ResponseTypeConstants.Code],
            PostLogoutRedirectUris = ["https://webapp.authserver.dk/post-logout-callback"],
            Scope = [ScopeConstants.OpenId],
            ClientUri = "https://webapp.authserver.dk",
            PolicyUri = "https://webapp.authserver.dk/policy",
            LogoUri = "https://webapp.authserver.dk/logo",
            TosUri = "https://webapp.authserver.dk/tos",
            AccessTokenExpiration = 500,
            AuthorizationCodeExpiration = 60,
            BackchannelLogoutUri = "https://webapp.authserver.dk/remote-logout",
            ClientSecretExpiration = 86400,
            DefaultAcrValues = [LevelOfAssuranceStrict],
            DefaultMaxAge = 500,
            InitiateLoginUri = "https://webapp.authserver.dk/remote-login",
            RefreshTokenExpiration = 86400,
            RequireReferenceToken = false,
            RequireSignedRequestObject = true,
            RequirePushedAuthorizationRequests = true,
            RequestUriExpiration = 500,
            RequestObjectEncryptionAlg = EncryptionAlg.RsaPKCS1,
            RequestObjectEncryptionEnc = EncryptionEnc.Aes128CbcHmacSha256,
            RequestObjectSigningAlg = SigningAlg.RsaSha256,
            UserinfoEncryptedResponseAlg = EncryptionAlg.RsaPKCS1,
            UserinfoEncryptedResponseEnc = EncryptionEnc.Aes128CbcHmacSha256,
            UserinfoSignedResponseAlg = SigningAlg.RsaSha256,
            IdTokenEncryptedResponseAlg = EncryptionAlg.RsaPKCS1,
            IdTokenEncryptedResponseEnc = EncryptionEnc.Aes128CbcHmacSha256,
            IdTokenSignedResponseAlg = SigningAlg.RsaSha256,
            TokenEndpointAuthSigningAlg = SigningAlg.RsaSha256,
            Jwks = jwks.PublicJwks,
            JwksUri = "https://webapp.authserverdk/jwks",
            JwksExpiration = 86400 * 30,
            SectorIdentifierUri = "https://webapp.authserver.dk/sector",
        };

        // Act
        await unitOfWork.Begin(CancellationToken.None);
        var processResult = await processor.Process(request, CancellationToken.None);
        await unitOfWork.Commit(CancellationToken.None);

        // Assert
        var response = processResult.Value!;
        var client = await IdentityContext
            .Set<Client>()
            .Include(x => x.ResponseTypes)
            .Include(x => x.RedirectUris)
            .Include(x => x.PostLogoutRedirectUris)
            .Include(x => x.RequestUris)
            .Include(x => x.ClientAuthenticationContextReferences)
            .ThenInclude(x => x.AuthenticationContextReference)
            .Include(x => x.Contacts)
            .Include(x => x.Scopes)
            .Include(x => x.GrantTypes)
            .Include(x => x.ClientTokens)
            .SingleOrDefaultAsync(x => x.Id == response.ClientId, CancellationToken.None);

        Assert.NotNull(client);
        Assert.Equal(client.CreatedAt.Ticks, response.ClientIdIssuedAt);
        Assert.True(CryptographyHelper.VerifyPassword(client.SecretHash!, response.ClientSecret!));
        Assert.Equal(client.SecretExpiresAt!.Value.Ticks, response.ClientSecretExpiresAt);
        Assert.Equal($"{DiscoveryDocument.RegistrationEndpoint}?client_id={response.ClientId}",
            response.RegistrationClientUri);
        Assert.Equal(client.ClientTokens.Single(x => x.RevokedAt is null).Reference, response.RegistrationAccessToken);
        Assert.Equal(request.ApplicationType, response.ApplicationType);
        Assert.Equal(request.TokenEndpointAuthMethod, response.TokenEndpointAuthMethod);
        Assert.Equal(request.ClientName, response.ClientName);
        Assert.Equal(request.GrantTypes, response.GrantTypes);
        Assert.Equal(request.Scope, response.Scope);
        Assert.Equal(request.ResponseTypes, response.ResponseTypes);
        Assert.Equal(request.RedirectUris, response.RedirectUris);
        Assert.Equal(request.PostLogoutRedirectUris, response.PostLogoutRedirectUris);
        Assert.Equal(request.RequestUris, response.RequestUris);
        Assert.Equal(request.BackchannelLogoutUri, response.BackchannelLogoutUri);
        Assert.Equal(request.ClientUri, response.ClientUri);
        Assert.Equal(request.PolicyUri, response.PolicyUri);
        Assert.Equal(request.TosUri, response.TosUri);
        Assert.Equal(request.InitiateLoginUri, response.InitiateLoginUri);
        Assert.Equal(request.LogoUri, response.LogoUri);
        Assert.Null(response.Jwks);
        Assert.Equal(request.JwksUri, response.JwksUri);
        Assert.Equal(request.RequireSignedRequestObject, response.RequireSignedRequestObject);
        Assert.Equal(request.RequireReferenceToken, response.RequireReferenceToken);
        Assert.Equal(request.RequirePushedAuthorizationRequests, response.RequirePushedAuthorizationRequests);
        Assert.Equal(request.SubjectType, response.SubjectType);
        Assert.Equal(request.DefaultMaxAge, response.DefaultMaxAge);
        Assert.Equal(request.DefaultAcrValues, response.DefaultAcrValues);
        Assert.Equal(request.Contacts, response.Contacts);
        Assert.Equal(request.AuthorizationCodeExpiration, response.AuthorizationCodeExpiration);
        Assert.Equal(request.AccessTokenExpiration, response.AccessTokenExpiration);
        Assert.Equal(request.RefreshTokenExpiration, response.RefreshTokenExpiration);
        Assert.Equal(request.JwksExpiration, response.JwksExpiration);
        Assert.Equal(request.RequestUriExpiration, response.RequestUriExpiration);
        Assert.Equal(request.TokenEndpointAuthSigningAlg, response.TokenEndpointAuthSigningAlg);
        Assert.Equal(request.RequestObjectEncryptionAlg, response.RequestObjectEncryptionAlg);
        Assert.Equal(request.RequestObjectEncryptionEnc, response.RequestObjectEncryptionEnc);
        Assert.Equal(request.RequestObjectSigningAlg, response.RequestObjectSigningAlg);
        Assert.Equal(request.UserinfoEncryptedResponseAlg, response.UserinfoEncryptedResponseAlg);
        Assert.Equal(request.UserinfoEncryptedResponseEnc, response.UserinfoEncryptedResponseEnc);
        Assert.Equal(request.UserinfoSignedResponseAlg, response.UserinfoSignedResponseAlg);
        Assert.Equal(request.IdTokenEncryptedResponseAlg, response.IdTokenEncryptedResponseAlg);
        Assert.Equal(request.IdTokenEncryptedResponseEnc, response.IdTokenEncryptedResponseEnc);
        Assert.Equal(request.IdTokenSignedResponseAlg, response.IdTokenSignedResponseAlg);
    }

    [Fact]
    public async Task Process_PutRegister_ExpectRegisterResponse()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var processor = serviceProvider
            .GetRequiredService<IRequestProcessor<RegisterValidatedRequest, ProcessResult<RegisterResponse, Unit>>>();
        var unitOfWork = serviceProvider.GetRequiredService<IUnitOfWork>();

        var client = await GetClient();
        var token = client.ClientTokens.OfType<RegistrationToken>().Single();
        
        var request = new RegisterValidatedRequest
        {
            Method = HttpMethod.Put,
            ClientId = client.Id,
            RegistrationAccessToken = token.Reference,
            ApplicationType = ApplicationType.Web,
            ClientName = "web-app"
        };

        // Act
        await unitOfWork.Begin(CancellationToken.None);
        var processResult = await processor.Process(request, CancellationToken.None);
        await unitOfWork.Commit(CancellationToken.None);

        // Assert
        var response = processResult.Value!;
        client = await IdentityContext
            .Set<Client>()
            .Include(x => x.ResponseTypes)
            .Include(x => x.RedirectUris)
            .Include(x => x.PostLogoutRedirectUris)
            .Include(x => x.RequestUris)
            .Include(x => x.ClientAuthenticationContextReferences)
            .ThenInclude(x => x.AuthenticationContextReference)
            .Include(x => x.Contacts)
            .Include(x => x.Scopes)
            .Include(x => x.GrantTypes)
            .Include(x => x.ClientTokens)
            .SingleAsync(x => x.Id == response.ClientId, CancellationToken.None);

        Assert.Equal(client.Id, response.ClientId);
        Assert.Empty(response.GrantTypes);
        Assert.Empty(response.Scope);
        Assert.Empty(response.ResponseTypes);
        Assert.Empty(response.RedirectUris);
        Assert.Empty(response.PostLogoutRedirectUris);
        Assert.Empty(response.RequestUris);
        Assert.Empty(response.DefaultAcrValues);
        Assert.Empty(response.Contacts);
    }

    [Fact]
    public async Task Process_GetRegister_ExpectRegisterResponse()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var processor = serviceProvider
            .GetRequiredService<IRequestProcessor<RegisterValidatedRequest, ProcessResult<RegisterResponse, Unit>>>();
        var unitOfWork = serviceProvider.GetRequiredService<IUnitOfWork>();
        
        var client = await GetClient();
        var token = client.ClientTokens.OfType<RegistrationToken>().Single();
        
        var request = new RegisterValidatedRequest
        {
            Method = HttpMethod.Get,
            ClientId = client.Id,
            RegistrationAccessToken = token.Reference
        };
        
        // Act
        await unitOfWork.Begin(CancellationToken.None);
        var processResult = await processor.Process(request, CancellationToken.None);
        await unitOfWork.Commit(CancellationToken.None);
        
        // Assert
        var response = processResult.Value!;
        Assert.Equal(client.Id, response.ClientId);
        Assert.Equal(client.CreatedAt.Ticks, response.ClientIdIssuedAt);
        Assert.True(CryptographyHelper.VerifyPassword(client.SecretHash!, response.ClientSecret!));
        Assert.Equal(client.SecretExpiresAt!.Value.Ticks, response.ClientSecretExpiresAt);
        Assert.Equal($"{DiscoveryDocument.RegistrationEndpoint}?client_id={response.ClientId}",
            response.RegistrationClientUri);
        Assert.Equal(client.ClientTokens.Single(x => x.RevokedAt is null).Reference, response.RegistrationAccessToken);
        Assert.Equal(client.ApplicationType, response.ApplicationType);
        Assert.Equal(client.TokenEndpointAuthMethod, response.TokenEndpointAuthMethod);
        Assert.Equal(client.Name, response.ClientName);
        Assert.Equal(client.GrantTypes.Select(x => x.Name), response.GrantTypes);
        Assert.Equal(client.Scopes.Select(x => x.Name), response.Scope);
        Assert.Equal(client.ResponseTypes.Select(x => x.Name), response.ResponseTypes);
        Assert.Equal(client.RedirectUris.Select(x => x.Uri), response.RedirectUris);
        Assert.Equal(client.PostLogoutRedirectUris.Select(x => x.Uri), response.PostLogoutRedirectUris);
        Assert.Equal(client.RequestUris.Select(x => x.Uri), response.RequestUris);
        Assert.Equal(client.BackchannelLogoutUri, response.BackchannelLogoutUri);
        Assert.Equal(client.ClientUri, response.ClientUri);
        Assert.Equal(client.PolicyUri, response.PolicyUri);
        Assert.Equal(client.TosUri, response.TosUri);
        Assert.Equal(client.InitiateLoginUri, response.InitiateLoginUri);
        Assert.Equal(client.LogoUri, response.LogoUri);
        Assert.Null(response.Jwks);
        Assert.Equal(client.JwksUri, response.JwksUri);
        Assert.Equal(client.RequireSignedRequestObject, response.RequireSignedRequestObject);
        Assert.Equal(client.RequireReferenceToken, response.RequireReferenceToken);
        Assert.Equal(client.RequirePushedAuthorizationRequests, response.RequirePushedAuthorizationRequests);
        Assert.Equal(client.SubjectType, response.SubjectType);
        Assert.Equal(client.DefaultMaxAge, response.DefaultMaxAge);
        Assert.Equal(client.ClientAuthenticationContextReferences.Select(x => x.AuthenticationContextReference.Name), response.DefaultAcrValues);
        Assert.Equal(client.Contacts.Select(x => x.Email), response.Contacts);
        Assert.Equal(client.AuthorizationCodeExpiration, response.AuthorizationCodeExpiration);
        Assert.Equal(client.AccessTokenExpiration, response.AccessTokenExpiration);
        Assert.Equal(client.RefreshTokenExpiration, response.RefreshTokenExpiration);
        Assert.Equal(client.JwksExpiration, response.JwksExpiration);
        Assert.Equal(client.RequestUriExpiration, response.RequestUriExpiration);
        Assert.Equal(client.TokenEndpointAuthSigningAlg, response.TokenEndpointAuthSigningAlg);
        Assert.Equal(client.RequestObjectEncryptionAlg, response.RequestObjectEncryptionAlg);
        Assert.Equal(client.RequestObjectEncryptionEnc, response.RequestObjectEncryptionEnc);
        Assert.Equal(client.RequestObjectSigningAlg, response.RequestObjectSigningAlg);
        Assert.Equal(client.UserinfoEncryptedResponseAlg, response.UserinfoEncryptedResponseAlg);
        Assert.Equal(client.UserinfoEncryptedResponseEnc, response.UserinfoEncryptedResponseEnc);
        Assert.Equal(client.UserinfoSignedResponseAlg, response.UserinfoSignedResponseAlg);
        Assert.Equal(client.IdTokenEncryptedResponseAlg, response.IdTokenEncryptedResponseAlg);
        Assert.Equal(client.IdTokenEncryptedResponseEnc, response.IdTokenEncryptedResponseEnc);
        Assert.Equal(client.IdTokenSignedResponseAlg, response.IdTokenSignedResponseAlg);
    }

    [Fact]
    public async Task Process_DeleteRegister_ExpectRegisterResponse()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var processor = serviceProvider
            .GetRequiredService<IRequestProcessor<RegisterValidatedRequest, ProcessResult<RegisterResponse, Unit>>>();
        var unitOfWork = serviceProvider.GetRequiredService<IUnitOfWork>();
        
        var client = await GetClient();
        var token = client.ClientTokens.OfType<RegistrationToken>().Single();
        
        var request = new RegisterValidatedRequest
        {
            Method = HttpMethod.Delete,
            ClientId = client.Id,
            RegistrationAccessToken = token.Reference
        };
        
        // Act
        await unitOfWork.Begin(CancellationToken.None);
        var processResult = await processor.Process(request, CancellationToken.None);
        await unitOfWork.Commit(CancellationToken.None);
        
        // Assert
        Assert.False(processResult.IsSuccess);
        client = await IdentityContext.Set<Client>().SingleOrDefaultAsync(x => x.Id == client.Id, CancellationToken.None);
        Assert.Null(client);
    }

    private async Task<Client> GetClient()
    {
        var jwks = ClientJwkBuilder.GetClientJwks();
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic)
        {
            BackchannelLogoutUri = "https://webapp.authserver.dk/remote-logout",
            ClientUri = "https://webapp.authserver.dk",
            PolicyUri = "https://webapp.authserver.dk/policy",
            TosUri = "https://webapp.authserver.dk/tos",
            Jwks = jwks.PublicJwks,
            JwksUri = "https://webapp.authserver.dk/jwks",
            RequireSignedRequestObject = true,
            RequireReferenceToken = false,
            RequirePushedAuthorizationRequests = true,
            SubjectType = SubjectType.Pairwise,
            DefaultMaxAge = 86400,
            AuthorizationCodeExpiration = 500,
            AccessTokenExpiration = 500,
            RefreshTokenExpiration = 86400,
            SecretExpiration = 86400 * 30,
            JwksExpiration = 86400 * 30,
            RequestUriExpiration = 60,
            TokenEndpointAuthSigningAlg = SigningAlg.RsaSha256,
            RequestObjectEncryptionAlg = EncryptionAlg.RsaPKCS1,
            RequestObjectEncryptionEnc = EncryptionEnc.Aes128CbcHmacSha256,
            RequestObjectSigningAlg = SigningAlg.RsaSha256,
            UserinfoEncryptedResponseAlg = EncryptionAlg.RsaPKCS1,
            UserinfoEncryptedResponseEnc = EncryptionEnc.Aes128CbcHmacSha256,
            UserinfoSignedResponseAlg = SigningAlg.RsaSha256,
            IdTokenEncryptedResponseAlg = EncryptionAlg.RsaPKCS1,
            IdTokenEncryptedResponseEnc = EncryptionEnc.Aes128CbcHmacSha256,
            IdTokenSignedResponseAlg = SigningAlg.RsaSha256
        };
        client.SetSecret(CryptographyHelper.GetRandomString(16));
        
        client.GrantTypes.Add(await GetGrantType(GrantTypeConstants.AuthorizationCode));
        client.Scopes.Add(await GetScope(ScopeConstants.OpenId));
        client.ResponseTypes.Add(await GetResponseType(ResponseTypeConstants.Code));
        client.ClientAuthenticationContextReferences.Add(
            new ClientAuthenticationContextReference(
                client,
                await GetAuthenticationContextReference(LevelOfAssuranceStrict),
                0));
        
        client.RedirectUris.Add(new RedirectUri("https://webapp.authserver.dk/callback", client));
        client.PostLogoutRedirectUris.Add(new PostLogoutRedirectUri("https://webapp.authserver.dk/post-logout", client));
        client.RequestUris.Add(new RequestUri("https://webapp.authserver.dk/request", client));
        client.Contacts.Add(new Contact("info@authserver.dk", client));
        client.ClientTokens.Add(new RegistrationToken(client, "aud", "iss", ScopeConstants.Register));
        client.AuthorizeMessages.Add(
            new AuthorizeMessage(CryptographyHelper.GetRandomString(16), DateTime.UtcNow.AddSeconds(60), client));
        
        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var authorizationGrant = new AuthorizationGrant(
            session,
            client,
            subjectIdentifier.Id,
            await GetAuthenticationContextReference(LevelOfAssuranceStrict));

        authorizationGrant.AuthenticationMethodReferences.Add(
            await GetAuthenticationMethodReference(AuthenticationMethodReferenceConstants.Face));

        authorizationGrant.GrantTokens.Add(
            new GrantAccessToken(authorizationGrant, "aud", "iss", ScopeConstants.OpenId, 500));

        var nonce = CryptographyHelper.GetRandomString(16);
        authorizationGrant.Nonces.Add(new Nonce(nonce, nonce.Sha256(), authorizationGrant));

        var authorizationCode = new AuthorizationCode(authorizationGrant, 60);
        authorizationCode.SetValue(CryptographyHelper.GetRandomString(16));
        authorizationGrant.AuthorizationCodes.Add(authorizationCode);

        await AddEntity(authorizationGrant);
        
        var consentGrant = new ConsentGrant(subjectIdentifier, client);
        consentGrant.ConsentedScopes.Add(await GetScope(ScopeConstants.OpenId));
        consentGrant.ConsentedClaims.Add(await GetClaim(ClaimNameConstants.Name));
        await AddEntity(consentGrant);
        
        return client;
    }
}