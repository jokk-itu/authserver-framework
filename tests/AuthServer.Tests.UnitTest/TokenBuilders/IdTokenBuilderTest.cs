﻿using AuthServer.Authentication.Abstractions;
using AuthServer.Constants;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Extensions;
using AuthServer.Helpers;
using AuthServer.Tests.Core;
using AuthServer.TokenBuilders;
using AuthServer.TokenBuilders.Abstractions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.TokenBuilders;

public class IdTokenBuilderTest(ITestOutputHelper outputHelper) : BaseUnitTest(outputHelper)
{
    [Theory]
    [InlineData(SigningAlg.RsaSha256)]
    [InlineData(SigningAlg.RsaSha384)]
    [InlineData(SigningAlg.RsaSha512)]
    [InlineData(SigningAlg.RsaSsaPssSha256)]
    [InlineData(SigningAlg.RsaSsaPssSha384)]
    [InlineData(SigningAlg.RsaSsaPssSha512)]
    [InlineData(SigningAlg.EcdsaSha256)]
    [InlineData(SigningAlg.EcdsaSha384)]
    [InlineData(SigningAlg.EcdsaSha512)]
    public async Task BuildToken_NoRegisteredEncryption_IsOnlySignedToken(SigningAlg signingAlg)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(new Mock<IClientJwkService>());
        });
        var idTokenBuilder = serviceProvider.GetRequiredService<ITokenBuilder<IdTokenArguments>>();
        var authorizationGrant = await GetAuthorizationGrant(signingAlg);

        // Act
        var token = await idTokenBuilder.BuildToken(new IdTokenArguments
        {
            AuthorizationGrantId = authorizationGrant.Id,
            Scope = [ ScopeConstants.OpenId, ScopeConstants.Profile ]
        }, CancellationToken.None);

        // Assert
        var jsonWebTokenHandler = new JsonWebTokenHandler();
        var validatedTokenResult = await jsonWebTokenHandler.ValidateTokenAsync(token, new TokenValidationParameters
        {
            IssuerSigningKey = JwksDocument.GetSigningKey(signingAlg),
            ValidAudience = authorizationGrant.Client.Id,
            ValidIssuer = DiscoveryDocument.Issuer,
            ValidTypes = [TokenTypeHeaderConstants.IdToken],
            NameClaimType = ClaimNameConstants.Name,
            RoleClaimType = ClaimNameConstants.Roles
        });

        Assert.NotNull(validatedTokenResult);
        Assert.Null(validatedTokenResult.Exception);
        Assert.True(validatedTokenResult.IsValid);
        Assert.Equal(authorizationGrant.Session.Id, validatedTokenResult.Claims[ClaimNameConstants.Sid].ToString());
        Assert.Equal(authorizationGrant.Subject, validatedTokenResult.Claims[ClaimNameConstants.Sub].ToString());
        Assert.Equal(authorizationGrant.Client.Id, validatedTokenResult.Claims[ClaimNameConstants.ClientId].ToString());
        Assert.Equal(authorizationGrant.Id, validatedTokenResult.Claims[ClaimNameConstants.GrantId].ToString());
        Assert.Equal(authorizationGrant.Nonces.Single().Value, validatedTokenResult.Claims[ClaimNameConstants.Nonce].ToString());
        Assert.Equal(UserConstants.Name, validatedTokenResult.ClaimsIdentity.Name);
        Assert.Equal(LevelOfAssuranceLow, validatedTokenResult.Claims[ClaimNameConstants.Acr].ToString());
        Assert.Equal(AuthenticationMethodReferenceConstants.Password, validatedTokenResult.Claims[ClaimNameConstants.Amr].ToString());
        Assert.NotNull(validatedTokenResult.Claims[ClaimNameConstants.Jti]);
    }

    [Theory]
    [InlineData(EncryptionAlg.RsaPKCS1, EncryptionEnc.Aes128CbcHmacSha256)]
    [InlineData(EncryptionAlg.RsaPKCS1, EncryptionEnc.Aes192CbcHmacSha384)]
    [InlineData(EncryptionAlg.RsaPKCS1, EncryptionEnc.Aes256CbcHmacSha512)]
    [InlineData(EncryptionAlg.RsaOAEP, EncryptionEnc.Aes128CbcHmacSha256)]
    [InlineData(EncryptionAlg.RsaOAEP, EncryptionEnc.Aes192CbcHmacSha384)]
    [InlineData(EncryptionAlg.RsaOAEP, EncryptionEnc.Aes256CbcHmacSha512)]
    public async Task BuildToken_RsaRegisteredEncryption_IsEncryptedAndSignedToken(EncryptionAlg encryptionAlg, EncryptionEnc encryptionEnc)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var idTokenBuilder = serviceProvider.GetRequiredService<ITokenBuilder<IdTokenArguments>>();
        var clientJwk = ClientJwkBuilder.GetClientJwks(SigningAlg.RsaSha256, encryptionAlg);
        var authorizationGrant = await GetAuthorizationGrant(SigningAlg.RsaSha256, encryptionAlg, encryptionEnc, clientJwk.PublicJwks);

        // Act
        var token = await idTokenBuilder.BuildToken(new IdTokenArguments
        {
            AuthorizationGrantId = authorizationGrant.Id,
            Scope = [ScopeConstants.OpenId ]
        }, CancellationToken.None);

        // Assert
        var jsonWebTokenHandler = new JsonWebTokenHandler();
        var validatedTokenResult = await jsonWebTokenHandler.ValidateTokenAsync(token, new TokenValidationParameters
        {
            IssuerSigningKey = JwksDocument.GetSigningKey(SigningAlg.RsaSha256),
            TokenDecryptionKeys = JsonWebKeySet.Create(clientJwk.PrivateJwks).Keys,
            ValidAudience = authorizationGrant.Client.Id,
            ValidIssuer = DiscoveryDocument.Issuer,
            ValidTypes = [TokenTypeHeaderConstants.IdToken]
        });

        Assert.NotNull(validatedTokenResult);
        Assert.Null(validatedTokenResult.Exception);
        Assert.True(validatedTokenResult.IsValid);
    }

    [Theory]
    [InlineData(EncryptionAlg.EcdhEsA128KW, EncryptionEnc.Aes128CbcHmacSha256)]
    [InlineData(EncryptionAlg.EcdhEsA192KW, EncryptionEnc.Aes192CbcHmacSha384)]
    [InlineData(EncryptionAlg.EcdhEsA256KW, EncryptionEnc.Aes256CbcHmacSha512)]
    public async Task BuildToken_EcdhRegisteredEncryption_IsEncryptedAndSignedToken(EncryptionAlg encryptionAlg, EncryptionEnc encryptionEnc)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var idTokenBuilder = serviceProvider.GetRequiredService<ITokenBuilder<IdTokenArguments>>();
        var clientJwk = ClientJwkBuilder.GetClientJwks(SigningAlg.RsaSha256, encryptionAlg);
        var authorizationGrant = await GetAuthorizationGrant(SigningAlg.RsaSha256, encryptionAlg, encryptionEnc, clientJwk.PublicJwks);

        // Act
        var token = await idTokenBuilder.BuildToken(new IdTokenArguments
        {
            AuthorizationGrantId = authorizationGrant.Id,
            Scope = [ScopeConstants.OpenId, ScopeConstants.Profile]
        }, CancellationToken.None);

        // Assert
        var clientJsonWebKey = JsonWebKeySet.Create(clientJwk.PrivateJwks).Keys
            .Single(x => x.Alg == encryptionAlg.GetDescription());
        var clientPrivateKey = TokenHelper.ConvertToSecurityKey(clientJsonWebKey, true);
        var jsonWebTokenHandler = new JsonWebTokenHandler();
        var validatedTokenResult = await jsonWebTokenHandler.ValidateTokenAsync(token, new TokenValidationParameters
        {
            IssuerSigningKey = JwksDocument.GetSigningKey(SigningAlg.RsaSha256),
            TokenDecryptionKeyResolver = (_, _, _, _) => [clientPrivateKey],
            TokenDecryptionKey = JwksDocument.GetEncryptionKey(encryptionAlg),
            ValidAudience = authorizationGrant.Client.Id,
            ValidIssuer = DiscoveryDocument.Issuer,
            ValidTypes = [TokenTypeHeaderConstants.IdToken]
        });

        Assert.NotNull(validatedTokenResult);
        Assert.Null(validatedTokenResult.Exception);
        Assert.True(validatedTokenResult.IsValid);
    }

    private async Task<AuthorizationGrant> GetAuthorizationGrant(SigningAlg signingAlg)
    {
        var openIdScope = await IdentityContext
            .Set<Scope>()
            .SingleAsync(x => x.Name == ScopeConstants.OpenId);

        var profileScope = await IdentityContext
            .Set<Scope>()
            .SingleAsync(x => x.Name == ScopeConstants.Profile);

        var client = new Client("PinguApp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            IdTokenSignedResponseAlg = signingAlg,
            SubjectType = SubjectType.Pairwise,
            RequireIdTokenClaims = true
        };

        client.Scopes.Add(openIdScope);
        client.Scopes.Add(profileScope);

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var authenticationMethodReference = await GetAuthenticationMethodReference(AuthenticationMethodReferenceConstants.Password);
        var authenticationContextReference = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, authenticationContextReference)
        {
            AuthenticationMethodReferences = [authenticationMethodReference]
        };

        var value = CryptographyHelper.GetRandomString(32);
        var nonce = new AuthorizationGrantNonce(value, value.Sha256(), authorizationGrant);
        authorizationGrant.Nonces.Add(nonce);

        var nameClaim = await IdentityContext.Set<Claim>().SingleAsync(x => x.Name == ClaimNameConstants.Name);
        var nameClaimConsent = new ClaimConsent(subjectIdentifier, client, nameClaim);
        var openIdScopeConsent = new ScopeConsent(subjectIdentifier, client, openIdScope);
        var profileScopeConsent = new ScopeConsent(subjectIdentifier, client, profileScope);

        var authorizationGrantNameClaimConsent = new AuthorizationGrantClaimConsent(nameClaimConsent, authorizationGrant);
        var authorizationGrantOpenIdScopeConsent = new AuthorizationGrantScopeConsent(openIdScopeConsent, authorizationGrant, "https://weather.authserver.dk");
        var authorizationGrantProfileScopeConsent = new AuthorizationGrantScopeConsent(profileScopeConsent, authorizationGrant, "https://weather.authserver.dk");

        authorizationGrant.AuthorizationGrantConsents.Add(authorizationGrantNameClaimConsent);
        authorizationGrant.AuthorizationGrantConsents.Add(authorizationGrantOpenIdScopeConsent);
        authorizationGrant.AuthorizationGrantConsents.Add(authorizationGrantProfileScopeConsent);

        await AddEntity(authorizationGrant);

        return authorizationGrant;
    }

    private async Task<AuthorizationGrant> GetAuthorizationGrant(SigningAlg signingAlg, EncryptionAlg encryptionAlg, EncryptionEnc encryptionEnc, string clientJwks)
    {
        var openIdScope = await IdentityContext
            .Set<Scope>()
            .SingleAsync(x => x.Name == ScopeConstants.OpenId);

        var profileScope = await IdentityContext
            .Set<Scope>()
            .SingleAsync(x => x.Name == ScopeConstants.Profile);

        var client = new Client("PinguApp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            IdTokenSignedResponseAlg = signingAlg,
            IdTokenEncryptedResponseAlg = encryptionAlg,
            IdTokenEncryptedResponseEnc = encryptionEnc,
            SubjectType = SubjectType.Pairwise,
            Jwks = clientJwks,
            RequireIdTokenClaims = false,
            RequireConsent = false
        };

        client.Scopes.Add(openIdScope);
        client.Scopes.Add(profileScope);

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var authenticationMethodReference = await GetAuthenticationMethodReference(AuthenticationMethodReferenceConstants.Password);
        var authenticationContextReference = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, authenticationContextReference)
        {
            AuthenticationMethodReferences = [authenticationMethodReference]
        };

        var value = CryptographyHelper.GetRandomString(32);
        var nonce = new AuthorizationGrantNonce(value, value.Sha256(), authorizationGrant);
        authorizationGrant.Nonces.Add(nonce);

        await AddEntity(authorizationGrant);

        return authorizationGrant;
    }
}