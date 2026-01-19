using AuthServer.Authentication.Abstractions;
using AuthServer.Authentication.Models;
using AuthServer.Authorization.Abstractions;
using AuthServer.Authorization.Models;
using AuthServer.Authorize;
using AuthServer.Authorize.Abstractions;
using AuthServer.Core;
using AuthServer.Endpoints.Responses;
using AuthServer.Tests.Core;
using AuthServer.TokenDecoders;
using AuthServer.TokenDecoders.Abstractions;
using AuthServer.UserInterface.Abstractions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.UserInterface;

public class AuthorizeServiceTest : BaseUnitTest
{
    public AuthorizeServiceTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Fact]
    public async Task GetSubject_AuthorizeUser_ExpectSubjectDto()
    {
        // Arrange
        var authorizeUserAccessorMock = new Mock<IUserAccessor<AuthorizeUser>>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authorizeUserAccessorMock);
        });
        var authorizeService = serviceProvider.GetRequiredService<IAuthorizeService>();

        var authorizeUser = new AuthorizeUser("subject", true, "grant");
        authorizeUserAccessorMock
            .Setup(x => x.TryGetUser())
            .Returns(authorizeUser)
            .Verifiable();

        var authorizeRequestDto = new AuthorizeRequestDto();

        // Act
        var subjectDto = await authorizeService.GetSubject(authorizeRequestDto, CancellationToken.None);

        // Assert
        Assert.Equal(authorizeUser.SubjectIdentifier, subjectDto.Subject);
        Assert.Equal(authorizeUser.AuthorizationGrantId, subjectDto.GrantId);
        authorizeUserAccessorMock.Verify();
    }

    [Fact]
    public async Task GetSubject_IdTokenHint_ExpectSubjectDto()
    {
        // Arrange
        var authorizeUserAccessorMock = new Mock<IUserAccessor<AuthorizeUser>>();
        var serverTokenDecoderMock = new Mock<IServerTokenDecoder>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authorizeUserAccessorMock);
            services.AddScopedMock(serverTokenDecoderMock);
        });
        var authorizeService = serviceProvider.GetRequiredService<IAuthorizeService>();

        var authorizeRequestDto = new AuthorizeRequestDto
        {
            IdTokenHint = "id_token"
        };

        var tokenResult = new TokenResult
        {
            Sub = "subject",
            GrantId = "grant",
            ClientId = "client_id",
            Scope = ["scope"],
            Jti = "jti",
            Typ = "typ"
        };
        serverTokenDecoderMock
            .Setup(x => x.Read(authorizeRequestDto.IdTokenHint, CancellationToken.None))
            .ReturnsAsync(tokenResult)
            .Verifiable();

        // Act
        var subjectDto = await authorizeService.GetSubject(authorizeRequestDto, CancellationToken.None);

        // Assert
        Assert.Equal(tokenResult.Sub, subjectDto.Subject);
        Assert.Equal(tokenResult.GrantId, subjectDto.GrantId);
        serverTokenDecoderMock.Verify();
    }

    [Fact]
    public async Task GetSubject_AuthenticatedUser_ExpectSubjectDto()
    {
        // Arrange
        var authorizeUserAccessorMock = new Mock<IUserAccessor<AuthorizeUser>>();
        var serverTokenDecoderMock = new Mock<IServerTokenDecoder>();
        var authenticatedUserAccessorMock = new Mock<IAuthenticatedUserAccessor>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authorizeUserAccessorMock);
            services.AddScopedMock(serverTokenDecoderMock);
            services.AddScopedMock(authenticatedUserAccessorMock);
        });
        var authorizeService = serviceProvider.GetRequiredService<IAuthorizeService>();

        var authenticatedUser = new AuthenticatedUser("subject", "grant");
        authenticatedUserAccessorMock
            .Setup(x => x.GetAuthenticatedUser())
            .ReturnsAsync(authenticatedUser)
            .Verifiable();

        var authorizeRequestDto = new AuthorizeRequestDto();

        // Act
        var subjectDto = await authorizeService.GetSubject(authorizeRequestDto, CancellationToken.None);

        // Assert
        Assert.Equal(authenticatedUser.SubjectIdentifier, subjectDto.Subject);
        Assert.Equal(authenticatedUser.AuthorizationGrantId, subjectDto.GrantId);
        authenticatedUserAccessorMock.Verify();
    }

    [Fact]
    public async Task GetSubject_NoUser_ExpectInvalidOperationException()
    {
        // Arrange
        var authorizeUserAccessorMock = new Mock<IUserAccessor<AuthorizeUser>>();
        var serverTokenDecoderMock = new Mock<IServerTokenDecoder>();
        var authenticatedUserAccessorMock = new Mock<IAuthenticatedUserAccessor>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authorizeUserAccessorMock);
            services.AddScopedMock(serverTokenDecoderMock);
            services.AddScopedMock(authenticatedUserAccessorMock);
        });
        var authorizeService = serviceProvider.GetRequiredService<IAuthorizeService>();

        var authorizeRequestDto = new AuthorizeRequestDto();

        // Act && Assert
        await Assert.ThrowsAsync<InvalidOperationException>(() => authorizeService.GetSubject(authorizeRequestDto, CancellationToken.None));
    }

    [Fact]
    public async Task GetErrorResult_InvalidRequestUri_ExpectBadRequestObjectResult()
    {
        // Arrange
        var authorizeUserAccessorMock = new Mock<IUserAccessor<AuthorizeUser>>();
        var secureRequestServiceMock = new Mock<ISecureRequestService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authorizeUserAccessorMock);
            services.AddScopedMock(secureRequestServiceMock);
        });
        var authorizeService = serviceProvider.GetRequiredService<IAuthorizeService>();

        var oauthError = new OAuthError(ErrorCode.ServerError, "unknown error");

        // Act
        var errorResult = await authorizeService.GetErrorResult(
            "request_uri",
            "client_id",
            oauthError,
            new DefaultHttpContext(),
            CancellationToken.None);

        // Assert
        Assert.IsType<BadRequestObjectResult>(errorResult);
        Assert.Equal(oauthError, (errorResult as BadRequestObjectResult)!.Value);
    }

    [Fact]
    public async Task GetErrorResult_ValidRequestUri_ExpectRedirectResult()
    {
        // Arrange
        var authorizeUserAccessorMock = new Mock<IUserAccessor<AuthorizeUser>>();
        var secureRequestServiceMock = new Mock<ISecureRequestService>();
        var authorizeResponseBuilderMock = new Mock<IAuthorizeResponseBuilder>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authorizeUserAccessorMock);
            services.AddScopedMock(secureRequestServiceMock);
            services.AddScopedMock(authorizeResponseBuilderMock);
        });
        var authorizeService = serviceProvider.GetRequiredService<IAuthorizeService>();

        const string requestUri = "request_uri";
        const string clientId = "client_id";

        var requestDto = new AuthorizeRequestDto();
        secureRequestServiceMock
            .Setup(x =>
                x.GetRequestByPushedRequest(requestUri, clientId, CancellationToken.None))
            .ReturnsAsync(requestDto)
            .Verifiable();

        var redirectResult = new RedirectResult("http://127.0.0.1/sign-in-callback");
        var oauthError = new OAuthError(ErrorCode.ServerError, "unknown error");
        authorizeResponseBuilderMock
            .Setup(x =>
                x.BuildResponse(
                    It.IsAny<AuthorizeRequest>(),
                    It.Is<IDictionary<string, string>>(y =>
                        y[Parameter.Error] == oauthError.Error
                        && y[Parameter.ErrorDescription] == oauthError.ErrorDescription),
                    CancellationToken.None))
            .ReturnsAsync(redirectResult)
            .Verifiable();

        // Act
        var errorResult = await authorizeService.GetErrorResult(
            requestUri,
            clientId,
            oauthError,
            new DefaultHttpContext(),
            CancellationToken.None);

        // Assert
        Assert.Equal(redirectResult, errorResult);
        secureRequestServiceMock.Verify();
        authorizeResponseBuilderMock.Verify();
    }

    [Fact]
    public async Task GetValidatedRequest_ValidRequestUri_ExpectAuthorizeRequestDto()
    {
        // Arrange
        var secureRequestServiceMock = new Mock<ISecureRequestService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(secureRequestServiceMock);
        });
        var authorizeService = serviceProvider.GetRequiredService<IAuthorizeService>();

        const string requestUri = "request_uri";
        const string clientId = "client_id";

        var requestDto = new AuthorizeRequestDto();
        secureRequestServiceMock
            .Setup(x => x.GetRequestByPushedRequest(requestUri, clientId, CancellationToken.None))
            .ReturnsAsync(requestDto)
            .Verifiable();

        // Act
        var authorizeRequestDto = await authorizeService.GetValidatedRequest(requestUri, clientId, CancellationToken.None);

        // Assert
        Assert.Equal(requestDto, authorizeRequestDto);
    }
}