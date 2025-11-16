using AuthServer.Authentication.Abstractions;
using AuthServer.Authorization.Abstractions;
using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Core.Abstractions;
using AuthServer.Extensions;
using AuthServer.Helpers;
using AuthServer.Options;
using AuthServer.Repositories.Abstractions;
using AuthServer.TokenDecoders;
using AuthServer.TokenDecoders.Abstractions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using Claim = System.Security.Claims.Claim;

namespace AuthServer.Authentication.OAuthToken;
internal class OAuthTokenAuthenticationHandler : AuthenticationHandler<OAuthTokenAuthenticationOptions>
{
    private readonly IUserClaimService _userClaimService;
    private readonly IOptionsMonitor<DiscoveryDocument> _discoveryDocumentOptions;
    private readonly IDPoPService _dPoPService;
    private readonly INonceRepository _nonceRepository;
    private readonly IServerTokenDecoder _serverTokenDecoder;
    private readonly IUnitOfWork _unitOfWork;

    public OAuthTokenAuthenticationHandler(
        IOptionsMonitor<OAuthTokenAuthenticationOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        IUserClaimService userClaimService,
        IOptionsMonitor<DiscoveryDocument> discoveryDocumentOptions,
        IDPoPService dPoPService,
        INonceRepository nonceRepository,
        IServerTokenDecoder serverTokenDecoder,
        IUnitOfWork unitOfWork)
        : base(options, logger, encoder)
    {
        _userClaimService = userClaimService;
        _discoveryDocumentOptions = discoveryDocumentOptions;
        _dPoPService = dPoPService;
        _nonceRepository = nonceRepository;
        _serverTokenDecoder = serverTokenDecoder;
        _unitOfWork = unitOfWork;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var hasAuthorizationHeader = AuthenticationHeaderValue.TryParse(Context.Request.Headers.Authorization, out var parsedHeader);
        if (!hasAuthorizationHeader)
        {
            return AuthenticateResult.NoResult();
        }

        var scheme = parsedHeader!.Scheme;
        if (!TokenTypeSchemaConstants.TokenTypeSchemas.Contains(scheme))
        {
            return AuthenticateResult.NoResult();
        }
        
        var token = parsedHeader.Parameter;
        if (string.IsNullOrEmpty(token))
        {
            return AuthenticateResult.Fail(new OAuthTokenException(ErrorCode.InvalidRequest, "token is null", scheme));
        }

        var (claimsIdentity, result) = await AuthenticateToken(token, scheme, Request.HttpContext.RequestAborted);

        if (result is not null)
        {
            return result;
        }

        var authenticationProperties = new AuthenticationProperties();
        authenticationProperties.StoreTokens(
        [
            new AuthenticationToken
            {
                Name = Parameter.AccessToken,
                Value = token!
            },
            new AuthenticationToken
            {
                Name = "TokenTypeScheme",
                Value = scheme
            }
        ]);
        
        var principal = new ClaimsPrincipal(claimsIdentity!);
        var authenticationTicket = new AuthenticationTicket(principal, authenticationProperties, OAuthTokenAuthenticationDefaults.AuthenticationScheme);
        return AuthenticateResult.Success(authenticationTicket);
    }

    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        var authenticationResult = await HandleAuthenticateOnceSafeAsync();
        var authenticateBuilder = new StringBuilder();
        if (authenticationResult.None)
        {
            AppendBearer(authenticateBuilder, null);
            authenticateBuilder.Append(", ");
            AppendDPoP(authenticateBuilder, null);
        }
        else if (authenticationResult.Failure is OAuthTokenException oAuthTokenException)
        {
            AppendBearer(authenticateBuilder, oAuthTokenException);
            authenticateBuilder.Append(", ");
            AppendDPoP(authenticateBuilder, oAuthTokenException);

            if (oAuthTokenException.Error == ErrorCode.UseDPoPNonce)
            {
                Response.Headers[Parameter.DPoPNonce] = oAuthTokenException.DPoPNonce;
            }
        }

        Response.Headers.WWWAuthenticate = authenticateBuilder.ToString();
        Response.StatusCode = StatusCodes.Status401Unauthorized;
    }

    protected override async Task HandleForbiddenAsync(AuthenticationProperties properties)
    {
        var tokenTypeScheme = (await Context.GetTokenAsync(OAuthTokenAuthenticationDefaults.AuthenticationScheme,"TokenTypeScheme"))!;

        var error = properties.GetParameter<string>(OAuthTokenAuthenticationDefaults.ErrorParameter);
        var errorDescription = properties.GetParameter<string>(OAuthTokenAuthenticationDefaults.ErrorDescriptionParameter);
        var insufficientScope = properties.GetParameter<string>(OAuthTokenAuthenticationDefaults.ScopeParameter);

        OAuthTokenException oAuthTokenException;
        if (error is not null && errorDescription is not null)
        {
            oAuthTokenException = new OAuthTokenException(error, errorDescription, tokenTypeScheme);
        }
        else if (insufficientScope is not null)
        {
            oAuthTokenException = new OAuthTokenException(ErrorCode.InsufficientScope, "provide a token with the required scope", tokenTypeScheme, insufficientScope);
        }
        else
        {
            oAuthTokenException = new OAuthTokenException(ErrorCode.InvalidToken, "token is invalid", tokenTypeScheme);
        }

        var authenticateBuilder = new StringBuilder();
        AppendBearer(authenticateBuilder, oAuthTokenException);
        authenticateBuilder.Append(", ");
        AppendDPoP(authenticateBuilder, oAuthTokenException);

        Response.Headers.WWWAuthenticate = authenticateBuilder.ToString();
        Response.StatusCode = StatusCodes.Status403Forbidden;
    }

    private static void AppendBearer(StringBuilder authenticateBuilder, OAuthTokenException? exception)
    {
        authenticateBuilder.Append("Bearer");
        if (exception?.Scheme == TokenTypeSchemaConstants.Bearer)
        {
            authenticateBuilder.Append($" error=\"{exception.Error}\", error_description=\"{exception.ErrorDescription}\"");
            if (exception.Scope is not null)
            {
                authenticateBuilder.Append($", scope=\"{exception.Scope}\"");
            }
        }
    }

    private void AppendDPoP(StringBuilder authenticateBuilder, OAuthTokenException? exception)
    {
        var dPoPAlgorithms = string.Join(' ', _discoveryDocumentOptions.CurrentValue.DPoPSigningAlgValuesSupported);
        authenticateBuilder.Append($"DPoP algs=\"{dPoPAlgorithms}\"");
        if (exception?.Scheme == TokenTypeSchemaConstants.DPoP)
        {
            authenticateBuilder.Append($", error=\"{exception.Error}\", error_description=\"{exception.ErrorDescription}\"");
            if (exception.Scope is not null)
            {
                authenticateBuilder.Append($", scope=\"{exception.Scope}\"");
            }
        }
    }

    private async Task<(ClaimsIdentity?, AuthenticateResult?)> AuthenticateToken(string token, string scheme, CancellationToken cancellationToken)
    {
        var tokenResult = await _serverTokenDecoder.Validate(
            token,
            new ServerTokenDecodeArguments
            {
                Audiences = [],
                TokenTypes = [ TokenTypeHeaderConstants.AccessToken ],
                ValidateLifetime = true
            },
            cancellationToken);

        if (tokenResult is null)
        {
            var authenticateResult = AuthenticateResult.Fail(new OAuthTokenException(ErrorCode.InvalidToken, "token is not valid", scheme));
            return (null, authenticateResult);
        }

        var dPoPAuthenticateResult = await ValidateDPoP(token, tokenResult.ClientId, tokenResult.Jkt, scheme);
        if (dPoPAuthenticateResult is not null)
        {
            return (null, dPoPAuthenticateResult);
        }

        var claims = new List<Claim>
        {
            new(ClaimNameConstants.Scope, string.Join(' ', tokenResult.Scope)),
            new(ClaimNameConstants.ClientId, tokenResult.ClientId),
            new(ClaimNameConstants.Sub, tokenResult.Sub)
        };

        if (tokenResult.GrantId is not null)
        {
            claims.Add(new Claim(ClaimNameConstants.GrantId, tokenResult.GrantId));
        }

        if (tokenResult.Sid is not null)
        {
            claims.Add(new Claim(ClaimNameConstants.Sid, tokenResult.Sid));

            var userClaims = await _userClaimService.GetClaims(tokenResult.Sub, CancellationToken.None);
            claims.AddRange(userClaims);
        }

        return (new ClaimsIdentity(claims), null);
    }

    private async Task<AuthenticateResult?> ValidateDPoP(string token, string clientId, string? jkt, string scheme)
    {
        if (scheme != TokenTypeSchemaConstants.DPoP && jkt is not null)
        {
            return AuthenticateResult.Fail(new OAuthTokenException(ErrorCode.InvalidToken, "token is DPoP bound, but scheme is not DPoP", scheme));
        }

        if (scheme == TokenTypeSchemaConstants.DPoP && jkt is null)
        {
            return AuthenticateResult.Fail(new OAuthTokenException(ErrorCode.InvalidToken, "token is not DPoP bound, but scheme is DPoP", scheme));
        }

        if (scheme != TokenTypeSchemaConstants.DPoP)
        {
            return null;
        }

        var dPoP = Context.Request.Headers.GetValue(Parameter.DPoP);
        if (string.IsNullOrEmpty(dPoP))
        {
            return AuthenticateResult.Fail(new OAuthTokenException(ErrorCode.InvalidRequest, "DPoP header is missing", scheme));
        }

        var dPoPValidationResult = await _dPoPService.ValidateDPoP(dPoP, clientId, Context.RequestAborted);
        if (dPoPValidationResult is { IsValid: false, RenewDPoPNonce: false })
        {
            return AuthenticateResult.Fail(new OAuthTokenException(ErrorCode.InvalidDPoPProof, "DPoP proof is invalid", scheme));
        }

        if (dPoPValidationResult is { IsValid: false, RenewDPoPNonce: true })
        {
            await _unitOfWork.Begin(Context.RequestAborted);
            var dPoPNonce = await _nonceRepository.CreateDPoPNonce(clientId, Context.RequestAborted);
            await _unitOfWork.Commit(Context.RequestAborted);

            return AuthenticateResult.Fail(new OAuthTokenException(ErrorCode.UseDPoPNonce, "use the provided DPoP nonce", scheme, null, dPoPNonce));
        }

        var accessTokenHash = CryptographyHelper.HashToken(token);
        if (accessTokenHash != dPoPValidationResult.AccessTokenHash)
        {
            return AuthenticateResult.Fail(new OAuthTokenException(ErrorCode.InvalidToken, "DPoP ath claim is not equal to provided access token", scheme));
        }

        if (dPoPValidationResult.DPoPJkt != jkt)
        {
            return AuthenticateResult.Fail(new OAuthTokenException(ErrorCode.InvalidToken, "DPoP jkt is not equal to provided access token", scheme));
        }

        return null;
    }
}
