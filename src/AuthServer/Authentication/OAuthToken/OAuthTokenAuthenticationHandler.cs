using AuthServer.Authentication.Abstractions;
using AuthServer.Authorization.Abstractions;
using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Core.Abstractions;
using AuthServer.Entities;
using AuthServer.Extensions;
using AuthServer.Helpers;
using AuthServer.Options;
using AuthServer.Repositories.Abstractions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Claim = System.Security.Claims.Claim;

namespace AuthServer.Authentication.OAuthToken;
internal class OAuthTokenAuthenticationHandler : AuthenticationHandler<OAuthTokenAuthenticationOptions>
{
    private readonly AuthorizationDbContext _authorizationDbContext;
    private readonly IUserClaimService _userClaimService;
    private readonly IOptionsMonitor<JwksDocument> _jwksDocumentOptions;
    private readonly IOptionsMonitor<DiscoveryDocument> _discoveryDocumentOptions;
    private readonly IDPoPService _dPoPService;
    private readonly INonceRepository _nonceRepository;
    private readonly IUnitOfWork _unitOfWork;

    public OAuthTokenAuthenticationHandler(
        IOptionsMonitor<OAuthTokenAuthenticationOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        AuthorizationDbContext authorizationDbContext,
        IUserClaimService userClaimService,
        IOptionsMonitor<JwksDocument> jwksDocumentOptions,
        IOptionsMonitor<DiscoveryDocument> discoveryDocumentOptions,
        IDPoPService dPoPService,
        INonceRepository nonceRepository,
        IUnitOfWork unitOfWork)
        : base(options, logger, encoder)
    {
        _authorizationDbContext = authorizationDbContext;
        _userClaimService = userClaimService;
        _jwksDocumentOptions = jwksDocumentOptions;
        _discoveryDocumentOptions = discoveryDocumentOptions;
        _dPoPService = dPoPService;
        _nonceRepository = nonceRepository;
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

        ClaimsIdentity? claimsIdentity;
        AuthenticateResult? result;
        if (TokenHelper.IsJsonWebToken(token))
        {
            (claimsIdentity, result) = await AuthenticateJsonWebToken(token, scheme);
        }
        else
        {
            (claimsIdentity, result) = await AuthenticateReferenceToken(token, scheme);
        }

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

    private async Task<(ClaimsIdentity?, AuthenticateResult?)> AuthenticateReferenceToken(string token, string scheme)
    {
        var query = await _authorizationDbContext
            .Set<Token>()
            .Where(t => t.Reference == token)
            .Select(t => new
            {
                Token = t,
                ClientIdFromClientToken = (t as ClientToken)!.Client.Id,
                ClientIdFromGrantToken = (t as GrantToken)!.AuthorizationGrant.Client.Id,
                GrantId = (t as GrantToken)!.AuthorizationGrant.Id,
                SubjectIdentifier = (t as GrantToken)!.AuthorizationGrant.Session.SubjectIdentifier.Id,
                (t as GrantToken)!.AuthorizationGrant.Subject,
                SessionId = (t as GrantToken)!.AuthorizationGrant.Session.Id
            })
            .SingleOrDefaultAsync();

        if (query is null)
        {
            Logger.LogDebug("Token {Token} does not exist", token);
            return (null, AuthenticateResult.Fail(new OAuthTokenException(ErrorCode.InvalidToken, "token does not exist", scheme)));
        }

        if (!query.Token.Audience.Split(' ').Contains(_discoveryDocumentOptions.CurrentValue.Issuer))
        {
            return (null, AuthenticateResult.Fail(new OAuthTokenException(ErrorCode.InvalidToken, "token does not have AuthServer as audience", scheme)));
        }

        if (query.Token.RevokedAt != null)
        {
            return (null, AuthenticateResult.Fail(new OAuthTokenException(ErrorCode.InvalidToken, "token is revoked", scheme)));
        }

        if (query.Token.IssuedAt > DateTime.UtcNow)
        {
            return (null, AuthenticateResult.Fail(new OAuthTokenException(ErrorCode.InvalidToken, "token is not yet active", scheme)));
        }

        if (query.Token.ExpiresAt < DateTime.UtcNow)
        {
            return (null, AuthenticateResult.Fail(new OAuthTokenException(ErrorCode.InvalidToken, "token has expired", scheme)));
        }

        var clientId = query.Token is GrantAccessToken
            ? query.ClientIdFromGrantToken
            : query.ClientIdFromClientToken;

        var dPoPAuthenticationResult = await ValidateDPoP(token, clientId, query.Token.Jkt, scheme);
        if (dPoPAuthenticationResult is not null)
        {
            return (null, dPoPAuthenticationResult);
        }

        var claims = new List<Claim>();
        if (query.Token.Scope is not null)
        {
            claims.Add(new Claim(ClaimNameConstants.Scope, query.Token.Scope));
        }

        claims.Add(new Claim(ClaimNameConstants.ClientId, clientId));

        if (query.Token is GrantToken)
        {
            claims.Add(new Claim(ClaimNameConstants.GrantId, query.GrantId));
            claims.Add(new Claim(ClaimNameConstants.Sid, query.SessionId));
            claims.Add(new Claim(ClaimNameConstants.Sub, query.Subject));

            var userClaims = await _userClaimService.GetClaims(query.SubjectIdentifier, CancellationToken.None);
            claims.AddRange(userClaims);
        }
        else if (query.Token is ClientToken)
        {
            claims.Add(new Claim(ClaimNameConstants.Sub, query.ClientIdFromClientToken));
        }

        return (new ClaimsIdentity(claims), null);
    }

    private async Task<(ClaimsIdentity?, AuthenticateResult?)> AuthenticateJsonWebToken(string token, string scheme)
    {
        var tokenHandler = new JsonWebTokenHandler();
        var tokenSigningKey = _jwksDocumentOptions.CurrentValue.GetTokenSigningKey();
        var tokenValidationParameters = new TokenValidationParameters
        {
            ClockSkew = TimeSpan.FromSeconds(0),
            IssuerSigningKey = tokenSigningKey.Key,
            ValidIssuer = _discoveryDocumentOptions.CurrentValue.Issuer,
            ValidAudience = _discoveryDocumentOptions.CurrentValue.Issuer,
            ValidTypes = [TokenTypeHeaderConstants.AccessToken],
            ValidAlgorithms = [tokenSigningKey.Alg.GetDescription()],
            RoleClaimType = ClaimNameConstants.Roles,
            NameClaimType = ClaimNameConstants.Name
        };
        var validationResult = await tokenHandler.ValidateTokenAsync(token, tokenValidationParameters);
        if (!validationResult.IsValid)
        {
            Logger.LogWarning(validationResult.Exception, "Token validation failed");
            return (null, AuthenticateResult.Fail(new OAuthTokenException(ErrorCode.InvalidToken, "token is not valid", scheme)));
        }

        var clientId = validationResult.Claims[ClaimNameConstants.ClientId].ToString()!;

        string? jkt = null;
        if (validationResult.Claims.TryGetValue(ClaimNameConstants.Cnf, out var cnfClaim)
            && cnfClaim is JsonElement jsonElement
            && jsonElement.TryGetProperty(ClaimNameConstants.Jkt, out var jktNode))
        {
            jkt = jktNode!.ToString();
        }

        var dPoPAuthenticationResult = await ValidateDPoP(token, clientId, jkt, scheme);
        if (dPoPAuthenticationResult is not null)
        {
            return (null, dPoPAuthenticationResult);
        }

        return (validationResult.ClaimsIdentity, null);
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
