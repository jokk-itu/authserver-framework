using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Base64UrlTextEncoder = Microsoft.AspNetCore.Authentication.Base64UrlTextEncoder;

namespace AuthServer.TestClient;

public class OpenIdConnectHandler : RemoteAuthenticationHandler<OpenIdConnectOptions>, IAuthenticationSignOutHandler
{
    private readonly ITokenReplayCache _tokenReplayCache;
    private OpenIdConnectConfiguration? _configuration;
    
    public OpenIdConnectHandler(IOptionsMonitor<OpenIdConnectOptions> options, ILoggerFactory logger, UrlEncoder encoder, ITokenReplayCache tokenReplayCache)
        : base(options, logger, encoder)
    {
        _tokenReplayCache = tokenReplayCache;
    }

    public override async Task<bool> HandleRequestAsync()
    {
        if (Request.Path == "/signout-oidc")
        {
            return await HandleRemoteSignOutAsync();
        }
        else if (Request.Path == "/signout-callback-oidc")
        {
            return await HandleCallbackSignOutAsync();
        }
        
        return await base.HandleRequestAsync();
    }

    protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
    {
        ProtocolMessage? authenticationMessage = null;
        if (HttpMethods.IsGet(Request.Method) && Request.Query.Count != 0)
        {
            var query = Request.Query.Select(x => new KeyValuePair<string, string[]>(x.Key, x.Value.ToArray()!));
            authenticationMessage = new ProtocolMessage(query);
            
            // tokens must not be sent through the front channel
            if (authenticationMessage.GetParameter("id_token") != null || authenticationMessage.GetParameter("access_token") != null)
            {
                return HandleRequestResult.Fail("id_token and access_token are not allowed through front channels");
            }
        }
        else if (HttpMethods.IsPost(Request.Method)
                 && !string.IsNullOrEmpty(Request.ContentType)
                 && Request.ContentType.StartsWith("application/x-www-form-urlencoded"))
        {
            var form = await Request.ReadFormAsync();
            authenticationMessage = new ProtocolMessage(form.Select(x => new KeyValuePair<string, string[]>(x.Key, x.Value.ToArray()!)));
        }

        if (authenticationMessage == null)
        {
            return HandleRequestResult.Fail("missing parameters");
        }
        
        var authenticationProperties = ReadAuthenticationProperties(authenticationMessage);
        if (authenticationProperties is null)
        {
            return HandleRequestResult.Fail("state is invalid");
        }

        if (!ValidateCorrelationId(authenticationProperties))
        {
            return HandleRequestResult.Fail("correlation failed", authenticationProperties);
        }

        var error = authenticationMessage.GetParameter("error");
        if (!string.IsNullOrEmpty(error))
        {
            return HandleRequestResult.Fail(error, authenticationProperties);
        }

        if (_configuration is null)
        {
            _configuration = await Options.ConfigurationManager.GetConfigurationAsync(Context.RequestAborted);
        }

        var tokenRequest = new HttpRequestMessage(HttpMethod.Post, _configuration.TokenEndpoint);
        var tokenParameters = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "authorization_code"),
            new("code", authenticationMessage.GetParameter("code")!),
            new("client_id", Options.ClientId),
            new("client_secret", Options.ClientSecret!),
            new("code_verifier", authenticationProperties.Items["code_verifier"]!),
            new("redirect_uri", authenticationProperties.Items["redirect_uri"]!)
        };

        var resources = authenticationProperties
                .Items["resource"]!
                .Split(' ')
                .Select(resource => new KeyValuePair<string, string>("resource", resource))
                .ToList();

        tokenParameters.AddRange(resources);
        tokenRequest.Content = new FormUrlEncodedContent(tokenParameters);
        var tokenResponse = await Options.Backchannel.SendAsync(tokenRequest, Context.RequestAborted);
        tokenResponse.EnsureSuccessStatusCode();

        var tokenMessage = new ProtocolMessage(await tokenResponse.Content.ReadAsStringAsync());

        var validationParameters = Options.TokenValidationParameters.Clone();
        var jsonWebTokenHandler = new JsonWebTokenHandler();
        validationParameters.IssuerSigningKeys = _configuration.SigningKeys;
        validationParameters.ValidTypes = ["id+jwt"];
        var validationResult = await jsonWebTokenHandler.ValidateTokenAsync(tokenMessage.GetParameter("id_token"), validationParameters);
        if (validationResult.Exception is not null)
        {
            throw validationResult.Exception;
        }

        var validatedIdToken = (validationResult.SecurityToken as JsonWebToken)!;

        authenticationProperties.IssuedUtc = validatedIdToken.ValidFrom;
        authenticationProperties.ExpiresUtc = validatedIdToken.ValidTo;

        var user = new ClaimsPrincipal(validationResult.ClaimsIdentity);
        var nonce = ReadNonceCookie(validatedIdToken.GetClaim("nonce").Value);

        var idSecurityToken = JwtSecurityTokenConverter.Convert(validatedIdToken);

        Options.ProtocolValidator.ValidateTokenResponse(
            new OpenIdConnectProtocolValidationContext
            {
                ClientId = Options.ClientId,
                ProtocolMessage = new OpenIdConnectMessage
                {
                    IdToken = tokenMessage.GetParameter("id_token"),
                    AccessToken = tokenMessage.GetParameter("access_token")
                },
                Nonce = nonce,
                ValidatedIdToken = idSecurityToken
            });

        authenticationProperties.StoreTokens(
        [
            new AuthenticationToken
            {
                Name = "access_token",
                Value = tokenMessage.GetParameter("access_token")!
            },
            new AuthenticationToken
            {
                Name = "id_token",
                Value = tokenMessage.GetParameter("id_token")!
            },
            new AuthenticationToken
            {
                Name = "refresh_token",
                Value = tokenMessage.GetParameter("refresh_token")!
            },
            new AuthenticationToken
            {
                Name = "token_type",
                Value = tokenMessage.GetParameter("token_type")!
            },
            new AuthenticationToken
            {
                Name = "expires_in",
                Value = tokenMessage.GetParameter("expires_in")!
            },
            new AuthenticationToken
            {
                Name = "grant_id",
                Value = tokenMessage.GetParameter("grant_id")!
            }
        ]);

        var userinfoRequest = new HttpRequestMessage(HttpMethod.Get, _configuration.UserInfoEndpoint);
        userinfoRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokenMessage.GetParameter("access_token"));

        var userinfoResponse = await Options.Backchannel.SendAsync(userinfoRequest, Context.RequestAborted);
        userinfoResponse.EnsureSuccessStatusCode();

        var userinfoMessage = await userinfoResponse.Content.ReadAsStringAsync(Context.RequestAborted);
        var userFromUserinfo = JsonDocument.Parse(userinfoMessage);

        Options.ProtocolValidator.ValidateUserInfoResponse(
            new OpenIdConnectProtocolValidationContext
            {
                UserInfoEndpointResponse = userinfoMessage,
                ValidatedIdToken = idSecurityToken
            });

        foreach (var claimAction in Options.ClaimActions)
        {
            claimAction.Run(userFromUserinfo.RootElement, validationResult.ClaimsIdentity, ClaimsIssuer);
        }

        return HandleRequestResult.Success(new AuthenticationTicket(user, authenticationProperties, Scheme.Name));
    }

    private async Task<bool> HandleRemoteSignOutAsync()
    {
        if (!HttpMethods.IsPost(Request.Method))
        {
            throw new InvalidOperationException("must be post");
        }

        if (_configuration is null)
        {
            _configuration = await Options.ConfigurationManager.GetConfigurationAsync(Context.RequestAborted);
        }

        var content = await Request.ReadFormAsync();
        var logoutToken = content["logout_token"].ToString();

        var tokenValidationParameters = Options.TokenValidationParameters.Clone();
        tokenValidationParameters.ValidTypes = ["logout+jwt"];
        tokenValidationParameters.TokenReplayCache = _tokenReplayCache;
        tokenValidationParameters.IssuerSigningKeys = _configuration.SigningKeys;

        var jsonWebTokenHandler = new JsonWebTokenHandler();
        var validationResult = await jsonWebTokenHandler.ValidateTokenAsync(logoutToken, tokenValidationParameters);

        if (validationResult.Exception != null)
        {
            throw validationResult.Exception;
        }

        if (!validationResult.Claims.TryGetValue("events", out var events)
            || events is not JsonElement jsonElement
            || !jsonElement.TryGetProperty("http://schemas.openid.net/event/backchannel-logout", out _))
        {
            Response.StatusCode = StatusCodes.Status400BadRequest;
            Response.Headers.CacheControl = "no-cache, no-store";
            await Response.WriteAsync("{\"error\":\"invalid_request\", \"error_description\":\"logout_token is missing events claim\"}", Context.RequestAborted);
            return false;
        }

        if (validationResult.Claims.ContainsKey("nonce"))
        {
            Response.StatusCode = StatusCodes.Status400BadRequest;
            Response.Headers.CacheControl = "no-cache, no-store";
            await Response.WriteAsync("{\"error\":\"invalid_request\", \"error_description\":\"logout_token has a nonce claim\"}", Context.RequestAborted);
            return false;
        }

        Response.StatusCode = StatusCodes.Status200OK;
        Response.Headers.CacheControl = "no-cache, no-store";
        return true;

        // TODO have a Context where sid and sub can be used
    }

    private Task<bool> HandleCallbackSignOutAsync()
    {
        if (!HttpMethods.IsGet(Request.Method))
        {
            throw new InvalidOperationException("post_logout_redirect_uri only accepts HTTP GET");
        }

        var query = Request.Query
            .Select(x => new KeyValuePair<string, string[]>(x.Key, x.Value.ToArray()!))
            .ToList();

        var message = new ProtocolMessage(query);

        var state = message.GetParameter("state");
        if (string.IsNullOrEmpty(state))
        {
            throw new InvalidOperationException("state is missing");
        }

        var properties = Options.StateDataFormat.Unprotect(message.GetParameter("state"));
        if (properties is null)
        {
            throw new InvalidOperationException("state is invalid");
        }

        Response.Redirect(properties.RedirectUri!);
        return Task.FromResult(true);
    }
    
    public async Task SignOutAsync(AuthenticationProperties? properties)
    {
        properties ??= new AuthenticationProperties();

        if (_configuration is null)
        {
            _configuration = await Options.ConfigurationManager.GetConfigurationAsync(Context.RequestAborted);
        }

        var endSessionParameters = new List<KeyValuePair<string, string>>
        {
            new("client_id", Options.ClientId)
        };

        var redirectUri = properties.RedirectUri;
        if (!string.IsNullOrEmpty(redirectUri))
        {
            endSessionParameters.Add(new("post_logout_redirect_uri", "https://localhost:7226/signout-callback-oidc"));

            var state = Options.StateDataFormat.Protect(properties);
            endSessionParameters.Add(new("state", state));
        }

        var idToken = await Context.GetTokenAsync(Options.SignInScheme, "id_token");
        if (!string.IsNullOrEmpty(idToken))
        {
            endSessionParameters.Add(new("id_token_hint", idToken));
        }

        var message = new ProtocolMessage(endSessionParameters)
        {
            IssuerAddress = _configuration.EndSessionEndpoint
        };

        var endSessionUri = message.BuildRedirectUrl();
        Response.Redirect(endSessionUri);
    }

    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        if (string.IsNullOrEmpty(properties.RedirectUri))
        {
            properties.RedirectUri = OriginalPathBase + OriginalPath + Request.QueryString;
        }

        if (_configuration is null)
        {
            _configuration = await Options.ConfigurationManager.GetConfigurationAsync(Context.RequestAborted);
        }

        var redirectUri = BuildRedirectUri(Options.CallbackPath);
        properties.Items.Add("redirect_uri", redirectUri);

        var parameters = new List<KeyValuePair<string, string>>
        {
            new("client_id", Options.ClientId),
            new("redirect_uri", redirectUri),
            new("response_type", "code"),
            new("scope", string.Join(' ', properties.GetParameter<string[]>("scope")!))
        };

        var resource = properties
            .GetParameter<string[]>("resource")!
            .Select(x => new KeyValuePair<string, string>("resource", x))
            .ToList();

        properties.Items.Add("resource", string.Join(' ', resource.Select(x => x.Value)));
        parameters.AddRange(resource);

        var bytes = RandomNumberGenerator.GetBytes(32);
        var codeVerifier = Base64UrlTextEncoder.Encode(bytes);
        properties.Items.Add("code_verifier", codeVerifier);

        var challengeBytes = SHA256.HashData(Encoding.UTF8.GetBytes(codeVerifier));
        var codeChallenge = WebEncoders.Base64UrlEncode(challengeBytes);

        parameters.Add(new KeyValuePair<string, string>("code_challenge", codeChallenge));
        parameters.Add(new KeyValuePair<string, string>("code_challenge_method", "S256"));

        var nonce = Options.ProtocolValidator.GenerateNonce();
        parameters.Add(new KeyValuePair<string, string>("nonce", nonce));
        var nonceCookieOptions = Options.NonceCookie.Build(Context, TimeProvider.GetUtcNow());
        Response.Cookies.Append(
            Options.NonceCookie.Name + Options.StringDataFormat.Protect(nonce),
            "N",
            nonceCookieOptions);

        GenerateCorrelationId(properties);

        parameters.Add(new KeyValuePair<string, string>("state", Options.StateDataFormat.Protect(properties)));

        var message = new ProtocolMessage(parameters)
        {
            IssuerAddress = _configuration.AuthorizationEndpoint
        };

        var authenticationRedirectUrl = message.BuildRedirectUrl();
        Response.Redirect(authenticationRedirectUrl);
    }

    private AuthenticationProperties? ReadAuthenticationProperties(ProtocolMessage message)
    {
        var state = message.GetParameter("state");
        if (string.IsNullOrEmpty(state))
        {
            return null;
        }
        
        var properties = Options.StateDataFormat.Unprotect(state);
        return properties;
    }

    private string? ReadNonceCookie(string nonce)
    {
        foreach (var nonceKey in Request.Cookies.Keys)
        {
            if (nonceKey.StartsWith(Options.NonceCookie.Name!, StringComparison.Ordinal))
            {
                var nonceDecodedValue = Options.StringDataFormat.Unprotect(
                    nonceKey.Substring(Options.NonceCookie.Name!.Length,
                        nonceKey.Length - Options.NonceCookie.Name.Length));

                if (nonceDecodedValue == nonce)
                {
                    var cookieOptions = Options.NonceCookie.Build(Context, TimeProvider.GetUtcNow());
                    Response.Cookies.Delete(nonceKey, cookieOptions);
                    return nonce;
                }
            }
        }

        return null;
    }
}