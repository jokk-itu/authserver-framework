using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace AuthServer.TestClient;

public class OpenIdConnectHandler : RemoteAuthenticationHandler<OpenIdConnectOptions>, IAuthenticationSignOutHandler
{
    private OpenIdConnectConfiguration? _configuration;
    
    public OpenIdConnectHandler(IOptionsMonitor<OpenIdConnectOptions> options, ILoggerFactory logger, UrlEncoder encoder)
        : base(options, logger, encoder)
    {
    }

    public override async Task<bool> HandleRequestAsync()
    {
        if (Request.Path == "signout-oidc")
        {
            return await HandleRemoteSignOutAsync();
        }
        else if (Request.Path == "signout-callback-oidc")
        {
            return await HandleCallbackSignOutAsync();
        }
        
        return await base.HandleRequestAsync();
    }

    protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
    {
        OpenIdConnectMessage? message = null;
        if (Request.Method == "GET" && Request.Query.Count != 0)
        {
            message = new OpenIdConnectMessage(Request.Query.Select(x => new KeyValuePair<string, string[]>(x.Key, x.Value.ToArray()!)));
            
            // tokens must not be sent through the front channel
            if (message.IdToken != null || message.AccessToken != null)
            {
                return HandleRequestResult.Fail("id_token and access_token are not allowed through front channels");
            }
        }
        else if (Request.Method == "POST"
                 && !string.IsNullOrEmpty(Request.ContentType)
                 && Request.ContentType.StartsWith("application/x-www-form-urlencoded"))
        {
            var form = await Request.ReadFormAsync();
            message = new OpenIdConnectMessage(form.Select(x => new KeyValuePair<string, string[]>(x.Key, x.Value.ToArray()!)));
        }

        if (message == null)
        {
            return HandleRequestResult.Fail("missing parameters");
        }
        
        var authenticationProperties = ReadAuthenticationProperties(message);
        if (authenticationProperties is null)
        {
            return HandleRequestResult.Fail("state is invalid");
        }

        if (!ValidateCorrelationId(authenticationProperties))
        {
            return HandleRequestResult.Fail("correlation failed", authenticationProperties);
        }

        if (!string.IsNullOrEmpty(message.Error))
        {
            return HandleRequestResult.Fail(message.Error, authenticationProperties);
        }

        if (_configuration is null)
        {
            _configuration = await Options.ConfigurationManager.GetConfigurationAsync(Context.RequestAborted);
        }
        
        ClaimsPrincipal? user = null;
        JwtSecurityToken? jwt = null;
        string? nonce = null;
        var validationParameters = Options.TokenValidationParameters.Clone();

        var tokenRequest = new HttpRequestMessage(HttpMethod.Post, _configuration.TokenEndpoint);
        var tokenParameters = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "authorization_code"),
            new("code", message.Code),
            new("scope", authenticationProperties.GetParameter<string>("scope")!),
            new("client_id", Options.ClientId),
            new("client_secret", Options.ClientSecret!)
        };
        tokenParameters.AddRange(authenticationProperties.GetParameter<string[]>("resource")!.Select(resource => new KeyValuePair<string, string>("resource", resource)));
        var tokenContent = new FormUrlEncodedContent(tokenParameters);
        var tokenResponse = await Options.Backchannel.SendAsync(tokenRequest, Context.RequestAborted);
        
        // get authorization_code
        // invoke token endpoint
        // validate id_token
        // get information from userinfo endpoint
        // populate ClaimsPrincipal
        // save all tokens received
        
        throw new NotImplementedException();
    }

    private async Task<bool> HandleRemoteSignOutAsync()
    {
        // must be post
        // get LogoutToken and validate it
        // Pass sid and sub into OpenIdConnectMessage
        
        // TODO find out how to clear server side user
        
        throw new NotImplementedException();
    }

    private async Task<bool> HandleCallbackSignOutAsync()
    {
        throw new NotImplementedException();
    }
    
    public Task SignOutAsync(AuthenticationProperties? properties)
    {
        // create state parameter
        // create id_token_hint parameter
        // create post_logout_redirect_uri
        
        // redirect browser to end-session endpoint (support get and form_post)
        throw new NotImplementedException();
    }

    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        // setup all values in OpenIdConnectMessage
        // redirect browser to authorize endpoint (support get and form_post)
        throw new NotImplementedException();
    }

    private AuthenticationProperties? ReadAuthenticationProperties(OpenIdConnectMessage message)
    {
        if (string.IsNullOrEmpty(message.State))
        {
            return null;
        }
        
        var properties = Options.StateDataFormat.Unprotect(message.State);
        if (properties == null)
        {
            return properties;
        }
        
        properties.Items.TryGetValue(OpenIdConnectDefaults.UserStatePropertiesKey, out var userState);
        message.State = userState;
        return properties;
    }
}