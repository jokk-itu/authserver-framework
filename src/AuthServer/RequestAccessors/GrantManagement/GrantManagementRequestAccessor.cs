using System.Text;
using AuthServer.Authentication.OAuthToken;
using AuthServer.Core;
using AuthServer.Core.Abstractions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AuthServer.RequestAccessors.GrantManagement;

internal class GrantManagementRequestAccessor : IRequestAccessor<GrantManagementRequest>
{
    public async Task<GrantManagementRequest> GetRequest(HttpRequest httpRequest)
    {
        var pathBuilder = new StringBuilder();
        if (httpRequest.Path.Value?.StartsWith('/') == true)
        {
            pathBuilder.Append('/');
        }
        pathBuilder.Append("connect/grants/");
        
        var grantId = httpRequest.Path.Value?[pathBuilder.ToString().Length..];
        var token = (await httpRequest.HttpContext.GetTokenAsync(OAuthTokenAuthenticationDefaults.AuthenticationScheme, Parameter.AccessToken))!;
        return new GrantManagementRequest
        {
            Method = HttpMethod.Parse(httpRequest.Method),
            AccessToken = token,
            GrantId = string.IsNullOrEmpty(grantId) ? null : grantId
        };
    }
}