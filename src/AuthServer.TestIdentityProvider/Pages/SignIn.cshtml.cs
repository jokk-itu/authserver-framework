using System.Security.Claims;
using System.Web;
using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Tests.Core;
using AuthServer.UserInterface.Abstractions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace AuthServer.TestIdentityProvider.Pages;

[ValidateAntiForgeryToken]
public class SignInModel : PageModel
{
    private readonly IAuthorizeService _authorizeService;
    private readonly IAuthorizationCodeGrantService _authorizationCodeGrantService;

    public SignInModel(
        IAuthorizeService authorizeService,
        IAuthorizationCodeGrantService authorizationCodeGrantService)
    {
        _authorizeService = authorizeService;
        _authorizationCodeGrantService = authorizationCodeGrantService;
    }

    [BindProperty]
    public InputModel Input { get; set; }

    [BindProperty(Name = "returnUrl", SupportsGet = true)]
    public string ReturnUrl { get; set; }

    public class InputModel
    {
        public required string Username { get; set; }
        public required string Password { get; set; }
    }

    public void OnGet(string returnUrl)
    {
        ReturnUrl = returnUrl ?? Url.Content("~/");
    }

    public async Task<IActionResult> OnPost(string returnUrl, CancellationToken cancellationToken)
    {
        ReturnUrl = returnUrl ?? Url.Content("~/");
        if (!ModelState.IsValid)
        {
            return Page();
        }

        if (Input is { Username: UserConstants.Username, Password: UserConstants.Password })
        {
            var query = HttpUtility.ParseQueryString(new Uri(ReturnUrl).Query);
            var requestUri = query.Get(Parameter.RequestUri)!;
            var clientId = query.Get(Parameter.ClientId)!;
            var request = (await _authorizeService.GetValidatedRequest(requestUri, clientId, cancellationToken))!;
            await _authorizationCodeGrantService.HandleAuthorizationCodeGrant(UserConstants.SubjectIdentifier, request, [AuthenticationMethodReferenceConstants.Password], cancellationToken);

            var claimsIdentity = new ClaimsIdentity(
                [new Claim(ClaimNameConstants.Sub, UserConstants.SubjectIdentifier)],
                CookieAuthenticationDefaults.AuthenticationScheme);

            var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, claimsPrincipal);

            if (request.Prompt?.Contains(PromptConstants.Consent) == true)
            {
                return Redirect($"/Consent?returnUrl={HttpUtility.UrlEncode(returnUrl)}");
            }
            
            return Redirect(ReturnUrl);
        }

        ModelState.AddModelError(string.Empty, "Invalid login attempt.");
        return Page();
    }
}