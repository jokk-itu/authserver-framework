using AuthServer.EndSession.UserInterface.Abstractions;
using AuthServer.Tests.Core;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace AuthServer.TestIdentityProvider.Pages;

[ValidateAntiForgeryToken]
public class SignOutModel : PageModel
{
    private readonly IEndSessionService _endSessionService;

    public SignOutModel(IEndSessionService endSessionService)
    {
        _endSessionService = endSessionService;
    }

    [BindProperty(Name = "returnUrl", SupportsGet = true)]
    public string ReturnUrl { get; set; }

    public void OnGet(string returnUrl)
    {
        ReturnUrl = returnUrl ?? Url.Content("~/");
    }

    public async Task<IActionResult> OnPostAccept(string returnUrl, CancellationToken cancellationToken)
    {
        ReturnUrl = returnUrl ?? Url.Content("~/");

        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        _endSessionService.SetUser(UserConstants.SubjectIdentifier, true);
        return Redirect(ReturnUrl);
    }

    public async Task<IActionResult> OnPostDecline(string returnUrl, CancellationToken cancellationToken)
    {
        ReturnUrl = returnUrl ?? Url.Content("~/");

        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        _endSessionService.SetUser(UserConstants.SubjectIdentifier, false);
        return Redirect(ReturnUrl);
    }
}