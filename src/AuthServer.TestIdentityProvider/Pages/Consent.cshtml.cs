using AuthServer.Authorize.Abstractions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Web;
using AuthServer.Core;
using AuthServer.Endpoints.Responses;
using AuthServer.Helpers;

namespace AuthServer.TestIdentityProvider.Pages;

[ValidateAntiForgeryToken]
public class ConsentModel : PageModel
{
    private readonly IAuthorizeService _authorizeService;

    public ConsentModel(IAuthorizeService authorizeService)
    {
        _authorizeService = authorizeService;
    }

    [BindProperty] public InputModel Input { get; set; }

    [BindProperty(Name = "returnUrl", SupportsGet = true)]
    public string ReturnUrl { get; set; }

    public class InputModel
    {
        public string? ClientName { get; set; }
        public string? ClientUri { get; set; }
        public string? ClientLogoUri { get; set; }
        public string? Username { get; set; }
        public List<string> RequestedScope { get; set; } = [];
        public List<ClaimDto> RequestedClaims { get; set; } = [];
        public List<string> ConsentedScope { get; set; } = [];
        public List<string> ConsentedClaims { get; set; } = [];
    }

    public class ClaimDto
    {
        public required string Name { get; set; }
        public bool IsGranted { get; set; }
    }

    public async Task OnGet(string returnUrl, CancellationToken cancellationToken)
    {
        ReturnUrl = returnUrl ?? Url.Content("~/");

        var query = HttpUtility.ParseQueryString(new Uri(ReturnUrl).Query);
        var requestUri = query.Get(Parameter.RequestUri)!;
        var clientId = query.Get(Parameter.ClientId)!;

        var request = (await _authorizeService.GetRequest(requestUri, clientId, cancellationToken))!;

        var subject = await _authorizeService.GetSubject(request);
        var consentGrantDto = await _authorizeService.GetConsentGrantDto(subject, clientId, cancellationToken);
        
        var requestedScope = request.Scope.ToList();

        // Display requested claims, also if they are already consented. This makes sure the end-user can change their full consent.
        var requestedClaims = ClaimsHelper.MapToClaims(requestedScope)
            .Select(x => new ClaimDto
            {
                Name = x,
                IsGranted = consentGrantDto.ConsentedClaims.Any(y => y == x)
            })
            .ToList();

        Input = new InputModel
        {
            ClientName = consentGrantDto.ClientName,
            ClientUri = consentGrantDto.ClientUri,
            ClientLogoUri = consentGrantDto.ClientLogoUri,
            Username = consentGrantDto.Username,
            RequestedScope = requestedScope,
            RequestedClaims = requestedClaims
        };
    }

    public async Task<IActionResult> OnPostAccept(string returnUrl, CancellationToken cancellationToken)
    {
        ReturnUrl = returnUrl ?? Url.Content("~/");

        var query = HttpUtility.ParseQueryString(new Uri(ReturnUrl).Query);
        var clientId = query.Get(Parameter.ClientId)!;
        var requestUri = query.Get(Parameter.RequestUri)!;
        var request = (await _authorizeService.GetRequest(requestUri, clientId, cancellationToken))!;
        var subject = await _authorizeService.GetSubject(request);
        await _authorizeService.CreateOrUpdateConsentGrant(subject, clientId, Input.ConsentedScope, Input.ConsentedClaims, cancellationToken);

        return Redirect(ReturnUrl);
    }

    public async Task<IActionResult> OnPostDecline(string returnUrl, CancellationToken cancellationToken)
    {
        ReturnUrl = returnUrl ?? Url.Content("~/");

        var query = HttpUtility.ParseQueryString(new Uri(ReturnUrl).Query);
        var requestUri = query.Get(Parameter.RequestUri)!;
        var clientId = query.Get(Parameter.ClientId)!;

        return await _authorizeService.GetErrorResult(
            requestUri,
            clientId,
            new OAuthError(ErrorCode.ConsentRequired, "end-user has declined consent"),
            HttpContext,
            cancellationToken);
    }
}