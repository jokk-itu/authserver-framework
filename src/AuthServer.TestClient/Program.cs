using AuthServer.TestClient;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorPages();
builder.Services.AddAuthorization();
builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    })
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
    {
        options.Cookie.Name = "Client.Identity";
    })
    .AddScheme<OpenIdConnectOptions, OpenIdConnectHandler>(OpenIdConnectDefaults.AuthenticationScheme, null);

builder.Services.AddSingleton<ITokenReplayCache, DefaultTokenReplayCache>();

builder.Services.AddOptions();
builder.Services.ConfigureOptions<ConfigureOpenIdConnectOptions>();
builder.Services.ConfigureOptions<PostConfigureOpenIdConnectOptions>();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
}
app.UseHsts();
app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.MapRazorPages();
app.MapGet("/api/login", (HttpContext httpContext, [FromServices] IOptionsMonitor<OpenIdConnectOptions> openIdConnectOptions, string? prompt, string? responseMode, int? maxAge) =>
{
    if (httpContext.User.Identity?.IsAuthenticated == true)
    {
        return Results.Redirect("~/");
    }

    var properties = new AuthenticationProperties();
    if (prompt is not null)
    {
        properties.Parameters.Add("prompt", prompt);
    }

    if (responseMode is not null)
    {
        properties.Parameters.Add("response_mode", responseMode);
    }

    if (maxAge is not null)
    {
        properties.Parameters.Add("max_age", maxAge.Value);
    }

    properties.Parameters.Add("resource", new[] {openIdConnectOptions.CurrentValue.Authority});
    properties.Parameters.Add("scope", new[] {"openid", "authserver:userinfo", "profile"});

    return Results.Challenge(properties, [OpenIdConnectDefaults.AuthenticationScheme]);
});
app.MapGet("/api/logout/silent", async httpContext =>
{
    await httpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    await httpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);
});
app.MapGet("/api/logout/interactive", async httpContext =>
{
    await httpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    var parameters = new Dictionary<string, object?>
    {
        { "interactive", true }
    };
    var authenticationProperties = new AuthenticationProperties(null, parameters)
    {
        RedirectUri = "https://localhost:7226/"
    };
    await httpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme, authenticationProperties);
});

app.Run();