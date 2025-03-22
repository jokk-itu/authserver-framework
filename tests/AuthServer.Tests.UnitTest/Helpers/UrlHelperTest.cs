using AuthServer.Helpers;

namespace AuthServer.Tests.UnitTest.Helpers;
public class UrlHelperTest
{
    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("http://native.app/callback")]
    [InlineData("https://native.app/callback#fragment")]
    [InlineData("https://native.app/callback?query=random")]
    public void IsUrlValidForNativeClient_InvalidNativeUrl_ExpectFalse(string? url)
    {
        Assert.False(UrlHelper.IsUrlValidForNativeClient(url));
    }

    [Theory]
    [InlineData("native.app:/callback")]
    [InlineData("https://native.app://callback")]
    [InlineData("http://localhost:5000/callback")]
    [InlineData("http://127.0.0.1:5000/callback")]
    [InlineData("http://[::1]:5000/callback")]
    public void IsUrlValidForNativeClient_ValidNativeUrl_ExpectTrue(string? url)
    {
        Assert.True(UrlHelper.IsUrlValidForNativeClient(url));
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("https://localhost:5000/callback")]
    [InlineData("https://127.0.0.1:5000/callback")]
    [InlineData("https://[::1]:5000/callback")]
    [InlineData("http://webapp.authserver.dk/callback")]
    [InlineData("https://webapp.authserver.dk/callback#fragment")]
    [InlineData("https://webapp.authserver.dk/callback?query=random")]
    public void IsUrlValidForWebClient_InvalidWebUrl_ExpectFalse(string? url)
    {
        Assert.False(UrlHelper.IsUrlValidForWebClient(url));
    }

    [Theory]
    [InlineData("https://webapp.authserver.dk/callback")]
    public void IsUrlValidForWebClient_ValidNativeUrl_ExpectTrue(string? url)
    {
        Assert.True(UrlHelper.IsUrlValidForWebClient(url));
    }
}