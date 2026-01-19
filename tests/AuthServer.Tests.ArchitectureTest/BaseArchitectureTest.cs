using AuthServer.Authentication.Abstractions;
using AuthServer.Tests.Core;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit.Abstractions;

namespace AuthServer.Tests.ArchitectureTest;

[Collection("ArchitectureTest")]
public abstract class BaseArchitectureTest : IClassFixture<WebApplicationFactory<Program>>
{
    protected readonly ITestOutputHelper TestOutputHelper;
    protected readonly IServiceProvider ServiceProvider;

    protected BaseArchitectureTest(WebApplicationFactory<Program> factory, ITestOutputHelper testOutputHelper)
    {
        var webApplicationFactory = factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Integration");
            builder.ConfigureServices(services =>
            {
                var authenticatedUserAccessor = new Mock<IAuthenticatedUserAccessor>();
                authenticatedUserAccessor
                    .Setup(x => x.CountAuthenticatedUsers())
                    .ReturnsAsync(2);

                services.AddScopedMock(authenticatedUserAccessor);
            });
        });

        TestOutputHelper = testOutputHelper;
        ServiceProvider = webApplicationFactory.Services.CreateScope().ServiceProvider;
    }
}