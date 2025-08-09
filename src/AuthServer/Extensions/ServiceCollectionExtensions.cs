using Microsoft.Extensions.DependencyInjection;

namespace AuthServer.Extensions;

public static class ServiceCollectionExtensions
{
    public static AuthServerBuilder AddAuthServer(this IServiceCollection services)
    {
        return new AuthServerBuilder(services);
    }
}