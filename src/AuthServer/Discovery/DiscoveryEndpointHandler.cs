using AuthServer.Core.Abstractions;
using AuthServer.Options;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace AuthServer.Discovery;

internal class DiscoveryEndpointHandler : IEndpointHandler
{
    private readonly IOptionsSnapshot<DiscoveryDocument> _discoveryDocumentOptions;

    public DiscoveryEndpointHandler(
        IOptionsSnapshot<DiscoveryDocument> discoveryDocumentOptions)
    {
        _discoveryDocumentOptions = discoveryDocumentOptions;
    }

    public Task<IResult> Handle(HttpContext httpContext, CancellationToken cancellationToken)
    {
        return Task.FromResult(Results.Ok(_discoveryDocumentOptions.Value));
    }
}