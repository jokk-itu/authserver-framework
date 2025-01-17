using AuthServer.Core;
using AuthServer.Options;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.FeatureManagement;

namespace AuthServer.Endpoints;
internal static class DiscoveryDocumentEndpoint
{
    public static async Task<IResult> HandleDiscoveryDocument(
        [FromServices] IOptionsSnapshot<DiscoveryDocument> discoveryDocumentOptions,
        [FromServices] IFeatureManagerSnapshot featureManagerSnapshot)
    {
        if (await featureManagerSnapshot.IsEnabledAsync(FeatureFlags.Discovery))
        {
            return Results.Ok(discoveryDocumentOptions.Value);
        }
        
        return Results.NotFound();
    }
}