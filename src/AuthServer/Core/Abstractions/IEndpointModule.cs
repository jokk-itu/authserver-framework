using Microsoft.AspNetCore.Routing;

namespace AuthServer.Core.Abstractions;
internal interface IEndpointModule
{
    /// <summary>
    /// 
    /// </summary>
    /// <param name="endpointRouteBuilder"></param>
    /// <returns></returns>
    void RegisterEndpoint(IEndpointRouteBuilder endpointRouteBuilder);
}
