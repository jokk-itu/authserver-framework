using Microsoft.AspNetCore.Http;

namespace AuthServer.Core.Abstractions;
internal interface IRequestAccessor<TRequest>
    where TRequest : class
{
    Task<TRequest> GetRequest(HttpRequest httpRequest);
}