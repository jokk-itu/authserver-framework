using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AuthServer.Authorize.Abstractions;

internal interface IAuthorizeResponseBuilder
{
    /// <summary>
    /// Get an HTTP response based on the request parameters.
    ///
    /// This is useful in Minimal APIs.
    /// </summary>
    /// <param name="request"></param>
    /// <param name="additionalParameters"></param>
    /// <param name="httpResponse"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<IResult> BuildResponse(AuthorizeRequest request, IDictionary<string, string> additionalParameters,
        HttpResponse httpResponse, CancellationToken cancellationToken);

    /// <summary>
    /// Get an HTTP response based on the request parameters.
    ///
    /// This is useful in MVC APIs.
    /// </summary>
    /// <param name="request"></param>
    /// <param name="additionalParameters"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<IActionResult> BuildResponse(AuthorizeRequest request, IDictionary<string, string> additionalParameters,
        CancellationToken cancellationToken);
}