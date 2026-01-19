using System.Diagnostics;
using AuthServer.Core.Abstractions;
using AuthServer.Metrics.Abstractions;
using Microsoft.Extensions.Logging;

namespace AuthServer.Core.Request;

internal abstract class RequestHandler<TRequest, TValidatedRequest, TResponse> : IRequestHandler<TRequest, TResponse>
    where TRequest : class
    where TValidatedRequest : class
    where TResponse : class
{
    private readonly IMetricService _metricService;
    private readonly ILogger<RequestHandler<TRequest, TValidatedRequest, TResponse>> _logger;

    protected RequestHandler(
        IMetricService metricService,
        ILogger<RequestHandler<TRequest, TValidatedRequest, TResponse>> logger)
    {
        _metricService = metricService;
        _logger = logger;
    }

    /// <inheritdoc cref="IRequestProcessor{TRequest,TResponse}"/>
    public async Task<ProcessResult<TResponse, ProcessError>> Handle(TRequest request,
        CancellationToken cancellationToken)
    {
        using var activity = _metricService.ActivitySource.StartActivity();

        _logger.LogTrace("Start request handling {@Request}", request);
        var validationResult = await ValidateRequest(request, cancellationToken);

        return await validationResult.Match(
            async validatedRequest =>
            {
                _logger.LogDebug("Validation succeeded for request {@ValidatedRequest}", validatedRequest);

                activity?.AddEvent(new ActivityEvent("Request validation succeeded"));
                var response = await ProcessValidatedRequest(validatedRequest, cancellationToken);
                activity?.AddEvent(new ActivityEvent("Request processing succeeded"));
                return response;
            },
            error =>
            {
                _logger.LogDebug("Validation failed for request {@ErrorRequest}", error);

                activity?.AddEvent(new ActivityEvent("Request validation failed"));
                return Task.FromResult(new ProcessResult<TResponse, ProcessError>(error));
            });
    }

    /// <summary>
    /// Assumes that <typeparam name="TValidatedRequest"></typeparam> has been validated.
    /// </summary>
    /// <param name="request"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    protected abstract Task<ProcessResult<TResponse, ProcessError>> ProcessValidatedRequest(TValidatedRequest request,
        CancellationToken cancellationToken);

    /// <summary>
    /// Assumes that <typeparam name="TRequest"></typeparam> is raw from the endpoint.
    /// </summary>
    /// <param name="request"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    protected abstract Task<ProcessResult<TValidatedRequest, ProcessError>> ValidateRequest(TRequest request,
        CancellationToken cancellationToken);
}