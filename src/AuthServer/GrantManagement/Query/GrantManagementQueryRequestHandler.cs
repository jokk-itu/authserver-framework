using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.Metrics.Abstractions;

namespace AuthServer.GrantManagement.Query;
internal class GrantManagementQueryRequestHandler : RequestHandler<GrantManagementRequest, GrantManagementValidatedRequest, GrantResponse>
{
    private readonly IRequestValidator<GrantManagementRequest, GrantManagementValidatedRequest> _requestValidator;
    private readonly IRequestProcessor<GrantManagementValidatedRequest, GrantResponse> _requestProcessor;

    public GrantManagementQueryRequestHandler(
        IMetricService metricService,
        IRequestValidator<GrantManagementRequest, GrantManagementValidatedRequest> requestValidator,
        IRequestProcessor<GrantManagementValidatedRequest, GrantResponse> requestProcessor)
        : base(metricService)
    {
        _requestValidator = requestValidator;
        _requestProcessor = requestProcessor;
    }

    protected override async Task<ProcessResult<GrantResponse, ProcessError>> ProcessValidatedRequest(GrantManagementValidatedRequest request, CancellationToken cancellationToken)
    {
        return await _requestProcessor.Process(request, cancellationToken);
    }

    protected override async Task<ProcessResult<GrantManagementValidatedRequest, ProcessError>> ValidateRequest(GrantManagementRequest request, CancellationToken cancellationToken)
    {
        return await _requestValidator.Validate(request, cancellationToken);
    }
}
