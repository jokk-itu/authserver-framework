using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.Metrics.Abstractions;
using AuthServer.RequestAccessors.GrantManagement;

namespace AuthServer.GrantManagement;

internal class GrantManagementRequestHandler : RequestHandler<GrantManagementRequest, GrantManagementValidatedRequest, Unit>
{
    private readonly IRequestValidator<GrantManagementRequest, GrantManagementValidatedRequest> _requestValidator;
    private readonly IRequestProcessor<GrantManagementValidatedRequest, Unit> _requestProcessor;
    private readonly IUnitOfWork _unitOfWork;

    public GrantManagementRequestHandler(
        IMetricService metricService,
        IRequestValidator<GrantManagementRequest, GrantManagementValidatedRequest> requestValidator,
        IRequestProcessor<GrantManagementValidatedRequest, Unit> requestProcessor,
        IUnitOfWork unitOfWork)
        : base(metricService)
    {
        _requestValidator = requestValidator;
        _requestProcessor = requestProcessor;
        _unitOfWork = unitOfWork;
    }

    protected override async Task<ProcessResult<Unit, ProcessError>> ProcessRequest(GrantManagementValidatedRequest request, CancellationToken cancellationToken)
    {
        await _unitOfWork.Begin(cancellationToken);
        var result = await _requestProcessor.Process(request, cancellationToken);
        await _unitOfWork.Commit(cancellationToken);
        return result;
    }

    protected override async Task<ProcessResult<GrantManagementValidatedRequest, ProcessError>> ValidateRequest(GrantManagementRequest request, CancellationToken cancellationToken)
    {
        return await _requestValidator.Validate(request, cancellationToken);
    }
}