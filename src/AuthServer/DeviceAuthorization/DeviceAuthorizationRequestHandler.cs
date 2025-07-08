using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.Metrics.Abstractions;

namespace AuthServer.DeviceAuthorization;

internal class DeviceAuthorizationRequestHandler : RequestHandler<DeviceAuthorizationRequest, DeviceAuthorizationValidatedRequest, DeviceAuthorizationResponse>
{
    private readonly IRequestProcessor<DeviceAuthorizationValidatedRequest, DeviceAuthorizationResponse> _requestProcessor;
    private readonly IRequestValidator<DeviceAuthorizationRequest, DeviceAuthorizationValidatedRequest> _requestValidator;
    private readonly IUnitOfWork _unitOfWork;

    public DeviceAuthorizationRequestHandler(
        IMetricService metricService,
        IRequestProcessor<DeviceAuthorizationValidatedRequest, DeviceAuthorizationResponse> requestProcessor,
        IRequestValidator<DeviceAuthorizationRequest, DeviceAuthorizationValidatedRequest> requestValidator,
        IUnitOfWork unitOfWork)
        : base(metricService)
    {
        _requestProcessor = requestProcessor;
        _requestValidator = requestValidator;
        _unitOfWork = unitOfWork;
    }

    protected override async Task<ProcessResult<DeviceAuthorizationResponse, ProcessError>> ProcessValidatedRequest(DeviceAuthorizationValidatedRequest request, CancellationToken cancellationToken)
    {
        await _unitOfWork.Begin(cancellationToken);
        var result = await _requestProcessor.Process(request, cancellationToken);
        await _unitOfWork.Commit(cancellationToken);
        return result;
    }

    protected override async Task<ProcessResult<DeviceAuthorizationValidatedRequest, ProcessError>> ValidateRequest(DeviceAuthorizationRequest request, CancellationToken cancellationToken)
    {
        return await _requestValidator.Validate(request, cancellationToken);
    }
}