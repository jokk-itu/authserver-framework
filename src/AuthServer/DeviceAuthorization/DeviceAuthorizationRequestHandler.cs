using AuthServer.Authorization.Models;
using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.Metrics.Abstractions;
using AuthServer.Repositories.Abstractions;

namespace AuthServer.DeviceAuthorization;

internal class DeviceAuthorizationRequestHandler : RequestHandler<DeviceAuthorizationRequest, DeviceAuthorizationValidatedRequest, DeviceAuthorizationResponse>
{
    private readonly IRequestProcessor<DeviceAuthorizationValidatedRequest, DeviceAuthorizationResponse> _requestProcessor;
    private readonly IRequestValidator<DeviceAuthorizationRequest, DeviceAuthorizationValidatedRequest> _requestValidator;
    private readonly INonceRepository _nonceRepository;
    private readonly IUnitOfWork _unitOfWork;

    public DeviceAuthorizationRequestHandler(
        IMetricService metricService,
        IRequestProcessor<DeviceAuthorizationValidatedRequest, DeviceAuthorizationResponse> requestProcessor,
        IRequestValidator<DeviceAuthorizationRequest, DeviceAuthorizationValidatedRequest> requestValidator,
        INonceRepository nonceRepository,
        IUnitOfWork unitOfWork)
        : base(metricService)
    {
        _requestProcessor = requestProcessor;
        _requestValidator = requestValidator;
        _nonceRepository = nonceRepository;
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
        var response = await _requestValidator.Validate(request, cancellationToken);
        if (response is
            {
                IsSuccess: false,
                Error: DPoPNonceProcessError
                {
                    DPoPNonce: null,
                    ClientId: not null
                } dPoPNonceProcessError
            })
        {
            await _unitOfWork.Begin(cancellationToken);
            var dPoPNonce = await _nonceRepository.CreateDPoPNonce(dPoPNonceProcessError.ClientId, cancellationToken);
            await _unitOfWork.Commit(cancellationToken);

            return dPoPNonceProcessError with { DPoPNonce = dPoPNonce };
        }

        return response;
    }
}