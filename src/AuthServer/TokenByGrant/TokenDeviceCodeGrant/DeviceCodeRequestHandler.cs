using AuthServer.Authorization.Models;
using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.Metrics.Abstractions;
using AuthServer.Repositories.Abstractions;
using Microsoft.Extensions.Logging;

namespace AuthServer.TokenByGrant.TokenDeviceCodeGrant;

internal class DeviceCodeRequestHandler : RequestHandler<TokenRequest, DeviceCodeValidatedRequest, TokenResponse>
{
    private readonly IRequestValidator<TokenRequest, DeviceCodeValidatedRequest> _requestValidator;
    private readonly IRequestProcessor<DeviceCodeValidatedRequest, TokenResponse> _requestProcessor;
    private readonly IUnitOfWork _unitOfWork;
    private readonly INonceRepository _nonceRepository;
    private readonly IDeviceCodeRepository _deviceCodeRepository;

    public DeviceCodeRequestHandler(
        IMetricService metricService,
        IRequestValidator<TokenRequest, DeviceCodeValidatedRequest> requestValidator,
        IRequestProcessor<DeviceCodeValidatedRequest, TokenResponse> requestProcessor,
        IUnitOfWork unitOfWork,
        INonceRepository nonceRepository,
        IDeviceCodeRepository deviceCodeRepository,
        ILogger<RequestHandler<TokenRequest, DeviceCodeValidatedRequest, TokenResponse>> logger)
        : base(metricService, logger)
    {
        _requestValidator = requestValidator;
        _requestProcessor = requestProcessor;
        _unitOfWork = unitOfWork;
        _nonceRepository = nonceRepository;
        _deviceCodeRepository = deviceCodeRepository;
    }
    
    protected override async Task<ProcessResult<TokenResponse, ProcessError>> ProcessValidatedRequest(DeviceCodeValidatedRequest request, CancellationToken cancellationToken)
    {
        await _unitOfWork.Begin(cancellationToken);
        var response = await _requestProcessor.Process(request, cancellationToken);
        await _unitOfWork.Commit(cancellationToken);
        return response;
    }

    protected override async Task<ProcessResult<DeviceCodeValidatedRequest, ProcessError>> ValidateRequest(TokenRequest request, CancellationToken cancellationToken)
    {
        var response = await _requestValidator.Validate(request, cancellationToken);
        if (response is
            {
                IsSuccess: false,
                Error: RenewDPoPNonceProcessError dPoPNonceProcessError
            })
        {
            await _unitOfWork.Begin(cancellationToken);
            var dPoPNonce = await _nonceRepository.CreateDPoPNonce(dPoPNonceProcessError.ClientId, cancellationToken);
            await _unitOfWork.Commit(cancellationToken);

            return new DPoPNonceProcessError(dPoPNonce, dPoPNonceProcessError.Error,
                dPoPNonceProcessError.ErrorDescription, dPoPNonceProcessError.ResultCode);
        }

        if (response is
            {
                IsSuccess: false,
                Error: SlowDownProcessError slowDownProcessError
            })
        {
            await _unitOfWork.Begin(cancellationToken);
            await _deviceCodeRepository.UpdateInterval(slowDownProcessError.DeviceCodeId, cancellationToken);
            await _deviceCodeRepository.UpdatePoll(slowDownProcessError.DeviceCodeId, cancellationToken);
            await _unitOfWork.Commit(cancellationToken);

            return slowDownProcessError;
        }

        if (response is
            {
                IsSuccess: false,
                Error: AuthorizationPendingProcessError authorizationPendingProcessError
            })
        {
            await _unitOfWork.Begin(cancellationToken);
            await _deviceCodeRepository.UpdatePoll(authorizationPendingProcessError.DeviceCodeId, cancellationToken);
            await _unitOfWork.Commit(cancellationToken);

            return authorizationPendingProcessError;
        }

        return response;
    }
}