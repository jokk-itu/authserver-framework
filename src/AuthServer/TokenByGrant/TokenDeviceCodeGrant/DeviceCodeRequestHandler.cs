using AuthServer.Authorization.Models;
using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.Metrics.Abstractions;
using AuthServer.Repositories.Abstractions;

namespace AuthServer.TokenByGrant.TokenDeviceCodeGrant;

internal class DeviceCodeRequestHandler : RequestHandler<TokenRequest, DeviceCodeValidatedRequest, TokenResponse>
{
    private readonly IRequestValidator<TokenRequest, DeviceCodeValidatedRequest> _requestValidator;
    private readonly IRequestProcessor<DeviceCodeValidatedRequest, TokenResponse> _requestProcessor;
    private readonly IUnitOfWork _unitOfWork;
    private readonly INonceRepository _nonceRepository;

    public DeviceCodeRequestHandler(
        IMetricService metricService,
        IRequestValidator<TokenRequest, DeviceCodeValidatedRequest> requestValidator,
        IRequestProcessor<DeviceCodeValidatedRequest, TokenResponse> requestProcessor,
        IUnitOfWork unitOfWork,
        INonceRepository nonceRepository)
        : base(metricService)
    {
        _requestValidator = requestValidator;
        _requestProcessor = requestProcessor;
        _unitOfWork = unitOfWork;
        _nonceRepository = nonceRepository;
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