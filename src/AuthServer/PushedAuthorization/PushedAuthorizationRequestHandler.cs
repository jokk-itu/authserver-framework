using AuthServer.Authorization.Models;
using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.Metrics.Abstractions;
using AuthServer.Repositories.Abstractions;

namespace AuthServer.PushedAuthorization;

internal class PushedAuthorizationRequestHandler : RequestHandler<PushedAuthorizationRequest,
    PushedAuthorizationValidatedRequest, PushedAuthorizationResponse>
{
    private readonly IRequestValidator<PushedAuthorizationRequest, PushedAuthorizationValidatedRequest>
        _requestValidator;

    private readonly IRequestProcessor<PushedAuthorizationValidatedRequest, PushedAuthorizationResponse>
        _requestProcessor;

    private readonly INonceRepository _nonceRepository;

    private readonly IUnitOfWork _unitOfWork;

    public PushedAuthorizationRequestHandler(
        IMetricService metricService,
        IRequestValidator<PushedAuthorizationRequest, PushedAuthorizationValidatedRequest> requestValidator,
        IRequestProcessor<PushedAuthorizationValidatedRequest, PushedAuthorizationResponse> requestProcessor,
        INonceRepository nonceRepository,
        IUnitOfWork unitOfWork)
        : base(metricService)
    {
        _requestValidator = requestValidator;
        _requestProcessor = requestProcessor;
        _nonceRepository = nonceRepository;
        _unitOfWork = unitOfWork;
    }

    protected override async Task<ProcessResult<PushedAuthorizationResponse, ProcessError>> ProcessValidatedRequest(
        PushedAuthorizationValidatedRequest request, CancellationToken cancellationToken)
    {
        await _unitOfWork.Begin(cancellationToken);
        var result = await _requestProcessor.Process(request, cancellationToken);
        await _unitOfWork.Commit(cancellationToken);
        return result;
    }

    protected override async Task<ProcessResult<PushedAuthorizationValidatedRequest, ProcessError>> ValidateRequest(
        PushedAuthorizationRequest request, CancellationToken cancellationToken)
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