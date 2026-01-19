using AuthServer.Authorization.Models;
using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.Metrics.Abstractions;
using AuthServer.Repositories.Abstractions;
using Microsoft.Extensions.Logging;

namespace AuthServer.TokenByGrant.TokenExchangeGrant;
internal class TokenExchangeRequestHandler : RequestHandler<TokenRequest, TokenExchangeValidatedRequest, TokenResponse>
{
    private readonly IUnitOfWork _unitOfWork;
    private readonly INonceRepository _nonceRepository;
    private readonly IRequestValidator<TokenRequest, TokenExchangeValidatedRequest> _requestValidator;
    private readonly IRequestProcessor<TokenExchangeValidatedRequest, TokenResponse> _requestProcessor;

    public TokenExchangeRequestHandler(
        IMetricService metricService,
        IUnitOfWork unitOfWork,
        INonceRepository nonceRepository,
        IRequestValidator<TokenRequest, TokenExchangeValidatedRequest> requestValidator,
        IRequestProcessor<TokenExchangeValidatedRequest, TokenResponse> requestProcessor,
        ILogger<TokenExchangeRequestHandler> logger)
        : base(metricService, logger)
    {
        _unitOfWork = unitOfWork;
        _nonceRepository = nonceRepository;
        _requestValidator = requestValidator;
        _requestProcessor = requestProcessor;
    }

    protected override async Task<ProcessResult<TokenResponse, ProcessError>> ProcessValidatedRequest(TokenExchangeValidatedRequest request, CancellationToken cancellationToken)
    {
        await _unitOfWork.Begin(cancellationToken);
        var response = await _requestProcessor.Process(request, cancellationToken);
        await _unitOfWork.Commit(cancellationToken);
        return response;
    }

    protected override async Task<ProcessResult<TokenExchangeValidatedRequest, ProcessError>> ValidateRequest(TokenRequest request, CancellationToken cancellationToken)
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

        return response;
    }
}
