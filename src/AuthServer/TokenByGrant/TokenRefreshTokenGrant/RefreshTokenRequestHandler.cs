using AuthServer.Authorization.Models;
using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.Metrics.Abstractions;
using AuthServer.Repositories.Abstractions;

namespace AuthServer.TokenByGrant.TokenRefreshTokenGrant;
internal class RefreshTokenRequestHandler : RequestHandler<TokenRequest, RefreshTokenValidatedRequest, TokenResponse>
{
	private readonly IUnitOfWork _unitOfWork;
	private readonly IRequestValidator<TokenRequest, RefreshTokenValidatedRequest> _requestValidator;
    private readonly IRequestProcessor<RefreshTokenValidatedRequest, TokenResponse> _refreshTokenProcessor;
    private readonly INonceRepository _nonceRepository;

    public RefreshTokenRequestHandler(
        IUnitOfWork unitOfWork,
        IRequestValidator<TokenRequest, RefreshTokenValidatedRequest> requestValidator,
        IRequestProcessor<RefreshTokenValidatedRequest, TokenResponse> refreshTokenProcessor,
        INonceRepository nonceRepository,
        IMetricService metricService)
        : base(metricService)
    {
	    _unitOfWork = unitOfWork;
	    _requestValidator = requestValidator;
        _refreshTokenProcessor = refreshTokenProcessor;
        _nonceRepository = nonceRepository;
    }

    protected override async Task<ProcessResult<TokenResponse, ProcessError>> ProcessValidatedRequest(RefreshTokenValidatedRequest request, CancellationToken cancellationToken)
    {
	    await _unitOfWork.Begin(cancellationToken);
        var result = await _refreshTokenProcessor.Process(request, cancellationToken);
        await _unitOfWork.Commit(cancellationToken);
        return result;
    }

    protected override async Task<ProcessResult<RefreshTokenValidatedRequest, ProcessError>> ValidateRequest(TokenRequest request, CancellationToken cancellationToken)
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