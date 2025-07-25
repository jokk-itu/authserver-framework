using AuthServer.Authorization.Models;
using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.Metrics.Abstractions;
using AuthServer.Repositories.Abstractions;

namespace AuthServer.TokenByGrant.TokenAuthorizationCodeGrant;
internal class AuthorizationCodeRequestHandler : RequestHandler<TokenRequest, AuthorizationCodeValidatedRequest, TokenResponse>
{
    private readonly IRequestProcessor<AuthorizationCodeValidatedRequest, TokenResponse> _requestProcessor;
    private readonly IRequestValidator<TokenRequest, AuthorizationCodeValidatedRequest> _requestValidator;
    private readonly INonceRepository _nonceRepository;
    private readonly IUnitOfWork _unitOfWork;

    public AuthorizationCodeRequestHandler(
	    IRequestProcessor<AuthorizationCodeValidatedRequest, TokenResponse> requestProcessor,
        IRequestValidator<TokenRequest, AuthorizationCodeValidatedRequest> requestValidator,
        INonceRepository nonceRepository,
        IUnitOfWork unitOfWork,
        IMetricService metricService)
        : base(metricService)
    {
        _requestProcessor = requestProcessor;
        _requestValidator = requestValidator;
        _nonceRepository = nonceRepository;
        _unitOfWork = unitOfWork;
    }

    protected override async Task<ProcessResult<TokenResponse, ProcessError>> ProcessValidatedRequest(AuthorizationCodeValidatedRequest request, CancellationToken cancellationToken)
    {
	    await _unitOfWork.Begin(cancellationToken);
        var result = await _requestProcessor.Process(request, cancellationToken);
        await _unitOfWork.Commit(cancellationToken);
        return result;
    }

    protected override async Task<ProcessResult<AuthorizationCodeValidatedRequest, ProcessError>> ValidateRequest(TokenRequest request, CancellationToken cancellationToken)
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