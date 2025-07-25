using AuthServer.Authorization.Models;
using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.Metrics.Abstractions;
using AuthServer.Repositories.Abstractions;

namespace AuthServer.TokenByGrant.TokenClientCredentialsGrant;
internal class ClientCredentialsRequestHandler : RequestHandler<TokenRequest, ClientCredentialsValidatedRequest, TokenResponse>
{
	private readonly IUnitOfWork _unitOfWork;
	private readonly IRequestValidator<TokenRequest, ClientCredentialsValidatedRequest> _requestValidator;
    private readonly IRequestProcessor<ClientCredentialsValidatedRequest, TokenResponse> _requestProcessor;
    private readonly INonceRepository _nonceRepository;

    public ClientCredentialsRequestHandler(
        IUnitOfWork unitOfWork,
        IRequestValidator<TokenRequest, ClientCredentialsValidatedRequest> requestValidator,
        IRequestProcessor<ClientCredentialsValidatedRequest, TokenResponse> requestProcessor,
        INonceRepository nonceRepository,
        IMetricService metricService)
        : base(metricService)
    {
	    _unitOfWork = unitOfWork;
	    _requestValidator = requestValidator;
        _requestProcessor = requestProcessor;
        _nonceRepository = nonceRepository;
    }

    protected override async Task<ProcessResult<TokenResponse, ProcessError>> ProcessValidatedRequest(ClientCredentialsValidatedRequest request, CancellationToken cancellationToken)
    {
	    await _unitOfWork.Begin(cancellationToken);
        var result = await _requestProcessor.Process(request, cancellationToken);
        await _unitOfWork.Commit(cancellationToken);
        return result;
    }

    protected override async Task<ProcessResult<ClientCredentialsValidatedRequest, ProcessError>> ValidateRequest(TokenRequest request, CancellationToken cancellationToken)
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