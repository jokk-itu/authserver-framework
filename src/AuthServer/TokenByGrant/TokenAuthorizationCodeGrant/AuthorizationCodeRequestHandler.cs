using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.Metrics.Abstractions;

namespace AuthServer.TokenByGrant.TokenAuthorizationCodeGrant;
internal class AuthorizationCodeRequestHandler : RequestHandler<TokenRequest, AuthorizationCodeValidatedRequest, TokenResponse>
{
    private readonly IRequestProcessor<AuthorizationCodeValidatedRequest, TokenResponse> _processor;
    private readonly IRequestValidator<TokenRequest, AuthorizationCodeValidatedRequest> _validator;
    private readonly IUnitOfWork _unitOfWork;

    public AuthorizationCodeRequestHandler(
	    IRequestProcessor<AuthorizationCodeValidatedRequest, TokenResponse> processor,
        IRequestValidator<TokenRequest, AuthorizationCodeValidatedRequest> validator,
        IUnitOfWork unitOfWork,
        IMetricService metricService)
        : base(metricService)
    {
        _processor = processor;
        _validator = validator;
        _unitOfWork = unitOfWork;
    }

    protected override async Task<ProcessResult<TokenResponse, ProcessError>> ProcessValidatedRequest(AuthorizationCodeValidatedRequest request, CancellationToken cancellationToken)
    {
	    await _unitOfWork.Begin(cancellationToken);
        var result = await _processor.Process(request, cancellationToken);
        await _unitOfWork.Commit(cancellationToken);
        return result;
    }

    protected override async Task<ProcessResult<AuthorizationCodeValidatedRequest, ProcessError>> ValidateRequest(TokenRequest request, CancellationToken cancellationToken)
    {
        return await _validator.Validate(request, cancellationToken);
    }
}