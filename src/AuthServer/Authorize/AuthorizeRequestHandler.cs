using AuthServer.Authorization.Models;
using AuthServer.Constants;
using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.Metrics.Abstractions;
using AuthServer.Repositories.Abstractions;

namespace AuthServer.Authorize;

internal class AuthorizeRequestHandler : RequestHandler<AuthorizeRequest, AuthorizeValidatedRequest, string>
{
	private readonly IUnitOfWork _unitOfWork;
	private readonly IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest> _requestValidator;
    private readonly IRequestProcessor<AuthorizeValidatedRequest, string> _requestProcessor;
    private readonly IClientRepository _clientRepository;

    public AuthorizeRequestHandler(
        IUnitOfWork unitOfWork,
        IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest> requestValidator,
        IRequestProcessor<AuthorizeValidatedRequest, string> requestProcessor,
        IClientRepository clientRepository,
        IMetricService metricService)
        : base(metricService)
    {
	    _unitOfWork = unitOfWork;
	    _requestValidator = requestValidator;
	    _requestProcessor = requestProcessor;
        _clientRepository = clientRepository;
    }

    protected override async Task<ProcessResult<string, ProcessError>> ProcessValidatedRequest(AuthorizeValidatedRequest request, CancellationToken cancellationToken)
    {
	    await _unitOfWork.Begin(cancellationToken);
        var result = await _requestProcessor.Process(request, cancellationToken);
        await _unitOfWork.Commit(cancellationToken);
        return result;
    }

    protected override async Task<ProcessError> ProcessInvalidRequest(ProcessError error, CancellationToken cancellationToken)
    {
        if (error is PersistRequestUriError persistRequestUriError)
        {
            var authorizeRequestDto = new AuthorizeRequestDto(persistRequestUriError.AuthorizeRequest);
            var authorizeMessage = await _clientRepository.AddAuthorizeMessage(authorizeRequestDto, cancellationToken);
            var requestUri = $"{RequestUriConstants.RequestUriPrefix}{authorizeMessage.Reference}";

            return new AuthorizeInteractionError(
                persistRequestUriError.Error,
                persistRequestUriError.ErrorDescription,
                persistRequestUriError.ResultCode,
                requestUri,
                persistRequestUriError.AuthorizeRequest.ClientId!);
        }

        return error;
    }

    protected override async Task<ProcessResult<AuthorizeValidatedRequest, ProcessError>> ValidateRequest(AuthorizeRequest request, CancellationToken cancellationToken)
    {
        return await _requestValidator.Validate(request, cancellationToken);
    }
}