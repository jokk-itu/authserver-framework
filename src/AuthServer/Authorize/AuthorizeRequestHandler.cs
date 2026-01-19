using AuthServer.Authorization.Models;
using AuthServer.Constants;
using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.Metrics.Abstractions;
using AuthServer.Repositories.Abstractions;
using Microsoft.Extensions.Logging;

namespace AuthServer.Authorize;

internal class AuthorizeRequestHandler : RequestHandler<AuthorizeRequest, AuthorizeValidatedRequest, AuthorizeResponse>
{
	private readonly IUnitOfWork _unitOfWork;
	private readonly IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest> _requestValidator;
    private readonly IRequestProcessor<AuthorizeValidatedRequest, AuthorizeResponse> _requestProcessor;
    private readonly IClientRepository _clientRepository;

    public AuthorizeRequestHandler(
        IUnitOfWork unitOfWork,
        IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest> requestValidator,
        IRequestProcessor<AuthorizeValidatedRequest, AuthorizeResponse> requestProcessor,
        IClientRepository clientRepository,
        IMetricService metricService,
        ILogger<AuthorizeRequestHandler> logger)
        : base(metricService, logger)
    {
	    _unitOfWork = unitOfWork;
	    _requestValidator = requestValidator;
	    _requestProcessor = requestProcessor;
        _clientRepository = clientRepository;
    }

    protected override async Task<ProcessResult<AuthorizeResponse, ProcessError>> ProcessValidatedRequest(AuthorizeValidatedRequest request, CancellationToken cancellationToken)
    {
	    await _unitOfWork.Begin(cancellationToken);
        var result = await _requestProcessor.Process(request, cancellationToken);
        await _unitOfWork.Commit(cancellationToken);
        return result;
    }

    protected override async Task<ProcessResult<AuthorizeValidatedRequest, ProcessError>> ValidateRequest(AuthorizeRequest request, CancellationToken cancellationToken)
    {
        var response = await _requestValidator.Validate(request, cancellationToken);

        if (response is { IsSuccess: false, Error: PersistRequestUriError persistRequestUriError })
        {
            await _unitOfWork.Begin(cancellationToken);
            var authorizeRequestDto = new AuthorizeRequestDto(persistRequestUriError.AuthorizeRequest);
            var authorizeMessage = await _clientRepository.AddAuthorizeMessage(authorizeRequestDto, cancellationToken);
            await _unitOfWork.Commit(cancellationToken);

            var requestUri = $"{RequestUriConstants.RequestUriPrefix}{authorizeMessage.Reference}";

            return new AuthorizeInteractionError(
                persistRequestUriError.Error,
                persistRequestUriError.ErrorDescription,
                persistRequestUriError.ResultCode,
                requestUri,
                persistRequestUriError.AuthorizeRequest.ClientId!);
        }

        return response;
    }
}