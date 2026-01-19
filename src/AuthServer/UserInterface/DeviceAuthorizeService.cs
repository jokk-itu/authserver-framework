using AuthServer.Authentication.Abstractions;
using AuthServer.Codes;
using AuthServer.Codes.Abstractions;
using AuthServer.Repositories.Abstractions;
using AuthServer.UserInterface.Abstractions;

namespace AuthServer.UserInterface;

internal class DeviceAuthorizeService : IDeviceAuthorizeService
{
    private readonly IAuthenticatedUserAccessor _authenticatedUserAccessor;
    private readonly ICodeEncoder<EncodedDeviceCode> _deviceCodeEncoder;
    private readonly IDeviceCodeRepository _deviceCodeRepository;

    public DeviceAuthorizeService(
        IAuthenticatedUserAccessor authenticatedUserAccessor,
        ICodeEncoder<EncodedDeviceCode> deviceCodeEncoder,
        IDeviceCodeRepository deviceCodeRepository)
    {
        _authenticatedUserAccessor = authenticatedUserAccessor;
        _deviceCodeEncoder = deviceCodeEncoder;
        _deviceCodeRepository = deviceCodeRepository;
    }

    public async Task<DeviceAuthorizeDto?> GetDeviceAuthorizeDto(string userCode, CancellationToken cancellationToken)
    {
        var deviceCode = await _deviceCodeRepository.GetDeviceCode(userCode, cancellationToken);
        if (deviceCode is null)
        {
            return null;
        }

        var encodedDeviceCode = _deviceCodeEncoder.Decode(deviceCode.RawValue);
        if (encodedDeviceCode is null)
        {
            return null;
        }

        return new DeviceAuthorizeDto
        {
            ClientId = encodedDeviceCode.ClientId,
            DeviceCodeId = encodedDeviceCode.DeviceCodeId,
            UserCodeId = encodedDeviceCode.UserCodeId,
            AcrValues = encodedDeviceCode.AcrValues,
            AuthorizationGrantId = encodedDeviceCode.AuthorizationGrantId,
            GrantManagementAction = encodedDeviceCode.GrantManagementAction,
            Scope = encodedDeviceCode.Scope
        };
    }

    public async Task<SubjectDto> GetSubject(CancellationToken cancellationToken)
    {
        var authenticatedUser = await _authenticatedUserAccessor.GetAuthenticatedUser();
        if (authenticatedUser is not null)
        {
            return new SubjectDto
            {
                Subject = authenticatedUser.SubjectIdentifier,
                GrantId = authenticatedUser.AuthorizationGrantId
            };
        }

        throw new InvalidOperationException("subject cannot be deduced");
    }
}