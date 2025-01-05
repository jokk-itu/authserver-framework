using AuthServer.Core;
using AuthServer.Core.Request;

namespace AuthServer.GrantManagement;

public class GrantManagementError
{
    public static readonly ProcessError InvalidGrantId =
        new(ErrorCode.InvalidRequest, "grant_id is required", ResultCode.BadRequest);

    public static readonly ProcessError UnexistingGrantId =
        new(ErrorCode.InvalidRequest, "grant does not exist", ResultCode.BadRequest);
    
    public static readonly ProcessError InvalidGrant =
        new(ErrorCode.InvalidGrant, "grant is issued to other client", ResultCode.BadRequest);
}