﻿using AuthServer.Core.Request;

namespace AuthServer.Authorize;

public class AuthorizeInteractionError(
    string Error,
    string ErrorDescription,
    ResultCode ResultCode,
    string RequestUri,
    string ClientId,
    bool RedirectToInteraction) : ProcessError(Error, ErrorDescription, ResultCode)
{
    public string RequestUri = RequestUri;
    public string ClientId = ClientId;
    public bool RedirectToInteraction = RedirectToInteraction;
}