﻿namespace AuthServer.Authorize;

public record AuthorizeUser(string SubjectIdentifier, bool IsFreshGrant);