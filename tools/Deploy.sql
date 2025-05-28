BEGIN
	IF NOT EXISTS (SELECT 1 FROM Client WHERE [Name] = 'authserver')
	BEGIN
		INSERT INTO Client (Id, [Name], ClientUri, ApplicationType, TokenEndpointAuthMethod, TokenEndpointAuthSigningAlg, CreatedAt, AccessTokenExpiration, DPoPNonceExpiration, RequireConsent, RequirePushedAuthorizationRequests, RequireReferenceToken, RequireSignedRequestObject, RequireIdTokenClaims, RequireDPoPBoundAccessTokens)
		VALUES (NEWID(), 'authserver', 'https://localhost:7254', 0, 0, 0, GETUTCDATE(), 0, 0, 0, 0, 0, 0, 0, 0)
	END
	
	DECLARE @ClientId UNIQUEIDENTIFIER = (SELECT Id FROM Client WHERE [Name] = 'authserver')
	DECLARE @UserInfoScope INT = (SELECT Id FROM Scope WHERE [Name] = 'authserver:userinfo')

    IF NOT EXISTS (SELECT 1 FROM ClientScope WHERE ClientId = @ClientId AND ScopeId = @UserInfoScope)
    BEGIN
        INSERT INTO ClientScope (ClientId, ScopeId)
	    VALUES (@ClientId, @UserinfoScope)
    END
END

BEGIN
	IF NOT EXISTS (SELECT 1 FROM SubjectIdentifier WHERE Id = '9ce5c367-5617-44bf-8aeb-347f604c10db')
	BEGIN
		INSERT INTO SubjectIdentifier (Id)
		VALUES ('9ce5c367-5617-44bf-8aeb-347f604c10db')
	END
END

BEGIN
	IF NOT EXISTS (SELECT 1 FROM AuthenticationContextReference WHERE [Name] = 'urn:authserver:loa:low')
	BEGIN
		INSERT INTO AuthenticationContextReference ([Name])
		VALUES ('urn:authserver:loa:low')
	END
END

BEGIN
	IF NOT EXISTS (SELECT 1 FROM AuthenticationContextReference WHERE [Name] = 'urn:authserver:loa:substantial')
	BEGIN
		INSERT INTO AuthenticationContextReference ([Name])
		VALUES ('urn:authserver:loa:substantial')
	END
END

BEGIN
	IF NOT EXISTS (SELECT 1 FROM AuthenticationContextReference WHERE [Name] = 'urn:authserver:loa:strict')
	BEGIN
		INSERT INTO AuthenticationContextReference ([Name])
		VALUES ('urn:authserver:loa:strict')
	END
END