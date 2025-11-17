<script lang="ts">
    import CodeBlock from "../../../components/CodeBlock.svelte";
    import PageTitle from "../../../components/PageTitle.svelte";
    import Section from "../../../components/Section.svelte";
    import Table from "../../../components/Table.svelte";
    import { RowCellDefinition } from "../../../table";

    let grantTypeHeaders: string[] = ["Name", "Description"];
    let grantTypeRows: RowCellDefinition[][] = [
        [ new RowCellDefinition('Authorization Code'), new RowCellDefinition('Use a code in exchange of tokens.') ],
        [ new RowCellDefinition('Refresh Token'), new RowCellDefinition('Use a refresh token in exchange of tokens.') ],
        [ new RowCellDefinition('Client Credentials'), new RowCellDefinition('Use client authentication in exchange of tokens.') ]
    ];

    let specificationHeaders: string[] = ["Name", "Description"];
    let specificationRows: RowCellDefinition[][] = [
        [ new RowCellDefinition('OAuth2.1', 'https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/'), new RowCellDefinition('Core specification for OAuth') ],
        [ new RowCellDefinition('OpenId Connect', 'https://openid.net/specs/openid-connect-core-1_0.html'), new RowCellDefinition('Core specification for OpenId Connect') ],
        [ new RowCellDefinition('Device Authorization', 'https://datatracker.ietf.org/doc/html/rfc8628'), new RowCellDefinition('Specification for device authorization') ],
        [ new RowCellDefinition("Token Exchange", "https://datatracker.ietf.org/doc/html/rfc8693"), new RowCellDefinition("Specification to exchange tokens") ],
        [ new RowCellDefinition('JWT', 'https://datatracker.ietf.org/doc/html/rfc7519'), new RowCellDefinition('JsonWebToken specification') ],
        [ new RowCellDefinition('JWS', 'https://datatracker.ietf.org/doc/html/rfc7515'), new RowCellDefinition('JsonWebSignature specification') ],
        [ new RowCellDefinition('JWE', 'https://datatracker.ietf.org/doc/html/rfc7516'), new RowCellDefinition('JsonbWebEncryption specification') ],
        [ new RowCellDefinition('Resource', 'https://datatracker.ietf.org/doc/html/rfc8707/'), new RowCellDefinition('Resource indicators specification') ],
        [ new RowCellDefinition('Step up authentication', 'https://datatracker.ietf.org/doc/html/rfc9470/'), new RowCellDefinition('Step up authentication specification') ],
        [ new RowCellDefinition("DPoP", "https://datatracker.ietf.org/doc/html/rfc9449"), new RowCellDefinition("Specification for sender constraining tokens using DPoP") ]
    ];

    let accessTokenHeaders: string[] = ["Name", "Description"];
    let accessTokenRows: RowCellDefinition[][] = [
        [ new RowCellDefinition("jti"), new RowCellDefinition("Unique identifier of the token") ],
        [ new RowCellDefinition("scope"), new RowCellDefinition("String of space delimited scope values, which the token is authorized for") ],
        [ new RowCellDefinition("aud"), new RowCellDefinition("List of URIs of resources, which are authorized to receive the token") ],
        [ new RowCellDefinition("grant_id"), new RowCellDefinition("Unique identifier of the grant, which the token is authorized through") ],
        [ new RowCellDefinition("sub"), new RowCellDefinition("Identifier of the subject, which the token acts from") ],
        [ new RowCellDefinition("sid"), new RowCellDefinition("Identifier of the session, which the subject owns") ],
        [ new RowCellDefinition("client_id"), new RowCellDefinition("Identifier of the client, which requested the token") ],
        [ new RowCellDefinition("auth_time"), new RowCellDefinition("Unix time of the subjects authentication") ],
        [ new RowCellDefinition("acr"), new RowCellDefinition("String of the authentication context reference from when the subject authenticated") ],
        [ new RowCellDefinition("cnf"), new RowCellDefinition("Object with one field, which is jkt. That is the thumbprint of the DPoP if the token is sender-constrained") ],
        [ new RowCellDefinition("act"), new RowCellDefinition("Object with one field, which is sub. That is the subject of the actor using the token on behalf of the tokens subject") ],
        [ new RowCellDefinition("may_act"), new RowCellDefinition("Object with one field, which is sub. That is the subject of the actor allowed to use the token on behalf of the tokens subject") ],
        [ new RowCellDefinition("access_control"), new RowCellDefinition("Custom object of permission claims belonging to the subject") ],
    ];

    let idTokenHeaders: string[] = ["Name", "Description"];
    let idTokenRows: RowCellDefinition[][] = [
        [ new RowCellDefinition("jti"), new RowCellDefinition("Unique identifier of the token") ],
        [ new RowCellDefinition("nonce"), new RowCellDefinition("Client provided nonce during authorization") ],
        [ new RowCellDefinition("aud"), new RowCellDefinition("List of URIs of resources, which are authorized to receive the token") ],
        [ new RowCellDefinition("grant_id"), new RowCellDefinition("Unique identifier of the grant, which the token is authorized through") ],
        [ new RowCellDefinition("sub"), new RowCellDefinition("Identifier of the subject, which the token acts from") ],
        [ new RowCellDefinition("sid"), new RowCellDefinition("Identifier of the session, which the subject owns") ],
        [ new RowCellDefinition("client_id"), new RowCellDefinition("Identifier of the client, which requested the token") ],
        [ new RowCellDefinition("auth_time"), new RowCellDefinition("Unix time of the subjects authentication") ],
        [ new RowCellDefinition("acr"), new RowCellDefinition("String of the authentication context reference from when the subject authenticated") ],
        [ new RowCellDefinition("amr"), new RowCellDefinition("List of strings of the authentication method references from when the subject authenticated") ],
        [ new RowCellDefinition("azp"), new RowCellDefinition("Identifier of the client, which is the authorized party") ],
        [ new RowCellDefinition("act"), new RowCellDefinition("Object with one field, which is sub. That is the subject of the actor using the token on behalf of the tokens subject") ],
        [ new RowCellDefinition("may_act"), new RowCellDefinition("Object with one field, which is sub. That is the subject of the actor allowed to use the token on behalf of the tokens subject") ],
    ];

    let requestHeaders: string[] = ["Name", "Description"];
    let requestFields: RowCellDefinition[][] = [
        [ new RowCellDefinition("grant_type"), new RowCellDefinition("The type of grant to authorize for an exchange of a token") ],
        [ new RowCellDefinition("code"), new RowCellDefinition("The authorization_code grant which is used in the authorization_code grant type") ],
        [ new RowCellDefinition("code_verifier"), new RowCellDefinition("The value to verify against the code_challenge provided during authorization") ],
        [ new RowCellDefinition("redirect_uri"), new RowCellDefinition("The redirect_uri provided during authorization") ],
        [ new RowCellDefinition("refresh_token"), new RowCellDefinition("The refresh_token grant which is used in the refresh_token grant type") ],
        [ new RowCellDefinition("scope"), new RowCellDefinition("The scope which the token is authorized for") ],
        [ new RowCellDefinition("resource"), new RowCellDefinition("The resource URIs which the token is authorized to") ],
        [ new RowCellDefinition("device_code"), new RowCellDefinition("The device code received from initiating device authorization") ],
        [ new RowCellDefinition("dpop"), new RowCellDefinition("The dpop token used to bind the access token") ],
        [ new RowCellDefinition("requested_token_type"), new RowCellDefinition("The type of token to receive from token exchange") ],
        [ new RowCellDefinition("subject_token"), new RowCellDefinition("The token to exchange") ],
        [ new RowCellDefinition("subject_token_type"), new RowCellDefinition("The type of token to exchange") ],
        [ new RowCellDefinition("actor_token"), new RowCellDefinition("The token to bind delegation with the exchanged token") ],
        [ new RowCellDefinition("actor_token_type"), new RowCellDefinition("The type of token to bind delegation with the exchanged token") ],
    ];

    let responseHeaders: string[] = ["Name", "Description"];
    let responseFields: RowCellDefinition[][] = [
        [ new RowCellDefinition("access_token"), new RowCellDefinition("The access token in exchange of the grant") ],
        [ new RowCellDefinition("refresh_token"), new RowCellDefinition("The refresh token, if the client is authorized for the refresh_token grant_type") ],
        [ new RowCellDefinition("id_token"), new RowCellDefinition("The id token, if the grant_type is used with openid") ],
        [ new RowCellDefinition("expires_in"), new RowCellDefinition("Unix time of when the access_token expires") ],
        [ new RowCellDefinition("scope"), new RowCellDefinition("Space delimitied string of scopes, which the access_token is authorized for") ],
        [ new RowCellDefinition("grant_id"), new RowCellDefinition("The identifier of the grant, from where the access_token comes from.") ],
        [ new RowCellDefinition("token_type"), new RowCellDefinition("The type of usage of the access token received") ],
        [ new RowCellDefinition("issued_token_type"), new RowCellDefinition("The type of token received in the access token field") ],
        [ new RowCellDefinition("error"), new RowCellDefinition("The code of the error") ],
        [ new RowCellDefinition("error_description"), new RowCellDefinition("The description of the error") ]
    ];
</script>

<svelte:head>
	<title>Token Endpoint</title>
</svelte:head>

<PageTitle title="Token" />
<Section title="Introduction">
    <p>
        The token endpoint, in general terms, is used to get access tokens through grants.
        The grants are identified through a grant type. The supported grant types are listed in Table 1.
    </p>
    <br>
    <Table title="Grant types" tableNumber={1} headers={grantTypeHeaders} rowCellDefinitions={grantTypeRows} />
</Section>
<Section title="Specifications">
    <Table title="Specifications" tableNumber={2} headers={specificationHeaders} rowCellDefinitions={specificationRows} />
</Section>
<Section title="Token structure">
    <p>The tokens returned can be in different formats. The supported formats are JWT or Reference.</p>
    <br>
    <p>JWT is a well structured token format using JSON, and it supports signatures and encryption.</p>
    <br>
    <p>Reference is a random string, which is only understood by AuthServer. The content of the token, can be retrieved from the Introspection endpoint.</p>
    <br>
    <p>The client can choose between the two in its metadata, through the field "UseReferenceToken".</p>
    <p>If bandwidth of the client is of concern, or you require the content of token is only send through backchannels, then the Reference token is a suitable candidate.
        It however requires an extra roundtrip at the protected resource, to verify the token at AuthServer.
    </p>
    <br>
    <p>Finally, it is also possible to sender-constraint a token, irrespective of its structure.</p>
    <p>It means the token is cryptographically bound to the client that requested the token, and therefore can only be used by that client.</p>
    <p>This is achievable through DPoP.</p>
</Section>
<Section title="Fine grained tokens">
    <p>It is recommended that tokens have a short lifespan, in minutes and at most an hour.</p>
    <p>This can be adjusted for each client in its metadata. Each type of token, has a specific field for adjusting its expiration.</p>
    <br>
    <p>It is recommended that tokens are only used at protected resources, which the client requests.</p>
    <p>This is done through the "resource" parameter, which is a single protected resource absolute base URI.
        The parameter can be provided as many times as needed, and the URI is visible in the audience claim.
    </p>
    <p>For example if a protected resource URI is reachable at "https://weather.authserver.dk", then that URI will be provded as the resource parameter.</p>
    <br>
    <p>It is recommended that tokens are only used for what they request.</p>
    <p>This is done through the "scope" parameter, which is a space seperated string of scopes that the token is authorized for.</p>
    <p>For example if a token must be used to fetch data about the weather, and the scope required for requesting weather is named "weather:read".
        Then the scope parameter will be set to "weather:read".
    </p>
</Section>
<Section title="Access token claims">
    <p>Structured access tokens contain payload claims listed in the following table.</p>
    <Table title="Access token claims" tableNumber={3} headers={accessTokenHeaders} rowCellDefinitions={accessTokenRows} />
</Section>
<Section title="Id token claims">
    <p>Id tokens contain payload claims listed in the following table.</p>
    <Table title="Id token claims" tableNumber={4} headers={idTokenHeaders} rowCellDefinitions={idTokenRows} />
</Section>
<Section title="Token Endpoint">
    <p>The token endpoint accepts the POST HTTP method, and the content is application/x-www-form-urlencoded.</p>
    <p>The endpoint also allows for client authentication, and the parameters are defined in the Client Authentication page.</p>
    <p>The content differs by which grant_type is provided, a list of all parameters is seen in the following table.</p>
    <Table title="Token request parameters" tableNumber={5} headers={requestHeaders} rowCellDefinitions={requestFields} />
    <br>
    <p>The token endpoint returns HTTP 200 if successful, and 400 if an error occurred.</p>
    <p>The content is application/json, and a list of all parameters is seen in the following table.</p>
    <Table title="Token response parameters" tableNumber={6} headers={responseHeaders} rowCellDefinitions={responseFields} />
    <br>
    <p>HTTP request examples are provided for each grant type, as each request and response differs depending on the grant type used.</p>
    <p>However, the error does not differ, and the following request example shows an error scenario.</p>
    <CodeBlock>
        {`
POST /connect/token HTTP/1.1
Host: idp.authserver.dk
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

grant_type=invalid_grant_type
        `}
    </CodeBlock>
    <p>The following HTTP example shows the error response.</p>
    <CodeBlock>
        {`
HTTP/1.1 400 BadRequest
Content-Type: application/json;charset=UTF-8
Cache-Control: no-cache, no-store

{
  "error":"unsupported_grant_type",
  "error_description":"grant_type is unsupported"
}
        `}
    </CodeBlock>
</Section>