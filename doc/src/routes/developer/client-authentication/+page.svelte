<script>
    import CodeBlock from "../../../components/CodeBlock.svelte";
    import InformationBanner from "../../../components/InformationBanner.svelte";
    import PageTitle from "../../../components/PageTitle.svelte";
    import Section from "../../../components/Section.svelte";
    import Table from "../../../components/Table.svelte";

    let specificationHeaders = ["Name", "Link", "Description"];
    let specificationRows = [
        ["OAuth2.1", "https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/", "Core specification for OAuth"],
        ["OpenId Connect", "https://openid.net/specs/openid-connect-core-1_0.html", "Core specification for OpenId Connect"],
        ["JWT Assertion framework", "https://datatracker.ietf.org/doc/rfc7523/", "Specification for JWT assertions"],
        ["Assertion framework", "https://datatracker.ietf.org/doc/rfc7521/", "Specification for OAuth assertions"]
    ];

    let privateKeyClaimHeaders = ["Name", "Description"];
    let privateKeyClaimRows = [
        ["iss", "Required. Issuer of the token, must be the client id"],
        ["sub", "Required. Subject of the token, must be the client id"],
        ["aud", "Required. Audience of the token, must be the endpoint where the client is authenticating"],
        ["jti", "Required. Unique id of the token"],
        ["exp", "Required. Expiration time of the token"],
        ["iat", "Optional. Time at which the token was issued"],
        ["typ", "Required. Type of token, which must be: pk+jwt"]
    ];
</script>

<PageTitle title="Client Authentication" />
<Section title="Introduction">
    <p>
        The client can authenticate itself when requesting endpoints, through a
        backchannel, for example at the token endpoint.
    </p>
    <br />
    <p>
        Authentication is grouped into either using shared secrets, or using
        public key cryptography.
    </p>
</Section>
<Section title="Specifications">
    <Table title="Specifications" tableNumber={1} headers={specificationHeaders} rows={specificationRows} />
</Section>
<Section title="Client Secret Basic">
    <p>Authenticate using the HTTP Authorization header, using the basic schema.</p>
    <p>The header contains the client id as the username and the client secret as the password.</p>
    <p>The combination of client id and secret is afterwards base64 encoded.</p>
    <p>The following example is for the token endpoint. The client id is s6BhdRkqt3 and the client secret is gX1fBat3bV.</p>
    <CodeBlock>
        {`
POST /token HTTP/1.1
Host: idp.authserver.com
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
Content-Type: application/x-www-form-urlencoded
grant_type=client_credentials&scope=weather:read
        `}
    </CodeBlock>
</Section>
<Section title="Client Secret Post">
    <p>Authenticate using the HTTP body. The body contains the client id and the client secret.</p>
    <p>The following example is for the token endpoint.</p>
    <CodeBlock>
        {`
POST /token HTTP/1.1
Host: idp.authserver.com
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&scope=weather:read&
client_id=s6BhdRkqt3&client_secret=gX1fBat3bV
        `}
    </CodeBlock>
</Section>
<Section title="Client Secret JWT">
    <InformationBanner>
        <p>
            The client secret must be shared between the client and AuthServer for client secret JWT to work.
            AuthServer does not support this, because secrets are hashed.
        </p>
    </InformationBanner>
</Section>
<Section title="Private key JWT">
    <p>Authenticate using the HTTP body. The body contains the client assertion type, the client assertion and optionally the client id.</p>
    <p>The following example is for the token endpoint.</p>
    <CodeBlock>
        {`
POST /token HTTP/1.1
Host: idp.authserver.dk
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&
scope=weather:read&
client_id=s6BhdRkqt3&
client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&
client_assertion=eyJ0eXAiOiJKV1QiLCJh...82U
        `}
    </CodeBlock>
    <p>The following table describes the possible claims in the token.</p>
    <Table title="Private key JWT claims" tableNumber={2} headers={privateKeyClaimHeaders} rows={privateKeyClaimRows} />
</Section>