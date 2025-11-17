<script lang="ts">
    import CodeBlock from "../../../components/CodeBlock.svelte";
    import PageTitle from "../../../components/PageTitle.svelte";
    import Section from "../../../components/Section.svelte";
    import Table from "../../../components/Table.svelte";
    import { RowCellDefinition } from "../../../table";

    let specificationHeaders: string[] = ["Name", "Description"];
    let specificationRows: RowCellDefinition[][] = [
        [ new RowCellDefinition("Token Exchange", "https://datatracker.ietf.org/doc/html/rfc8693"), new RowCellDefinition("Specification to exchange tokens") ]
    ];
</script>

<svelte:head>
	<title>Token Exchange</title>
</svelte:head>

<PageTitle title="Token Exchange" />
<Section title="Introduction">
    <p>
        The token exchange grant type is used to exchange a token for another one.
        There are several use cases for this, where one can exchange one type of token for another one,
        or decrease/replace authorization of a token.
    </p>
    <br>
    <p>
        Token Exchange can happen in two forms: Impersonation or Delegation.
    </p>
    <p>
        A client can impersonate another client by requesting a token exchange,
        and act as the client, and there is no trace of impersonation in the exchanged token.
    </p>
    <p>
        A client can be delegated access from another client, by request a token exchange,
        and link a token to the exchanged token, thereby tracing that the token has been exchanged.
    </p>
</Section>
<Section title="Specifications">
    <Table title="Specifications" tableNumber={1} headers={specificationHeaders} rowCellDefinitions={specificationRows} />
</Section>
<Section title="Restrictions and Extensions">
    <p>
        Only confidential clients are are eligible for token exchange, as it requires client authentication.
    </p>
    <p>
        Only access_token and id_token can be used as subject, actor and requested tokens.
    </p>
    <p>
        Only tokens from AuthServer are allowed to participate in token exchange.
    </p>
    <p>
        The act claim is not nested, and does not allow for tracing a full transaction of multiple token exchanges.
    </p>
    <br>
    <p>
        Validation can be extended by implementing the interface "IExtendedTokenExchangeRequestValidator".
    </p>
</Section>
<Section title="Token endpoint">
    <p>
        If the parameter "grant_type" is passed with value "urn:ietf:params:oauth:grant-type:token-exchange" to the token endpoint, then a subject_token is exchanged for a requested token.
    </p>
    <p>
        The subject_token is used to exchange it for a new token, which is passed in the "access_token" field.
        The specific type of token is defined by the requestor, in the field "requested_token_type",
        and is also set in the response field "issued_token_type".
    </p>
    <p>The following is an example HTTP request using token exchange.</p>
    <CodeBlock>
{`
POST /connect/token HTTP/1.1
Host: idp.authserver.dk
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=eyJhbGciOiJSUzI1NiIsImtpZCI...
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&requested_token_type=urn:ietf:params:oauth:token-type:access_token
&scope=account:update%20account:delete
&resource=https%3A%2F%2Fapi-one.protectedresource.dk
&resource=https%3A%2F%2Fapi-two.protectedresource.dk
`}
    </CodeBlock>
    <p>The following is an example HTTP response using token exchange.</p>
    <CodeBlock>
{`
HTTP/1.1 200 BadRequest
Content-Type: application/json;charset=UTF-8
Cache-Control: no-cache, no-store

{
  "access_token":"eyJhbGciOiJSUzI1NiIsImtpZCI...",
  "expires_in": 300,
  "scope": "account:update account:delete",
  "token_type": "Bearer",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token"
}
`}
    </CodeBlock>
</Section>
<Section title="Decrease access">
    <p>
        If a protected resource receives a token with a lot privileges,
        and the protected resource needs to send it downstream, but less privilege is needed.
    </p>
    <p>The protected resource can exchange the token with the least privilege required using token exchange.</p>
</Section>
<Section title="Create access">
    <p>If a protected resource receives a token that it needs to send downstream, but it is missing required privileges.</p>
    <p>The protected resource can exchange the token with the required privilege required using token exchange.</p>
</Section>
<Section title="Impersonating an end user">
    <p>Explain the use case of impersonating an end user and using the may_act claim.</p>
</Section>
<Section title="DPoP bound exchanged token">
    <p>Explain how to DPoP bound and how it works</p>
</Section>
<Section title="Id token encryption">
    <p>Explain that the client invoking the endpoint, is used as the encryptor for the id token.</p>
</Section>