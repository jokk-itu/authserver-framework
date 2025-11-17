import{f as r,a as n,t as x}from"../chunks/Z1HRfbhX.js";import"../chunks/BQYPTkyu.js";import{p as D,f as y,a as F,e as R,s as o,$ as j,n as i}from"../chunks/Iw8VLsBB.js";import{h as z}from"../chunks/BhNhnXGn.js";import{i as A}from"../chunks/Bwhf-QOO.js";import{C as T}from"../chunks/CVzv1ABR.js";import{P as H,S as a}from"../chunks/D5cW4fPA.js";import{T as O,R as b}from"../chunks/DtqDFwhC.js";var J=r(`<p>The token exchange grant type is used to exchange a token for another one.
        There are several use cases for this, where one can exchange one type of token for another one,
        or decrease/replace authorization of a token.</p> <br/> <p>Token Exchange can happen in two forms: Impersonation or Delegation.</p> <p>A client can impersonate another client by requesting a token exchange,
        and act as the client, and there is no trace of impersonation in the exchanged token.</p> <p>A client can be delegated access from another client, by request a token exchange,
        and link a token to the exchanged token, thereby tracing that the token has been exchanged.</p>`,1),B=r('<p>Only confidential clients are are eligible for token exchange, as it requires client authentication.</p> <p>Only access_token and id_token can be used as subject, actor and requested tokens.</p> <p>Only tokens from AuthServer are allowed to participate in token exchange.</p> <p>The act claim is not nested, and does not allow for tracing a full transaction of multiple token exchanges.</p> <br/> <p>Validation can be extended by implementing the interface "IExtendedTokenExchangeRequestValidator".</p>',1),N=r(`<p>If the parameter "grant_type" is passed with value "urn:ietf:params:oauth:grant-type:token-exchange" to the token endpoint, then a subject_token is exchanged for a requested token.</p> <p>The subject_token is used to exchange it for a new token, which is passed in the "access_token" field.
        The specific type of token is defined by the requestor, in the field "requested_token_type",
        and is also set in the response field "issued_token_type".</p> <p>The following is an example HTTP request using token exchange.</p> <!> <p>The following is an example HTTP response using token exchange.</p> <!>`,1),V=r(`<p>If a protected resource receives a token with a lot privileges,
        and the protected resource needs to send it downstream, but less privilege is needed.</p> <p>The protected resource can exchange the token with the least privilege required using token exchange.</p>`,1),G=r("<p>If a protected resource receives a token that it needs to send downstream, but it is missing required privileges.</p> <p>The protected resource can exchange the token with the required privilege required using token exchange.</p>",1),U=r("<p>Explain the use case of impersonating an end user and using the may_act claim.</p>"),Z=r("<p>Explain how to DPoP bound and how it works</p>"),M=r("<p>Explain that the client invoking the endpoint, is used as the encryptor for the id token.</p>"),W=r("<!> <!> <!> <!> <!> <!> <!> <!> <!> <!>",1);function oe(w,P){D(P,!1);let I=["Name","Description"],q=[[new b("Token Exchange","https://datatracker.ietf.org/doc/html/rfc8693"),new b("Specification to exchange tokens")]];A();var l=W();z("a19h53",e=>{R(()=>{j.title="Token Exchange"})});var d=y(l);H(d,{title:"Token Exchange"});var h=o(d,2);a(h,{title:"Introduction",children:(e,s)=>{var t=J();i(8),n(e,t)},$$slots:{default:!0}});var u=o(h,2);a(u,{title:"Specifications",children:(e,s)=>{O(e,{title:"Specifications",tableNumber:1,get headers(){return I},get rowCellDefinitions(){return q}})},$$slots:{default:!0}});var f=o(u,2);a(f,{title:"Restrictions and Extensions",children:(e,s)=>{var t=B();i(10),n(e,t)},$$slots:{default:!0}});var g=o(f,2);a(g,{title:"Token endpoint",children:(e,s)=>{var t=N(),v=o(y(t),6);T(v,{children:(p,S)=>{i();var c=x();c.nodeValue=`
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
`,n(p,c)},$$slots:{default:!0}});var E=o(v,4);T(E,{children:(p,S)=>{i();var c=x();c.nodeValue=`
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
`,n(p,c)},$$slots:{default:!0}}),n(e,t)},$$slots:{default:!0}});var k=o(g,2);a(k,{title:"Decrease access",children:(e,s)=>{var t=V();i(2),n(e,t)},$$slots:{default:!0}});var m=o(k,2);a(m,{title:"Create access",children:(e,s)=>{var t=G();i(2),n(e,t)},$$slots:{default:!0}});var _=o(m,2);a(_,{title:"Impersonating an end user",children:(e,s)=>{var t=U();n(e,t)},$$slots:{default:!0}});var $=o(_,2);a($,{title:"DPoP bound exchanged token",children:(e,s)=>{var t=Z();n(e,t)},$$slots:{default:!0}});var C=o($,2);a(C,{title:"Id token encryption",children:(e,s)=>{var t=M();n(e,t)},$$slots:{default:!0}}),n(w,l),F()}export{oe as component};
