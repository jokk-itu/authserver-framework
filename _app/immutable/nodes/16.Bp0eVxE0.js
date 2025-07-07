import{t as p,h as x,a as o,b as k}from"../chunks/BdD32qd5.js";import"../chunks/BOyCDzPS.js";import{p as F,f as $,a as y,$ as I,s as n,n as i}from"../chunks/Db0b_LWK.js";import{i as S}from"../chunks/hXpMuBZJ.js";import{C as _}from"../chunks/Dg6GzD5d.js";import{P as O,S as c}from"../chunks/DcIxqC40.js";import{T as A,R as s}from"../chunks/BL1phRJf.js";var D=p(`<p>When the client has received its initial access token,
        it can be efficient to refresh the token when it expires,
        or if the tokens scope or audience needs to be updated.</p> <p>The use case is covered by the refresh_token grant type,
        which exchanges a fresh access token by a refresh_token.</p> <br> <p>The refresh token typically has a longer lifetime than the access tokens,
        and can be defined in the client metadata.</p> <br> <p>If the refresh token request uses DPoP,
        and the client is public, then the refresh token must also be DPoP bound.
        It is recommended to sender-constraint the refresh token, instead of rotating refresh tokens.</p>`,1),z=p(`<p>The request contains a refresh token from the initial token request,
        which returned the first token from another grant such as authorization_code.</p> <br> <p>It is possible to change the scope and audience of the access token,
        through the parameters "scope" and "resource".</p> <br> <p>The following HTTP example shows a token request using the code from the identity provider.</p> <!> <p>The following HTTP example shows a token response containing tokens exchanged from the refresh token.</p> <!>`,1),H=p("<!> <!> <!> <!>",1);function J(T,b){F(b,!1);let g=["Name","Description"],v=[[new s("OAuth2.1","https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/"),new s("Core specification for OAuth")],[new s("OpenId Connect","https://openid.net/specs/openid-connect-core-1_0.html"),new s("Core specification for OpenId Connect")]];S();var h=H();x(e=>{I.title="Refresh Token Grant"});var d=$(h);O(d,{title:"Refresh Token"});var l=n(d,2);c(l,{title:"Introduction",children:(e,u)=>{var r=D();i(10),o(e,r)},$$slots:{default:!0}});var f=n(l,2);c(f,{title:"Specifications",children:(e,u)=>{A(e,{title:"Specifications",tableNumber:1,headers:g,rowCellDefinitions:v})},$$slots:{default:!0}});var w=n(f,2);c(w,{title:"Token Endpoint",children:(e,u)=>{var r=z(),m=n($(r),10);_(m,{children:(a,P)=>{i();var t=k();t.nodeValue=`
POST /connect/token HTTP/1.1
Host: idp.authserver.dk
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

grant_type=refresh_token
&refresh_token=SplxlOBeZQQYbYS6WxSbIA
&scope=weather:read
&resource=https%3A%2F%2Fapi-one.protectedresource.dk
`,o(a,t)},$$slots:{default:!0}});var C=n(m,4);_(C,{children:(a,P)=>{i();var t=k();t.nodeValue=`
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Cache-Control: no-cache, no-store

{
  "access_token":"2YotnFZFEjr1zCsicMWpAA",
  "token_type":"Bearer",
  "expires_in":3600,
  "scope":"weather:read",
  "id_token":"eyJhbGciOiJSUzI1NiIsImtpZCI...",
  "grant_id":"78FF77E8-F146-4F37-9C28-5FD0BC936980"
}
        `,o(a,t)},$$slots:{default:!0}}),o(e,r)},$$slots:{default:!0}}),o(T,h),y()}export{J as component};
