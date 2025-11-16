import{t as u,h as R,a as i,b as a}from"../chunks/BdD32qd5.js";import"../chunks/BOyCDzPS.js";import{p as B,f as q,a as A,$ as z,s as o,n as r}from"../chunks/Db0b_LWK.js";import{i as V}from"../chunks/hXpMuBZJ.js";import{C as p}from"../chunks/Dg6GzD5d.js";import{I as C}from"../chunks/BqXxNwWv.js";import{P as E,S as d}from"../chunks/DcIxqC40.js";import{T as l,R as e}from"../chunks/BL1phRJf.js";var Z=u(`<p>The token introspection endpoint is used to introspect tokens.
        This is useful when the client requires opaque tokens that are not structured,
        such that protected resources can request the introspection endpoint and get information about the token.
        The endpoint supports introspecting access tokens and refresh tokens.</p>`),K=u("<p>The token introspection endpoint accepts the POST HTTP method, and the content is application/x-www-form-urlencoded.</p> <p>The endpoint also requires client authentication, and the parameters are defined in the Client Authentication page.</p> <!> <br> <p>The token introspection endpoint returns HTTP 200 if successful, and 400 if an error occurred.</p> <!> <br> <p>The following table shows the parameters that can be sent to the endpoint.</p> <!> <br> <!> <br> <p>The following HTTP example shows a request to introspect an access token.</p> <!> <p>The following HTTP example shows a response with an active dpop bound token and an end-user as the subject.</p> <!> <p>The following HTTP example shows a response with an active bearer token and the client as the subject.</p> <!> <p>The following HTTP example shows a response with an inactive token.</p> <!>",1),W=u("<!> <!> <!> <!>",1);function te(j,I){B(I,!1);let y=["Name","Description"],H=[[new e("OpenId Connect","https://openid.net/specs/openid-connect-core-1_0.html"),new e("Core specification for OpenId Connect")],[new e("Token Introspection","https://datatracker.ietf.org/doc/html/rfc7662"),new e("Specification for introspecting tokens")],[new e("DPoP","https://datatracker.ietf.org/doc/html/rfc9449"),new e("Specification for sender constraining tokens using DPoP")],[new e("Step up authentication","https://datatracker.ietf.org/doc/html/rfc9470/"),new e("Step up authentication specification")],[new e("Token Exchange","https://datatracker.ietf.org/doc/html/rfc8693"),new e("Specification to exchange tokens")]],S=["Name","Description"],D=[[new e("token"),new e("The token to be introspected. It is required.")],[new e("token_type_hint"),new e("The type of token to be introspected. It is optional.")]],O=["Name","Description"],U=[[new e("active"),new e("Boolean determining if the token is active or not. This is required.")],[new e("scope"),new e("Space delimited string of scopes. This is required if active.")],[new e("client_id"),new e("Id of client that owns the token. This is required if active.")],[new e("username"),new e("Username of the token's subject. This is optional.")],[new e("token_type"),new e("The token's type, which is either Bearer or DPoP. This is required if active.")],[new e("exp"),new e("Unix timestamp when the token expires. This is required if active.")],[new e("iat"),new e("Unix timestamp when the token was issued. This is required if active.")],[new e("nbf"),new e("Unix timestamp when the token is active from. This is required if active.")],[new e("sub"),new e("Subject of the token. Either the end-user or the client. This is required if active.")],[new e("aud"),new e("Array of URIs that may accept the token. This is required if active.")],[new e("iss"),new e("URI of AuthServer. This is required if active.")],[new e("jti"),new e("Unique identifier of the token. This is required if active.")],[new e("auth_time"),new e("Unix timestamp of when the end-user authenticated. This is optional.")],[new e("acr"),new e("The AuthenticationContextReference used when the end-user authenticated. This is optional.")],[new e("cnf"),new e("Object with one field, which is jkt. That is the thumbprint of the DPoP if the token is sender-constrained. This is optional.")],[new e("act"),new e("Object with one field, which is sub. That is the subject of the actor using the token on behalf of the tokens subject. This is optional.")],[new e("may_act"),new e("Object with one field, which is sub. That is the subject of the actor allowed to use the token on behalf of the tokens subject. This is optional.")],[new e("access_control"),new e("Object with end-user claims used for authorization purposes. This is optional.")]];V();var f=W();R(s=>{z.title="Token Introspection Endpoint"});var w=q(f);E(w,{title:"Token Introspection"});var T=o(w,2);d(T,{title:"Introduction",children:(s,k)=>{var h=Z();i(s,h)},$$slots:{default:!0}});var m=o(T,2);d(m,{title:"Specifications",children:(s,k)=>{l(s,{title:"Specifications",tableNumber:1,headers:y,rowCellDefinitions:H})},$$slots:{default:!0}});var F=o(m,2);d(F,{title:"Token Introspection Endpoint",children:(s,k)=>{var h=K(),v=o(q(h),4);C(v,{children:(n,c)=>{r();var t=a("The endpoint requires client authentication by confidential clients.");i(n,t)},$$slots:{default:!0}});var b=o(v,6);C(b,{children:(n,c)=>{r();var t=a(`If the token does not exist, is revoked, expired then the token is deemed inactive.
        If the client is not authorized for any scope of the token,
        or if the client is not an audience of the token, then the token is deemed inactive.`);i(n,t)},$$slots:{default:!0}});var $=o(b,6);l($,{title:"Token Introspection request parameters",tableNumber:2,headers:S,rowCellDefinitions:D});var _=o($,4);l(_,{title:"Token Introspection response parameters",tableNumber:3,headers:O,rowCellDefinitions:U});var P=o(_,6);p(P,{children:(n,c)=>{r();var t=a();t.nodeValue=`
POST /connect/introspection HTTP/1.1
Host: idp.authserver.dk
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

token=23nthgnreag67n
        `,i(n,t)},$$slots:{default:!0}});var g=o(P,4);p(g,{children:(n,c)=>{r();var t=a();t.nodeValue=`
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Cache-Control: no-cache, no-store

{
  "active": true,
  "scope": "scope:read scope:write",
  "client_id": "35d7d4f0-27c8-463c-8057-d39953a16972",
  "username": "john",
  "token_type": "DPoP",
  "exp": 1751708358,
  "iat": 1751708058,
  "nbf": 1751708058,
  "sub": "ec14d771-d1bb-4d0c-9965-8243700a739f",
  "aud": [ "https://api.authserver.dk" ],
  "iss": "https://idp.authserver.dk",
  "jti": "ec26ea37-e612-45f7-8989-612554499117",
  "auth_time": 1751707358,
  "acr": "urn:authserver:loa:substantial",
  "cnf":
  {
    "jkt": "ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
  },
  "act":
  {
    "sub": "dca0964b-aaa0-4822-8c55-9c8828f80b5a"
  },
  "may_act":
  {
    "sub": "6279c8b3-7f7e-48ef-96cc-649a7e5da7f6"
  },
  "access_control":
  {
    "roles": [ "admin" ]
  }
}
        `,i(n,t)},$$slots:{default:!0}});var x=o(g,4);p(x,{children:(n,c)=>{r();var t=a();t.nodeValue=`
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Cache-Control: no-cache, no-store

{
  "active": true,
  "scope": "scope:read scope:write",
  "client_id": "35d7d4f0-27c8-463c-8057-d39953a16972",
  "token_type": "Bearer",
  "exp": 1751708358,
  "iat": 1751708058,
  "nbf": 1751708058,
  "sub": "35d7d4f0-27c8-463c-8057-d39953a16972",
  "aud": [ "https://api.authserver.dk" ],
  "iss": "https://idp.authserver.dk",
  "jti": "ec26ea37-e612-45f7-8989-612554499117"
}
        `,i(n,t)},$$slots:{default:!0}});var N=o(x,4);p(N,{children:(n,c)=>{r();var t=a();t.nodeValue=`
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Cache-Control: no-cache, no-store

{
  "active": false
}
        `,i(n,t)},$$slots:{default:!0}}),i(s,h)},$$slots:{default:!0}}),i(j,f),A()}export{te as component};
