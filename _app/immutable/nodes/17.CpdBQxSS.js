import{f as h,a as n,t as k}from"../chunks/Z1HRfbhX.js";import"../chunks/BQYPTkyu.js";import{p as x,f as _,a as F,e as y,s as o,$ as I,n as i}from"../chunks/Iw8VLsBB.js";import{h as S}from"../chunks/BhNhnXGn.js";import{i as O}from"../chunks/Bwhf-QOO.js";import{C as $}from"../chunks/CVzv1ABR.js";import{P as A,S as c}from"../chunks/D5cW4fPA.js";import{T as D,R as s}from"../chunks/DtqDFwhC.js";var z=h(`<p>When the client has received its initial access token,
        it can be efficient to refresh the token when it expires,
        or if the tokens scope or audience needs to be updated.</p> <p>The use case is covered by the refresh_token grant type,
        which exchanges a fresh access token by a refresh_token.</p> <br/> <p>The refresh token typically has a longer lifetime than the access tokens,
        and can be defined in the client metadata.</p> <br/> <p>If the refresh token request uses DPoP,
        and the client is public, then the refresh token must also be DPoP bound.
        It is recommended to sender-constraint the refresh token, instead of rotating refresh tokens.</p>`,1),H=h(`<p>The request contains a refresh token from the initial token request,
        which returned the first token from another grant such as authorization_code.</p> <br/> <p>It is possible to change the scope and audience of the access token,
        through the parameters "scope" and "resource".</p> <br/> <p>The following HTTP example shows a token request using the code from the identity provider.</p> <!> <p>The following HTTP example shows a token response containing tokens exchanged from the refresh token.</p> <!>`,1),R=h("<!> <!> <!> <!>",1);function N(g,T){x(T,!1);let v=["Name","Description"],b=[[new s("OAuth2.1","https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/"),new s("Core specification for OAuth")],[new s("OpenId Connect","https://openid.net/specs/openid-connect-core-1_0.html"),new s("Core specification for OpenId Connect")]];O();var p=R();S("1nv3v2h",e=>{y(()=>{I.title="Refresh Token Grant"})});var d=_(p);A(d,{title:"Refresh Token"});var f=o(d,2);c(f,{title:"Introduction",children:(e,u)=>{var r=z();i(10),n(e,r)},$$slots:{default:!0}});var l=o(f,2);c(l,{title:"Specifications",children:(e,u)=>{D(e,{title:"Specifications",tableNumber:1,get headers(){return v},get rowCellDefinitions(){return b}})},$$slots:{default:!0}});var w=o(l,2);c(w,{title:"Token Endpoint",children:(e,u)=>{var r=H(),m=o(_(r),10);$(m,{children:(a,P)=>{i();var t=k();t.nodeValue=`
POST /connect/token HTTP/1.1
Host: idp.authserver.dk
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

grant_type=refresh_token
&refresh_token=SplxlOBeZQQYbYS6WxSbIA
&scope=weather:read
&resource=https%3A%2F%2Fapi-one.protectedresource.dk
`,n(a,t)},$$slots:{default:!0}});var C=o(m,4);$(C,{children:(a,P)=>{i();var t=k();t.nodeValue=`
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
        `,n(a,t)},$$slots:{default:!0}}),n(e,r)},$$slots:{default:!0}}),n(g,p),F()}export{N as component};
