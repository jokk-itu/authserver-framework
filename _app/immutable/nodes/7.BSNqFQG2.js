import{f,a,t as p}from"../chunks/BHF9wNqu.js";import"../chunks/CU9afjlv.js";import{p as P,f as c,a as F,e as S,s as t,t as y,$ as A,c as H,n as l,r as I}from"../chunks/DL6eumzt.js";import{h as O}from"../chunks/DMOXgEdX.js";import{a as q}from"../chunks/BqRdp-zL.js";import{i as B}from"../chunks/DQgLNG-F.js";import{b as D}from"../chunks/DjK__fpz.js";import{C as d}from"../chunks/DbZgjyKz.js";import{P as E,S as h}from"../chunks/C3UgRdqy.js";import{T as Q,R as u}from"../chunks/4YLJMDwf.js";var W=f(`<p>The authorization code grant type is used to exchange a code for an access token,
        id token and optional refresh token.</p> <br/> <p>The following image shows the authorization code flow, from authenticating at the authorize endpoint,
        to exchanging the authorization code for tokens.</p> <figure><img class="mx-auto" alt="authorization code flow"/> <figCaption class="text-center">Image 1: Authorization Code flow</figCaption></figure>`,1),Y=f(`<p>Triggering the authorization code flow starts at the authorize endpoint,
        by requesting with the parameter "response_type" and value "code".</p> <p>The code returned from the IdentityProvider is encrypted,
        and contains information related to the original request,
        such that it can be validated and correlated to the token request.</p> <p>For example, it contains the redirect_uri, code_challenge, dpop_jkt and more.</p> <br/> <p>The following HTTP example shows an authorize request with the response_type.
        The example is not complete to better illustrate the flow.</p> <!> <p>The following HTTP example shows an authorize response with a code.
        The example is not complete to better illustrate the flow.</p> <!>`,1),Z=f(`<p>The returned code is then used in the subsequent token request, in exchange for tokens.</p> <br/> <p>The following HTTP example shows a token request using the code from the identity provider.
        The example is not complete to better illustrate the flow.</p> <!> <p>The following HTTP example shows a token response containing tokens exchanged from an authoriazation_code.
        The example is not complete to better illustrate the flow.</p> <!>`,1),G=f("<!> <!> <!> <!> <!>",1);function ee(x,b){P(b,!1);let k=["Name","Description"],z=[[new u("OAuth2.1","https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/"),new u("Core specification for OAuth")],[new u("OpenId Connect","https://openid.net/specs/openid-connect-core-1_0.html"),new u("Core specification for OpenId Connect")]];B();var T=G();O("f2gtqf",o=>{S(()=>{A.title="Authorization Code Grant"})});var $=c(T);E($,{title:"Authorization Code"});var _=t($,2);h(_,{title:"Introduction",children:(o,m)=>{var n=W(),r=t(c(n),6),s=H(r);l(2),I(r),y(()=>q(s,"src",`${D??""}/authorization-code.png`)),a(o,n)},$$slots:{default:!0}});var w=t(_,2);h(w,{title:"Specifications",children:(o,m)=>{Q(o,{title:"Specifications",tableNumber:1,get headers(){return k},get rowCellDefinitions(){return z}})},$$slots:{default:!0}});var v=t(w,2);h(v,{title:"Authorize Endpoint",children:(o,m)=>{var n=Y(),r=t(c(n),10);d(r,{children:(i,g)=>{l();var e=p();e.nodeValue=`
GET /connect/authorize?response_type=code HTTP/1.1
Host: idp.authserver.dk
        `,a(i,e)},$$slots:{default:!0}});var s=t(r,4);d(s,{children:(i,g)=>{l();var e=p();e.nodeValue=`
HTTP/1.1 303 SeeOther
Location: https://web-client.authserver.dk/callback?code=SplxlOBeZQQYbYS6WxSbIA
        `,a(i,e)},$$slots:{default:!0}}),a(o,n)},$$slots:{default:!0}});var C=t(v,2);h(C,{title:"Token Endpoint",children:(o,m)=>{var n=Z(),r=t(c(n),6);d(r,{children:(i,g)=>{l();var e=p();e.nodeValue=`
POST /connect/token HTTP/1.1
Host: idp.authserver.dk
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&resource=https%3A%2F%2Fapi-one.protectedresource.dk
        `,a(i,e)},$$slots:{default:!0}});var s=t(r,4);d(s,{children:(i,g)=>{l();var e=p();e.nodeValue=`
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Cache-Control: no-cache, no-store

{
  "access_token":"2YotnFZFEjr1zCsicMWpAA",
  "token_type":"Bearer",
  "expires_in":3600,
  "id_token":"eyJhbGciOiJSUzI1NiIsImtpZCI...",
  "grant_id":"78FF77E8-F146-4F37-9C28-5FD0BC936980"
}
        `,a(i,e)},$$slots:{default:!0}}),a(o,n)},$$slots:{default:!0}}),a(x,T),F()}export{ee as component};
