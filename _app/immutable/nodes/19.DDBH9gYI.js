import{f as p,a as o,t as u}from"../chunks/BHF9wNqu.js";import"../chunks/CU9afjlv.js";import{p as V,f as b,a as B,e as E,s as n,t as J,$ as F,c as W,n as c,r as A}from"../chunks/DL6eumzt.js";import{h as G}from"../chunks/DMOXgEdX.js";import{a as z}from"../chunks/BqRdp-zL.js";import{i as K}from"../chunks/DQgLNG-F.js";import{b as M}from"../chunks/BojIqHjv.js";import{C as g}from"../chunks/DbZgjyKz.js";import{I as x}from"../chunks/CuMYCe1t.js";import{P as Q,S as m}from"../chunks/C3UgRdqy.js";import{T,R as e}from"../chunks/4YLJMDwf.js";var X=p(`<p>The client (or relying party RP) can initiate logout at the IdP through an end session endpoint.
        The flow can logout the end user of the initiating client, or end the session at the IdP, and logging out all clients on the session of the end user.</p> <p>The logout of all clients is done through backchannel logout from the IdP.</p> <br/> <p>The following image shows the logout flow, from logout at the client, to backchannel logout at the identity provider.</p> <br/> <figure><img class="mx-auto" alt="rp-initiated logout flow"/> <figCaption class="text-center">Image 1: RP-Initiated Logout flow</figCaption></figure>`,1),Y=p("<p>The page being displayed for the end-user is custom and defined at the LogoutUri.</p>"),Z=p(`<p>Once the client has initiated the logout flow, the client redirects to the identity provider "end-session" endpoint.</p> <p>The identity provider then provides a page for the end-user to let the user either continue logging out from the client, or continue a single sign out flow.</p> <p>The single sign out flow differs by initiating a backchannel logout request to all clients with grants in the end-user's session.
        Whereas only logging out from the initiating client, requests backchannel logout to that client, and the session is not revoked.</p> <br/> <!> <br/> <p>The request parameters for the end session endpoint are described in table 2.</p> <br/> <!> <br/> <p>The following HTTP example shows an end-session request.</p> <!> <br/> <p>The following HTTP example shows an end-session response, redirecting to the LogoutUri.</p> <!> <br/> <p>The following HTTP example shows an end-session response, redirecting to the PostLogoutRedirectUri.</p> <!>`,1),ee=p(`<p>Once the end user has logged out, a request is sent from the IdP to the client logging out on behalf of the end user, and optionally all clients participating in the session.</p> <br/> <p>The request parameters for the backchannel logout endpoint are described in table 3.</p> <br/> <!> <br/> <p>The following HTTP example shows a backchannel logout request to a client.</p> <p>The endpoint is defined by the client, through their client metadata.
        The endpoint must accept the POST method, and the body content type is "application/x-www-form-urlencoded".</p> <br/> <!> <br/> <p>The following HTTP example shows a backchannel logout response.</p> <br/> <!>`,1),te=p("<p>The token must contain a sid or sub claim, and optionally it can contain both.</p>"),ne=p(`<p>The logout token is a structured JWT and is signed the same as an Id token.
        It can optionally be encrypted the same as an Id token.
        The behaviour is defined by the client metadata for id tokens.</p> <p>The token contains the fields defined in table 4.</p> <br/> <!> <br/> <!> <br/> <p>The following JSON example shows a base64 decoded logout token sent to a backchannel logout endpoint.</p> <p>The signature block is omitted.</p> <!>`,1),oe=p("<!> <!> <!> <!> <!> <!>",1);function fe(y,C){V(C,!1);let S=["Name","Description"],R=[[new e("OpenId Connect RP-Initiated Logout","https://openid.net/specs/openid-connect-rpinitiated-1_0.html"),new e("Specification for the RP to logout at the IdP")],[new e("OpenId Connect Backchannel Logout","https://openid.net/specs/openid-connect-backchannel-1_0.html"),new e("Specification for the IdP to logout clients")],[new e("OpenId Connect Core","https://openid.net/specs/openid-connect-core-1_0.html"),new e("Core specification for OpenId Connect")]],H=["Name","Description"],L=[[new e("id_token_hint"),new e("Id token belonging to the end user logging out. This is optional.")],[new e("client_id"),new e("ClientId of the client logging out on behalf of the end user. This is optional.")],[new e("post_logout_redirect_uri"),new e("URI to redirect to after logging out. This is optional.")],[new e("state"),new e("State parameter used with the redirect URI to mitigate CSRF attacks. This is required if redirect uri is provided.")]],O=["Name","Description"],N=[[new e("logout_token"),new e("JWT containing claims about the end user being logged out.")]],D=["Name","Description"],j=[[new e("iss"),new e("URI of AuthServer, as defined in the discovery document. This is required.")],[new e("sub"),new e("End user identifier. This is required if sid is not provided.")],[new e("aud"),new e("Client identifier. This is required.")],[new e("iat"),new e("Time of token issuance. This is required.")],[new e("exp"),new e("Time of token expiration. This is required.")],[new e("jti"),new e("Token identifier. This is required.")],[new e("sid"),new e("Session identifier. This is required if sub is not provided.")],[new e("typ"),new e("Type of JsonWebToken. This is a required header and must be logout+jwt.")],[new e("events"),new e("JSON object, with field http://schemas.openid.net/event/backchannel-logout. This is a required.")]];K();var $=oe();G("1qlspw5",r=>{E(()=>{F.title="RP-Initiated Logout"})});var _=b($);Q(_,{title:"RP-Initiated Logout"});var k=n(_,2);m(k,{title:"Introduction",children:(r,w)=>{var i=X(),s=n(b(i),10),a=W(s);c(2),A(s),J(()=>z(a,"src",`${M??""}/rp-initiated-logout.png`)),o(r,i)},$$slots:{default:!0}});var P=n(k,2);m(P,{title:"Specifications",children:(r,w)=>{T(r,{title:"Specifications",tableNumber:1,get headers(){return S},get rowCellDefinitions(){return R}})},$$slots:{default:!0}});var I=n(P,2);m(I,{title:"End session endpoint",children:(r,w)=>{var i=Z(),s=n(b(i),8);x(s,{children:(t,v)=>{var d=Y();o(t,d)},$$slots:{default:!0}});var a=n(s,8);T(a,{title:"End session request fields",tableNumber:2,get headers(){return H},get rowCellDefinitions(){return L}});var h=n(a,6);g(h,{children:(t,v)=>{c();var d=u();d.nodeValue=`
GET /connect/end-session?id_token_hint=eybjsdvbb HTTP/1.1
Host: idp.authserver.dk
`,o(t,d)},$$slots:{default:!0}});var l=n(h,6);g(l,{children:(t,v)=>{c();var d=u();d.nodeValue=`
HTTP/1.1 303 SeeOther
Location: https://idp.authserver.dk/SignOut
Cache-Control: no-cache, no-store
`,o(t,d)},$$slots:{default:!0}});var f=n(l,6);g(f,{children:(t,v)=>{c();var d=u();d.nodeValue=`
HTTP/1.1 303 SeeOther
Location: https://app.example.com/logout-callback?state=narfojdobnob
Cache-Control: no-cache, no-store
`,o(t,d)},$$slots:{default:!0}}),o(r,i)},$$slots:{default:!0}});var q=n(I,2);m(q,{title:"Backchannel logout endpoint",children:(r,w)=>{var i=ee(),s=n(b(i),8);T(s,{title:"Backchannel logout request fields",tableNumber:3,get headers(){return O},get rowCellDefinitions(){return N}});var a=n(s,10);g(a,{children:(l,f)=>{c();var t=u();t.nodeValue=`
POST /backchannel-logout HTTP/1.1
Host: app.example.com
Content-Type: application/x-www-form-urlencoded

logout_token=eyascdiuvbiuv
`,o(l,t)},$$slots:{default:!0}});var h=n(a,8);g(h,{children:(l,f)=>{c();var t=u();t.nodeValue=`
HTTP/1.1 200 Ok
`,o(l,t)},$$slots:{default:!0}}),o(r,i)},$$slots:{default:!0}});var U=n(q,2);m(U,{title:"Logout token",children:(r,w)=>{var i=ne(),s=n(b(i),6);T(s,{title:"Logout token fields",tableNumber:4,get headers(){return D},get rowCellDefinitions(){return j}});var a=n(s,4);x(a,{children:(l,f)=>{var t=te();o(l,t)},$$slots:{default:!0}});var h=n(a,8);g(h,{children:(l,f)=>{c();var t=u();t.nodeValue=`
{
  "typ": "logout+jwt",
  "alg": "ES256"
}
.
{
  "iss": "https://idp.authserver.dk",
  "sub": "527deb3f-ea48-46c5-bb94-4d267a080fa7",
  "sid": "2a105f5a-06fc-4c5b-ba92-88ac2524b44b",
  "aud": "16a5c393-0084-4e2b-a538-f1c8a50b6161",
  "iat": 1471566154,
  "exp": 1471569754,
  "jti": "2c91dc13-6c7b-4dff-9f1c-e10c48bc549c",
  "events": {
    "http://schemas.openid.net/event/backchannel-logout"
  }
}
`,o(l,t)},$$slots:{default:!0}}),o(r,i)},$$slots:{default:!0}}),o(y,$),B()}export{fe as component};
