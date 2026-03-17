import{f as _,a as o,t as l}from"../chunks/BHF9wNqu.js";import"../chunks/CU9afjlv.js";import{p as I,f as m,a as U,e as B,s as t,t as M,$ as j,c as N,n as p,r as E}from"../chunks/DL6eumzt.js";import{h as O}from"../chunks/DMOXgEdX.js";import{a as V}from"../chunks/BqRdp-zL.js";import{i as W}from"../chunks/DQgLNG-F.js";import{P as Z,S as g}from"../chunks/C3UgRdqy.js";import{T as w,R as e}from"../chunks/4YLJMDwf.js";import{C as u}from"../chunks/DbZgjyKz.js";import{b as L}from"../chunks/BojIqHjv.js";import{I as G}from"../chunks/CuMYCe1t.js";var J=_(`<p>Device Authorization is used to issue a code, which can be used to exchange tokens at the token endpoint,
        using the device code grant type.</p> <br/> <p>The flow is used for clients which cannot authenticate the end user, for example an app on a smart tv.</p> <p>Upon getting the code from the device authorization endpoint, the end-user is instructed to access the identity provider from another device, where they can authenticate.
        For example through their phone or computer.</p> <p>Simultaneously the app also polls the token endpoint using its own code, and once the end-user has redeemed their code through authentication, the app successfully redeems its own code and receives tokens.</p> <br/> <figure><img class="mx-auto" alt="device authorization flow"/> <figCaption class="text-center">Image 1: Device Authorization flow</figCaption></figure>`,1),Q=_(`<p>The client starts by invoking the device authorization endpoint.</p> <p>It receives a device code, which is used to poll the token endpoint, until the identity provider returns that the authorization attempt has failed or successfully and tokens are returned.</p> <p>It also receives a user, which is used by the end user to authenticate at the identity provider, through another device, such as a computer or a phone.</p> <br/> <!> <br/> <p>The endpoint supports DPoP, and can prove possession from authorization to the token endpoint.</p> <p>The endpoint supports client authentication for public and confidential clients.</p> <br/> <!> <br/> <p>The following HTTP request is an example of the device authorization endpoint.</p> <!> <br/> <p>The following HTTP response is an example of the device authorization endpoint.</p> <!> <br/> <p>The following HTTP resposne is an example of a failure at the device authorization endpoint,
        where the client does not request the openid scope.</p> <!>`,1),Y=_("<p>Once the end user has the user code, they have to navigate to the device endpoint on their secondary device and authenticate.</p> <!>",1),K=_(`<p>Once the client has requested the device authorization endpoint successfully, it receives a device code.</p> <p>It starts polling the token endpoint, using the device code grant type, and polls in the interval returned from the device authorization endpoint.
        Default is every 5 seconds.</p> <br/> <p>The following HTTP request is an example of a polling request at the token endpoint.</p> <!> <br/> <p>The following HTTP response ia an example of a pending polling response at the token endpoint.</p> <!> <br/> <p>The following HTTP response is an example of a successfull polling response at the token endpoint.</p> <!> <br/> <p>The following HTTP response is an example of a failed polling response at the token endpoint.</p> <!>`,1),X=_("<!> <!> <!> <!> <!> <!>",1);function he(k,x){I(x,!1);let F=["Name","Description"],A=[[new e("Device Authorization","https://datatracker.ietf.org/doc/html/rfc8628"),new e("Specification for device authorization")]],D=["Name","Description"],H=[[new e("code_challenge"),new e("Hash of random string used to verify the requester between authorization and token endpoints. This is required.")],[new e("code_challenge_method"),new e("Name of the hashing method used for the code_challenge. This is required.")],[new e("nonce"),new e("Cryptographically random value. This is required.")],[new e("grant_id"),new e("The id of a previous grant, used to merge or replace consent. This is optional.")],[new e("grant_management_action"),new e("The grant action performed when the end-user authenticates. This is optional.")],[new e("scope"),new e("Space delimited scopes. This is required.")],[new e("acr_values"),new e("Space delimited authentication context references. This is optional.")],[new e("resource"),new e("URL of protected resource that is the audience of the access token. This is required.")]],q=["Name","Description"],R=[[new e("device_code"),new e("The code the client uses when polling the token endpoint.")],[new e("user_code"),new e("The code the end-user redeems when authenticating.")],[new e("verification_uri"),new e("The URL the end-user navigates to authenticate.")],[new e("verification_uri_complete"),new e("The URL with user_code the end-user navigates to authenticate.")],[new e("expires_in"),new e("The amount of seconds until the token expires, from the issued time.")],[new e("interval"),new e("The interval in seconds the client waits between polling attempts at the token endpoint.")]];W();var $=X();O("bvsboe",r=>{B(()=>{j.title="Device Authorization"})});var b=m($);Z(b,{title:"Device Authorization"});var z=t(b,2);g(z,{title:"Introduction",children:(r,T)=>{var i=J(),a=t(m(i),12),s=N(a);p(2),E(a),M(()=>V(s,"src",`${L??""}/device-authorization.png`)),o(r,i)},$$slots:{default:!0}});var C=t(z,2);g(C,{title:"Specifications",children:(r,T)=>{w(r,{title:"Specifications",tableNumber:1,get headers(){return F},get rowCellDefinitions(){return A}})},$$slots:{default:!0}});var P=t(C,2);g(P,{title:"Device Authorization Endpoint",children:(r,T)=>{var i=Q(),a=t(m(i),8);w(a,{title:"Device Authorization request parameters",tableNumber:2,get headers(){return D},get rowCellDefinitions(){return H}});var s=t(a,10);w(s,{title:"Device Authorzation response parameters",tableNumber:3,get headers(){return q},get rowCellDefinitions(){return R}});var f=t(s,6);u(f,{children:(c,n)=>{p();var h=l();h.nodeValue=`
POST /connect/device-authorization HTTP/1.1
Host: idp.authserver.dk
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

code_challenge=cf4957ce5fea8d2fdf0ab6edb93b78331c15c1e94fb052
&code_challenge_method=S256
&nonce=0ad740f0794057ab635a80590907e8b5
&scope=openid%20account:delete
&resource=https://api.authserver.dk
&client_id=3a2e766d-ba78-47f5-9daa-1f3f106a5aa3
        `,o(c,h)},$$slots:{default:!0}});var v=t(f,6);u(v,{children:(c,n)=>{p();var h=l();h.nodeValue=`
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Cache-Control: no-cache, no-store

{
  "device_code":"2YotnFZFEjr1zCsicMWpAA",
  "user_code":"AUPFLMQE",
  "verification_uri":"https://idp.authserver.dk/device",
  "verification_uri_complete":"https://idp.authserver.dk/device?user_code=AUPFLMQE",
  "expires_in":300,
  "interval":5
}
        `,o(c,h)},$$slots:{default:!0}});var d=t(v,6);u(d,{children:(c,n)=>{p();var h=l();h.nodeValue=`
HTTP/1.1 400 BadRequest
Content-Type: application/json;charset=UTF-8
Cache-Control: no-cache, no-store

{
  "error":"invalid_scope",
  "error_description":"openid is required"
}
        `,o(c,h)},$$slots:{default:!0}}),o(r,i)},$$slots:{default:!0}});var y=t(P,2);g(y,{title:"Redeeming the user code",children:(r,T)=>{var i=Y(),a=t(m(i),2);G(a,{children:(s,f)=>{p();var v=l("The device endpoint is custom, and needs to be implemented by you. It must allow the end user to authenticate, like at the authorize endpoint during the authorization code grant type.");o(s,v)},$$slots:{default:!0}}),o(r,i)},$$slots:{default:!0}});var S=t(y,2);g(S,{title:"Device Code Grant",children:(r,T)=>{var i=K(),a=t(m(i),8);u(a,{children:(d,c)=>{p();var n=l();n.nodeValue=`
POST /connect/token HTTP/1.1
Host: idp.authserver.dk
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

grant_type=urn:ietf:params:oauth:grant-type:device_code
&device_code=2YotnFZFEjr1zCsicMWpAA
        `,o(d,n)},$$slots:{default:!0}});var s=t(a,6);u(s,{children:(d,c)=>{p();var n=l();n.nodeValue=`
HTTP/1.1 400 BadRequest
Content-Type: application/json;charset=UTF-8
Cache-Control: no-cache, no-store

{
  "error":"authorization_pending",
  "error_description":"device authorization is pending"
}
        `,o(d,n)},$$slots:{default:!0}});var f=t(s,6);u(f,{children:(d,c)=>{p();var n=l();n.nodeValue=`
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Cache-Control: no-cache, no-store

{
  "access_token":"2YotnFZFEjr1zCsicMWpAA",
  "token_type":"Bearer",
  "expires_in":3600,
  "id_token":"eyJhbGciOiJSUzI1NiIsImtpZCI...",
  "grant_id":"78FF77E8-F146-4F37-9C28-5FD0BC936980",
  "scope": "account:update account:delete"
}
        `,o(d,n)},$$slots:{default:!0}});var v=t(f,6);u(v,{children:(d,c)=>{p();var n=l();n.nodeValue=`
HTTP/1.1 400 BadRequest
Content-Type: application/json;charset=UTF-8
Cache-Control: no-cache, no-store

{
  "error":"access_denied",
  "error_description":"end-user has denied the request"
}
        `,o(d,n)},$$slots:{default:!0}}),o(r,i)},$$slots:{default:!0}}),o(k,$),U()}export{he as component};
