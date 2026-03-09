import{f as m,a as o,t as h}from"../chunks/BHF9wNqu.js";import"../chunks/CU9afjlv.js";import{p as I,f as w,a as M,e as U,s as t,t as j,$ as B,c as N,n as p,r as O}from"../chunks/DL6eumzt.js";import{h as E}from"../chunks/DMOXgEdX.js";import{a as V}from"../chunks/BqRdp-zL.js";import{i as W}from"../chunks/DQgLNG-F.js";import{P as Z,S as v}from"../chunks/C3UgRdqy.js";import{T,R as e}from"../chunks/4YLJMDwf.js";import{C as u}from"../chunks/DbZgjyKz.js";import{b as G}from"../chunks/8vVhMRMI.js";var J=m(`<p>Device Authorization is used to issue a code, which can be used to exchange tokens at the token endpoint,
        using the device code grant type.</p> <br/> <p>The flow is used for clients which cannot authenticate the end user, for example an app on a smart tv.</p> <p>Upon getting the code from the device authorization endpoint, the end-user is instructed to access the identity provider from another device, where they can authenticate.
        For example through their phone or computer.</p> <p>Simultaneously the app also polls the token endpoint using its own code, and once the end-user has redeemed their code through authentication, the app successfully redeems its own code and receives tokens.</p> <br/> <figure><img class="mx-auto" alt="device authorization flow"/> <figCaption class="text-center">Image 1: Device Authorization flow</figCaption></figure>`,1),Q=m(`<p>The client starts by invoking the device authorization endpoint.</p> <p>It receives a device code, which is used to poll the token endpoint, until the identity provider returns that the authorization attempt has failed or successfully and tokens are returned.</p> <p>It also receives a user, which is used by the end user to authenticate at the identity provider, through another device, such as a computer or a phone.</p> <br/> <!> <br/> <p>The endpoint supports DPoP, and can prove possession from authorization to the token endpoint.</p> <p>The endpoint supports client authentication for public and confidential clients.</p> <br/> <!> <br/> <p>The following HTTP request is an example of the device authorization endpoint.</p> <!> <br/> <p>The following HTTP response is an example of the device authorization endpoint.</p> <!> <br/> <p>The following HTTP resposne is an example of a failure at the device authorization endpoint,
        where the client does not request the openid scope.</p> <!>`,1),Y=m("<p>TODO</p>"),K=m(`<p>Once the client has requested the device authorization endpoint successfully, it receives a device code.</p> <p>It starts polling the token endpoint, using the device code grant type, and polls in the interval returned from the device authorization endpoint.
        Default is every 5 seconds.</p> <br/> <p>The following HTTP request is an example of a polling request at the token endpoint.</p> <!> <br/> <p>The following HTTP response ia an example of a pending polling response at the token endpoint.</p> <!> <br/> <p>The following HTTP response is an example of a successfull polling response at the token endpoint.</p> <!> <br/> <p>The following HTTP response is an example of a failed polling response at the token endpoint.</p> <!>`,1),L=m("<!> <!> <!> <!> <!> <!>",1);function de(F,k){I(k,!1);let y=["Name","Description"],A=[[new e("Device Authorization","https://datatracker.ietf.org/doc/html/rfc8628"),new e("Specification for device authorization")]],D=["Name","Description"],H=[[new e("code_challenge"),new e("Hash of random string used to verify the requester between authorization and token endpoints.")],[new e("code_challenge_method"),new e("Name of the hashing method used for the code_challenge")],[new e("nonce"),new e("")],[new e("grant_id"),new e("")],[new e("grant_management_action"),new e("")],[new e("scope"),new e("")],[new e("acr_values"),new e("")],[new e("resource"),new e("")]],q=["Name","Description"],R=[[new e("device_code"),new e("")],[new e("user_code"),new e("")],[new e("verification_uri"),new e("")],[new e("verification_uri_complete"),new e("")],[new e("expires_in"),new e("")],[new e("interval"),new e("")]];W();var $=L();E("bvsboe",i=>{U(()=>{B.title="Device Authorization"})});var b=w($);Z(b,{title:"Device Authorization"});var z=t(b,2);v(z,{title:"Introduction",children:(i,_)=>{var r=J(),c=t(w(r),12),l=N(c);p(2),O(c),j(()=>V(l,"src",`${G??""}/device-authorization.png`)),o(i,r)},$$slots:{default:!0}});var C=t(z,2);v(C,{title:"Specifications",children:(i,_)=>{T(i,{title:"Specifications",tableNumber:1,get headers(){return y},get rowCellDefinitions(){return A}})},$$slots:{default:!0}});var P=t(C,2);v(P,{title:"Device Authorization Endpoint",children:(i,_)=>{var r=Q(),c=t(w(r),8);T(c,{title:"Device Authorization request parameters",tableNumber:2,get headers(){return D},get rowCellDefinitions(){return H}});var l=t(c,10);T(l,{title:"Device Authorzation response parameters",tableNumber:3,get headers(){return q},get rowCellDefinitions(){return R}});var f=t(l,6);u(f,{children:(s,n)=>{p();var d=h();d.nodeValue=`
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
        `,o(s,d)},$$slots:{default:!0}});var g=t(f,6);u(g,{children:(s,n)=>{p();var d=h();d.nodeValue=`
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
        `,o(s,d)},$$slots:{default:!0}});var a=t(g,6);u(a,{children:(s,n)=>{p();var d=h();d.nodeValue=`
HTTP/1.1 400 BadRequest
Content-Type: application/json;charset=UTF-8
Cache-Control: no-cache, no-store

{
  "error":"invalid_scope",
  "error_description":"openid is required"
}
        `,o(s,d)},$$slots:{default:!0}}),o(i,r)},$$slots:{default:!0}});var x=t(P,2);v(x,{title:"Redeeming the user code",children:(i,_)=>{var r=Y();o(i,r)},$$slots:{default:!0}});var S=t(x,2);v(S,{title:"Device Code Grant",children:(i,_)=>{var r=K(),c=t(w(r),8);u(c,{children:(a,s)=>{p();var n=h();n.nodeValue=`
POST /connect/token HTTP/1.1
Host: idp.authserver.dk
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

grant_type=urn:ietf:params:oauth:grant-type:device_code
&device_code=2YotnFZFEjr1zCsicMWpAA
        `,o(a,n)},$$slots:{default:!0}});var l=t(c,6);u(l,{children:(a,s)=>{p();var n=h();n.nodeValue=`
HTTP/1.1 400 BadRequest
Content-Type: application/json;charset=UTF-8
Cache-Control: no-cache, no-store

{
  "error":"authorization_pending",
  "error_description":"device authorization is pending"
}
        `,o(a,n)},$$slots:{default:!0}});var f=t(l,6);u(f,{children:(a,s)=>{p();var n=h();n.nodeValue=`
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
        `,o(a,n)},$$slots:{default:!0}});var g=t(f,6);u(g,{children:(a,s)=>{p();var n=h();n.nodeValue=`
HTTP/1.1 400 BadRequest
Content-Type: application/json;charset=UTF-8
Cache-Control: no-cache, no-store

{
  "error":"access_denied",
  "error_description":"end-user has denied the request"
}
        `,o(a,n)},$$slots:{default:!0}}),o(i,r)},$$slots:{default:!0}}),o(F,$),M()}export{de as component};
