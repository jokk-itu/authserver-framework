import{t as w,h as Q,a,b as d}from"../chunks/BdD32qd5.js";import"../chunks/BOyCDzPS.js";import{p as j,f as $,a as B,$ as W,s as r,n as l}from"../chunks/Db0b_LWK.js";import{i as K}from"../chunks/hXpMuBZJ.js";import{C as h}from"../chunks/Dg6GzD5d.js";import{I as J}from"../chunks/BqXxNwWv.js";import{P as L,S as T}from"../chunks/DcIxqC40.js";import{T as m,R as e}from"../chunks/BL1phRJf.js";var Z=w(`<p>A grant is proof of an end-user authenticating and consenting to a client to act on behalf of them.
        The grant can be single use, and when the end-user authenticates again, a new grant is created.</p> <p>Grants can also be re-used, by updating the grant through merging or replacing privileges of the grant.
        It is also possible to have concurrent grants.</p> <p>The grant can be queried and all the associated details are returned, and it is also possible to revoke a grant.</p> <br> <p>There are use cases such as incremental authorization, where privileges are added to the grant over time as needed.
        Or fine grained grants, where each grant has a small subset of privileges instead of having one large grant.</p>`,1),X=w(`<p>During authorization it is possible to request a new grant to be created, or reusing an existing grant by replacing or merging privileges.
        The parameters are described in table 2.</p> <br> <!> <br> <!>`,1),Y=w(`<p>After authorization and the grant has been created, it is possible to query the grant from an endpoint.
        It can be useful to query the grant to show its content to the end-user
        or programmatically increase or decrease privileges on subsequent authorization requests.</p> <br> <p>The endpoint accepts HTTP GET and an id of the grant, which is retrieved when requesting the token endpoint.
        And an access token that requires the scope "grant_management_query" and the token must belong to the grant being queried.</p> <p>Only confidential clients are allowed to request the endpoint, as it requires client authentication.</p> <br> <p>The request parameters are described in table 3.</p> <br> <!> <br> <p>The response parameters are described in table 4 and 5.</p> <br> <!> <br> <!> <br> <p>The following HTTP example shows a request to the endpoint.</p> <!> <br> <p>The following HTTP example shows an OK response from the endpoint.</p> <!> <br> <p>The following HTTP example shows a NotFound response from the endpoint.</p> <!> <br> <p>The following HTTP example shows a Forbidden response from the endpoint.</p> <!>`,1),ee=w(`<p>After authorization and the grant has been created, it is possible to revoke the grant from an endpoint.
        It can be useful to revoke the grant when it is no longer of use. It revokes all data associated with the grant.</p> <br> <p>The endpoint accepts HTTP DELETE and an id of the grant, which is retrieved when requesting the token endpoint.
        And an access token that requires the scope "grant_management_revoke" and the token must belong to the grant being revoked.</p> <p>Only confidential clients are allowed to request the endpoint, as it requires client authentication.</p> <p>The response is HTTP status code 204 no content.</p> <br> <p>The request parameters are described in table 6.</p> <br> <!> <br> <p>The following HTTP example shows a request to the endpoint.</p> <!> <br> <p>The following HTTP example shows an OK response from the endpoint.</p> <!> <br> <p>The following HTTP example shows a NotFound response from the endpoint.</p> <!> <br> <p>The following HTTP example shows a Forbidden response from the endpoint.</p> <!>`,1),te=w("<!> <!> <!> <!> <!> <!>",1);function pe(x,R){j(R,!1);let G=["Name","Description"],D=[[new e("Grant Management","https://openid.net/specs/oauth-v2-grant-management.html"),new e("Grant Management specification")]],z=["Name","Description"],F=[[new e("grant_id"),new e("Unique identifier of the grant. This is required if a grant is updated.")],[new e("grant_management_action"),new e("Action to perform for the grant. Either create, merge or replace. This is optional.")]],N=["Name","Description"],A=[[new e("grant_id"),new e("Unique identifier of the grant passed as a path parameter. This is required.")]],I=["Name","Description"],U=[[new e("scopes"),new e("Array of scope objects. This is required.")],[new e("claims"),new e("Array of claim types. This is required.")],[new e("created_at"),new e("Unix time in seconds of authorization grant creation. This is required.")],[new e("updated_at"),new e("Unix time in seconds of authorization grant latest update. This is required.")]],E=["Name","Description"],M=[[new e("scopes"),new e("Array of scopes that are allowed to be combined with the resource URI. This is required.")],[new e("resources"),new e("Array of resource URIs that are allowed audiences of tokens associated with the grant. It only contains one URI. This is required.")]],S=["Name","Description"],V=[[new e("grant_id"),new e("Unique identifier of the grant passed as a path parameter. This is required.")]];K();var q=te();Q(o=>{W.title="Grant Management"});var P=$(q);L(P,{title:"Grant Management"});var H=r(P,2);T(H,{title:"Introduction",children:(o,v)=>{var s=Z();l(8),a(o,s)},$$slots:{default:!0}});var y=r(H,2);T(y,{title:"Specifications",children:(o,v)=>{m(o,{title:"Specifications",tableNumber:1,headers:G,rowCellDefinitions:D})},$$slots:{default:!0}});var C=r(y,2);T(C,{title:"Authorization grant",children:(o,v)=>{var s=X(),p=r($(s),4);m(p,{title:"Authorization grant request fields",tableNumber:2,headers:z,rowCellDefinitions:F});var c=r(p,4);J(c,{children:(u,g)=>{l();var f=d("If the grant_management_action is not provided, then the default behaviour is creating a grant.");a(u,f)},$$slots:{default:!0}}),a(o,s)},$$slots:{default:!0}});var k=r(C,2);T(k,{title:"Query grant",children:(o,v)=>{var s=Y(),p=r($(s),14);m(p,{title:"Query grant request fields",tableNumber:3,headers:N,rowCellDefinitions:A});var c=r(p,8);m(c,{title:"Query grant response fields",tableNumber:4,headers:I,rowCellDefinitions:U});var u=r(c,4);m(u,{title:"Query grant scope response fields",tableNumber:5,headers:E,rowCellDefinitions:M});var g=r(u,6);h(g,{children:(t,_)=>{l();var n=d();n.nodeValue=`
GET /connect/grants/6faccb76-08a9-4b7e-ac7d-548c773d98ab HTTP/1.1
Host: idp.authserver.dk
Accept: application/json;charset=UTF-8
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
        `,a(t,n)},$$slots:{default:!0}});var f=r(g,6);h(f,{children:(t,_)=>{l();var n=d();n.nodeValue=`
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Cache-Control: no-cache, no-store

{
  "scopes": [
    {
      "scopes": ["weather:read", "weather:write"],
      "resources": ["weather.authserver.dk"]
    },
    {
      "scopes": ["payment:read"],
      "resources": ["banking.authserver.dk"]
    }
  ],
  "claims": ["name", "given_name", "address"],
  "created_at": 1751917809,
  "updated_at": 1751917809
}
        `,a(t,n)},$$slots:{default:!0}});var i=r(f,6);h(i,{children:(t,_)=>{l();var n=d();n.nodeValue=`
HTTP/1.1 404 NotFound
Cache-Control: no-cache, no-store  
        `,a(t,n)},$$slots:{default:!0}});var b=r(i,6);h(b,{children:(t,_)=>{l();var n=d();n.nodeValue=`
HTTP/1.1 403 Forbidden
Cache-Control: no-cache, no-store
        `,a(t,n)},$$slots:{default:!0}}),a(o,s)},$$slots:{default:!0}});var O=r(k,2);T(O,{title:"Revoke grant",children:(o,v)=>{var s=ee(),p=r($(s),16);m(p,{title:"Revoke grant request fields",tableNumber:6,headers:S,rowCellDefinitions:V});var c=r(p,6);h(c,{children:(i,b)=>{l();var t=d();t.nodeValue=`
DELETE /connect/grants/6faccb76-08a9-4b7e-ac7d-548c773d98ab HTTP/1.1
Host: idp.authserver.dk
Accept: application/json;charset=UTF-8
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
        `,a(i,t)},$$slots:{default:!0}});var u=r(c,6);h(u,{children:(i,b)=>{l();var t=d();t.nodeValue=`
HTTP/1.1 204 NoContent
Cache-Control: no-cache, no-store
        `,a(i,t)},$$slots:{default:!0}});var g=r(u,6);h(g,{children:(i,b)=>{l();var t=d();t.nodeValue=`
HTTP/1.1 404 NotFound
Cache-Control: no-cache, no-store  
        `,a(i,t)},$$slots:{default:!0}});var f=r(g,6);h(f,{children:(i,b)=>{l();var t=d();t.nodeValue=`
HTTP/1.1 403 Forbidden
Cache-Control: no-cache, no-store
        `,a(i,t)},$$slots:{default:!0}}),a(o,s)},$$slots:{default:!0}}),a(x,q),B()}export{pe as component};
