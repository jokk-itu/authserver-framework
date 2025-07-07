import{t as c,h as k,a as s,b as o}from"../chunks/BdD32qd5.js";import"../chunks/BOyCDzPS.js";import{p as H,f as g,a as q,$ as R,s as i,n}from"../chunks/Db0b_LWK.js";import{i as A}from"../chunks/hXpMuBZJ.js";import{C as T}from"../chunks/Dg6GzD5d.js";import{I as w}from"../chunks/BqXxNwWv.js";import{P as D,S as l}from"../chunks/DcIxqC40.js";import{T as O,R as y}from"../chunks/BL1phRJf.js";var B=c(`<p>The subject is a unique identifier for an entity, which is either the end-user or the client.
        It is used as the sub claim in access tokens and id tokens.</p> <br> <p>The value can be globally used from AuthServer among all clients,
        or the value can be scoped to a sector identifier, where clients using the same sector identifier will share the same subjects.</p> <br> <p>Determining the type of the subject is done through the client metadata "subject_type".
        The available subject types are found at the discovery endpoint. There are two available values "public" and "pairwise".</p>`,1),F=c(`<p>Subjects that are public are shared among all clients from AuthServer.
        The unique identifier of the end-user is used as the subject value.</p> <p>The public subject type might be unacceptable for high security scenarios, where anonymity is required.
        Because the public subject can be used to track end-user activity across all clients in the end-users single-sign-on session.</p>`,1),N=c(`<p>Subjects that are pairwise are shared among all clients that use the same sector identifier.
        For each unique sector identifier, there will be a unique subject for each end-user.
        Resulting in an end-user having many subjects.</p> <p>It can be useful to share the same sector identifier among multiple clients, if the clients have a trust among them.
        For example an enterprise having multiple programs they own, where they want to track an end-users activity between all their owned clients.</p> <br> <p>The sector identifier is provided as client metadata and done through "sector_identifier_uri".
        It must be an HTTPS absolute URI which responds with a JSON array of all the client uris that share the sector_identifier_uri.
        That makes sure a malicious client cannot register a sector_identifier_uri that is only supposed to shared among trusted clients.</p> <!> <br> <!> <br> <p>The following HTTP example shows a request from AuthServer to the sector_identifer_uri.</p> <!> <p>The following HTTP example shows a response where the sector_identifier_uri responds with trusted client uris.</p> <!>`,1),U=c("<!> <!> <!> <!> <!>",1);function Q(j,P){H(P,!1);let S=["Name","Description"],x=[[new y("OpenId Connect","https://openid.net/specs/openid-connect-core-1_0.html"),new y("Core specification for OpenId Connect")]];A();var d=U();k(t=>{R.title="Subject Type"});var p=g(d);D(p,{title:"Subject Type"});var f=i(p,2);l(f,{title:"Introduction",children:(t,u)=>{var a=B();n(8),s(t,a)},$$slots:{default:!0}});var m=i(f,2);l(m,{title:"Specifications",children:(t,u)=>{O(t,{title:"Specifications",tableNumber:1,headers:S,rowCellDefinitions:x})},$$slots:{default:!0}});var b=i(m,2);l(b,{title:"Public",children:(t,u)=>{var a=F();n(2),s(t,a)},$$slots:{default:!0}});var C=i(b,2);l(C,{title:"Pairwise",children:(t,u)=>{var a=N(),v=i(g(a),8);w(v,{children:(r,h)=>{n();var e=o(`The sector_identifier_uri should not be considered a secret, as it cannot be used to register malicious clients,
        or deduce the pairwise subjects of end-users as the pairwise subject is a hash of combining the sector identifier, a salt and the public subject.`);s(r,e)},$$slots:{default:!0}});var $=i(v,4);w($,{children:(r,h)=>{n();var e=o(`The URIs in the response must match the values from the client's registered "client_uri" at AuthServer.`);s(r,e)},$$slots:{default:!0}});var _=i($,6);T(_,{children:(r,h)=>{n();var e=o();e.nodeValue=`
GET /sector-identifier HTTP/1.1
Host: client.authserver.dk
Accept: application/json
        `,s(r,e)},$$slots:{default:!0}});var I=i(_,4);T(I,{children:(r,h)=>{n();var e=o();e.nodeValue=`
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Cache-Control: no-cache, no-store

["https://client.authserver.dk"]
        `,s(r,e)},$$slots:{default:!0}}),s(t,a)},$$slots:{default:!0}}),s(j,d),q()}export{Q as component};
