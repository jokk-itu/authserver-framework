import{f,a as t,t as u}from"../chunks/Z1HRfbhX.js";import"../chunks/BQYPTkyu.js";import{p as F,f as p,a as q,e as x,s as r,$ as I,n as h}from"../chunks/Iw8VLsBB.js";import{h as R}from"../chunks/BhNhnXGn.js";import{i as S}from"../chunks/Bwhf-QOO.js";import{C as g}from"../chunks/CVzv1ABR.js";import{I as y}from"../chunks/h_8lfFjQ.js";import{P as C,S as l}from"../chunks/D5cW4fPA.js";import{T as A,R as n}from"../chunks/DtqDFwhC.js";var H=f(`<p>Access tokens are usable at resources, where their identifier is in the audience claim of the access token.
        The audience claim is deduced by the client passing resource indicators as the request parameter "resource".</p> <br/> <!>`,1),D=f(`<p>The resource parameter must be one or many URIs, which match the ClientUri of a registered Client at the AuthServer.
        The available resources are specified at the discovery endpoint, identified by the field 'protected_resources'.</p> <p>The resource can only be specified as an audience, if it is authorized for at least one of the requested scopes.</p> <br/> <p>The following HTTP example is a token request, with multiple resource parameters.</p> <p>The resource parameters are then used as the audience in the issued access token.</p> <!> <p>The following HTTP example is an incomplete authorize request, with multiple resource parameters.</p> <p>The resource parameters are then used as the authorized audience of issued access tokens, in relation to the grant of the authorize request.</p> <p>The resources are authorized once the end user has consented to the authorization request.</p> <!>`,1),B=f("<!> <!> <!> <!>",1);function Q(_,k){F(k,!1);let P=["Name","Description"],b=[[new n("Resource Indicators","https://datatracker.ietf.org/doc/html/rfc8707"),new n("Specification for specifying resources")],[new n("Protected Resource Metadata","https://datatracker.ietf.org/doc/html/rfc9728/"),new n("Specification for protected resource metadata")]];S();var m=B();R("cvsin4",e=>{x(()=>{I.title="Resource Indicators"})});var $=p(m);C($,{title:"Resource Indicators"});var T=r($,2);l(T,{title:"Introduction",children:(e,w)=>{var o=H(),a=r(p(o),4);y(a,{children:(c,i)=>{h();var d=u(`The resource indicator is required, to demand the client specifies which resources are the intended audience.
        If that is not a requirement, then all resources authorized for the requested scope, would have to be specified as the audience in the token,
        whether or not the resources are intended for usage.
        This means the resource indicators are used to enforce least privilege for tokens.`);t(c,d)},$$slots:{default:!0}}),t(e,o)},$$slots:{default:!0}});var v=r(T,2);l(v,{title:"Specifications",children:(e,w)=>{A(e,{title:"Specifications",tableNumber:1,get headers(){return P},get rowCellDefinitions(){return b}})},$$slots:{default:!0}});var z=r(v,2);l(z,{title:"Indicating resources",children:(e,w)=>{var o=D(),a=r(p(o),10);g(a,{children:(i,d)=>{h();var s=u();s.nodeValue=`
POST /connect/token HTTP/1.1
Host: idp.authserver.dk
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

grant_type=client_credentials
&scope=account:update%20account:delete
&resource=https%3A%2F%2Fapi-one.protectedresource.dk
&resource=https%3A%2F%2Fapi-two.protectedresource.dk
`,t(i,s)},$$slots:{default:!0}});var c=r(a,8);g(c,{children:(i,d)=>{h();var s=u();s.nodeValue=`
GET /connect/authorize?resource=https%3A%2F%2Fapi-one.protectedresource.dk&resource=https%3A%2F%2Fapi-two.protectedresource.dk HTTP/1.1
Host: idp.authserver.dk
`,t(i,s)},$$slots:{default:!0}}),t(e,o)},$$slots:{default:!0}}),t(_,m),q()}export{Q as component};
