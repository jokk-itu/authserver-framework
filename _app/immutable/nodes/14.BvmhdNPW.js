import{f as l,a as i,t as m}from"../chunks/Z1HRfbhX.js";import"../chunks/BQYPTkyu.js";import{p as J,f as y,a as K,e as W,s as n,$ as A,n as k}from"../chunks/Iw8VLsBB.js";import{h as C}from"../chunks/BhNhnXGn.js";import{i as N}from"../chunks/Bwhf-QOO.js";import{C as T}from"../chunks/CVzv1ABR.js";import{P as R,S as s}from"../chunks/D5cW4fPA.js";import{T as g,R as e}from"../chunks/DtqDFwhC.js";var j=l("<p>The JWKS endpoint returns a JSON document containing public keys used for verifying signatures in tokens, and encrypting tokens.</p>"),D=l("<p>The jwks endpoint is invoked through HTTP using the GET method.</p> <p>The following exmaple is a GET request to the jwks endpoint.</p> <!> <p>The following example is a GET response to the jwks endpoint.</p> <!> <p>The following table describes the fields in the JSON document.</p> <!>",1),O=l("<!> <!> <!> <!>",1);function M(v,b){J(b,!1);let $=["Name","Description"],S=[[new e("JSON Web Key","https://datatracker.ietf.org/doc/html/rfc7517"),new e("Core specification for JSON Web Key")]],x=["Name","Description"],_=[[new e("keys"),new e("Array of Json Web Keys")],[new e("kty"),new e("The cryptographic algorithm family, the key can use")],[new e("use"),new e("The usage of the key")],[new e("alg"),new e("The cryptographic algorithm the key can be used with")],[new e("key_ops"),new e("The operations the key can be used with")],[new e("kid"),new e("The unique identifier of the key")],[new e("crv"),new e("The elliptic curve used by the key")],[new e("x"),new e("The base64 x coordinate on the curve")],[new e("y"),new e("The base64 y coordinate on the curve")],[new e("n"),new e("The modulus value used with kty: RSA")],[new e("e"),new e("The exponnent value used with kty: RSA")],[new e("x5c"),new e("Array of one base64 certificate")],[new e("x5t"),new e("The SHA1 thumpbrint of the certificate")],[new e("x5t#S256"),new e("The SHA256 thumbprint of the certificate")]];N();var p=O();C("l7x5f7",t=>{W(()=>{A.title="JWKS Metadata Endpoint"})});var c=y(p);R(c,{title:"JWKS"});var d=n(c,2);s(d,{title:"Introduction",children:(t,u)=>{var r=j();i(t,r)},$$slots:{default:!0}});var h=n(d,2);s(h,{title:"Specifications",children:(t,u)=>{g(t,{title:"Specifications",tableNumber:1,get headers(){return $},get rowCellDefinitions(){return S}})},$$slots:{default:!0}});var P=n(h,2);s(P,{title:"JWKS Endpoint",children:(t,u)=>{var r=D(),f=n(y(r),4);T(f,{children:(a,E)=>{k();var o=m();o.nodeValue=`
GET /.well-known/jwks HTTP/1.1
Host: idp.authserver.dk
        `,i(a,o)},$$slots:{default:!0}});var w=n(f,4);T(w,{children:(a,E)=>{k();var o=m();o.nodeValue=`
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8

{
  "keys": [
    {
      "kty": "EC",
      "use": "enc",
      "crv": "P-256",
      "alg": "ECDH-ES+A128KW",
      "key_ops": ["encryption"],
      "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
      "kid": "d890e7ed-662b-48c5-8914-c5c58571f8b6"
    },
    {
      "kty":"RSA",
      "use": "sig",
      "alg": "RS256",
      "key_ops": ["verify"],
      "n": "0vx7agoebGcQSuuPi...",
      "e":"AQAB",
      "kid":"b3f74555-ce9f-4dd3-a3fc-9789a77580a9"
    }
  ]
}
        `,i(a,o)},$$slots:{default:!0}});var H=n(w,4);g(H,{title:"JWKS fields",tableNumber:3,get headers(){return x},get rowCellDefinitions(){return _}}),i(t,r)},$$slots:{default:!0}}),i(v,p),K()}export{M as component};
