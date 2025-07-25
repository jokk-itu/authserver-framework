import{t as i,h as T,a as s}from"../chunks/BdD32qd5.js";import"../chunks/BOyCDzPS.js";import{f as u,$ as _,s as r,c as g,n,r as m}from"../chunks/Db0b_LWK.js";import{a as v}from"../chunks/CANx_FtO.js";import{P as I,S as o}from"../chunks/DcIxqC40.js";import{b as $}from"../chunks/CS8n-eVR.js";var P=i("<p>The AuthServer framework has been built as a single NuGet package.</p>"),w=i(`<p>Endpoints have been designed as a minimum HTTP handler, with an accessor
        to parse the request, and a handler to validate and process the request. <br></p> <br> <figure><img alt="endpoint architecture"> <figCaption class="text-center">Image 1: Class diagram of request handling</figCaption></figure> <br> <p><b>IRequestAccessor</b> is responsible for parsing the request into a
        single request. It can for example contain parsed headers, query
        parameters and body parameters. <br><br> <b>RequestHandler</b> is responsible for accepting a request, then
        validate it through its <b>IRequestValidator</b> and if valid, then
        process it through <b>IRequestProcessor</b>. <br><br> <b>IEndpointHandler</b> is the HTTP request entrypoint and is
        responsible for handling the request by using <b>IRequestHandler</b> and <b>IRequestAccessor</b>.</p>`,1),x=i(`<p>The AuthServer framework consists of a single csharp project, containing
        feature folders, and core functionality shared across features. <br><br> For example, the authorize endpoint is a single feature, but some functionality
        is shared with the pushed authorization feature. <br><br> Consumers of the framework might not use all features that AuthServer has
        to offer, and therefore each feature can be enabled or disabled. <br> Some features, like Dynamic Client Registration offers fine grained feature
        control, grouped by action. <br> Therefore, getting a client is one feature, whereas creating a client is
        another feature. <br><br> Managing features is implemented through the Microsoft.FeatureManagement
        library.</p> <br> <figure><img class="mx-auto" alt="module architecture"> <figcaption class="text-center">Image 2: State machine diagram of module handling</figcaption></figure> <br> <p>The feature flag filter is responsible for checking all incoming HTTP requests,
        whether the endpoint it reaches has been enabled through FeatureManagement.
        If it has been enabled, the execution flow continues normally,
        if it has not, then the request is cancelled immediately and the HTTP status code 404 is returned. <br> The feature flag check is also handled in the Discovery endpoint,
        to make sure metadata about disabled features is not exposed.</p>`,1),S=i(`<p>The <b>Client</b> and related data is accessed in almost every request,
        and that is by far mostly reading the client, as updating the client should rarely be done.
        Therefore, to alleviate the data store, all clients are cached in a distributed cache,
        for faster retrieval of data.</p>`),k=i("<!> <!> <!> <!> <!>",1);function F(q){var h=k();T(t=>{_.title="Software Architecture in AuthServer"});var c=u(h);I(c,{title:"Architecture"});var f=r(c,2);o(f,{title:"Introduction",children:(t,l)=>{var e=P();s(t,e)},$$slots:{default:!0}});var p=r(f,2);o(p,{title:"Endpoints",children:(t,l)=>{var e=w(),a=r(u(e),4),d=g(a);v(d,"src",`${$??""}/endpoint-architecture.png`),n(2),m(a),n(4),s(t,e)},$$slots:{default:!0}});var b=r(p,2);o(b,{title:"Modules",children:(t,l)=>{var e=x(),a=r(u(e),4),d=g(a);v(d,"src",`${$??""}/module-architecture.png`),n(2),m(a),n(4),s(t,e)},$$slots:{default:!0}});var y=r(b,2);o(y,{title:"Cache",children:(t,l)=>{var e=S();s(t,e)},$$slots:{default:!0}}),s(q,h)}export{F as component};
