import { base } from "$app/paths";

class Link {
    Name: string;
    Href: string;

    constructor(name: string, href: string) {
        this.Name = name;
        this.Href = base + href;
    }
}

class DeveloperLink extends Link {
    constructor(name: string, href: string) {
        super(name, '/developer' + href);
    }
}

export const developerLinks = [
    new DeveloperLink('Architecture', '/architecture'),
    new DeveloperLink('Setup', '/setup'),
    new DeveloperLink('Client Authentication', '/client-authentication'),
    new DeveloperLink('Discovery', '/discovery'),
    new DeveloperLink('JWKS', '/jwks'),
    new DeveloperLink('PKCE', '/pkce'),
    new DeveloperLink('Subject Type', '/subject-type'),
    new DeveloperLink('Resource', '/resource'),
    new DeveloperLink('DPoP', '/dpop'),
    new DeveloperLink('Token', '/token'),
    new DeveloperLink('Client Credentials', '/client-credentials'),
    new DeveloperLink('Authorization Code', '/authorization-code'),
    new DeveloperLink('Refresh Token', '/refresh-token'),
    new DeveloperLink('Token Revocation', '/token-revocation'),
    new DeveloperLink('Token Introspection', '/token-introspection'),
    new DeveloperLink('Grant Management', '/grant-management')
];

export const navLinks = [
    new Link('Intro', '/intro'),
    new Link('Demo', '/demo'),
    new Link('Developer', '/developer'),
]