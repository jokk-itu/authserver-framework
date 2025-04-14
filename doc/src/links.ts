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
    new DeveloperLink('Datamodel', '/datamodel'),
    new DeveloperLink('Setup', '/setup'),
    new DeveloperLink('Client Authentication', '/client-authentication'),
    new DeveloperLink('Discovery', '/discovery'),
    new DeveloperLink('Client Credentials', '/client-credentials'),
];

export const navLinks = [
    new Link('Intro', '/intro'),
    new Link('Demo', '/demo'),
    new Link('Developer', '/developer'),
]