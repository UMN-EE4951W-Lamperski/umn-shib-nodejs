# umn-shib-nodejs

A Node.js implementation of the UMN Community Shibboleth API

## Description

This is a fork of a Node.js implementation of the [UMN Community Shibboleth
BasicAuthenticator API](https://github.umn.edu/umn-community-shib/umn-shib-api).

It is intended as an easy to use interface to construct Shibboleth SP
login/logout URLs, redirect through the Shibboleth SessionInitiator, and access
standard attributes. Its dependence on Apache mod_shib means this is only
useful when running Node.js applications on Apache via a proxy like Passenger.

The implementation, like the API which describes it, is intended to provide a
baseline set of common functions coupled with access to the standard set of
Shibboleth attributes Identity Management exposes to all service providers. It
has been designed to be easily extensible, allowing you to add features specific
to your academic or departmental unit.

## Prerequisites

- Apache and Passenger installed and configured
- The Shibboleth Native SP installed, configured, and running

## Installation

Install the module via `npm`, by adding its repository to your `package.json`.

```json
"dependencies": {
  "umn-shib-nodejs": "git+ssh://git@github.umn.edu/umn-community-shib/umn-shib-nodejs.git#RELEASE"
}
```

The `#RELEASE` above may be any tag or Git commmit hash.

After adding it to your `package.json`, install it.

```
$ npm install
```

## Basic Usage

Basic usage consists of a `require()` to load the module, instantiating a `BasicAuthenticator` object, and calling methods on it.

```javascript
// Require the module
var shib = require("umn-shib-nodejs");

// Assuming a simple Node.js application, inside the HTTP listener
var server = http.createServer(function (request, response) {
  // Instantiate a new BasicAuthenticator, passing in the
  // event's request and response objects
  var umnshib = new shib.BasicAuthenticator(request, response);

  // Check for an active Shibboleth session
  if (!umnshib.hasSession()) {
    umnshib.redirectToLogin();
  }

  response.writeHead(200, { "Content-Type": "text/plain" });
  var output = "";

  // Access Shibboleth attributes
  output += "Username: " + umnshib.getAttributeValue("eppn") + "\n";
  output += "Name: " + umnshib.getAttributeValue("givenName") + "\n";

  response.end(output);
});
server.listen(3000);
```

## Configuration

### Shibboleth.sso handler URL

Most commonly (by default), the Shibboleth SP handler URL is located at
`/Shibboleth.sso` and this library expects to find it there unless otherwise
instructed.

```javascript
umnshib.setHandlerURL("/some/other/path/Shibboleth.sso");
```

### Shibboleth environment or HTTP headers

**NOTICE: Some passenger versions incorrectly handle per-request environment
variables in Node.js. It may not be safe to use the environment, so HTTP headers
are the default location this module searches.**

```javascript
// Default is from HTTP headers
umnshib.setAttributeAccessMethod(umnshib.UMN_ATTRS_FROM_HEADERS);

// Retrieve from environment variables instead NOT USABLE WITH PASSENGER AT THIS
TIME;
umnshib.setAttributeAccessMethod(umnshib.UMN_ATTRS_FROM_ENV);
```

## Login / Logout Options

These options are functionally equivalent to those in [the UMN Community
Shibboleth PHP
implementation](https://github.umn.edu/umn-community-shib/umn-shib-php/blob/master/README.md#login--logout-options)

This document details only the implementation syntax. For full explanations of
all options, visit the PHP project's documentation.

```javascript
// Options are passed to URL methods as an object literal.
var url = umnshib.buildLoginURL({
  target: "https://example.umn.edu/return/url/path",
  passive: true,
});

// Alternatively, default options can be set in the BasicAuthenticator constructor
var loginOptions = {
  target: "https://example.umn.edu/return/url/path",
  passive: true,
};
var logoutOptions = {
  logoutFromIdP: true,
};
var umnshib = new BasicAuthenticator(
  request,
  response,
  loginOptions,
  logoutOptions
);

// The authenticator will use those options when calling URL or redirection methods
umnshib.redirectToLogin();
// redirects to the IdP with isPassive, returning to https://example.umn.edu/return/url/path
```

## Testing

This library uses the Mocha testing framework. To run tests, use

```shell
$ mocha spec
```

Or via `npm`:

```shell
$ npm test
```

# IMPORTANT

Since this was in the UMN GitHub, this is probably proprietary software.
