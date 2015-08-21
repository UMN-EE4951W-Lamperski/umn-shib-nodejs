var expect = require("chai").expect,
  httpMocks = require("node-mocks-http"),
  BasicAuthenticator = require("../lib/BasicAuthenticator");

describe("Login URL", function() {
  var request = {
    hostname: 'example.com',
    uri: '/',
    passive: true
  };

  it("should have a default target", function() {
    var auth = new BasicAuthenticator(request);
    
    var expected = 'https://' + request.hostname + '/Shibboleth.sso/Login';
    // Default return target is current request URI if unspecified
    var expTarget = '?target=' + encodeURIComponent('https://' + request.hostname + request.uri);
    expect(auth.buildLoginURL()).to.equal(expected + expTarget);
  });

  it("should contain a URL encoded target URL", function() {
    var auth = new BasicAuthenticator(request);
    var loginURL = auth.buildLoginURL({target: "https://example.com/targetURL"});
    expect(loginURL).to.include("target=" + encodeURIComponent("https://example.com/targetURL"));
  });

  it("should contain expected extra login options", function() {
    var auth = new BasicAuthenticator(request);
    var opts = {
      'passive': true,
      'forceAuthn': true
    };
    var loginURL = auth.buildLoginURL(opts);
    expect(loginURL).to.include("isPassive=true");
    expect(loginURL).to.include("forceAuthn=true");
  });

  it("should use the MKey authnContext", function() {
    var auth = new BasicAuthenticator(request);
    expect(auth.buildLoginURL({mkey: true})).to.include('authnContextClassRef=' + encodeURIComponent(auth.UMN_MKEY_AUTHN_CONTEXT));
  });
});

describe("Logout URL", function() {
  var request = {
    hostname: 'example.com',
    uri: '/',
    passive: true
  };
  var returl = "https://example.com/returnURL";

  it("should begin with the SP logout endpoint", function() {
    var auth = new BasicAuthenticator(request);
    expect(auth.buildLogoutURL()).to.match(/^https:\/\/example.com\/Shibboleth\.sso\/Logout/);
  }); 

  it("should contain a URL encoded return URL", function() {
    var auth = new BasicAuthenticator(request, {}, {"return": "https://example.com/returnURL?param=123"});
    expect(auth.buildLogoutURL()).to.include("return%3D" + encodeURIComponent(returl));
  });

  it("should not logout from the IdP", function() {
    var auth = new BasicAuthenticator(request);
    expect(auth.buildLogoutURL({logoutFromIdP: false})).to.not.include("return=" + encodeURIComponent(auth.UMN_IDP_LOGOUT_URL));

    var logoutNoIdPButReturn = auth.buildLogoutURL({logoutFromIdP: false, "return": returl});
    expect(logoutNoIdPButReturn).to.not.include("return=" + encodeURIComponent(auth.UMN_IDP_LOGOUT_URL));
    expect(logoutNoIdPButReturn).to.match(/%2FreturnURL$/);
  });
});

describe("Login/Logout Redirects", function() {
  var request = {
    hostname: 'example.com',
    uri: '/',
    passive: true
  };

  it("should redirect to login with expected parameters", function() {
    var auth = new BasicAuthenticator(request);
    var opts = {
      'passive': true,
      'forceAuthn': true
    };
    var response = new httpMocks.createResponse();
    auth.redirectToLogin(opts, response);
    expect(response.getHeader("Location")).to.include("target=");
  });
  it("should redirect to logout with expected parameters", function() {
    var opts = {
      logoutFromIdP: true
    };
    var auth = new BasicAuthenticator(request);
    var response = new httpMocks.createResponse();
    auth.redirectToLogout(opts, response);
    expect(response.getHeader("Location")).to.include("return=" + encodeURIComponent(auth.UMN_IDP_LOGOUT_URL));
  });
});

describe("Session attributes", function() {
  it.skip("should detect a valid session", function() {});
  it.skip("should be logged in with MKey", function() {});
  it.skip("should report the correct authentication instant", function() {
  });
});

describe("Attribute access", function() {
  it("should default to HTTP header access", function() {
    var auth = new BasicAuthenticator();
    expect(auth.getAttributeAccessMethod()).to.equal((new BasicAuthenticator()).UMN_ATTRS_FROM_HEADERS);
  });
  it("should accept known values for access methods", function() {
    var auth = new BasicAuthenticator();
    auth.setAttributeAccessMethod(auth.UMN_ATTRS_FROM_ENV);
    expect(auth.getAttributeAccessMethod()).to.equal((new BasicAuthenticator()).UMN_ATTRS_FROM_ENV);
    auth.setAttributeAccessMethod(auth.UMN_ATTRS_FROM_HEADERS);
    expect(auth.getAttributeAccessMethod()).to.equal((new BasicAuthenticator()).UMN_ATTRS_FROM_HEADERS);
  });
  it("should not accept an unknown access method value", function() {
    var auth = new BasicAuthenticator();
    expect(function() {auth.setAttributeAccessMethod("badvalue")}).to.throw('Invalid attribute access method');
  });
});
describe("Attribute normalization", function() {
  it("should convert a HTTP header to a properly cased attribute name", function() {
    var auth = new BasicAuthenticator();
    auth.setAttributeAccessMethod(auth.UMN_ATTRS_FROM_HEADERS);
    expect(auth.normalizeAttributeName('HTTP_AN_ATTRIBUTE')).to.equal('an-attribute');

    auth.setAttributeAccessMethod(auth.UMN_ATTRS_FROM_ENV);
    expect(auth.normalizeAttributeName('AN_ATTRIBUTE')).to.equal('AN_ATTRIBUTE');
  });
});
