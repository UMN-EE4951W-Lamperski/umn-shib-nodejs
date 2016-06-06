var expect = require("chai").expect,
  httpMocks = require("node-mocks-http"),
  BasicAuthenticator = require("../lib/BasicAuthenticator");

describe("API implementation", function() {
  it("should implement all expected public API methods", function() {
    var methods = [];
    for (var method in (BasicAuthenticator.prototype)) {
      if (typeof BasicAuthenticator.prototype[method] == "function") {
        methods.push(method);
      }
    }
    expect(methods).to.have.all.members([
      'buildLoginURL',
      'buildLogoutURL',
      'redirectToLogin',
      'getAttributesOrRequestLogin',
      'redirectToLogout',
      'normalizeAttributeName',
      'hasSession',
      'hasSessionTimedOut',
      'loggedInWithMKey',
      'loggedInWithDuo',
      'loggedInSince',
      'getIdpEntityId',
      'getDefaultAttributeNames',
      'getAttributeNames',
      'getAttributeValues',
      'getAttributeValue',
      'getAttributes',
      'getAttributeAccessMethod',
      'setAttributeAccessMethod',
      'setHandlerURL'
    ]);
  });
});

describe("Login URL", function() {
  var request = {
    uri: '/',
    passive: true,
    headers: {
      host: 'example.com',
    }
  };

  it("should have a default target", function() {
    var auth = new BasicAuthenticator(request);

    var expected = 'https://' + request.headers.host + '/Shibboleth.sso/Login';
    // Default return target is current request URI if unspecified
    var expTarget = '?target=' + encodeURIComponent('https://' + request.headers.host + request.url);
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

  it("should use the Duo authnContext", function() {
    var auth = new BasicAuthenticator(request);
    expect(auth.buildLoginURL({duo: true})).to.include('authnContextClassRef=' + encodeURIComponent(auth.UMN_DUO_AUTHN_CONTEXT));
  });
});

describe("Logout URL", function() {
  var request = httpMocks.createRequest({
    url: '/',
    passive: true,
    headers: {
      host: 'example.com',
    }
  });
  var response = httpMocks.createResponse();
  var returl = "https://example.com/returnURL";

  it("should begin with the SP logout endpoint", function() {
    var auth = new BasicAuthenticator(request);
    expect(auth.buildLogoutURL()).to.match(/^https:\/\/example.com\/Shibboleth\.sso\/Logout/);
  });

  it("should contain a double-encoded return URL returning from IdP logout", function() {
    var auth = new BasicAuthenticator(request, response, {}, {"return": "https://example.com/returnURL?param=123"});
    expect(auth.buildLogoutURL()).to.include("return%3D" + encodeURIComponent(encodeURIComponent(returl)));
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
    uri: '/',
    passive: true,
    headers: {
      host: 'example.com',
    }
  };

  it("should redirect to login with expected parameters", function() {
    var opts = {
      'passive': true,
      'forceAuthn': true
    };
    var response = new httpMocks.createResponse();
    var auth = new BasicAuthenticator(request, response);
    auth.redirectToLogin(opts);
    expect(response.getHeader("Location")).to.include("target=");
  });

  it("should redirect to logout with expected parameters", function() {
    var opts = {
      logoutFromIdP: true
    };
    var response = new httpMocks.createResponse();
    var auth = new BasicAuthenticator(request, response);
    auth.redirectToLogout(opts);
    expect(response.getHeader("Location")).to.include("return=" + encodeURIComponent(auth.UMN_IDP_LOGOUT_URL));
  });
});

describe("Session attributes", function() {
  var request = httpMocks.createRequest({
    url: '/',
    headers: {
      host: 'example.com',
      'shib-identity-provider': 'https://idp2.shib.umn.edu/idp/shibboleth'
    }
  });

  it("should detect a valid session", function() {
    var auth = new BasicAuthenticator(request);
    expect(auth.hasSession()).to.be.true;
  });

  it("should correctly retrieve values from env", function() {
    // Set an attribute on process.env
    process.env.givenName = 'Hawking';

    // First one uses headers
    var auth = new BasicAuthenticator(request);
    auth.setAttributeAccessMethod(auth.UMN_ATTRS_FROM_HEADERS);
    expect(auth.getAttributeValue('givenName')).to.be.null;

    // First one uses headers
    var authEnv = new BasicAuthenticator(request);
    authEnv.setAttributeAccessMethod(authEnv.UMN_ATTRS_FROM_ENV);
    expect(authEnv.getAttributeValue('givenName')).to.equal('Hawking');

    // Clean up that attribute from env
    delete process.env.givenName;
  });

  it("should return multivalue attributes as an array or null", function() {
    var request = httpMocks.createRequest({
      url: '/',
      headers: {
        host: 'example.com',
        'umnLibAccess': '1;2;9',
        'customDelimiter': 'one,two,three'
      }
    });
    var auth = new BasicAuthenticator(request);
    expect(auth.getAttributeValues('umnLibAccess')).to.have.all.members(['1','2','9']);
    expect(auth.getAttributeValues('customDelimiter', ',')).to.have.all.members(['one','two','three']);
    expect(auth.getAttributeValues('shouldBeNull', ',')).to.be.null;
  });

  it("should return an object containing multiple requested attributes", function() {
    var request = httpMocks.createRequest({
      url: '/',
      headers: {
        'shib-identity-provider': 'https://idp2.shib.umn.edu/idp/shibboleth',
        'shib-authentication-instant': (new Date((((new Date()).getTime() / 1000) - 20) * 1000)).toISOString(),
        host: 'example.com',
        'umnLibAccess': '1;2;9',
        'customDelimiter': 'one,two,three'
      }
    });
    var auth = new BasicAuthenticator(request);

  });

  it("should not be logged in with MKey", function() {
    var auth = new BasicAuthenticator(request);
    expect(auth.loggedInWithMKey()).to.be.false;
  });

  it("should be logged in with MKey", function() {
    var mkeyRequest = httpMocks.createRequest({
      url: '/',
      headers: {
        host: 'example.com',
        'shib-identity-provider': 'https://idp2.shib.umn.edu/idp/shibboleth',
        'shib-authentication-method': (new BasicAuthenticator()).UMN_MKEY_AUTHN_CONTEXT
      }
    });
    var auth = new BasicAuthenticator(mkeyRequest);
    expect(auth.loggedInWithMKey()).to.be.true;
  });

  it("should be logged in with Duo", function() {
    var duoRequest = httpMocks.createRequest({
      url: '/',
      headers: {
        host: 'example.com',
        'shib-identity-provider': 'https://idp2.shib.umn.edu/idp/shibboleth',
        'shib-authentication-method': (new BasicAuthenticator()).UMN_DUO_AUTHN_CONTEXT
      }
    });
    var auth = new BasicAuthenticator(duoRequest);
    expect(auth.loggedInWithDuo()).to.be.true;
  });

  it("should report the correct authentication instant", function() {
    var tRequest = httpMocks.createRequest({
      url: '/',
      headers: {
        host: 'example.com',
        'shib-identity-provider': 'https://idp2.shib.umn.edu/idp/shibboleth',
        'shib-authentication-instant': '2015-08-25T17:47:14.785Z'
      }
    });
    var auth = new BasicAuthenticator(tRequest);
    expect(auth.loggedInSince().getTime()).to.equal(1440524834785);
  });

  it("should not return an authentication instant if no session is present", function() {
    var aRequest = httpMocks.createRequest({
      url: '/',
      headers: {
        host: 'example.com',
        'shib-authentication-instant': '2015-08-25T17:47:14.785Z'
      }
    });
    var auth = new BasicAuthenticator(aRequest);
    expect(auth.hasSessionTimedOut()).to.be.true;
  });

  it("should handle timeouts based on specified maxAge", function() {
    var aRequest = httpMocks.createRequest({
      url: '/',
      headers: {
        host: 'example.com',
        'shib-identity-provider': 'https://idp2.shib.umn.edu/idp/shibboleth',
        'shib-authentication-instant': null
      }
    });

    // Time 20s in the past
    aRequest.headers['shib-authentication-instant'] = (new Date((((new Date()).getTime() / 1000) - 20) * 1000)).toISOString()
    var auth = new BasicAuthenticator(aRequest);
    // maxAge smaller than 20s ago
    expect(auth.hasSessionTimedOut(19)).to.be.true;
    // maxAge equal to 20s ago
    expect(auth.hasSessionTimedOut(20)).to.be.true;
    // maxAge greater than 20s ago NOT TIMED OUT
    expect(auth.hasSessionTimedOut(21)).to.be.false;
  });

  it("should still find a valid, not timed out session", function() {
    var aRequest = httpMocks.createRequest({
      url: '/',
      headers: {
        host: 'example.com',
        'shib-identity-provider': 'https://idp2.shib.umn.edu/idp/shibboleth',
        'shib-authentication-instant': (new Date()).toISOString()
      }
    });
    var auth = new BasicAuthenticator(aRequest);
    expect(auth.hasSessionTimedOut()).to.be.false;
  });

  it("should report the correct IdP", function() {
    var auth = new BasicAuthenticator(request);
    expect(auth.getIdpEntityId()).to.equal(request.headers['shib-identity-provider']);
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

  it("should return the known default set of common attributes", function() {
    var auth = new BasicAuthenticator();
    expect(auth.getDefaultAttributeNames()).to.have.all.members(['uid','eppn','isGuest','umnDID']);
  });

  it("should return the expected set of merged attribute names", function() {
    var auth = new BasicAuthenticator();
    expect(auth.getAttributeNames(['attr1','attr2','attr3'])).to.have.all.members(['uid','eppn','isGuest','umnDID','attr1','attr2','attr3']);
  });

  it("should throw an error if a non-array was passed in", function() {
    var auth = new BasicAuthenticator();
    expect(function() {auth.getAttributeNames("not an array")}).to.throw('requestedAttributes must be an Array');
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
