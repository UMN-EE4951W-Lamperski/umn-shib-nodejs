var expect = require("chai").expect,
  BasicAuthenticator = require("../lib/BasicAuthenticator");

describe("Login URL", function() {
  it("should have a default target", function() {
    var auth = new BasicAuthenticator();

    var request = {
      hostname: 'example.com',
      uri: '/',
    }
    
    var expected = 'https://' + request.hostname + request.uri;
    // Default return target is current request URI if unspecified
    var expTarget = '?target=' + encodeURIComponent(expected);
    expect(auth.buildLoginURL(null)).to.equal(expected + target);
  });
});

describe("Logout URL", function() {
  it("should begin with the entity logout URL", function() {
    var auth = new BasicAuthenticator();
    expect(auth.buildLogoutURL()).to.include(auth.UMN_IDP_LOGOUT_URL);
  }); 

  it("should contain a URL encoded return URL", function() {
    var returl = "https://example.com/returnURL";

    var auth = new BasicAuthenticator({}, {"return": "https://example.com/returnURL"});
    expect(auth.buildLogoutURL()).to.include("?return=" + encodeURIComponent(returl));

  });
});
