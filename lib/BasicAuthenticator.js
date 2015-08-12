'use strict';

var URL = require("url-parse");

function BasicAuthenticator(request, loginOptions, logoutOptions) {
  this.loginOptions = loginOptions || {};
  this.logoutOptions = logoutOptions || {};

  this._handlerURL = '/Shibboleth.sso';
  this._attributeSource = this.UMN_ATTRS_FROM_HEADERS;
  this._request = request;
}

BasicAuthenticator.prototype.UMN_IDP_ENTITY_ID = 'https://idp2.shib.umn.edu/idp/shibboleth';
BasicAuthenticator.prototype.UMN_TEST_IDP_ENTITY_ID = 'https://idp-test.shib.umn.edu/idp/shibboleth';
BasicAuthenticator.prototype.UMN_SPOOF_IDP_ENTITY_ID = 'https://idp-spoof-test.shib.umn.edu/idp/shibboleth';
BasicAuthenticator.prototype.UMN_IDP_LOGOUT_URL = 'https://idp2.shib.umn.edu/idp/LogoutUMN';
BasicAuthenticator.prototype.UMN_TEST_IDP_LOGOUT_URL = 'https://idp-test.shib.umn.edu/idp/LogoutUMN';
BasicAuthenticator.prototype.UMN_SPOOF_IDP_LOGOUT_URL = 'https://idp-spoof-test.shib.umn.edu/idp/LogoutUMN';
BasicAuthenticator.prototype.UMN_MKEY_AUTHN_CONTEXT = 'https://www.umn.edu/shibboleth/classes/authncontext/mkey';
BasicAuthenticator.prototype.UMN_ATTRS_FROM_ENV = 'from_environment';
BasicAuthenticator.prototype.UMN_ATTRS_FROM_HEADERS = 'from_headers';

// Extended constants
BasicAuthenticator.prototype.UMN_SESSION_MAX_AGE = 10800;

BasicAuthenticator.prototype.buildLoginURL = function(options) {
  var loginURL = 'https://' + this._request.hostname + this._handlerURL + '/Login?target=';
  options = _mergeOpts(this.loginOptions, options);

  if (options.target) {
    loginURL += encodeURIComponent(options.target);
  }
  else {
    loginURL += encodeURIComponent('https://' + this._request.hostname + this._request.uri);
  }
  return loginURL;
};

BasicAuthenticator.prototype.buildLogoutURL = function(request, options) {
  var logoutURL = this.UMN_IDP_LOGOUT_URL;
  options = _mergeOpts(this.logoutOptions, options);
  if (options.hasOwnProperty("return")) {
    logoutURL += "?return=" + encodeURIComponent(options["return"]);
  }
  return logoutURL;
};

BasicAuthenticator.prototype.redirectToLogin = function() {};
BasicAuthenticator.prototype.getAttributesOrRequestLogin = function() {};
BasicAuthenticator.prototype.redirectToLogout = function() {};
BasicAuthenticator.prototype.hasSession = function() {};
BasicAuthenticator.prototype.hasSessionTimedOut = function() {};
BasicAuthenticator.prototype.loggedInWithMKey = function() {};
BasicAuthenticator.prototype.loggedInSince = function() {};
BasicAuthenticator.prototype.getIdpEntityId = function() {};
BasicAuthenticator.prototype.getDefaultAttributeNames = function() {};
BasicAuthenticator.prototype.getAttributeNames = function() {};
BasicAuthenticator.prototype.getAttributeValues = function(name, delimiter) {};
BasicAuthenticator.prototype.getAttributeValue = function(name) {};
BasicAuthenticator.prototype.getAttributes = function(requestedAttributes) {};
BasicAuthenticator.prototype.getAttributeAccessMethod = function() {};

BasicAuthenticator.prototype.setHandlerURL = function(newHandlerURL) {
  _handlerURL = newHandlerURL;
};

/**
 * This is private due to how Node.js exposes modules
 * */
function _mergeOpts(baseOpts, newOpts) {
  var mergeOpts = {};
  baseOpts = baseOpts || {};
  newOpts = newOpts || {};

  // All instance's current options first
  for (var opt in baseOpts) {
    mergeOpts[opt] = baseOpts[opt];
  }
  // Overwrite by properties passed in
  for (var opt in newOpts) {
    mergeOpts[opt] = newOpts[opt];
  }
  return mergeOpts;
}

module.exports = BasicAuthenticator;
