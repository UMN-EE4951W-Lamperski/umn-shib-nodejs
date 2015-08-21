'use strict';

var URL = require("url-parse");
var querystring = require("querystring");

function BasicAuthenticator(request, loginOptions, logoutOptions) {
  this._loginOptions = _mergeOpts(this.defaultLoginOptions, loginOptions);
  this._logoutOptions = _mergeOpts(this.defaultLogoutOptions, logoutOptions);

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

BasicAuthenticator.prototype.defaultLoginOptions = {};
BasicAuthenticator.prototype.defaultLogoutOptions = {
  'logoutFromIdP': true,
  'IdPLogoutURL': this.UMN_IDP_LOGOUT_URL
};


BasicAuthenticator.prototype.buildLoginURL = function(options) {
  var loginURL = 'https://' + this._request.hostname + this._handlerURL + '/Login?';
  var params = {};
  options = _mergeOpts(this._loginOptions, options);

  // Append target if specified, otherwise use current request URI
  if (options.target) {
    params.target = options.target;
  }
  else {
    params.target = 'https://' + this._request.hostname + this._request.uri;
  }

  // Set options with 1:1 mapping from input loginOptions
  var directOpts = ['forceAuthn','entityID','authnContextClassRef'];
  for (var p=0; p<directOpts.length; p++) {
    if (options.hasOwnProperty(directOpts[p])) {
      params[directOpts[p]] = options[directOpts[p]];
    }
  }
  // Other options that aren't 1:1 to input values
  if (options.hasOwnProperty('passive')) {
    params.isPassive = options.passive;
  }
  if (options.hasOwnProperty('mkey') && options.mkey) {
    params.authnContextClassRef = this.UMN_MKEY_AUTHN_CONTEXT;
  }

  // Build params from object to query string
  loginURL += querystring.stringify(params);

  return loginURL;
};

BasicAuthenticator.prototype.buildLogoutURL = function(options) {
  var logoutURL = 'https://' + this._request.hostname + this._handlerURL + '/Logout?';
  var params = {};

  options = _mergeOpts(this._logoutOptions, options);

  // If requesting an IdP logout, use that as the base return URL
  if (options.logoutFromIdP) {
    params["return"] = this.UMN_IDP_LOGOUT_URL;
    // And append another return URL to the IdP logout, NOT urlencoded 
    // so the result is not double-encoded
    if (options.hasOwnProperty("return")) {
      params["return"] += "?return=" + options["return"];
    }
  }
  else {
    if (options.hasOwnProperty("return")) {
      params["return"] = options["return"];
    }
  }
  logoutURL += querystring.stringify(params);
  return logoutURL;
};

BasicAuthenticator.prototype.redirectToLogin = function(options, response) {
  response.writeHead(302, {"Location": this.buildLoginURL(options)});
  response.end();
};

BasicAuthenticator.prototype.getAttributesOrRequestLogin = function() {};

BasicAuthenticator.prototype.redirectToLogout = function(options, response) {
  response.writeHead(302, {"Location": this.buildLogoutURL(options)});
  response.end();
};

BasicAuthenticator.prototype.normalizeAttributeName = function(name) {
  // Node http returns HTTP headers as lowercase, hyphenated
  if (this._attributeSource == this.UMN_ATTRS_FROM_HEADERS) {
    name = name.replace(/_/g, '-').toLowerCase().replace(/^http-/, '');
  }
  return name;
};

BasicAuthenticator.prototype.hasSession = function() {};
BasicAuthenticator.prototype.hasSessionTimedOut = function() {};
BasicAuthenticator.prototype.loggedInWithMKey = function() {
  if (this.hasSession()) {
    return this.getAttributeValue('Shib-Authentication-Method') == this.UMN_MKEY_AUTHN_CONTEXT;
  }
  return false;
};
BasicAuthenticator.prototype.loggedInSince = function() {
  var authInstant = this.getAttributeValue('Shib-Authentication-Instant');
  if (authInstant) {
    return Date.parse(authInstant);
  }
};
BasicAuthenticator.prototype.getIdpEntityId = function() {};
BasicAuthenticator.prototype.getDefaultAttributeNames = function() {};
BasicAuthenticator.prototype.getAttributeNames = function() {};
BasicAuthenticator.prototype.getAttributeValues = function(name, delimiter) {};
BasicAuthenticator.prototype.getAttributeValue = function(name) {};
BasicAuthenticator.prototype.getAttributes = function(requestedAttributes) {};

BasicAuthenticator.prototype.getAttributeAccessMethod = function() {
  return this._attributeSource;
};


BasicAuthenticator.prototype.setAttributeAccessMethod = function(method) {
  method = method.toLowerCase();
  if ([this.UMN_ATTRS_FROM_ENV, this.UMN_ATTRS_FROM_HEADERS].indexOf(method) >= 0) {
    this._attributeSource = method
  }
  else {
    throw new RangeError("Invalid attribute access method");
  }
};

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
