'use strict';

var URL = require("url-parse");
var querystring = require("querystring");

function BasicAuthenticator(request, response, loginOptions, logoutOptions) {
  this._loginOptions = _mergeOpts(this.defaultLoginOptions, loginOptions);
  this._logoutOptions = _mergeOpts(this.defaultLogoutOptions, logoutOptions);

  this._handlerURL = '/Shibboleth.sso';
  this._attributes = [
    'uid',
    'eppn',
    'isGuest',
    'umnDID'
  ];
  this._attributeSource = this.UMN_ATTRS_FROM_HEADERS;
  this._request = request;
  this._response = response;
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
  var loginURL = 'https://' + this._request.headers.host + this._handlerURL + '/Login?';
  var params = {};
  options = _mergeOpts(this._loginOptions, options);

  // Append target if specified, otherwise use current request URI
  if (options.target) {
    params.target = options.target;
  }
  else {
    params.target = 'https://' + this._request.headers.host + this._request.url;
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
  var logoutURL = 'https://' + this._request.headers.host + this._handlerURL + '/Logout?';
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

BasicAuthenticator.prototype.redirectToLogin = function(options) {
  this._response.writeHead(302, {"Location": this.buildLoginURL(options)});
  this._response.end();
};

BasicAuthenticator.prototype.getAttributesOrRequestLogin = function(options, requestedAttributes, maxAge) {
  if (!this.hasSession()) {
    this.redirectToLogin(options);
  }
  if (this.hasSession() && this.hasSessionTimedOut(maxAge)) {
    options.forceAuthn = true;
    this.redirectToLogin(options);
  }
  else {
    return this.getAttributes(requestedAttributes);
  }
};

BasicAuthenticator.prototype.redirectToLogout = function(options) {
  this._response.writeHead(302, {"Location": this.buildLogoutURL(options)});
  this._response.end();
};

BasicAuthenticator.prototype.normalizeAttributeName = function(name) {
  // Node http returns HTTP headers as lowercase, hyphenated
  if (this.getAttributeAccessMethod() == this.UMN_ATTRS_FROM_HEADERS) {
    name = name.replace(/_/g, '-').toLowerCase().replace(/^http-/, '');
  }
  return name;
};

BasicAuthenticator.prototype.hasSession = function() {
  // Any of the IdP values will indicate a session is present
  var idps = [this.UMN_IDP_ENTITY_ID, this.UMN_TEST_IDP_ENTITY_ID, this.UMN_SPOOF_IDP_ENTITY_ID];
  return (idps.indexOf(this.getIdpEntityId()) >= 0);
};

BasicAuthenticator.prototype.hasSessionTimedOut = function(maxAge) {
  var authInstant = this.loggedInSince();
  maxAge = maxAge || this.UMN_SESSION_MAX_AGE;

  if (!this.hasSession()) {
    return true;
  }
  if (authInstant) {
    // Timestamps in MS, so need to change maxAge to MS
    return (authInstant.getTime() + maxAge*1000 < (new Date()).getTime());
  }
  else {
    return false;
  }
};

BasicAuthenticator.prototype.loggedInWithMKey = function() {
  if (this.hasSession()) {
    return this.getAttributeValue('Shib-Authentication-Method') == this.UMN_MKEY_AUTHN_CONTEXT;
  }
  return false;
};
BasicAuthenticator.prototype.loggedInSince = function() {
  var authInstant = this.getAttributeValue('Shib-Authentication-Instant');
  if (authInstant) {
    return new Date(Date.parse(authInstant));
  }
};

BasicAuthenticator.prototype.getIdpEntityId = function() {
  return this.getAttributeValue('Shib-Identity-Provider');
};

BasicAuthenticator.prototype.getDefaultAttributeNames = function() {
  return this._attributes;
};

BasicAuthenticator.prototype.getAttributeNames = function(requestedAttributes) {
  var attrs = [];
  // requestedAttributes not passed in, default to array
  if (typeof requestedAttributes == 'undefined') {
    requestedAttributes = [];
  }
  // Exception if something other than an array was passed
  if (!Array.isArray(requestedAttributes)) {
    throw new TypeError("requestedAttributes must be an Array");
  }
  // Copy default attrs to output
  for (var i=0; i<this._attributes.length; i++) {
    attrs.push(this._attributes[i]);
  }
  // Copy additional requested attrs to output if not already in default set
  for (var j=0; j<requestedAttributes.length; j++) {
    if (attrs.indexOf(requestedAttributes[j]) == -1) {
      attrs.push(requestedAttributes[j]);
    }
  }
  return attrs;
};

BasicAuthenticator.prototype.getAttributeValues = function(name, delimiter) {
  var value = this.getAttributeValue(name);
  // Default delimiter is semicolon
  delimiter = delimiter || ';';

  if (value !== null) {
    return value.split(delimiter);
  }
  return null;
};

BasicAuthenticator.prototype.getAttributeValue = function(name) {
  name = this.normalizeAttributeName(name);
  if (this.getAttributeAccessMethod() == this.UMN_ATTRS_FROM_ENV) {
    return process.env.hasOwnProperty(name) ? process.env[name] : null;
  }
  if (this.getAttributeAccessMethod() == this.UMN_ATTRS_FROM_HEADERS) {
    return this._request.headers.hasOwnProperty(name) ? this._request.headers[name] : null;
  }
};

BasicAuthenticator.prototype.getAttributes = function(requestedAttributes) {
  // Default attribute names together with what's requested
  var attrNames = this.getAttributeNames().concat(requestedAttributes),
      attrs = {};

  attrNames.forEach(function(attrName) {
    attrs[attrName] = this.getAttributeValue(attrName);
  });
  return attrs;
};

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
