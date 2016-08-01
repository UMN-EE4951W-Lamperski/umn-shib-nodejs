'use strict';

var querystring = require("querystring");

/**
 * Represents an authenticator object
 * @constructor
 * @param {object} request HTTP request - object
 * @param {object} response HTTP response - object
 * @param {object} loginOptions - Object literal structure of key:value pairs for login options, optional
 * @param {object} logoutOptions - Object literal structure of key:value pairs for logout options, optional
 */
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
BasicAuthenticator.prototype.UMN_IDP_LOGOUT_URL = 'https://login.umn.edu/idp/LogoutUMN';
BasicAuthenticator.prototype.UMN_TEST_IDP_LOGOUT_URL = 'https://login-test.umn.edu/idp/LogoutUMN';
BasicAuthenticator.prototype.UMN_SPOOF_IDP_LOGOUT_URL = 'https://idp-spoof-test.shib.umn.edu/idp/LogoutUMN';
BasicAuthenticator.prototype.UMN_MKEY_AUTHN_CONTEXT = 'https://www.umn.edu/shibboleth/classes/authncontext/mkey';
BasicAuthenticator.prototype.UMN_DUO_AUTHN_CONTEXT = 'https://www.umn.edu/shibboleth/classes/authncontext/duo';
BasicAuthenticator.prototype.UMN_ATTRS_FROM_ENV = 'from_environment';
BasicAuthenticator.prototype.UMN_ATTRS_FROM_HEADERS = 'from_headers';

// Extended constants
BasicAuthenticator.prototype.UMN_SESSION_MAX_AGE = 10800;

BasicAuthenticator.prototype.defaultLoginOptions = {};
BasicAuthenticator.prototype.defaultLogoutOptions = {
  'logoutFromIdP': true,
  'IdPLogoutURL': this.UMN_IDP_LOGOUT_URL
};

/**
 * Constructs and returns a login URL
 * @param {options} options - Object literal structure of key:value pairs merged with class default login options
 * @returns {String}
 */
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
  if (options.hasOwnProperty('duo') && options.duo) {
    params.authnContextClassRef = this.UMN_DUO_AUTHN_CONTEXT;
  }

  // Build params from object to query string
  loginURL += querystring.stringify(params);

  return loginURL;
};

/**
 * Construct and returns a logout URL
 * @function
 * @param {options} options - Object literal structure of key:value pairs merged with class default logout options
 * @returns {String}
 */
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
      params["return"] += "?return=" + encodeURIComponent(options["return"]);
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

/**
 * Redirects to a login URL constructed by buildLoginURL()
 * @function
 * @param {options} options - Object literal structure of key:value pairs merged with class default logout options
 * @returns {undefined}
 */
BasicAuthenticator.prototype.redirectToLogin = function(options) {
  this._response.writeHead(302, {"Location": this.buildLoginURL(options)});
  this._response.end();
};

/**
 * Return an object of requested attributes, or redirect to login if no session is active
 * @function
 * @param {object} options - Login options, passed to buildLoginURL()
 * @param {Array} requestedAttributes - Attributes to return in object
 * @param {Number} maxAge - Number of seconds to consider session valid, overriding SP & IdP defaults
 * @returns {object} Object literal structure of requested attributes, or redirects to login
 */
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

/**
 * Redirect to the logout handler
 * @function
 * @param {object} options - Logout options, passed to buildLogoutURL()
 */
BasicAuthenticator.prototype.redirectToLogout = function(options) {
  this._response.writeHead(302, {"Location": this.buildLogoutURL(options)});
  this._response.end();
};

/**
 * Normalize an attribute name for use with either HTTP headers or environment variables
 * as the attribute source
 * @function
 * @param {string} name - Attribute name to normalize
 * @returns {String}
 */
BasicAuthenticator.prototype.normalizeAttributeName = function(name) {
  // Node http returns HTTP headers as lowercase, hyphenated
  if (this.getAttributeAccessMethod() == this.UMN_ATTRS_FROM_HEADERS) {
    name = name.replace(/_/g, '-').toLowerCase().replace(/^http-/, '');
  }
  return name;
};

/**
 * Returns true if a Shibboleth session is active
 * @function
 * @returns {boolean}
 */
BasicAuthenticator.prototype.hasSession = function() {
  // Any of the IdP values will indicate a session is present
  var idps = [this.UMN_IDP_ENTITY_ID, this.UMN_TEST_IDP_ENTITY_ID, this.UMN_SPOOF_IDP_ENTITY_ID];
  return (idps.indexOf(this.getIdpEntityId()) >= 0);
};

/**
 * Returns true if the Shibboleth session does not exist, or has expired based on maxAge
 * @function
 * @param {Number} maxAge - Maximum seconds since login to consider a session active
 * @returns {boolean}
 */
BasicAuthenticator.prototype.hasSessionTimedOut = function(maxAge) {
  var authInstant = this.loggedInSince();
  maxAge = maxAge || this.UMN_SESSION_MAX_AGE;

  if (!this.hasSession()) {
    return true;
  }
  if (authInstant) {
    // Timestamps in MS, truncated down to seconds
    return Math.floor(authInstant.getTime()/1000) + maxAge <= (Math.floor((new Date()).getTime()/1000));
  }
  else {
    return false;
  }
};

/**
 * Returns true if the user logged in with a 2factor method
 * @function
 * @returns {boolean}
 */
BasicAuthenticator.prototype.loggedInWithMKey = function() {
  if (this.hasSession()) {
    return this.getAttributeValue('Shib-Authentication-Method') == this.UMN_MKEY_AUTHN_CONTEXT;
  }
  return false;
};

/**
 * Returns true if the user logged in with Duo 2factor method
 * @function
 * @returns {boolean}
 */
BasicAuthenticator.prototype.loggedInWithDuo = function() {
  if (this.hasSession()) {
    return this.getAttributeValue('Shib-Authentication-Method') == this.UMN_DUO_AUTHN_CONTEXT;
  }
  return false;
};

/**
 * Return a Date object representing the time the user logged in
 * @returns {Date}
 */
BasicAuthenticator.prototype.loggedInSince = function() {
  var authInstant = this.getAttributeValue('Shib-Authentication-Instant');
  if (authInstant) {
    return new Date(Date.parse(authInstant));
  }
};

/**
 * Return the Identity Provider's entity ID
 * @function
 * @returns {string}
 */
BasicAuthenticator.prototype.getIdpEntityId = function() {
  return this.getAttributeValue('Shib-Identity-Provider');
};

/**
 * Returns an array of the default attributes supplied by the class
 * @function
 * @returns {Array}
 */
BasicAuthenticator.prototype.getDefaultAttributeNames = function() {
  return this._attributes;
};

/**
 * Returns an array of the parameter array joined with the class default attribute names
 * @function
 * @returns {Array}
 */
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

/**
 * Returns an Array of values from a multi-value attribute string, split on the custom delimiter or semicolon (;)
 * @function
 * @param {string} name - Name of the attribute to return
 * @param {string} delimiter - Multi-value delimiter, default is semicolon (;)
 * @returns {Array}
 */
BasicAuthenticator.prototype.getAttributeValues = function(name, delimiter) {
  var value = this.getAttributeValue(name);
  // Default delimiter is semicolon
  delimiter = delimiter || ';';

  if (value !== null) {
    return value.split(delimiter);
  }
  return null;
};

/**
 * Return the scalar value of the requested attribute, based on the HTTP header or environment attribute source
 * Returns null if the attribute does not exist
 * @function
 * @param {string} name - Name of the attribute to return
 */
BasicAuthenticator.prototype.getAttributeValue = function(name) {
  name = this.normalizeAttributeName(name);
  if (this.getAttributeAccessMethod() == this.UMN_ATTRS_FROM_ENV) {
    return process.env.hasOwnProperty(name) ? process.env[name] : null;
  }
  if (this.getAttributeAccessMethod() == this.UMN_ATTRS_FROM_HEADERS) {
    return this._request.headers.hasOwnProperty(name) ? this._request.headers[name] : null;
  }
};

/**
 * Return an Array of attribute values (like getAttributeValue() but returns many at once)
 * Note: Multi-value, delimited attributes will not be split.
 * @function
 * @param {Array} requestedAttributes - Array of attribute names to retrieve
 * @returns {object} Object literal structure of key:value pairs
 */
BasicAuthenticator.prototype.getAttributes = function(requestedAttributes) {
  // Default attribute names together with what's requested
  var attrNames = this.getAttributeNames().concat(requestedAttributes),
      attrs = {};

  var self = this;
  attrNames.forEach(function(attrName) {
    attrs[attrName] = self.getAttributeValue(attrName);
  });
  return attrs;
};

/**
 * Returns the configured attribute access method
 * @function
 * @returns {string} UMN_ATTRS_FROM_ENV | UMN_ATTRS_FROM_HEADERS
 */
BasicAuthenticator.prototype.getAttributeAccessMethod = function() {
  return this._attributeSource;
};

/**
 * Set the attribute access method.
 * @function
 * @param {string} method - Attribute access method. Valid values are UMN_ATTRS_FROM_ENV | UMN_ATTRS_FROM_HEADERS
 */
BasicAuthenticator.prototype.setAttributeAccessMethod = function(method) {
  method = method.toLowerCase();
  if ([this.UMN_ATTRS_FROM_ENV, this.UMN_ATTRS_FROM_HEADERS].indexOf(method) >= 0) {
    this._attributeSource = method
  }
  else {
    throw new RangeError("Invalid attribute access method");
  }
};

/**
 * Set the authenticator handler URL (default /Shibboleth.sso)
 * @function
 * @param {string} newHandlerURL - The new handler URL, including leading /
 */
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
