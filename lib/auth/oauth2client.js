/**
 * Copyright 2012 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

var querystring = require('querystring');
var AuthClient = require('./authclient.js');
var util = require('util');

function OAuth2Client(clientId, clientSecret, redirectUri, opt_opts) {
  OAuth2Client.super_.call(this);

  this.clientId_ = clientId;
  this.clientSecret_ = clientSecret;
  this.redirectUri_ = redirectUri;
  this.opts = opt_opts || {};
  this.credentials = null;
}

/**
 * Inherit from AuthClient.
 */
util.inherits(OAuth2Client, AuthClient);

/**
 * The base URL for auth endpoints.
 * @const
 * @private
 *
 */
OAuth2Client.GOOGLE_OAUTH2_AUTH_BASE_URL_ =
  'https://accounts.google.com/o/oauth2/auth';

/**
 * The base endpoint for token retrieval.
 * @const
 * @private
 * The ..
 */
OAuth2Client.GOOGLE_OAUTH2_TOKEN_URL_ =
  'https://accounts.google.com/o/oauth2/token';

/**
 * The base endpoint to revoke tokens.
 * @const
 * @private
 */
OAuth2Client.GOOGLE_OAUTH2_REVOKE_URL_ =
  'https://accounts.google.com/o/oauth2/revoke';

/**
 * Generates URL for consent page landing.
 * @param {object=} opt_opts Options.
 * @return {string} URL to consent page.
 */
OAuth2Client.prototype.generateAuthUrl = function(opt_opts) {

  var opts = opt_opts || {};
  opts.response_type = opts.response_type || 'code';
  opts.client_id = this.clientId_;
  opts.redirect_uri = this.redirectUri_;

  var rootUrl = this.opts.authBaseUrl ||
    OAuth2Client.GOOGLE_OAUTH2_AUTH_BASE_URL_;

  return rootUrl + '?' + querystring.stringify(opts);
};

/**
 * Gets the access token for given code.
 * @param {string} code The authorization code.
 * @param {function=} opt_callback Optional callback fn.
 */
OAuth2Client.prototype.getToken = function(code, opt_callback) {

  var uri = this.opts.tokenUrl || OAuth2Client.GOOGLE_OAUTH2_TOKEN_URL_;
  var values = {
    code: code,
    client_id: this.clientId_,
    client_secret: this.clientSecret_,
    redirect_uri: this.redirectUri_,
    grant_type: 'authorization_code'
  };

  this.transporter.request({
    method: 'POST',
    uri: uri,
    form: values,
    json: true
  }, opt_callback);
};

/**
 * @private
 * Refreshes the access token.
 * @param {string} refresh_token Existing refresh token.
 * @param {function=} opt_callback Optional callback.
 */
OAuth2Client.prototype.refreshToken_ =
  function(refresh_token, opt_callback) {

  var uri = this.opts.tokenUrl || OAuth2Client.GOOGLE_OAUTH2_TOKEN_URL_;
  var values = {
    refresh_token: refresh_token,
    client_id: this.clientId_,
    client_secret: this.clientSecret_,
    grant_type: 'refresh_token'
  };

  // request for new token
  this.transporter.request({
    method: 'POST',
    uri: uri,
    form: values,
    json: true
  }, opt_callback);
};

/**
 * Retrieves access token using refresh token
 * @param {function=} callback callback
 */
OAuth2Client.prototype.refreshAccessToken =
  function(callback) {
    var that = this;

    if (! this.credentials.refresh_token){
      throw new Error('No refresh token is set');
    }

    this.refreshToken_(this.credentials.refresh_token, function(err, result) {
      if (err) {
        callback(err, null);
      } else {
        var tokens = result;
        tokens.refresh_token = that.credentials.refresh_token;
        that.credentials = tokens;
        callback(null, that.credentials);
      }
    });
  };

/**
 * Revokes the access given to token.
 * @param {string} token The existing token to be revoked.
 * @param {function=} opt_callback Optional callback fn.
 */
OAuth2Client.prototype.revokeToken = function(token, opt_callback) {
  this.transporter.request({
    uri: OAuth2Client.GOOGLE_OAUTH2_REVOKE_URL_ +
      '?' + querystring.stringify({ token: token }),
    json: true
  }, opt_callback);
};

function extend() {
    var options, name, src, copy, copyIsArray, clone, target = arguments[0] || {},
        i = 1,
        length = arguments.length,
        deep = false,
        toString = Object.prototype.toString,
        hasOwn = Object.prototype.hasOwnProperty,
        push = Array.prototype.push,
        slice = Array.prototype.slice,
        trim = String.prototype.trim,
        indexOf = Array.prototype.indexOf,
        class2type = {
          "[object Boolean]": "boolean",
          "[object Number]": "number",
          "[object String]": "string",
          "[object Function]": "function",
          "[object Array]": "array",
          "[object Date]": "date",
          "[object RegExp]": "regexp",
          "[object Object]": "object"
        },
        jQuery = {
          isFunction: function (obj) {
            return jQuery.type(obj) === "function"
          },
          isArray: Array.isArray ||
          function (obj) {
            return jQuery.type(obj) === "array"
          },
          isWindow: function (obj) {
            return obj != null && obj == obj.window
          },
          isNumeric: function (obj) {
            return !isNaN(parseFloat(obj)) && isFinite(obj)
          },
          type: function (obj) {
            return obj == null ? String(obj) : class2type[toString.call(obj)] || "object"
          },
          isPlainObject: function (obj) {
            if (!obj || jQuery.type(obj) !== "object" || obj.nodeType) {
              return false
            }
            try {
              if (obj.constructor && !hasOwn.call(obj, "constructor") && !hasOwn.call(obj.constructor.prototype, "isPrototypeOf")) {
                return false
              }
            } catch (e) {
              return false
            }
            var key;
            for (key in obj) {}
            return key === undefined || hasOwn.call(obj, key)
          }
        };
      if (typeof target === "boolean") {
        deep = target;
        target = arguments[1] || {};
        i = 2;
      }
      if (typeof target !== "object" && !jQuery.isFunction(target)) {
        target = {}
      }
      if (length === i) {
        target = this;
        --i;
      }
      for (i; i < length; i++) {
        if ((options = arguments[i]) != null) {
          for (name in options) {
            src = target[name];
            copy = options[name];
            if (target === copy) {
              continue
            }
            if (deep && copy && (jQuery.isPlainObject(copy) || (copyIsArray = jQuery.isArray(copy)))) {
              if (copyIsArray) {
                copyIsArray = false;
                clone = src && jQuery.isArray(src) ? src : []
              } else {
                clone = src && jQuery.isPlainObject(src) ? src : {};
              }
              // WARNING: RECURSION
              target[name] = extend(deep, clone, copy);
            } else if (copy !== undefined) {
              target[name] = copy;
            }
          }
        }
      }
      return target;
    }


/**
 * Provides a request implementation with OAuth 2.0 flow.
 * If credentials have a refresh_token, in cases of HTTP
 * 401 and 403 responses, it automatically asks for a new
 * access token and replays the unsuccessful request.
 * @param {object} opts Request options.
 * @param {function=} opt_callback Optional callback.
 * @param {boolean=} opt_dontForceRefresh If set, don't ask for a new token
 *    with refresh_token.
 */
OAuth2Client.prototype.request =
  function(opts, opt_callback, opt_dontForceRefresh, waitMSec) {

  var that = this;
  var credentials = this.credentials;

  if (!credentials.access_token && !credentials.refresh_token) {
    throw new Error('No access or refresh token is set.');
  }

  credentials.token_type = credentials.token_type || 'Bearer';
  opts.headers = opts.headers || {};
  opts.headers['Authorization']
      = credentials.token_type + ' ' + credentials.access_token;

  var optsClones = extend(true, {}, opts);
  this.transporter.request(opts, function(err, body, res) {
    // TODO: Check if it's not userRateLimitExceeded
    var hasAuthError = !res || res.statusCode == 401 || res.statusCode == 403;
    var hasAnyError = !res || res.statusCode === 403 || res.statusCode === 500;
    // if there is an auth error, refresh the token
    // and make the request again
    if (!opt_dontForceRefresh && hasAuthError && credentials.refresh_token) {
      // refresh access token and re-request
      that.refreshToken_(credentials.refresh_token, function(err, result) {
        if (err || (result && !result.access_token)) {
          opt_callback && opt_callback(err, result, res);
        } else {
          var tokens = result;
          tokens.refresh_token = credentials.refresh_token;
          that.credentials = tokens;
          that.request(optsClones, opt_callback, true);
        }
      });
    } 
    else if(!hasAnyError || waitMSec > 5000){
      opt_callback && opt_callback(err, body, res);
    }
    else {
      console.log('Drive error. StatusCode:', res.statusCode);
      setTimeout(function() {
        that.request(optsClones, opt_callback, opt_dontForceRefresh, 100+(Math.random()*500));
      }, waitMSec);
    }
  });
};


/**
 * Export OAuth2Client.
 */
module.exports = OAuth2Client;
