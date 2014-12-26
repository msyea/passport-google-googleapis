var passport = require('passport-strategy'),
  util = require('util'),
  google = require('googleapis'),
  oauth2 = google.oauth2('v2');

function GoogleAPIsStrategy(
  options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = undefined;
  }
  options = options || {};

  if (!verify) {
    throw new TypeError('GoogleAPIsStrategy requires a verify callback');
  }
  if (!options.clientID) {
    throw new TypeError('GoogleAPIsStrategy requires a clientID option');
  }
  if (!options.clientSecret) {
    throw new TypeError('GoogleAPIsStrategy requires a clientSecret option');
  }
  if (!options.redirectURL) {
    throw new TypeError('GoogleAPIsStrategy requires a redirectURL option');
  }

  passport.Strategy.call(this);
  this.name = 'googleapis';
  this._verify = verify;

  this.oauth2Client = new google.auth.OAuth2(options.clientID, options.clientSecret,
    options.redirectURL);

    this._scope = options.scope;
    this._passReqToCallback = options.passReqToCallback;
};

util.inherits(GoogleAPIsStrategy, passport.Strategy);

GoogleAPIsStrategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var self = this;

  if (req.query && req.query.error) {
    if (req.query.error == 'access_denied') {
      return this.fail({
        message: req.query.error_description
      });
    } else {
      return this.error(new Error(req.query.error_description, req
        .query.error, req.query.error_uri));
    }
  }

  if (req.query && req.query.code) {
    var code = req.query.code;

    self.oauth2Client.getToken(code, function(err, tokens) {
      if (err) {
        return self.error(self._createOAuthError(
          'Failed to obtain access token', err));
      }

      var accessToken = tokens.access_token,
        refreshToken = tokens.refresh_token || null;

      self.oauth2Client.setCredentials(tokens);

      oauth2.userinfo.get({
        auth: self.oauth2Client
      }, function(err, profile) {
        if (err) {
          return self.error(err);
        }

        function verified(err, user, info) {
          if (err) {
            return self.error(err);
          }
          if (!user) {
            return self.fail(info);
          }
          self.success(user, info);
        }

        try {
          var arity = self._verify.length;
          if (self._passReqToCallback) {
            if (arity == 6) {
              self._verify(req, accessToken, refreshToken, {}, profile,
                verified);
            } else { // arity == 5
              self._verify(req, accessToken, refreshToken, profile,
                verified);
            }
          } else {
            if (arity == 5) {
              self._verify(accessToken, refreshToken, {}, profile,
                verified);
            } else if (arity == 4) {
              self._verify(accessToken, refreshToken, profile, verified);
            } else { // arity == 3
              self._verify({
                accessToken: tokens.access_token,
                tokenType: tokens.token_type,
                idToken: tokens.id_token,
                refreshToken: tokens.refresh_token || null,
                expiryDate: tokens.expiry_date
              }, profile, verified);
            }
          }
        } catch (ex) {
          return self.error(ex);
        }
      });
    });
  } else {
    var params = this.authorizationParams(options);

    var scope = options.scope || this._scope;
    if (scope) {
      params.scope = scope;
    }

    var location = this.oauth2Client.generateAuthUrl(params);

    this.redirect(location);
  }
};

GoogleAPIsStrategy.prototype.authorizationParams = function(options) {
  return {};
};

GoogleAPIsStrategy.prototype.tokenParams = function(options) {
  return {};
};

GoogleAPIsStrategy.prototype.parseErrorResponse = function(body, status) {
  var json = JSON.parse(body);
  if (json.error) {
    return new Error(json.error_description, json.error, json.error_uri);
  }
  return null;
};

GoogleAPIsStrategy.prototype._createOAuthError = function(message, err) {
  var e;
  if (err.statusCode && err.data) {
    try {
      e = this.parseErrorResponse(err.data, err.statusCode);
    } catch (_) {}
  }
  if (!e) {
    e = new Error(message, err);
  }
  return e;
};

exports.Strategy = exports.GoogleAPIsStrategy = GoogleAPIsStrategy;
