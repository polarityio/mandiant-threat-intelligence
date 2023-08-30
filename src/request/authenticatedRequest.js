const requestWithDefaults = require('./requestWithDefaults');
const createToken = require('./createToken');
const handleRestErrors = require('./handleRestErrors');
const { getLogger } = require('../logging');

const MAX_AUTH_RETRIES = 2;

const NodeCache = require('node-cache');
const { encodeBase64 } = require('../dataTransformations');
const tokenCache = new NodeCache({
  stdTTL: 39600 // 11 hours
});

const authenticatedRequest = (options, requestOptions, cb, requestCounter = 0) => {
  const Logger = getLogger();
  if (requestCounter === MAX_AUTH_RETRIES) {
    // We reached the maximum number of auth retries
    return cb({
      detail: `Attempted to authenticate ${MAX_AUTH_RETRIES} times but failed authentication`
    });
  }

  requestOptions.headers = {
    ...requestOptions.headers,
    'X-App-Name': 'Polarity'
  };
  if (requestOptions.url.includes(options.urlV4)) {
    const requestOptionsWithAuth = {
      ...requestOptions,
      headers: {
        ...requestOptions.headers,
        Authorization: `Basic ${encodeBase64(
          options.publicKey + ':' + options.privateKey
        )}`
      }
    };
    Logger.trace({ requestOptions: requestOptionsWithAuth }, 'Request Options');
    requestWithDefaults(requestOptionsWithAuth, (err, resp, body) => {
      if (err) {
        if (err.code === 'ECONNRESET') {
          return cb(handleRestErrors({ ...resp, statusCode: 'ECONNRESET' }, body));
        } else {
          return cb(err, resp, body);
        }
      }

      if (resp.statusCode === 403) {
        // Unable to authenticate so we attempt to get a new token
        Logger.trace('Invalidating Token');
        tokenCache.del(options.publicKey + options.privateKey);
        authenticatedRequest(options, requestOptions, cb, ++requestCounter);
        return;
      }

      let restError = handleRestErrors(resp, body);
      if (restError) return cb(restError, resp, body);

      cb(null, resp, body);
    });
  } else {
    createToken(options, tokenCache, function (err, token) {
      if (err) {
        Logger.error({ err: err }, 'Error getting token');
        return cb({
          err: err,
          detail: 'Error creating authentication token'
        });
      }

      requestOptions.headers = {
        ...requestOptions.headers,
        Accept: 'application/vnd.oasis.stix+json; version=2.1',
        Authorization: `Bearer ${token}`
      };

      Logger.trace({ requestOptions }, 'Request');
      requestWithDefaults(requestOptions, (err, resp, body) => {
        if (err) {
          if (err.code === 'ECONNRESET') {
            return cb(handleRestErrors({ ...resp, statusCode: 'ECONNRESET' }, body));
          } else if (err.code === 'ECONNRESET') {
            return cb(handleRestErrors({ ...resp, statusCode: 'ECONNRESET' }, body));
          } else {
            return cb(err, resp, body);
          }
        }

        if (resp.statusCode === 403) {
          // Unable to authenticate so we attempt to get a new token
          Logger.trace('Invalidating Token');
          tokenCache.del(options.publicKey + options.privateKey);
          authenticatedRequest(options, requestOptions, cb, ++requestCounter);
          return;
        }

        let restError = handleRestErrors(resp, body);
        if (restError) {
          return cb(restError);
        }

        cb(null, resp, body);
      });
    });
  }
};

module.exports = authenticatedRequest;
