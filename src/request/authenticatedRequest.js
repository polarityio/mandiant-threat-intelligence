const requestWithDefaults = require('./requestWithDefaults');
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

  const requestOptionsWithAuth = {
    ...requestOptions,
    headers: {
      ...requestOptions.headers,
      "Content-Type": 'application/json',
      Accept: 'application/json',
      'X-App-Name': 'Polarity',
      Authorization: `Basic ${encodeBase64(options.publicKey + ':' + options.privateKey)}`
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
};

module.exports = authenticatedRequest;
