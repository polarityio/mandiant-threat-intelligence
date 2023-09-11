const requestWithDefaults = require('./requestWithDefaults');
const handleRestErrors = require('./handleRestErrors');
const { getLogger } = require('../logging');

function createToken(options, tokenCache, cb) {
  const Logger = getLogger();
  let token = tokenCache.get(options.publicKey + options.privateKey);
  if (token) {
    Logger.trace({ token: token }, 'Returning token from Cache');
    cb(null, token);
  } else {
    let requestOptions = {
      url: options.urlV3 + '/token',
      method: 'POST',
      form: {
        grant_type: 'client_credentials'
      },
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      auth: {
        username: options.publicKey,
        password: options.privateKey
      },
      json: true
    };

    Logger.trace({ request: requestOptions }, 'Generating new token');

    requestWithDefaults(requestOptions, function (err, response, body) {
      if (err) {
        return cb(err);
      }

      let restError = handleRestErrors(response, body);

      if (restError) {
        Logger.trace({ restError: restError }, 'REST Error generating token');
        cb(restError);
        return;
      }
      const token = body.access_token;
      Logger.trace({ token: token }, 'Set Token for Auth');
      tokenCache.set(options.publicKey + options.privateKey, token);

      cb(null, token);
    });
  }
}

module.exports = createToken;
