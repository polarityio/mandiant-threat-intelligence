const request = require('postman-request');
const fs = require('fs');

const {
  request: { ca, cert, key, passphrase, proxy }
} = require('../../config/config.js');

const _configFieldIsValid = (field) => typeof field === 'string' && field.length > 0;

const defaults = {
  ...(_configFieldIsValid(ca) && { ca: fs.readFileSync(ca) }),
  ...(_configFieldIsValid(cert) && { cert: fs.readFileSync(cert) }),
  ...(_configFieldIsValid(key) && { key: fs.readFileSync(key) }),
  ...(_configFieldIsValid(passphrase) && { passphrase }),
  ...(_configFieldIsValid(proxy) && { proxy }),
  json: true
};

const requestWithDefaults = request.defaults(defaults);

module.exports = requestWithDefaults;
