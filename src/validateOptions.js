function validateOptions(userOptions, cb) {
  let errors = [];
  if (
    typeof userOptions.uri.value !== 'string' ||
    (typeof userOptions.uri.value === 'string' && userOptions.uri.value.length === 0)
  ) {
    errors.push({
      key: 'uri',
      message: 'You must provide a valid REST Url'
    });
  }

  if (
    typeof userOptions.publicKey.value !== 'string' ||
    (typeof userOptions.publicKey.value === 'string' && userOptions.publicKey.value.length === 0)
  ) {
    errors.push({
      key: 'publicKey',
      message: 'You must provide a valid Mandiant Threat Intelligence API public key'
    });
  }

  if (
    typeof userOptions.privateKey.value !== 'string' ||
    (typeof userOptions.privateKey.value === 'string' && userOptions.privateKey.value.length === 0)
  ) {
    errors.push({
      key: 'privateKey',
      message: 'You must provide a valid Mandiant Threat Intelligence API private key'
    });
  }

  if (userOptions.minimumMScore.value < 0 || userOptions.minimumMScore.value > 100) {
    errors.push({
      key: 'minimumMScore',
      message: 'The Minimum MScore must be between 0 and 100'
    });
  }

  if (userOptions.maxConcurrent.value < 1) {
    errors = errors.concat({
      key: 'maxConcurrent',
      message: 'Max Concurrent Requests must be 1 or higher'
    });
  }

  if (userOptions.minTime.value < 1) {
    errors = errors.concat({
      key: 'minTime',
      message: 'Minimum Time Between Lookups must be 1 or higher'
    });
  }

  cb(null, errors);
}

module.exports = validateOptions;
