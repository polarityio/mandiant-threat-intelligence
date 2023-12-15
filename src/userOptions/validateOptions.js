const { compact, map, get } = require('lodash/fp');
const { validateStringOptions, validateUrlOption } = require('./utils');

const validateOptions = (options, callback) => {
  const stringOptionsErrorMessages = {
    urlV4: '* Required',
    publicKey: '* Required',
    privateKey: '* Required'
  };

  const stringValidationErrors = validateStringOptions(
    stringOptionsErrorMessages,
    options
  );

  let urlError = options.urlV4.value ? validateUrlOption(options, 'urlV4') : []

  const minScoreError =
    options.minimumMScore.value < 0 || options.minimumMScore.value > 100
      ? {
          key: 'minimumMScore',
          message: 'The Minimum ThreatScore must be between 0 and 100'
        }
      : [];

  const maxConcurrentError =
    options.maxConcurrent.value < 1
      ? {
          key: 'maxConcurrent',
          message: 'Max Concurrent Requests must be 1 or higher'
        }
      : [];

  const minTimeError =
    options.minTime.value < 1
      ? {
          key: 'minTime',
          message: 'Minimum Time Between Lookups must be 1 or higher'
        }
      : [];

  const errors = stringValidationErrors
    .concat(urlError)
    .concat(minScoreError)
    .concat(maxConcurrentError)
    .concat(minTimeError);

  callback(null, errors);
};

module.exports = validateOptions;
