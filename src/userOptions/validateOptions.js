const { validateStringOptions } = require('./utils');

const apiQueryVersionByRequiredFields = {
  v3: {
    urlV3: '* Required',
    publicKeyV3: '* Required',
    privateKeyV3: '* Required',
    apiQueryVersion: 'With V3 API selected here, V3 Public & Private Key must be set.'
  },
  v4: {
    urlV4: '* Required',
    publicKeyV4: '* Required',
    privateKeyV4: '* Required',
    apiQueryVersion: 'With V4 API selected here, V4 Public & Private Key must be set.'
  },
  v3v4: {
    urlV3: '* Required',
    publicKeyV3: '* Required',
    privateKeyV3: '* Required',
    urlV4: '* Required',
    publicKeyV4: '* Required',
    privateKeyV4: '* Required',
    apiQueryVersion: 'With V3 & V4 API selected here, V3 & V4 Public & Private Key must be set.'
  }
};
const validateOptions = async (options, callback) => {
  const stringOptionsErrorMessages = apiQueryVersionByRequiredFields[options.apiQueryVersion.value];

  const stringValidationErrors = validateStringOptions(stringOptionsErrorMessages, options);

  const minScoreError =
    userOptions.minimumMScore.value < 0 || userOptions.minimumMScore.value > 100
      ? {
          key: 'minimumMScore',
          message: 'The Minimum MScore must be between 0 and 100'
        }
      : [];

  const maxConcurrentError =
    userOptions.maxConcurrent.value < 1
      ? {
          key: 'maxConcurrent',
          message: 'Max Concurrent Requests must be 1 or higher'
        }
      : [];

  const minTimeError =
    userOptions.minTime.value < 1
      ? {
          key: 'minTime',
          message: 'Minimum Time Between Lookups must be 1 or higher'
        }
      : [];

  callback(null, stringValidationErrors.concat(minScoreError).concat(maxConcurrentError).concat(minTimeError));
};

module.exports = validateOptions;
