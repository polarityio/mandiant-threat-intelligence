const { size } = require('lodash/fp');
const { getLogger } = require('../logging');
const { validateStringOptions } = require('./utils');

const apiQueryVersionByRequiredFields = {
  v3: {
    urlV3: '* Required',
    publicKeyV3: '* Required',
    privateKeyV3: '* Required'
  },
  v4: {
    urlV4: '* Required',
    publicKeyV4: '* Required',
    privateKeyV4: '* Required'
  },
  v3v4: {
    urlV3: '* Required',
    publicKeyV3: '* Required',
    privateKeyV3: '* Required',
    urlV4: '* Required',
    publicKeyV4: '* Required',
    privateKeyV4: '* Required'
  }
};

const apiQueryVersionError = {
  v3: 'With V3 API selected here, V3 Public & Private Key must be set.',
  v4: 'With V4 API selected here, V4 Public & Private Key must be set.',
  v3v4: 'With V3 & V4 API selected here, V3 & V4 Public & Private Key must be set.'
};

const validateOptions = (options, callback) => {
  const stringOptionsErrorMessages =
    apiQueryVersionByRequiredFields[options.apiQueryVersion.value.value];

  const stringValidationErrors = validateStringOptions(
    stringOptionsErrorMessages,
    options
  );

  if (size(stringValidationErrors))
    stringValidationErrors.push({
      key: 'apiQueryVersion',
      message: apiQueryVersionError[options.apiQueryVersion.value.value]
    });

  const minScoreError =
    options.minimumMScore.value < 0 || options.minimumMScore.value > 100
      ? {
          key: 'minimumMScore',
          message: 'The Minimum MScore must be between 0 and 100'
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
    .concat(minScoreError)
    .concat(maxConcurrentError)
    .concat(minTimeError);

  callback(null, errors);
};

module.exports = validateOptions;
