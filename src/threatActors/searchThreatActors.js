const { isEmpty, omit, map, flow, get } = require('lodash/fp');
const { getLogger } = require('../logging');

const { authenticatedRequest } = require('../request');

const searchThreatActors = async (entity, options) =>
  new Promise((resolve, reject) => {
    const Logger = getLogger();

    let requestOptions = {
      url: `${options.urlV4}/v4/actor/${encodeURIComponent(entity.value)}`,
      headers: {
        Accept: 'application/json'
      }
    };

    authenticatedRequest(options, requestOptions, function (err, response, body) {
      if (err && get('statusCode', response) !== 400) {
        Logger.trace({ err: err, response: response }, 'Error running Threat Actor');
        return reject(err);
      }

      const threatActorResults = omit('error', body);
      if (isEmpty(threatActorResults)) return resolve();

      resolve(threatActorResults);
    });
  });

module.exports = searchThreatActors;
