const { isEmpty, omit } = require('lodash/fp');
const { getLogger } = require('../logging');

const { authenticatedRequest } = require('../request');

const searchThreatActors = async (entity, options) =>
  new Promise((resolve, reject) => {
    const Logger = getLogger();

    let requestOptions = {
      url: `${options.urlV4}/v4/actor/${entity.value}`,
      headers: {
        Accept: 'application/json'
      }
    };

    authenticatedRequest(options, requestOptions, function (err, response, body) {
      if (err) {
        Logger.trace({ err: err, response: response }, 'Error running Threat Actor');
        return reject(err);
      }

      Logger.trace({ data: body }, 'Threat Actor Body');
      const threatActorResults = omit('error', body);
      if (isEmpty(threatActorResults)) return resolve();

      resolve(threatActorResults);
    });
  });

module.exports = searchThreatActors;
