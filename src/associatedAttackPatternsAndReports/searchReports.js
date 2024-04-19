const { mergeAll, isEmpty, omit, map, flow, get, values } = require('lodash/fp');
const { getLogger } = require('../logging');

const { authenticatedRequest } = require('../request');

const searchReports = async (threatActorIds, options) =>
  mergeAll(
    await Promise.all(
      map(
        async (threatActorId) =>
          new Promise((resolve, reject) => {
            const Logger = getLogger();

            let requestOptions = {
              url: `${options.urlV4}/v4/actor/${threatActorId}/reports`,
              headers: {
                Accept: 'application/json'
              }
            };

            authenticatedRequest(options, requestOptions, function (err, response, body) {
              if (err && get('statusCode', response) !== 404) {
                Logger.trace(
                  { err: err, response: response },
                  'Error running Threat Actor'
                );
                return reject(err);
              }

              const reportsResults = omit('error', body);
              if (isEmpty(reportsResults)) return resolve();

              resolve({
                [threatActorId]: get('reports', reportsResults)
              });
            });
          }),
        threatActorIds
      )
    )
  );

module.exports = searchReports;
