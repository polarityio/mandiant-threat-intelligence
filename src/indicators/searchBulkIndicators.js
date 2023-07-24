const { getLogger } = require('../logging');
const { authenticatedRequest } = require('../request');

/**
 * Returns an object where the top level keys are the entity values that have results (lowercased)
 * {
 *   "8.8.8.8": {
 *     // data on entity
 *   },
 *   "sample.com": {
 *     // data on entity
 *   }
 * }
 * @param chunkQuery
 * @param options
 * @returns {Promise<unknown>}
 * @private
 */
const searchBulkIndicators = async (chunkQuery, options) =>
  new Promise((resolve, reject) => {
    const Logger = getLogger();
    let requestOptions = {
      uri: `${options.uri}/collections/indicators/objects`,
      method: 'POST',
      body: chunkQuery
    };

    Logger.trace({ request: requestOptions }, 'collection indicator search bulk request options');

    authenticatedRequest(options, requestOptions, function (err, response, body) {
      if (err) {
        Logger.trace({ err: err, response: response }, 'Error running collection indicator bulk search');
        return reject(err);
      }

      Logger.trace({ adding: true, data: body }, 'Collection Indicator Bulk Search Body');
      // body.data contains an object keyed on values. If there are no results body.data will be an empty
      // object.
      resolve(body.data);
    });
  });

module.exports = searchBulkIndicators;
