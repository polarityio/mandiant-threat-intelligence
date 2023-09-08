const { map, get, size, toLower, flow } = require('lodash/fp');
const { getLogger } = require('../logging');

const { authenticatedRequest } = require('../request');

/**
 * Used specifically to search for CVEs which cannot use the bulk endpoint.  Returns a completely different
 * format than the bulk endpoint which needs custom handling.  We refer to this as the "legacy" endpoint in
 * this code base.
 * @param entityObj
 * @param options
 * @param cb
 * @private
 */
const searchIndicators = async (entityChunk, options) =>
  new Promise((resolve, reject) => {
    const Logger = getLogger();

    let requestOptions = {
      method: 'POST',
      url: `${options.urlV4}/v4/indicator`,
      body: {
        include_reports: true,
        include_campaigns: true,
        requests: [{ values: map(flow(get('value'), toLower), entityChunk) }]
      },
      headers: { 'Content-Type': 'application/json' }
    };

    authenticatedRequest(options, requestOptions, function (err, response, body) {
      if (err) {
        Logger.trace({ err: err, response: response }, 'Error running Indicators search');
        return reject(err);
      }

      Logger.trace({ data: body }, 'Indicators Search Body');
      const indicators = get('indicators', body);
      if (!size(indicators)) return resolve([]);

      resolve(indicators);
    });
  });

module.exports = searchIndicators;
