const { map, get, size, flow } = require('lodash/fp');
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
const searchVulnerabilities = async (entityChunk, options) =>
  new Promise((resolve, reject) => {
    const Logger = getLogger();

    let requestOptions = {
      method: 'POST',
      url: `${options.urlV4}/v4/vulnerability`,
      body: {
        requests: [{ values: map(get('value'), entityChunk) }],
        rating_types: map('value', options.vulnerabilityRatingSources),
        has_cve: true
      },
      headers: {
        'Content-Type': 'application/json'
      }
    };

    authenticatedRequest(options, requestOptions, function (err, response, body) {
      if (err) {
        Logger.trace(
          { err: err, response: response },
          'Error running Vulnerabilities search'
        );
        return reject(err);
      }

      Logger.trace({ data: body }, 'Vulnerabilities Search Body');
      const vulnerabilities = get('vulnerabilities', body);
      if (!size(vulnerabilities)) return resolve([]);

      resolve(vulnerabilities);
    });
  });

module.exports = searchVulnerabilities;
