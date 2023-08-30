const { get, size, map } = require('lodash/fp');
const { getLogger } = require('../logging');

const { authenticatedRequest } = require('../request');
const { MAX_RESULTS } = require('../collections/indicatorTypes');

/**
 * Used specifically to search for CVEs which cannot use the bulk endpoint.  Returns a completely different
 * format than the bulk endpoint which needs custom handling.  We refer to this as the "legacy" endpoint in
 * this code base.
 * @param entityObj
 * @param options
 * @param cb
 * @private
 */
const doSearch = async (entity, options) =>
  new Promise((resolve, reject) => {
    const Logger = getLogger();

    let requestOptions = {
      method: 'POST',
      url: `${options.urlV4}/v4/search`,
      body: {
        search: entity.value,
        limit: MAX_RESULTS
      },
      headers: {
        'Content-Type': 'application/json'
      }
    };

    authenticatedRequest(options, requestOptions, function (err, response, body) {
      if (err) {
        Logger.trace({ err: err, response: response }, 'Error running General search');
        return reject(err);
      }

      Logger.trace({ data: body }, 'General Search Body');
      const searchResults = get('objects', body);
      if (!size(searchResults)) return resolve([]);

      resolve(
        map(
          (searchResult) => ({
            ...searchResult,
            audience: map(JSON.stringify, searchResult.audience)
          }),
          searchResults
        )
      );
    });
  });

module.exports = doSearch;
