const { get, size, flow, replace, toLower, includes } = require('lodash/fp');
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
const doSearch = async (entity, options) =>
  new Promise((resolve, reject) => {
    const Logger = getLogger();

    let requestOptions = {
      method: 'POST',
      url: `${options.urlV4}/v4/search`,
      body: {
        search: entity.value,
        type: options.searchResultsType.value,
        limit: 10
      }
    };

    authenticatedRequest(options, requestOptions, function (err, response, body) {
      if (err) {
        Logger.trace({ err: err, response: response }, 'Error running General search');
        return reject(err);
      }

      Logger.trace({ data: body }, 'General Search Body');
      const searchResults = get('objects', body);
      const searchResultsContainEntityValue = flow(
        JSON.stringify,
        replace(/[^\w]/g, ''),
        toLower,
        includes(flow(replace(/[^\w]/g, ''), toLower)(entity.value))
      )(searchResults);

      if (!size(searchResults) || !searchResultsContainEntityValue) return resolve([]);

      resolve(searchResults);
    });
  });

module.exports = doSearch;
