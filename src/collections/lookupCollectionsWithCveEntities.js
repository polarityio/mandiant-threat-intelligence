const { map, get } = require('lodash/fp');

const getResultObjectDataFields = require('./getResultObjectDataFields');
const searchCollections = require('./searchCollections');
const { getLimiter } = require('../request');

/**
 * CVE entities have to be looked up
 *
 * @param cveEntities
 * @param options
 * @returns {Promise<unknown>}
 */
const lookupCollectionsWithCveEntities = async (cveEntities, options) => {
  const limitedSearchCollections = getLimiter(options).wrap(searchCollections);

  return await Promise.all(
    map(async (entityObj) => {
      try {
        const result = await limitedSearchCollections(entityObj, options);

        return result.length === 0
          ? {
              entity: entityObj,
              data: null
            }
          : {
              entity: entityObj,
              data: getResultObjectDataFields([result.objects], entityObj)
            };
      } catch (error) {
        if (Math.floor(parseInt(get('errors.0.status', error)) / 100) * 100 === 500) {
          return {
            entity: entityObj,
            isVolatile: true,
            data: {
              summary: ['Search Returned Error'],
              details: { errorMessage: get('errors.0.detail', error) }
            }
          };
        }
        throw error;
      }
    }, cveEntities)
  );
};


module.exports = lookupCollectionsWithCveEntities;
