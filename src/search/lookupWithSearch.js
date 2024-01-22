const { map, get, size } = require('lodash/fp');

const { getLimiter } = require('../request');
const doSearch = require('./doSearch');

const lookupWithSearch = async (
  filteredEntities,
  cveEntities,
  customEntities,
  options
) => {
  const entities = filteredEntities
    .concat(cveEntities)
    .concat(customEntities);

  const limitedDoSearch = getLimiter(options).wrap(doSearch);

  return await Promise.all(
    map(async (entity) => {
      try {
        const searchResults = await limitedDoSearch(entity, options);

        return associateEntitiesWithSearchResults(entity, searchResults);
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
    }, entities)
  );
};

const associateEntitiesWithSearchResults = (entity, searchResults) => ({
  entity,
  data: !size(searchResults)
    ? null
    : {
        summary: [
          `Search: ${size(searchResults)}${size(searchResults) === 10 ? '+' : ''}`
        ],
        details: { searchResults }
      }
});

module.exports = lookupWithSearch;
