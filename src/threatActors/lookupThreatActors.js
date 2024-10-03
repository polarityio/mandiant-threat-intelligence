const { map, get, isEmpty } = require('lodash/fp');

const { getLimiter } = require('../request');
const searchThreatActors = require('./searchThreatActors');

const lookupThreatActors = async (customEntities, options) => {
  const limitedSearchThreatActors = getLimiter(options).wrap(searchThreatActors);

  return await Promise.all(
    map(async (entity) => {
      try {
        const threatActorsResults = await limitedSearchThreatActors(entity, options);

        return associateEntitiesWithSearchResults(entity, threatActorsResults);
      } catch (error) {
        if (Math.floor(parseInt(get('errors.0.status', error)) / 100) * 100 === 500) {
          return {
            entity,
            isVolatile: true,
            data: {
              summary: ['Search Returned Error'],
              details: { errorMessage: get('errors.0.detail', error) }
            }
          };
        }
        throw error;
      }
    }, customEntities)
  );
};

const associateEntitiesWithSearchResults = (entity, threatActorResults) => ({
  entity,
  data: isEmpty(threatActorResults)
    ? null
    : {
        summary: ['Threat Actor Found'],
        details: { threatActorResults }
      }
});

module.exports = lookupThreatActors;
