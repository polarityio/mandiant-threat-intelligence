const { map, get, flow, chunk, size, flatten, find } = require('lodash/fp');

const searchIndicators = require('./searchIndicators');
const { getLimiter } = require('../request');

const lookupIndicators = async (nonCveEntities, options) => {
  const limitedSearchIndicators = getLimiter(options).wrap(searchIndicators);

  return flatten(
    await Promise.all(
      flow(
        chunk(10),
        map(async (entityChunk) => {
          try {
            const indicators = await limitedSearchIndicators(entityChunk, options);

            return associateEntitiesWithIndicators(nonCveEntities, indicators, options);
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
        })
      )(nonCveEntities)
    )
  );
};

const associateEntitiesWithIndicators = (entities, indicators, options) =>
  map((entity) => {
    const indicatorV4 = find((indicator) => {
      const associatedHashValues = map(get('value'), get('associated_hashes', indicator));
      const possibleEntityValueLocations = [indicator.value].concat(associatedHashValues);

      const valueIsFoundInIndicator = possibleEntityValueLocations.includes(entity.value);

      const minScoreIsMet = indicator.mscore >= options.minimumMScore;
      return valueIsFoundInIndicator && minScoreIsMet;
    }, indicators);

    const entityWithIndicator = {
      entity,
      data: !size(indicatorV4)
        ? null
        : {
            summary: ['Indicator Found'],
            details: { indicatorV4 }
          }
    };

    return entityWithIndicator;
  }, entities);

module.exports = lookupIndicators;
