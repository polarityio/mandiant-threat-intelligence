const { map, get, flow, chunk, size, flatten, find } = require('lodash/fp');

const searchIndicators = require('./searchIndicators');
const { getLimiter } = require('../request');

const lookupIndicators = async (nonCveEntities, options) => {
  const limitedSearchIndicators = getLimiter(options).wrap(searchIndicators);

  return flatten(await Promise.all(
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
      }),
    )(nonCveEntities)
  ));
};

const associateEntitiesWithIndicators = (entities, indicators, options) =>
  map(
    (entity) =>
      flow(
        find(
          (indicator) =>
            entity.value === indicator.value && indicator.mscore >= options.minimumMScore
        ),
        (indicatorV4) => ({
          entity,
          data: !size(indicatorV4)
            ? null
            : {
              summary: [
                options.apiQueryVersion.value.includes('v3')
                  ? 'V4 Ind Found'
                  : 'Indicator Found'

              ],
              details: { indicatorV4 }
            }
        })
      )(indicators),
    entities
  );

module.exports = lookupIndicators;
