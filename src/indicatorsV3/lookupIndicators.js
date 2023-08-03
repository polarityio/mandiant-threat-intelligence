const { map, flow, chunk, keys, get, getOr } = require('lodash/fp');

const searchBulkIndicators = require('./searchBulkIndicators');
const getChunkQuery = require('./getChunkQuery');
const getSummaryTags = require('./getSummaryTags');
const { getLimiter } = require('../request');
const { getLogger } = require('../logging');

const MAX_ENTITIES_PER_LOOKUP = 100;

const lookupIndicators = async (filteredEntities, options) => {
  const limitedSearchBulkIndicators = getLimiter(options).wrap(searchBulkIndicators);

  return flow(
    chunk(MAX_ENTITIES_PER_LOOKUP),
    getIndicatorsOneChunkAtATime(options, limitedSearchBulkIndicators)
  )(filteredEntities);
};

const getIndicatorsOneChunkAtATime =
  (options, limitedSearchBulkIndicators) =>
  async ([lookupChunk, ...lookupChunks], ongoingLookupResults = []) => {
    const { searchedEntities, query } = lookupChunk
      ? getChunkQuery(lookupChunk)
      : { query: { requests: [] } };

    if (query.requests.length === 0) return ongoingLookupResults;

    let results, chunkLookupResults;
    try {
      results = await limitedSearchBulkIndicators(query, options);
    } catch (error) {
      if (Math.floor(parseInt(get('errors.0.status', error)) / 100) * 100 === 500) {
        chunkLookupResults = map(
          (entity) => ({
            entity,
            isVolatile: true,
            data: {
              summary: ['Search Returned Error'],
              details: { errorMessage: get('errors.0.detail', error) }
            }
          }),
          lookupChunk
        );
      } else {
        throw error;
      }
    }

    chunkLookupResults =
      chunkLookupResults ||
      flow(
        keys,
        map((entity) => {
          const entityLower = entity.toLowerCase();
          const entityObj = searchedEntities.get(entityLower);
          const indicatorV3 = results[entityLower];
          const mScore = getOr(0, 'indicator_verdict.mscore', indicatorV3);

          return {
            entity: entityObj,
            data:
              mScore >= options.minimumMScore
                ? {
                    summary: getSummaryTags(indicatorV3),
                    details: {
                      indicatorV3
                    }
                  }
                : null
          };
        })
      )(results);

    return await getIndicatorsOneChunkAtATime(options, limitedSearchBulkIndicators)(
      lookupChunks,
      ongoingLookupResults.concat(chunkLookupResults)
    );
  };

module.exports = lookupIndicators;
