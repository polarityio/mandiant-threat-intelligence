const { toLower } = require('lodash/fp');
const entityTypeToIndicatorType = require('./entityTypeToIndicatorType');

/**
 * Takes a "chunk" of entity objects and converts them into an array of request objects which are used to
 * query the FireEye API.
 * @param lookupChunk
 * @returns {[]}
 */
function getChunkQuery(lookupChunk) {
  const queries = [];
  const searchedEntities = new Map();
  for (let i = 0; i < lookupChunk.length; i++) {
    const entityObj = lookupChunk[i];
    searchedEntities.set(entityObj.value.toLowerCase(), entityObj);
    const object_type = entityTypeToIndicatorType(entityObj);
    if (object_type !== null) {
      queries.push({
        object_type,
        value: [toLower(entityObj.value)],
        extended: true
      });
    }
  }
  return {
    searchedEntities,
    query: {
      requests: queries
    }
  };
}

module.exports = getChunkQuery;
