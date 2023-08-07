const { getLogger } = require('./logging');

/**
 * Removes any entities that should be filtered out based on blocklists and also adds a
 * lookup miss for those entities to improve caching.
 *
 * @param entities {Array} array of entity objects to be looked up
 * @param options
 * @returns {{filteredEntities: [], cveEntities: [], lookupResults: []}}
 * filteredEntities: non-cve entities for lookup (has blocklisted entities removed)
 * lookupResults: lookup result objects for misses (i.e., blocked entities)
 * cveEntities: cve entities for lookup (we need these separate as they have to be looked up via a different endpoint)
 */
function getFilteredEntities(entities, options) {
  const Logger = getLogger();
  let lookupResults = [];
  let filteredEntities = [];
  let cveEntities = [];
  let customEntities = [];

  const domainBlocklistRegex = _setupRegexBlocklists(options);

  const blockList = options.blocklist.toLowerCase();
  for (let i = 0; i < entities.length; i++) {
    const entityObj = entities[i];
    if (blockList.includes(entityObj.value.toLowerCase())) {
      Logger.debug({ entity: entityObj.value }, 'Ignored BlockListed Entity Lookup');
      lookupResults.push({
        entity: entityObj,
        data: null
      });
    } else if (
      entityObj.isDomain &&
      domainBlocklistRegex &&
      domainBlocklistRegex.test(entityObj.value)
    ) {
      Logger.debug({ domain: entityObj.value }, 'Ignored BlockListed Domain Lookup');
      lookupResults.push({
        entity: entityObj,
        data: null
      });
    } else if (entityObj.type.includes('custom')) {
      customEntities.push(entityObj);
    } else if (entityObj.type === 'cve') {
      cveEntities.push(entityObj);
    } else {
      filteredEntities.push(entityObj);
    }
  }

  return { lookupResults, filteredEntities, cveEntities, customEntities };
}

const _setupRegexBlocklists = (options) =>
  options.domainBlocklistRegex.length === 0
    ? null
    : new RegExp(options.domainBlocklistRegex, 'i');

module.exports = getFilteredEntities;
