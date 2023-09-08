const { lookupCollectionsWithCveEntities } = require('./collections');
const { lookupVulnerabilitiesWithCveEntities } = require('./vulnerabilities');
const { mergeLookupResults } = require('./dataTransformations');

const lookupCveEntities = async (cveEntities, options) => {
  const [collectionLookupResults, vulnerabilitiesLookupResults] = await Promise.all([
    options.urlV3 ? await lookupCollectionsWithCveEntities(cveEntities, options) : [],
    options.urlV4 ? await lookupVulnerabilitiesWithCveEntities(cveEntities, options) : []
  ]);

  return mergeLookupResults(
    cveEntities,
    collectionLookupResults,
    vulnerabilitiesLookupResults
  );
};

module.exports = lookupCveEntities;
