const { lookupCollectionsWithCveEntities } = require('./collections');
const { lookupVulnerabilitiesWithCveEntities } = require('./vulnerabilities');
const { mergeLookupResults } = require('./dataTransformations');

const lookupCveEntities = async (cveEntities, options) => {
  const [collectionLookupResults, vulnerabilitiesLookupResults] = await Promise.all([
    await lookupCollectionsWithCveEntities(cveEntities, options),
    await lookupVulnerabilitiesWithCveEntities(cveEntities, options)
  ]);

  return mergeLookupResults(
    cveEntities,
    collectionLookupResults,
    vulnerabilitiesLookupResults
  );
};

module.exports = lookupCveEntities;
