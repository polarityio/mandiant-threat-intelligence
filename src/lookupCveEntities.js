const { lookupCollectionsWithCveEntities } = require('./collections');
const { lookupVulnerabilitiesWithCveEntities } = require('./vulnerabilities');
const { mergeLookupResults } = require('./dataTransformations');

const lookupCveEntities = async (cveEntities, options) => {
  const [collectionLookupResults, vulnerabilitiesLookupResults] = await Promise.all([
    options.apiQueryVersion.value.includes('v3')
      ? await lookupCollectionsWithCveEntities(cveEntities, options)
      : [],
    options.apiQueryVersion.value.includes('v4')
      ? await lookupVulnerabilitiesWithCveEntities(cveEntities, options)
      : []
  ]);

  return mergeLookupResults(cveEntities, [
    collectionLookupResults,
    vulnerabilitiesLookupResults
  ]);
};

module.exports = lookupCveEntities;
