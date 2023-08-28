const { mergeLookupResults } = require('./dataTransformations');
const { lookupWithSearch } = require('./search');

const lookupEntities = async (
  filteredEntities,
  cveEntities,
  customEntities,
  indicatorLookupResults,
  cveLookupResults,
  options
) => {
  const searchLookupResults = await lookupWithSearch(
    filteredEntities,
    cveEntities,
    customEntities,
    options
  );

  const searchAndOtherLookupResults = mergeLookupResults(
    filteredEntities.concat(cveEntities).concat(customEntities),
    indicatorLookupResults.concat(cveLookupResults),
    searchLookupResults
  );

  return searchAndOtherLookupResults;
};

module.exports = lookupEntities;
