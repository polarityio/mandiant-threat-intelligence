const { mergeLookupResults } = require('./dataTransformations');
const { getLogger } = require('./logging');
const { lookupWithSearch } = require('./search');
const { lookupThreatActors } = require('./threatActors');

const lookupEntities = async (
  filteredEntities,
  cveEntities,
  customEntities,
  indicatorLookupResults,
  cveLookupResults,
  options
) => {
  const [searchLookupResults, threatActorsLookupResults] = await Promise.all([
    // options.searchResultsType.value !== 'none'
    //   ? lookupWithSearch(filteredEntities, cveEntities, customEntities, options)
    //   : 
      [],
    lookupThreatActors(customEntities, options)
  ]);

  const allEntities = filteredEntities.concat(cveEntities).concat(customEntities);

  const searchAndOtherLookupResults = mergeLookupResults(
    allEntities,
    indicatorLookupResults.concat(cveLookupResults),
    searchLookupResults
  );

  const searchThreatActorsAndOtherLookupResults = mergeLookupResults(
    allEntities,
    searchAndOtherLookupResults,
    threatActorsLookupResults
  );

  return searchThreatActorsAndOtherLookupResults;
};

module.exports = lookupEntities;
