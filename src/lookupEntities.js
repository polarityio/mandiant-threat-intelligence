const { mergeLookupResults } = require('./dataTransformations');
const { getLogger } = require('./logging');
const { lookupWithSearch } = require('./search');
const { lookupThreatActors } = require('./threatActors');
const {
  getAssociatedAttackPatternsAndReports
} = require('./associatedAttackPatternsAndReports');

const lookupEntities = async (
  filteredEntities,
  cveEntities,
  customEntities,
  indicatorLookupResults,
  cveLookupResults,
  options
) => {
  let [threatActorsLookupResults, searchLookupResults] = await Promise.all([
    options.enableThreatActorSearch ? lookupThreatActors(customEntities, options) : [],
    options.searchResultsType.value !== 'none'
      ? lookupWithSearch(filteredEntities, cveEntities, customEntities, options)
      : []
  ]);

  [searchLookupResults, threatActorsLookupResults] =
    options.getThreatActorAssociatedAttackPatternsAndReports
      ? await getAssociatedAttackPatternsAndReports(
          searchLookupResults,
          threatActorsLookupResults,
          options
        )
      : [searchLookupResults, threatActorsLookupResults];

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
