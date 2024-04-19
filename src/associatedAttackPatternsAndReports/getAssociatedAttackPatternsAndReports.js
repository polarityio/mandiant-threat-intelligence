const lookupAssociatedAttackPatterns = require('./lookupAssociatedAttackPatterns');
const lookupAssociatedReports = require('./lookupAssociatedReports');

const getAssociatedAttackPatternsAndReports = async (
  searchLookupResults,
  threatActorsLookupResults,
  options
) => {
  const {
    searchLookupResults: searchLookupResultsWithAttackPatterns,
    threatActorsLookupResults: threatActorsLookupResultsWithAttackPatterns
  } = await lookupAssociatedAttackPatterns(
    searchLookupResults,
    threatActorsLookupResults,
    options
  );

  const {
    searchLookupResults: searchLookupResultsWithAttackPatternsAndReports,
    threatActorsLookupResults: threatActorsLookupResultsWithAttackPatternsAndReports
  } = await lookupAssociatedReports(
    searchLookupResultsWithAttackPatterns,
    threatActorsLookupResultsWithAttackPatterns,
    options
  );

  return [
    searchLookupResultsWithAttackPatternsAndReports,
    threatActorsLookupResultsWithAttackPatternsAndReports
  ];
};

module.exports = getAssociatedAttackPatternsAndReports;
