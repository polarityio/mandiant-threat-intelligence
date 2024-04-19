const { map, get, flow, eq, flatMap, filter, uniq, isEmpty } = require('lodash/fp');

const getThreatActorIds = (searchLookupResults, threatActorsLookupResults) => {
  const threatActorsLookupThreatActorIds = map(
    get('data.details.threatActorResults.id'),
    threatActorsLookupResults
  );

  const searchLookupThreatActorIds = flatMap(
    flow(
      get('data.details.searchResults'),
      filter(flow(get('type'), eq('threat-actor'))),
      map('id')
    ),
    searchLookupResults
  );

  return uniq(threatActorsLookupThreatActorIds.concat(searchLookupThreatActorIds));
};

const associateNewDataWithLookupResults = (
  detailsKey,
  searchLookupResults,
  threatActorsLookupResults,
  reports
) => ({
  threatActorsLookupResults: map(
    (threatActorsLookupResult) =>
      modifyLookupResultDetails(threatActorsLookupResult, {
        threatActorResults: flow(
          get('data.details.threatActorResults'),
          (threatActorResults) => ({
            ...threatActorResults,
            [detailsKey]: get(threatActorResults.id, reports)
          })
        )(threatActorsLookupResult)
      }),
    threatActorsLookupResults
  ),
  searchLookupResults: map(
    (searchLookupResult) =>
      modifyLookupResultDetails(searchLookupResult, {
        searchResults: flow(
          get('data.details.searchResults'),
          map((searchResult) =>
            get('type', searchResult) !== 'threat-actor'
              ? searchResult
              : {
                  ...searchResult,
                  [detailsKey]: get(searchResult.id, reports)
                }
          ),
          (searchResults) => (isEmpty(searchResults) ? undefined : searchResults)
        )(searchLookupResult)
      }),
    searchLookupResults
  )
});

const modifyLookupResultDetails = (lookupResult, modifiedDetails) => ({
  ...lookupResult,
  data: !lookupResult.data
    ? null
    : {
        ...get('data', lookupResult),
        details: {
          ...get('data.details', lookupResult),
          ...modifiedDetails
        }
      }
});

module.exports = {
  getThreatActorIds,
  associateNewDataWithLookupResults
};
