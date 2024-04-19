const { getLogger } = require('../logging');
const { getLimiter } = require('../request');
const { parseErrorToReadableJson } = require('../dataTransformations');
const searchReports = require('./searchReports');
const { getThreatActorIds, associateNewDataWithLookupResults } = require('./utils');

const lookupAssociatedReports = async (
  searchLookupResults,
  threatActorsLookupResults,
  options
) => {
  const Logger = getLogger();
  const limitedSearchReports = getLimiter(options).wrap(searchReports);

  try {
    const threatActorIds = getThreatActorIds(
      searchLookupResults,
      threatActorsLookupResults
    );

    const reports = await limitedSearchReports(threatActorIds, options);

    Logger.trace({ reports, threatActorIds }, 'Threat Actor Associated Reports Results');

    return associateNewDataWithLookupResults(
      'reports',
      searchLookupResults,
      threatActorsLookupResults,
      reports
    );
  } catch (error) {
    const err = parseErrorToReadableJson(error);
    Logger.error({ err, error }, 'Threat Actor Associated Reports Error');

    return {
      searchLookupResults,
      threatActorsLookupResults
    };
  }
};

module.exports = lookupAssociatedReports;
