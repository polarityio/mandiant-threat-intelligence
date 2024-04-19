const { getLogger } = require('../logging');
const { getLimiter } = require('../request');
const { parseErrorToReadableJson } = require('../dataTransformations');
const searchAttackPatterns = require('./searchAttackPatterns');
const { getThreatActorIds, associateNewDataWithLookupResults } = require('./utils');

const lookupAssociatedAttackPatterns = async (
  searchLookupResults,
  threatActorsLookupResults,
  options
) => {
  const Logger = getLogger();
  const limitedSearchAttackPatterns = getLimiter(options).wrap(searchAttackPatterns);

  try {
    const threatActorIds = getThreatActorIds(
      searchLookupResults,
      threatActorsLookupResults
    );

    const attackPatternsResults = await limitedSearchAttackPatterns(
      threatActorIds,
      options
    );

    Logger.trace(
      { attackPatternsResults, threatActorIds },
      'Threat Actor Associated Attack Patterns Results'
    );

    return associateNewDataWithLookupResults(
      'attackPatterns',
      searchLookupResults,
      threatActorsLookupResults,
      attackPatternsResults
    );
  } catch (error) {
    const err = parseErrorToReadableJson(error);
    Logger.error({ err, error }, 'Threat Actor Associated Attack Patterns Error');

    return {
      searchLookupResults,
      threatActorsLookupResults
    };
  }
};

module.exports = lookupAssociatedAttackPatterns;
