const { lookupIndicatorsV3 } = require('./indicatorsV3');
const { lookupIndicatorsV4 } = require('./indicatorsV4');
const { mergeLookupResults } = require('./dataTransformations');

const lookupNonCveEntities = async (entities, options) => {
  const [v3Indicators, v4Indicators] = await Promise.all([
    await lookupIndicatorsV3(entities, options),
    await lookupIndicatorsV4(entities, options)
  ]);

  return mergeLookupResults(entities, v3Indicators, v4Indicators);
};

module.exports = lookupNonCveEntities;
