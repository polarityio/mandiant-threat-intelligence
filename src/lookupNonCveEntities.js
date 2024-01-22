const { lookupIndicatorsV4 } = require('./indicatorsV4');

const lookupNonCveEntities = async (entities, options) =>
  await lookupIndicatorsV4(entities, options);

module.exports = lookupNonCveEntities;
