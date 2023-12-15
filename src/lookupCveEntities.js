const { lookupVulnerabilitiesWithCveEntities } = require('./vulnerabilities');

const lookupCveEntities = async (cveEntities, options) =>
  await lookupVulnerabilitiesWithCveEntities(cveEntities, options);

module.exports = lookupCveEntities;
