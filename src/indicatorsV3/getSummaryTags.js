const { get, capitalize } = require('lodash/fp');

function getSummaryTags(indicator) {
  let tags = [];
  if (indicator.indicator_verdict && indicator.indicator_verdict.mscore) {
    let mscore = indicator.indicator_verdict.mscore;
    // Adds the conclusion which is typically one of "malicious", "indeterminate", or "benign"
    if (indicator.analysis_conclusion) {
      mscore += ` (${indicator.analysis_conclusion})`;
    }
    tags.push(`MScore: ${mscore}`);
  }

  let threatActor = get('attributed_associations.threat_actors.0.name', indicator);
  if (threatActor) {
    tags.push(`Actor: ${threatActor}`);
  }

  let malware = get('attributed_associations.malware_families.0.name.value', indicator);
  if (malware) {
    tags.push(`Malware: ${malware}`);
  }

  if (indicator.external_references && indicator.external_references.length) {
    tags.push(`Reports: ${indicator.external_references.length}`);
  }

  if (indicator.analysis_conclusion) {
    tags.push(`Analysis: ${capitalize(indicator.analysis_conclusion)}`);
  }

  return tags;
}

module.exports = getSummaryTags;
