/**
 * Converts Polarity entity types to their respective Mandiant Threat Intel types
 * @param entityObj
 * @returns {string|null}
 */
function entityTypeToIndicatorType(entityObj) {
  if (entityObj.isIP) {
    return 'ip-address';
  }
  if (entityObj.isHash) {
    return 'hash';
  }
  if (entityObj.isEmail) {
    return 'email';
  }
  if (entityObj.isDomain) {
    return 'fqdn';
  }
  return null;
}

module.exports = entityTypeToIndicatorType;