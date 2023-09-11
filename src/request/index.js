const authenticatedRequest = require('./authenticatedRequest');
const { getLimiter } = require('./limiting');

module.exports = {
  authenticatedRequest,
  getLimiter
};
