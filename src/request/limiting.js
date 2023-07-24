const Bottleneck = require('bottleneck');

let limiter;

function setupLimiter(options) {
  limiter = new Bottleneck({
    maxConcurrent: Number.parseInt(options.maxConcurrent, 10), // no more than 5 lookups can be running at single time
    highWater: 50, // no more than 50 lookups can be queued up
    strategy: Bottleneck.strategy.OVERFLOW,
    minTime: Number.parseInt(options.minTime, 10) // don't run lookups faster than 1 every 200 ms
  });
  return limiter;
}

const getLimiter = (options) => (!limiter ? setupLimiter(options) : limiter);

module.exports = { getLimiter };
