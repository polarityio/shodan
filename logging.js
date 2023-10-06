const fs = require('fs');
const { flow, reduce } = require('lodash/fp');

const writeToDevRunnerResults = (loggingLevel) => (...content) =>
  fs.appendFileSync(
    'devRunnerResults.json',
    '\n' + JSON.stringify({ SOURCE: `Logger.${loggingLevel}`, content }, null, 2)
  );

let logger = flow(
  reduce((agg, level) => ({ ...agg, [level]: writeToDevRunnerResults(level) }), {})
)(['trace', 'debug', 'info', 'warn', 'error', 'fatal']);

const setLogger = (_logger) => {
  logger = _logger;
};

const getLogger = () => logger;

module.exports = { setLogger, getLogger };
