
module.exports = {
  coverageConfig: {
    reporters: [
      'html',
      'text',
      'text-summary',
    ],
    threshold: {
      statements: 70,
      branches: 70,
      functions: 70,
      lines: 70,
    },
  },
};
