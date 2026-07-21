export default {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'scope-enum': [2, 'always', [
      'auth0-fastify',
      'auth0-fastify-api',
      'ci',
      'security',
      'deps',
    ]],
    'scope-empty': [1, 'never'],
  },
};
