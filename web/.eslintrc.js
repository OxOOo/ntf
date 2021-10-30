module.exports = {
    root: true,
    env: {
        browser: true,
        node: true
    },
    parserOptions: {
        parser: '@babel/eslint-parser',
        requireConfigFile: false
    },
    extends: [
        '@nuxtjs',
        'plugin:nuxt/recommended'
    ],
    plugins: [
    ],
    // add your custom rules here
    rules: {
        semi: ['error', 'always'],
        indent: ['error', 4],
        'no-console': 'off',
        'require-await': 'off',
        'no-prototype-builtins': 'off',
        camelcase: 'off'
    }
};
