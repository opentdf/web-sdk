import register from '@babel/register';

register({
  extensions: ['.ts', '.tsx', '.js', '.jsx'],
  presets: ['@babel/env', '@babel/preset-typescript'],
  plugins: ['@babel/plugin-transform-runtime', '@babel/plugin-transform-modules-commonjs'],
});
