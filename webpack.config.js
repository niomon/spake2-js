const path = require('path')
const TerserPlugin = require('terser-webpack-plugin')

module.exports = {
  mode: 'production',
  entry: './src/index.js', // or './src/index.ts' if TypeScript
  output: {
    filename: 'spake2.min.js', // Desired file name. Same as in package.json's "main" field.
    path: path.resolve(__dirname, 'dist'),
    library: 'spake2', // Desired name for the global variable when using as a drop-in script-tag.
    libraryTarget: 'umd',
    globalObject: 'this'
  },
  module: {
    rules: [
      {
        include: path.resolve(__dirname, 'src')
      }
    ]
  },
  optimization: {
    minimize: true,
    minimizer: [new TerserPlugin()]
  }
}
