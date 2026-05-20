// scanner/parser_script.js
const acorn = require('acorn');
const fs = require('fs');

let input = '';
process.stdin.on('data', chunk => input += chunk);
process.stdin.on('end', () => {
  try {
    const ast = acorn.parse(input, {
      ecmaVersion: 2022,
      sourceType: 'script',
      locations: true,
      ranges: true
    });
    process.stdout.write(JSON.stringify(ast));
  } catch (err) {
    process.stderr.write('Parse Error: ' + err.message);
    process.exit(1);
  }
});
