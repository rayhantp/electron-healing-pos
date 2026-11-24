const { spawn } = require('child_process');
const path = require('path');

const pythonExe = 'C:\\Program Files\\Healing POS Desktop\\resources\\python-win\\python.exe';
const cliScript = 'C:\\Program Files\\Healing POS Desktop\\resources\\engine\\cli.py';

console.log('Testing spawn...');
const child = spawn(pythonExe, ['-u', cliScript, '--json', '-u', '--timeout', '5'], {
  windowsHide: true,
  cwd: path.dirname(cliScript)
});

let stdout = '';
let stderr = '';

child.stdout.on('data', (d) => {
  console.log('STDOUT:', d.toString());
  stdout += d.toString();
});

child.stderr.on('data', (d) => {
  console.log('STDERR:', d.toString());
  stderr += d.toString();
});

child.on('close', (code) => {
  console.log('Child closed with code:', code);
});

