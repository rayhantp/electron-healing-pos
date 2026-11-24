const path = require('path');
const { spawn } = require('child_process');

const pythonExe = 'C:\\Program Files\\Healing POS Desktop\\resources\\python-win\\python.exe';
const cliScript = path.join(__dirname, 'resources', 'engine', 'cli.py');

console.log('Testing Node -> Python CLI integration...');
console.log('Python:', pythonExe);
console.log('Script:', cliScript);

function testCommand(args) {
  return new Promise((resolve) => {
    const child = spawn(pythonExe, ['-u', cliScript, ...args], {
      windowsHide: true,
      cwd: path.dirname(cliScript)
    });

    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (d) => { stdout += d.toString(); });
    child.stderr.on('data', (d) => { stderr += d.toString(); });

    child.on('close', (code) => {
      resolve({ code, stdout: stdout.trim(), stderr: stderr.trim() });
    });
  });
}

async function run() {
  console.log('\n--- Test 1: list-devices ---');
  const t1 = await testCommand(['--action', 'list-devices', '--json']);
  console.log('T1 Exit Code:', t1.code);
  console.log('T1 Output:', t1.stdout);

  console.log('\n--- Test 2: scan with timeout 1s ---');
  const t2 = await testCommand(['--action', 'scan', '--json', '-u', '--timeout', '1']);
  console.log('T2 Exit Code:', t2.code);
  console.log('T2 Output:', t2.stdout);

  console.log('\n--- Test 3: register with NIK KRY001 and timeout 1s ---');
  const t3 = await testCommand(['--action', 'register', '--nik', 'KRY001', '--json', '-u', '--timeout', '1']);
  console.log('T3 Exit Code:', t3.code);
  console.log('T3 Output:', t3.stdout);
}

run();

