const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');

// Logger Error Global untuk mendeteksi crash
process.on('uncaughtException', (err) => {
  try {
    const logDir = app.getPath('userData');
    fs.mkdirSync(logDir, { recursive: true });
    fs.appendFileSync(path.join(logDir, 'app-error.log'), `[${new Date().toISOString()}] Uncaught Exception: ${err.stack || err}\n`);
  } catch (e) {}
});

process.on('unhandledRejection', (reason) => {
  try {
    const logDir = app.getPath('userData');
    fs.mkdirSync(logDir, { recursive: true });
    fs.appendFileSync(path.join(logDir, 'app-error.log'), `[${new Date().toISOString()}] Unhandled Rejection: ${reason}\n`);
  } catch (e) {}
});

let mainWindow;
let activeBioChild = null;

// URL Awal Aplikasi - Menu Login Terpadu (Kasir, Owner, SPV, Developer)
// Setel POS_URL di environment (.env) ke endpoint produksi Anda.
const CABANG_URL = process.env.POS_URL || 'https://pos.example.com/login.php';

function createWindow() {
  const icoCandidate = path.join(__dirname, 'assets', 'icon.ico');
  const pngCandidate = path.join(__dirname, 'assets', 'icon.png');
  const iconPath = fs.existsSync(icoCandidate) ? icoCandidate : pngCandidate;
  const winOptions = {
    width: 1366,
    height: 768,
    minWidth: 1024,
    minHeight: 600,
    title: 'Healing — Acupressure & Reflexology | POS & Concierge Suite',
    backgroundColor: '#0F0E0C',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true,
      webSecurity: true
    },
    autoHideMenuBar: false
  };

  if (fs.existsSync(iconPath)) {
    winOptions.icon = iconPath;
  }

  mainWindow = new BrowserWindow(winOptions);

  mainWindow.maximize();
  mainWindow.loadURL(CABANG_URL);

  mainWindow.webContents.on('did-fail-load', (event, errorCode, errorDescription) => {
    console.error('Failed to load:', errorCode, errorDescription);
    const fallbackUrl = process.env.POS_FALLBACK_URL || CABANG_URL;
    console.log('Mencoba URL fallback:', fallbackUrl);
    mainWindow.loadURL(fallbackUrl);
  });

  mainWindow.on('closed', () => {
    killActiveBioChild();
    mainWindow = null;
  });
}

function getPythonPath() {
  if (process.resourcesPath) {
    const extraPy = path.join(process.resourcesPath, 'python-win', 'python.exe');
    if (fs.existsSync(extraPy)) return extraPy;
    const unpackedPy = path.join(process.resourcesPath, 'app.asar.unpacked', 'python-win', 'python.exe');
    if (fs.existsSync(unpackedPy)) return unpackedPy;
  }
  const localPy = path.join(__dirname, 'python-win', 'python.exe');
  if (fs.existsSync(localPy)) return localPy;
  const devPy = path.join(__dirname, 'resources', 'python-win', 'python.exe');
  if (fs.existsSync(devPy)) return devPy;
  return 'python';
}

function getCliScriptPath() {
  if (process.resourcesPath) {
    const extraScript = path.join(process.resourcesPath, 'engine', 'cli.py');
    if (fs.existsSync(extraScript)) return extraScript;
    const unpackedScript = path.join(process.resourcesPath, 'app.asar.unpacked', 'engine', 'cli.py');
    if (fs.existsSync(unpackedScript)) return unpackedScript;
  }
  const localScript = path.join(__dirname, 'engine', 'cli.py');
  if (fs.existsSync(localScript)) return localScript;
  const devScript = path.join(__dirname, 'resources', 'engine', 'cli.py');
  if (fs.existsSync(devScript)) return devScript;
  return localScript.replace('app.asar', 'app.asar.unpacked');
}

function killActiveBioChild() {
  if (activeBioChild) {
    try {
      activeBioChild.kill();
    } catch (e) {}
    activeBioChild = null;
  }
}

const VALID_ACTIONS = new Set([
  'scan',
  'register',
  'enroll',
  'list-devices',
  'list-enrollments',
  'delete-enrollment',
  'open-windows-hello'
]);

function runNativeFingerprint(rawAction = 'scan', rawPayload = null) {
  // Defensive normalization: handle scanFingerprint(opts) where 1st arg is an object!
  let action = rawAction;
  let payload = rawPayload;
  if (action && typeof action === 'object') {
    payload = action;
    action = payload.action || 'scan';
  }
  if (typeof action !== 'string' || !VALID_ACTIONS.has(action)) {
    action = 'scan';
  }

  return new Promise((resolve) => {
    const pythonExe = getPythonPath();
    const cliScript = getCliScriptPath();

    if (!fs.existsSync(cliScript)) {
      resolve({
        success: false,
        status: 'ERROR',
        message: 'Engine biometrik tidak ditemukan: ' + cliScript
      });
      return;
    }

    // Untuk aksi sensor interaktif (scan/register/enroll), hentikan proses sensor lama agar tidak DEVICE_BUSY
    const isInteractive = action === 'scan' || action === 'register' || action === 'enroll';
    if (isInteractive) {
      killActiveBioChild();
    }

    const fmt = (payload && typeof payload === 'object' && payload.format) || 'alphanumeric_blocks';
    let timeoutSec = 30;
    if (action === 'register' || action === 'enroll') {
      timeoutSec = (payload && typeof payload === 'object' && parseInt(payload.timeout, 10)) || 90;
    } else if (action === 'scan') {
      timeoutSec = (payload && typeof payload === 'object' && parseInt(payload.timeout, 10)) || 30;
    } else {
      timeoutSec = 10;
    }
    if (isNaN(timeoutSec) || timeoutSec < 5) timeoutSec = 30;

    const args = [
      '-u',
      cliScript,
      '--action', action,
      '--json',
      '--timeout', String(timeoutSec),
      '--format', fmt
    ];

    if (typeof payload === 'string' && payload.trim()) {
      args.push('--nik', payload.trim());
    } else if (typeof payload === 'number') {
      args.push('--subfactor', String(payload));
    } else if (payload && typeof payload === 'object') {
      if (payload.nik) args.push('--nik', String(payload.nik));
      if (payload.subfactor !== undefined && payload.subfactor !== null) {
        args.push('--subfactor', String(payload.subfactor));
      } else if (payload.sub_factor !== undefined && payload.sub_factor !== null) {
        args.push('--subfactor', String(payload.sub_factor));
      }
      if (payload.enroll) {
        args.push('--enroll', String(typeof payload.enroll === 'number' ? payload.enroll : (payload.subfactor || 2)));
      }
      if (payload.allow_unregistered === true || payload.allow_unregistered === 'true' || payload.allow_unregistered === 1) {
        args.push('--allow-unregistered');
      }
      if (payload.overwrite === false || payload.overwrite === 'false' || payload.overwrite === 0) {
        args.push('--no-overwrite');
      }
    }

    let isResolved = false;
    let safetyTimer = null;
    const safeResolve = (data) => {
      if (!isResolved) {
        isResolved = true;
        if (safetyTimer) clearTimeout(safetyTimer);
        if (activeBioChild === child) {
          activeBioChild = null;
        }
        resolve(data);
      }
    };

    const child = spawn(pythonExe, args, {
      windowsHide: true,
      cwd: path.dirname(cliScript)
    });

    if (isInteractive) {
      activeBioChild = child;
    }

    let stdoutBuffer = '';
    let stderrBuffer = '';

    const handleParsedLine = (parsed) => {
      if (parsed.event === 'progress') {
        if (mainWindow && !mainWindow.isDestroyed()) {
          mainWindow.webContents.send('fingerprint:progress', parsed);
        }
        return false;
      }

      if (parsed.success === true) {
        safeResolve({
          ...parsed,
          success: true,
          status: parsed.status || 'SUCCESS',
          code: parsed.code || '',
          credential_id: parsed.code || '',
          template_data: parsed.code || '',
          finger_id: parsed.code || '',
          nik: parsed.nik || (typeof payload === 'string' ? payload : (payload && payload.nik ? payload.nik : '')),
          message: parsed.message || 'Pemindaian berhasil',
          sub_factor: parsed.sub_factor,
          sub_factor_name: parsed.sub_factor_name,
          is_unregistered: !!parsed.is_unregistered,
          devices: parsed.devices || [],
          enrollments: parsed.enrollments || []
        });
        return true;
      } else if (parsed.success === false) {
        safeResolve({
          ...parsed,
          success: false,
          status: parsed.status || 'ERROR',
          message: parsed.message || 'Gagal memproses sidik jari',
          devices: parsed.devices || [],
          enrollments: parsed.enrollments || []
        });
        return true;
      }
      return false;
    };

    child.stdout.on('data', (chunk) => {
      stdoutBuffer += chunk.toString('utf8');

      const lines = stdoutBuffer.split(/\r?\n/);
      stdoutBuffer = lines.pop();

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed.startsWith('{') || !trimmed.endsWith('}')) continue;
        try {
          const parsed = JSON.parse(trimmed);
          if (handleParsedLine(parsed)) return;
        } catch (e) {}
      }
    });

    child.stderr.on('data', (chunk) => {
      stderrBuffer += chunk.toString('utf8');
    });

    child.on('close', (exitCode, signal) => {
      if (isResolved) return;

      if (stdoutBuffer && stdoutBuffer.trim().startsWith('{')) {
        try {
          const parsed = JSON.parse(stdoutBuffer.trim());
          if (handleParsedLine(parsed)) return;
        } catch (e) {}
      }

      if (signal === 'SIGTERM' || signal === 'SIGKILL') {
        safeResolve({
          success: false,
          status: 'CANCELED',
          message: 'Operasi sensor dibatalkan.'
        });
        return;
      }

      safeResolve({
        success: false,
        status: 'ERROR',
        message: stderrBuffer.trim() || 'Waktu pemindaian habis (Sensor tidak mendeteksi sentuhan)'
      });
    });

    child.on('error', (err) => {
      safeResolve({
        success: false,
        status: 'ERROR',
        message: 'Gagal menjalankan engine biometrik: ' + err.message
      });
    });

    const safetyMs = (timeoutSec + 10) * 1000;
    safetyTimer = setTimeout(() => {
      if (!isResolved) {
        try { child.kill(); } catch (e) {}
        safeResolve({
          success: false,
          status: 'TIMEOUT',
          message: `Batas waktu sensor (${timeoutSec} detik) habis. Tidak ada sentuhan terdeteksi.`
        });
      }
    }, safetyMs);
  });
}

// Hardware & System IPC Handlers
ipcMain.handle('get-app-version', () => app.getVersion());

ipcMain.handle('hardware:scan-fingerprint', async (event, action, payload) => {
  return await runNativeFingerprint(action || 'scan', payload);
});

ipcMain.handle('hardware:register-fingerprint', async (event, karyawanNik, subfactor) => {
  let payload = {};
  if (karyawanNik && typeof karyawanNik === 'object') {
    payload = { ...karyawanNik };
    if (!payload.subfactor && subfactor) payload.subfactor = subfactor;
  } else {
    payload = { nik: karyawanNik, subfactor: subfactor || 0 };
  }
  return await runNativeFingerprint('register', payload);
});

ipcMain.handle('hardware:cancel-fingerprint', async () => {
  killActiveBioChild();
  return { success: true, status: 'CANCELED', message: 'Operasi sensor dibatalkan.' };
});

ipcMain.handle('hardware:list-enrollments', async () => {
  return await runNativeFingerprint('list-enrollments');
});

ipcMain.handle('hardware:delete-enrollment', async (event, subfactor) => {
  const sf = (subfactor && typeof subfactor === 'object')
    ? (subfactor.subfactor || subfactor.sub_factor || 0)
    : parseInt(subfactor, 10);
  return await runNativeFingerprint('delete-enrollment', { subfactor: sf });
});

ipcMain.handle('hardware:open-windows-hello', async () => {
  return await runNativeFingerprint('open-windows-hello');
});

ipcMain.handle('hardware:print-receipt', async (event, receiptData) => {
  return {
    status: 'success',
    printer: 'POS-58/80 Thermal',
    printed_at: new Date().toISOString()
  };
});

app.whenReady().then(() => {
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  killActiveBioChild();
  if (process.platform !== 'darwin') app.quit();
});
