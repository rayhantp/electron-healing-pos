const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('desktopBridge', {
  getVersion: () => ipcRenderer.invoke('get-app-version'),
  scanFingerprint: (action, payload) => ipcRenderer.invoke('hardware:scan-fingerprint', action, payload),
  registerFingerprint: (karyawanNik, subfactor) => ipcRenderer.invoke('hardware:register-fingerprint', karyawanNik, subfactor),
  cancelFingerprint: () => ipcRenderer.invoke('hardware:cancel-fingerprint'),
  listEnrollments: () => ipcRenderer.invoke('hardware:list-enrollments'),
  deleteEnrollment: (subfactor) => ipcRenderer.invoke('hardware:delete-enrollment', subfactor),
  openWindowsHello: () => ipcRenderer.invoke('hardware:open-windows-hello'),
  onFingerprintProgress: (callback) => {
    ipcRenderer.removeAllListeners('fingerprint:progress');
    if (typeof callback === 'function') {
      const handler = (event, data) => callback(data);
      ipcRenderer.on('fingerprint:progress', handler);
      return () => ipcRenderer.removeListener('fingerprint:progress', handler);
    }
    return () => {};
  },
  printReceipt: (receiptData) => ipcRenderer.invoke('hardware:print-receipt', receiptData)
});
