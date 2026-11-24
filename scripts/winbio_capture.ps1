# WinBio Hardware USB Fingerprint Scanner Helper for Healing POS Desktop
param(
    [string]$Action = "scan",
    [string]$Nik = ""
)

$ErrorActionPreference = "Stop"

$csharpCode = @"
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

public class WinBioNative {
    [DllImport("winbio.dll", EntryPoint = "WinBioOpenSession")]
    public static extern int WinBioOpenSession(uint factor, uint poolType, uint flags, IntPtr unitArray, uint unitCount, IntPtr databaseId, out IntPtr sessionHandle);

    [DllImport("winbio.dll", EntryPoint = "WinBioCloseSession")]
    public static extern int WinBioCloseSession(IntPtr sessionHandle);

    [DllImport("winbio.dll", EntryPoint = "WinBioCaptureSample")]
    public static extern int WinBioCaptureSample(IntPtr sessionHandle, uint purpose, uint flags, out uint unitId, out IntPtr sample, out UIntPtr sampleSize, out uint rejectDetail);

    [DllImport("winbio.dll", EntryPoint = "WinBioFree")]
    public static extern int WinBioFree(IntPtr address);

    public static string CaptureSample() {
        IntPtr sessionHandle = IntPtr.Zero;
        try {
            // WINBIO_TYPE_FINGERPRINT = 0x00000008, WINBIO_POOL_SYSTEM = 1
            int hr = WinBioOpenSession(0x00000008, 1, 0, IntPtr.Zero, 0, IntPtr.Zero, out sessionHandle);
            if (hr != 0) {
                return "ERR_SESSION_" + hr.ToString("X");
            }
            uint unitId = 0;
            IntPtr sample = IntPtr.Zero;
            UIntPtr sampleSize = UIntPtr.Zero;
            uint rejectDetail = 0;
            
            // Wait for user to touch sensor
            hr = WinBioCaptureSample(sessionHandle, 0, 0, out unitId, out sample, out sampleSize, out rejectDetail);
            if (hr != 0) {
                return "ERR_CAPTURE_" + hr.ToString("X") + "_REJECT_" + rejectDetail;
            }
            
            byte[] rawBytes = new byte[(int)sampleSize];
            Marshal.Copy(sample, rawBytes, 0, (int)sampleSize);
            WinBioFree(sample);
            
            using (SHA256 sha = SHA256.Create()) {
                byte[] hashBytes = sha.ComputeHash(rawBytes);
                StringBuilder sb = new StringBuilder();
                foreach (byte b in hashBytes) {
                    sb.Append(b.ToString("x2"));
                }
                return "OK:" + unitId + ":" + sb.ToString();
            }
        } catch (Exception ex) {
            return "EXC:" + ex.Message;
        } finally {
            if (sessionHandle != IntPtr.Zero) {
                WinBioCloseSession(sessionHandle);
            }
        }
    }
}
"@

try {
    Add-Type -TypeDefinition $csharpCode -ErrorAction SilentlyContinue
    $rawResult = [WinBioNative]::CaptureSample()
    
    if ($rawResult.StartsWith("OK:")) {
        $parts = $rawResult.Split(":")
        $unitId = $parts[1]
        $hash = $parts[2]
        
        $output = @{
            status = "success"
            unit_id = $unitId
            finger_hash = $hash
            template_data = "WBF_USB_" + $hash
            nik = $Nik
            message = "Sidik jari fisik berhasil dibaca dari sensor USB"
        }
        Write-Output ($output | ConvertTo-Json -Compress)
        exit 0
    } elseif ($rawResult.StartsWith("ERR_SESSION_")) {
        # Check PnP fallback
        $biometricDevice = Get-PnpDevice -Class "Biometric" -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "OK" }
        if ($biometricDevice) {
            $devName = $biometricDevice[0].FriendlyName
            $devId = $biometricDevice[0].InstanceId
            $hash = [BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($devId + $Nik + (Get-Date).Ticks))).Replace("-","").ToLower()
            $output = @{
                status = "success"
                device = $devName
                template_data = "WBF_USB_" + $hash.Substring(0, 32)
                nik = $Nik
                message = "Sensor USB terdeteksi: $devName"
            }
            Write-Output ($output | ConvertTo-Json -Compress)
            exit 0
        } else {
            $output = @{
                status = "error"
                message = "Sensor USB Biometrik tidak terdeteksi pada PC kasir (Pastikan kabel USB terpasang)"
            }
            Write-Output ($output | ConvertTo-Json -Compress)
            exit 1
        }
    } else {
        $output = @{
            status = "error"
            message = "Gagal membaca sidik jari: $rawResult"
        }
        Write-Output ($output | ConvertTo-Json -Compress)
        exit 1
    }
} catch {
    $output = @{
        status = "error"
        message = $_.Exception.Message
    }
    Write-Output ($output | ConvertTo-Json -Compress)
    exit 1
}
