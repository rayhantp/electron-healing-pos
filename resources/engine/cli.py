"""
FingerCode CLI - Terminal & Desktop Engine untuk Konversi Sidik Jari ke Kode
Mendukung Mode Interaktif dan --json untuk Healing POS Desktop (Electron).
"""

import sys
import os
import json
import argparse
import time
import threading
import subprocess

# Pastikan stdout/stderr UTF-8 di Windows
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from winbio_client import WinBioHardwareManager, SUBFACTOR_NAMES, get_current_user_sid
from code_generator import CodeGenerator
from keyboard_emulator import type_text


def emit_json(payload):
    print(json.dumps(payload, ensure_ascii=False), flush=True)


def copy_to_clipboard(text: str):
    try:
        import tkinter as tk
        r = tk.Tk()
        r.withdraw()
        r.clipboard_clear()
        r.clipboard_append(text)
        r.update()
        r.destroy()
        return True
    except Exception:
        return False


def build_success_payload(result_holder, gen, fmt, nik=""):
    sf = int(result_holder.get("sub_factor", 0))
    sf_name = result_holder.get("sub_factor_name") or SUBFACTOR_NAMES.get(sf, (f"Jari {sf}", ""))[0]
    is_unreg = bool(result_holder.get("is_unregistered", False))
    sid = result_holder.get("sid") or ("ANONYMOUS_TOUCH_SID" if is_unreg else get_current_user_sid())
    res_code = gen.generate_code(sid, sf, fmt)
    code = res_code["code"]
    return {
        "success": True,
        "status": "SUCCESS",
        "code": code,
        "credential_id": code,
        "template_data": code,
        "finger_id": code,
        "sub_factor": sf,
        "sub_factor_name": sf_name,
        "sid": sid,
        "nik": nik,
        "is_unregistered": is_unreg,
        "format": res_code.get("format", fmt),
        "message": result_holder.get("message") or "Pemindaian berhasil",
    }


def build_error_payload(status, message, extra=None):
    payload = {
        "success": False,
        "status": status,
        "code": "",
        "credential_id": "",
        "message": message,
    }
    if extra:
        payload.update(extra)
    return payload


def main():
    parser = argparse.ArgumentParser(
        description="FingerCode CLI: Mengubah scan sidik jari menjadi kode angka/huruf."
    )
    parser.add_argument(
        "--action",
        choices=[
            "scan",
            "register",
            "enroll",
            "list-devices",
            "list-enrollments",
            "delete-enrollment",
            "open-windows-hello",
        ],
        default="scan",
        help="Aksi biometrik yang dijalankan",
    )
    parser.add_argument(
        "--subfactor",
        type=int,
        default=0,
        help="Nomor slot jari 1-254 (0 = otomatis pilih slot kosong)",
    )
    parser.add_argument(
        "--nik",
        type=str,
        default="",
        help="NIK karyawan untuk identifikasi absensi",
    )
    parser.add_argument(
        "-f", "--format",
        choices=[
            "numeric_6", "numeric_8", "numeric_12",
            "alphanumeric_blocks", "alphanumeric_24",
            "password_strong", "sha256_hex",
            "totp_dynamic_numeric", "custom_vault",
        ],
        default="alphanumeric_blocks",
        help="Format kode output (default: alphanumeric_blocks)",
    )
    parser.add_argument(
        "-u", "--allow-unregistered",
        action="store_true",
        default=False,
        help="Izinkan sentuhan jari APA PUN tanpa daftar (Mode Bebas)",
    )
    parser.add_argument(
        "--no-overwrite",
        action="store_true",
        default=False,
        help="Jangan timpa template subfactor yang sudah ada saat enroll",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output JSON ke stdout (untuk Healing POS Desktop)",
    )
    parser.add_argument(
        "-c", "--copy",
        action="store_true",
        help="Otomatis salin kode ke clipboard Windows",
    )
    parser.add_argument(
        "-t", "--type",
        action="store_true",
        help="Otomatis ketikkan kode ke jendela kursor aktif setelah jeda 2 detik",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Batas waktu pemindaian dalam detik (default: 30)",
    )
    parser.add_argument(
        "-l", "--list-devices",
        action="store_true",
        help="Tampilkan daftar hardware sidik jari yang terdeteksi",
    )
    parser.add_argument(
        "--enroll",
        type=int,
        nargs="?",
        const=2,
        default=None,
        metavar="SUBFACTOR_ID",
        help="Daftarkan jari baru (1=Ibu Jari Kanan, 2=Telunjuk Kanan, dst)",
    )

    args, _ = parser.parse_known_args()
    json_mode = bool(args.json)
    allow_unreg = bool(args.allow_unregistered)

    mgr = WinBioHardwareManager()
    gen = CodeGenerator()

    def out(msg):
        if json_mode:
            print(msg, file=sys.stderr, flush=True)
        else:
            print(msg, flush=True)

    # 0. Buka Windows Hello Settings
    if args.action == "open-windows-hello":
        try:
            subprocess.Popen(["cmd", "/c", "start", "ms-settings:signinoptions"])
            if json_mode:
                emit_json({"success": True, "status": "SUCCESS", "message": "Pengaturan Windows Hello dibuka."})
            else:
                print("Pengaturan Windows Hello dibuka.")
            return
        except Exception as e:
            if json_mode:
                emit_json(build_error_payload("ERROR", str(e)))
            else:
                print(f"[!] {e}")
            sys.exit(1)

    # 1. Cek Perangkat + Jari Terdaftar
    if args.list_devices or args.action == "list-devices":
        devices = mgr.list_devices()
        enrollments = mgr.list_enrollments(devices[0]["unit_id"]) if devices else []
        if json_mode:
            if devices:
                emit_json({
                    "success": True,
                    "status": "SUCCESS",
                    "devices": devices,
                    "enrollments": enrollments,
                    "count": len(devices),
                })
            else:
                emit_json({
                    "success": False,
                    "status": "NO_HARDWARE",
                    "devices": [],
                    "enrollments": [],
                    "count": 0,
                    "message": "Scanner USB ChipSailing belum tertancap pada komputer kasir.",
                })
            return
        print("\n=== Perangkat Biometrik Terdeteksi ===")
        if not devices:
            print("Tidak ada sensor biometrik yang terdeteksi.")
        for d in devices:
            print(f"- Nama        : {d.get('description')}")
            print(f"  Unit ID     : {d.get('unit_id')}")
            print(f"  Instance ID : {d.get('device_instance_id')}")
        if enrollments:
            print(f"  Terdaftar   : {[e['sub_factor'] for e in enrollments]}")
        print()
        return

    # 1b. Daftar Jari Terdaftar di Sensor
    if args.action == "list-enrollments":
        devices = mgr.list_devices()
        if not devices:
            if json_mode:
                emit_json(build_error_payload("NO_HARDWARE", "Hardware scanner USB tidak terdeteksi.", {"enrollments": []}))
            else:
                print("[!] Hardware scanner USB tidak terdeteksi.")
            return
        enrollments = mgr.list_enrollments(devices[0]["unit_id"])
        sid = get_current_user_sid()
        for item in enrollments:
            item["code"] = gen.generate_code(sid, item["sub_factor"], args.format)["code"]
        if json_mode:
            emit_json({"success": True, "status": "SUCCESS", "enrollments": enrollments, "count": len(enrollments)})
        else:
            print(f"Jari terdaftar ({len(enrollments)}):")
            for item in enrollments:
                print(f"  {item['sub_factor']}: {item['sub_factor_name']} -> {item['code']}")
        return

    # 1c. Hapus Template Jari di Sensor
    if args.action == "delete-enrollment":
        res = mgr.delete_enrollment(args.subfactor)
        if json_mode:
            emit_json(res)
        else:
            print(res.get("message", ""))
        return

    # Tentukan mode: enroll atau scan
    is_enroll_mode = (args.enroll is not None) or (args.action in ["enroll", "register"])
    sf = args.enroll if args.enroll is not None else args.subfactor

    # Cek hardware sebelum scan/enroll
    devs = mgr.list_devices()
    if not devs:
        msg = "Hardware scanner sidik jari USB tidak terdeteksi. Silakan colokkan kabel scanner ke port USB komputer."
        if json_mode:
            emit_json(build_error_payload("NO_HARDWARE", msg))
        else:
            print(f"\n[!] {msg}")
        sys.exit(1)

    # 2. Mode Pendaftaran (Enrollment) - 1 orang = 1 jari (slot otomatis 1-254)
    if is_enroll_mode:
        unit_id = devs[0]["unit_id"]
        if sf is None or sf < 1 or sf > 254:
            sf = mgr.get_next_available_slot(unit_id)
        sf_name = f"Sidik Jari (Slot #{sf})"

        out("=" * 60)
        out(f"PENDAFTARAN JARI: {sf_name} (ID: {sf})")
        out("=" * 60)
        out("Tempelkan jari Anda ke sensor...")

        done_event = threading.Event()
        result_holder = {}

        def on_enroll_progress(data):
            st = data.get("status")
            pct = data.get("progress", 0)
            msg = data.get("message", "")
            if json_mode:
                emit_json({
                    "event": "progress",
                    "status": st,
                    "progress": pct,
                    "message": msg,
                })
            else:
                out(f"[{pct}%] {msg}")

            if st in ["SUCCESS", "ERROR", "TIMEOUT", "CANCELED", "NO_HARDWARE", "DUPLICATE_FINGER"]:
                result_holder.update(data)
                done_event.set()

        mgr.enroll_fingerprint_async(
            sf,
            unit_id,
            on_enroll_progress,
            timeout_seconds=max(args.timeout, 60),
            overwrite=(not args.no_overwrite),
            use_focus_window=json_mode,
        )
        try:
            done_event.wait()
        except KeyboardInterrupt:
            mgr.cancel_scan()
            if json_mode:
                emit_json(build_error_payload("CANCELED", "Pendaftaran dibatalkan."))
            else:
                print("\n[!] Dibatalkan.")
            sys.exit(1)

        st = result_holder.get("status")
        if st == "SUCCESS":
            if not result_holder.get("sub_factor"):
                result_holder["sub_factor"] = sf
                result_holder["sub_factor_name"] = sf_name

            payload = build_success_payload(result_holder, gen, args.format, nik=args.nik)
            payload["message"] = result_holder.get("message") or "Pendaftaran sidik jari berhasil"
            if json_mode:
                emit_json(payload)
            else:
                print(f"\n[+] Pendaftaran berhasil: {payload['sub_factor_name']}")
                print(f"    KODE : {payload['code']}\n")
            return

        msg = result_holder.get("message", "Pendaftaran gagal")
        if json_mode:
            emit_json(build_error_payload(st or "ERROR", msg))
        else:
            print(f"\n[!] {msg}")
        sys.exit(1)

    # 3. Mode Pemindaian (Scan)
    out("=" * 60)
    out("FingerCode CLI - Konverter Sidik Jari ke Kode")
    out("=" * 60)
    out(f"Format Dipilih : {args.format}")
    out(f"Mode Bebas     : {'Aktif' if allow_unreg else 'Nonaktif (identifikasi unik)'}")
    out("Status         : Silakan sentuh sensor sidik jari Anda...")
    out(f"Batas Waktu    : {args.timeout} detik")
    out("-" * 60)

    result_holder = {}
    completed_event = threading.Event()

    def on_result(res):
        result_holder.update(res)
        completed_event.set()

    mgr.scan_fingerprint_async(on_result, timeout_seconds=args.timeout, allow_unregistered=allow_unreg, use_focus_window=json_mode)

    try:
        completed_event.wait()
    except KeyboardInterrupt:
        mgr.cancel_scan()
        if json_mode:
            emit_json(build_error_payload("CANCELED", "Dibatalkan oleh pengguna."))
        else:
            print("\n[!] Dibatalkan oleh pengguna.")
        sys.exit(0)

    status = result_holder.get("status")

    if status == "SUCCESS":
        if result_holder.get("is_unregistered") and json_mode and not allow_unreg:
            payload = build_error_payload(
                "NO_MATCH",
                "Jari terdeteksi tapi belum terdaftar. Daftarkan dulu lewat menu Sidik Jari.",
            )
            emit_json(payload)
            sys.exit(1)

        payload = build_success_payload(result_holder, gen, args.format, nik=args.nik)
        code = payload["code"]

        if json_mode:
            emit_json(payload)
        else:
            sf_name = payload["sub_factor_name"]
            is_unreg = payload["is_unregistered"]
            print("\n[+] SENTUHAN FISIK SIDIK JARI TERDETEKSI!")
            print(f"    Status Jari     : {sf_name} {'[Mode Bebas / Tanpa Daftar]' if is_unreg else '[Terdaftar]'}")
            print(f"\n    KODE ANDA   : {code}\n")

        if args.copy:
            if copy_to_clipboard(code):
                out("[OK] Kode berhasil disalin ke clipboard!")

        if args.type:
            out("[...] Mengetik dalam 2 detik...")
            time.sleep(2)
            type_text(code)
            out("[OK] Kode telah diketikkan.")
        return

    if status == "NO_MATCH":
        msg = "Sentuhan jari terdeteksi, namun jari ini BELUM TERDAFTAR di sensor biometrik. Silakan daftarkan jari terlebih dahulu."
        if json_mode:
            emit_json(build_error_payload("NO_MATCH", msg))
        else:
            print(f"\n[!] {msg}")
        sys.exit(1)

    if status == "REJECTED":
        msg = result_holder.get("message", "Sentuhan kurang jelas")
        if json_mode:
            emit_json(build_error_payload("REJECTED", msg))
        else:
            print(f"\n[!] Sentuhan kurang jelas: {msg}")
        sys.exit(1)

    if status == "TIMEOUT":
        msg = f"Waktu habis ({args.timeout} detik). Sensor tidak mendeteksi sentuhan."
        if json_mode:
            emit_json(build_error_payload("TIMEOUT", msg))
        else:
            print(f"\n[!] {msg}")
        sys.exit(1)

    if status == "CANCELED":
        msg = result_holder.get("message", "Pemindaian dibatalkan.")
        if json_mode:
            emit_json(build_error_payload("CANCELED", msg))
        else:
            print(f"\n[!] {msg}")
        sys.exit(1)

    msg = result_holder.get("message", "Unknown error")
    if json_mode:
        emit_json(build_error_payload(status or "ERROR", msg))
    else:
        print(f"\n[!] Terjadi kesalahan: {msg}")
    sys.exit(1)


if __name__ == "__main__":
    main()
