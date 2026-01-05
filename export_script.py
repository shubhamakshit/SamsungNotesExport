import os
import sys
import subprocess
import urllib.request
import time
import ctypes
import threading
import glob

# --- CONFIGURATION ---
SNOTES_APPX_URL = "https://huggingface.co/datasets/Jaimodiji/SAMSUNG-NOTES/resolve/main/snotes.Msixbundle"
APP_FILENAME = "SamsungNotes.Msixbundle"
TARGET_NOTE = "input_note.sdocx"
OUTPUT_SVG = "Final_Export.svg"
EXPORT_PDF_TEMP = "C:\\Temp\\dummy.pdf"

# --- INSTALLATION LOGIC ---

def install_pip_deps():
    print("[*] Installing Python Dependencies...")
    # FIX: Added pyautogui and pillow explicitly
    packages = ["frida", "frida-tools", "uiautomation", "requests", "pyautogui", "pillow"]
    subprocess.check_call([sys.executable, "-m", "pip", "install"] + packages)

def install_local_dependencies():
    print("[*] Installing Dependency Appx files from Repo...")
    dep_files = glob.glob("*.Appx") + glob.glob("*.AppxBundle")
    
    for dep in dep_files:
        if "SamsungNotes" in dep: continue
        print(f"    -> Installing {dep}...")
        try:
            subprocess.run(["powershell", "Add-AppxPackage", "-Path", f".\\{dep}"], check=True)
        except:
            print(f"    [!] Warning: Failed to install {dep}")

def install_samsung_notes():
    if not os.path.exists(APP_FILENAME):
        print(f"[*] Downloading Samsung Notes from HuggingFace...")
        try:
            import requests
            response = requests.get(SNOTES_APPX_URL, stream=True)
            with open(APP_FILENAME, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            print("[+] Download Complete.")
        except Exception as e:
            print(f"[-] Download Failed: {e}")
            sys.exit(1)
    
    print("[*] Installing Samsung Notes...")
    # ForceUpdateFromAnyVersion allows reinstalling over existing versions
    cmd = ["powershell", "Add-AppxPackage", "-Path", APP_FILENAME, "-ForceUpdateFromAnyVersion", "-AllowUnsigned"]
    subprocess.run(cmd, capture_output=True, text=True)
    print("[+] App Install Process Finished.")

# --- FRIDA LOGIC ---

jscode = """
const docModule = "libSpen_document.dll";

// Smart Thinning Config
const THRESHOLD = 0.15;
const MOD_REDUCE = 0.50; 
const MOD_KEEP = 0.95;

const names = {
    point: "?GetPoint@ObjectStroke@SPen@@QEBAPEBUPointF@2@XZ",
    count: "?GetPointCount@ObjectStroke@SPen@@QEBAHXZ",
    color: "?GetColor@ObjectStroke@SPen@@QEBAIXZ",
    size:  "?GetPenSize@ObjectStroke@SPen@@QEBAMXZ",
    pressure: "?GetPressure@ObjectStroke@SPen@@QEBAPEBMXZ"
};

function main() {
    const mod = Process.findModuleByName(docModule);
    if (!mod) { return; } 

    const addrPoint = mod.findExportByName(names.point);
    const addrCount = mod.findExportByName(names.count);
    const addrColor = mod.findExportByName(names.color);
    const addrSize = mod.findExportByName(names.size);
    const addrPressure = mod.findExportByName(names.pressure);

    if (!addrPoint) return;

    const getCount = new NativeFunction(addrCount, 'int', ['pointer']);
    const getPoint = new NativeFunction(addrPoint, 'pointer', ['pointer']);
    const getColor = addrColor ? new NativeFunction(addrColor, 'uint', ['pointer']) : null;
    const getPenSize = addrSize ? new NativeFunction(addrSize, 'float', ['pointer']) : null;
    const getPressure = addrPressure ? new NativeFunction(addrPressure, 'pointer', ['pointer']) : null;

    Interceptor.attach(addrPoint, {
        onEnter(args) { this.stroke = args[0]; },
        onLeave(retval) {
            try {
                if (retval.isNull()) return;
                const count = getCount(this.stroke);
                if (count < 2 || count > 50000) return;

                const pointsPtr = retval;
                let pts = [];
                let rawData = ""; 
                
                let minP = 1.0, maxP = 0.0;
                let hasP = false;

                if (getPressure) {
                    const pPtr = getPressure(this.stroke);
                    if (!pPtr.isNull()) {
                        hasP = true;
                        for (let k = 0; k < count; k++) {
                            let v = pPtr.add(k*4).readFloat();
                            if (v < minP) minP = v;
                            if (v > maxP) maxP = v;
                        }
                    }
                }

                let scale = MOD_KEEP;
                const rawSize = getPenSize ? getPenSize(this.stroke) : 2.0;
                
                if (rawSize > 3.0) scale = 0.35; 
                else if (hasP && (maxP - minP) > THRESHOLD) scale = MOD_REDUCE;
                
                let finalSize = rawSize * scale;
                if (finalSize < 0.5) finalSize = 0.5;

                for (let i = 0; i < count; i++) {
                    let p = pointsPtr.add(i * 8);
                    let x = p.readFloat().toFixed(2);
                    let y = p.add(4).readFloat().toFixed(2);
                    let cur = x + "," + y;
                    
                    if (pts.length === 0 || cur !== pts[pts.length-1]) {
                        pts.push(cur);
                        rawData += cur; 
                    }
                }

                let color = "#000000";
                if (getColor) {
                    let fullHex = getColor(this.stroke).toString(16).padStart(8, '0');
                    color = "#" + fullHex.substring(2, 8);
                }

                const fullHash = count + "_" + color + "_" + rawData.substring(0, 50);
                const svgLine = `<polyline points="${pts.join(" ")}" fill="none" stroke="${color}" stroke-width="${finalSize.toFixed(2)}" stroke-linecap="round" stroke-linejoin="round" />`;
                
                send(fullHash + "||" + svgLine);

            } catch (e) {}
        }
    });
}

const interval = setInterval(() => {
    if (Process.findModuleByName(docModule)) {
        clearInterval(interval);
        main();
    }
}, 500);
"""

# --- MAIN EXECUTION ---

svg_buffer = []
saved_hashes = set()

def on_message(message, data):
    if message['type'] == 'send':
        try:
            hsh, svg = message['payload'].split("||", 1)
            if hsh not in saved_hashes:
                saved_hashes.add(hsh)
                svg_buffer.append(svg)
                sys.stdout.write(f"\r[+] Captured: {len(svg_buffer)} strokes   ")
                sys.stdout.flush()
        except: pass

def drive_ui():
    # Import inside thread to ensure it's loaded after install
    import pyautogui
    
    print("\n[UI] Waiting for App Window...")
    time.sleep(5) 
    
    # 1. Clear Popups
    print("    -> Clearing potential First-Run popups...")
    pyautogui.press('enter') 
    time.sleep(1)
    pyautogui.press('enter') 
    time.sleep(1)

    # 2. Navigate to Share Menu
    print("    -> Navigating to Share...")
    for i in range(8):
        pyautogui.press('tab')
        time.sleep(0.1)
    
    pyautogui.press('enter') # Open Menu
    time.sleep(1.5)
    
    # 3. Select PDF
    print("    -> Selecting PDF...")
    pyautogui.press('down')
    time.sleep(0.2)
    pyautogui.press('enter')
    time.sleep(1.5)
    
    # 4. Click Done
    print("    -> Confirming Share...")
    pyautogui.press('enter')
    time.sleep(1.5)
    
    # 5. Save Dialog
    print("    -> Saving Dummy File...")
    if not os.path.exists("C:\\Temp"): os.makedirs("C:\\Temp")
    
    pyautogui.write(EXPORT_PDF_PATH)
    time.sleep(0.5)
    pyautogui.press('enter')
    time.sleep(1.0)
    
    # Confirm Overwrite
    pyautogui.press('left')
    pyautogui.press('enter')
    print("[UI] Export Sequence Complete.")

def main():
    # 1. INSTALLATION
    install_pip_deps()
    install_local_dependencies()
    install_samsung_notes()
    
    import frida # Now safe to import

    if not os.path.exists(TARGET_NOTE):
        print(f"[-] Target {TARGET_NOTE} not found.")
        return

    # 2. LAUNCH
    print(f"[*] Launching {TARGET_NOTE}...")
    os.startfile(TARGET_NOTE)
    
    print("[*] Waiting 8 seconds for app startup...")
    time.sleep(8)

    # 3. FRIDA ATTACH
    try:
        print("[*] Attaching Data Thief...")
        session = frida.attach("SamsungNotes.exe")
        script = session.create_script(jscode)
        script.on("message", on_message)
        script.load()
    except Exception as e:
        print(f"[-] Failed to attach Frida: {e}")
        os.system("taskkill /f /im SamsungNotes.exe >nul 2>&1")
        return

    # 4. DRIVE UI
    # Force import check before thread start
    try:
        import pyautogui
    except ImportError:
        print("[-] FATAL: PyAutoGUI missing. Re-running install...")
        install_pip_deps()
        import pyautogui

    t = threading.Thread(target=drive_ui)
    t.start()
    t.join()
    
    # 5. HARVEST
    print("[*] Listening for data stream...")
    last_val = -1
    no_change = 0
    
    for _ in range(45):
        time.sleep(1)
        if len(svg_buffer) > 0 and len(svg_buffer) == last_val:
            no_change += 1
        else:
            no_change = 0
        last_val = len(svg_buffer)
        
        if len(svg_buffer) > 0 and no_change > 5:
            break
            
    # 6. SAVE OUTPUT
    if svg_buffer:
        with open(OUTPUT_SVG, "w", encoding="utf-8") as f:
            f.write('<?xml version="1.0" standalone="no"?>\n')
            f.write('<svg width="5000" height="200000" version="1.1" xmlns="http://www.w3.org/2000/svg" style="background-color:white">\n')
            for line in svg_buffer:
                f.write(line + "\n")
            f.write('</svg>')
        print(f"\n[+] SUCCESS! Saved to {OUTPUT_SVG}")
    else:
        print("\n[-] No data captured.")

    # 7. CLEANUP
    session.detach()
    os.system("taskkill /f /im SamsungNotes.exe >nul 2>&1")

if __name__ == "__main__":
    main()
