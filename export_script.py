import os
import sys
import subprocess
import urllib.request
import time
import ctypes
import threading
import glob
from datetime import datetime

# --- CONFIGURATION ---
SNOTES_APPX_URL = "https://huggingface.co/datasets/Jaimodiji/SAMSUNG-NOTES/resolve/main/snotes.Msixbundle"
APP_FILENAME = "SamsungNotes.Msixbundle"
TARGET_NOTE = "input_note.sdocx"
OUTPUT_SVG = "Final_Export.svg"
EXPORT_PDF_PATH = r"C:\Temp\dummy_export.pdf"
SCREENSHOT_DIR = "Debug_Screenshots"

# Global flags
stop_threads = False

# --- LOGGING & SCREENSHOTS ---
def log(msg):
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] {msg}", flush=True)

def take_snapshot(name="auto"):
    """Captures the screen for debugging."""
    if not os.path.exists(SCREENSHOT_DIR): os.makedirs(SCREENSHOT_DIR)
    
    try:
        import pyautogui
        timestamp = datetime.now().strftime("%H_%M_%S")
        filename = f"{SCREENSHOT_DIR}\\{timestamp}_{name}.png"
        pyautogui.screenshot(filename)
        log(f"[SNAPSHOT] Saved {filename}")
    except Exception as e:
        log(f"[SNAPSHOT] Failed: {e}")

def paparazzi_thread():
    """Takes a screenshot every 3 seconds."""
    while not stop_threads:
        take_snapshot("interval")
        time.sleep(3)

# --- SYSTEM CHECKS ---
def check_system_capabilities():
    log("[SYSTEM] Verifying Display and Mouse subsystems...")
    
    try:
        user32 = ctypes.windll.user32
        
        # 1. Check Screen Resolution
        width = user32.GetSystemMetrics(0)
        height = user32.GetSystemMetrics(1)
        log(f"[SYSTEM] Virtual Display Detected: {width}x{height}")
        
        if width == 0 or height == 0:
            log("[-] FATAL: No display detected. UI Automation will fail.")
            sys.exit(1)

        # 2. Check Cursor
        pt = ctypes.wintypes.POINT()
        if user32.GetCursorPos(ctypes.byref(pt)):
            log(f"[SYSTEM] Mouse Cursor active at ({pt.x}, {pt.y})")
        else:
            log("[-] Warning: Could not get cursor position.")

    except Exception as e:
        log(f"[-] System Check Error: {e}")
        # We continue anyway because sometimes CI environments are weird

# --- INSTALLATION LOGIC ---

def install_pip_deps():
    log("[SETUP] Installing Python Dependencies...")
    packages = ["frida", "frida-tools", "uiautomation", "requests", "pyautogui", "pillow"]
    subprocess.check_call([sys.executable, "-m", "pip", "install"] + packages)

def install_local_dependencies():
    log("[SETUP] Looking for Dependency Appx files in repo...")
    dep_files = glob.glob("*.Appx") + glob.glob("*.AppxBundle")
    
    for dep in dep_files:
        if "SamsungNotes" in dep: continue
        log(f"[SETUP] Installing Dependency: {dep}")
        try:
            subprocess.run(["powershell", "Add-AppxPackage", "-Path", f".\\{dep}"], check=True)
        except Exception as e:
            log(f"[SETUP] Warning: Failed to install {dep}")

def install_samsung_notes():
    if not os.path.exists(APP_FILENAME):
        log(f"[SETUP] Downloading Samsung Notes from HuggingFace...")
        try:
            import requests
            response = requests.get(SNOTES_APPX_URL, stream=True)
            with open(APP_FILENAME, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            log("[SETUP] Download Complete.")
        except Exception as e:
            log(f"[SETUP] Critical Error: Download Failed: {e}")
            sys.exit(1)
    
    log("[SETUP] Installing Samsung Notes Appx...")
    cmd = ["powershell", "Add-AppxPackage", "-Path", APP_FILENAME, "-ForceUpdateFromAnyVersion", "-AllowUnsigned"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        log(f"[SETUP] App Install Warning (Output): {result.stderr}")
    else:
        log("[SETUP] App Installed Successfully.")

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
                    
                    if (pts.length === 0 || cur !== pts[pts.length-1]) {
                        pts.push(x + "," + y);
                        rawData += x + y; 
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
                if len(svg_buffer) % 50 == 0:
                    log(f"[FRIDA] Captured {len(svg_buffer)} strokes so far...")
        except: pass

def drive_ui():
    import pyautogui
    
    log("[UI] Thread Started.")
    log("[UI] Waiting 5 seconds for App Window to stabilize...")
    time.sleep(5)
    
    take_snapshot("app_launched")
    
    # 1. Clear Popups
    log("[UI] Step 1: Clearing Popups (Pressing Enter)...")
    pyautogui.press('enter') 
    time.sleep(1)
    pyautogui.press('enter') 
    time.sleep(1)
    take_snapshot("popups_cleared")

    # 2. Navigate to Share Menu
    log("[UI] Step 2: Navigating to Toolbar (8x Tab)...")
    for i in range(8):
        pyautogui.press('tab')
        time.sleep(0.1)
    
    take_snapshot("tabbed_to_menu")
    log("[UI] Opening Share Menu (Enter)...")
    pyautogui.press('enter') 
    time.sleep(1.5)
    take_snapshot("menu_opened")
    
    # 3. Select PDF
    log("[UI] Step 3: Selecting PDF (Down -> Enter)...")
    pyautogui.press('down')
    time.sleep(0.2)
    pyautogui.press('enter')
    time.sleep(1.5)
    take_snapshot("pdf_selected")
    
    # 4. Click Done
    log("[UI] Step 4: Clicking Done (Enter)...")
    pyautogui.press('enter')
    time.sleep(1.5)
    
    # 5. Save Dialog
    log(f"[UI] Step 5: Handling Save Dialog...")
    if not os.path.exists("C:\\Temp"): os.makedirs("C:\\Temp")

    pyautogui.write(EXPORT_PDF_PATH)
    time.sleep(0.5)
    take_snapshot("filename_typed")
    
    pyautogui.press('enter')
    time.sleep(1.0)
    
    # Confirm Overwrite
    pyautogui.press('left')
    pyautogui.press('enter')
    log("[UI] Automation Sequence Complete.")
    take_snapshot("export_started")

def main():
    global stop_threads

    # 1. INSTALLATION
    install_pip_deps()
    install_local_dependencies()
    install_samsung_notes()
    
    # Late import
    import frida
    import pyautogui # For initial system check

    # 2. SYSTEM CHECK
    check_system_capabilities()

    if not os.path.exists(TARGET_NOTE):
        log(f"[-] FATAL: {TARGET_NOTE} not found in working directory.")
        return

    # Start Paparazzi
    t_snap = threading.Thread(target=paparazzi_thread)
    t_snap.daemon = True
    t_snap.start()

    # 3. LAUNCH
    log(f"[LAUNCH] Opening {TARGET_NOTE} via Windows Shell...")
    os.startfile(TARGET_NOTE)
    
    log("[LAUNCH] Waiting 8 seconds for application startup...")
    time.sleep(8)
    take_snapshot("startup_complete")

    # 4. FRIDA ATTACH
    try:
        log("[FRIDA] Attaching process...")
        session = frida.attach("SamsungNotes.exe")
        script = session.create_script(jscode)
        script.on("message", on_message)
        script.load()
        log("[FRIDA] Hooks injected successfully.")
    except Exception as e:
        log(f"[-] Frida Fatal Error: {e}")
        stop_threads = True
        take_snapshot("frida_error")
        os.system("taskkill /f /im SamsungNotes.exe >nul 2>&1")
        sys.exit(1)

    # 5. DRIVE UI
    t_ui = threading.Thread(target=drive_ui)
    t_ui.start()
    t_ui.join()
    
    # 6. HARVEST
    log("[HARVEST] Waiting for data stream to finish...")
    last_val = -1
    no_change = 0
    
    for _ in range(60):
        time.sleep(1)
        if len(svg_buffer) > 0 and len(svg_buffer) == last_val:
            no_change += 1
        else:
            no_change = 0
        last_val = len(svg_buffer)
        
        if len(svg_buffer) > 0 and no_change > 5:
            log("[HARVEST] Data stream stabilized. Finishing.")
            break
            
    # 7. SAVE OUTPUT
    if svg_buffer:
        log(f"[SAVE] Writing {len(svg_buffer)} strokes to {OUTPUT_SVG}...")
        with open(OUTPUT_SVG, "w", encoding="utf-8") as f:
            f.write('<?xml version="1.0" standalone="no"?>\n')
            f.write('<svg width="5000" height="200000" version="1.1" xmlns="http://www.w3.org/2000/svg" style="background-color:white">\n')
            for line in svg_buffer:
                f.write(line + "\n")
            f.write('</svg>')
        log(f"[SUCCESS] File saved: {OUTPUT_SVG}")
    else:
        log("[-] FAILURE: No data was captured. Check Debug_Screenshots folder!")

    # 8. CLEANUP
    stop_threads = True
    try: session.detach()
    except: pass
    os.system("taskkill /f /im SamsungNotes.exe >nul 2>&1")
    log("[EXIT] Process killed. Job done.")

if __name__ == "__main__":
    main()
