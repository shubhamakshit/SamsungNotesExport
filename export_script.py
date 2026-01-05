import os
import sys
import subprocess
import urllib.request
import time
import ctypes
import threading
import glob
import math
from datetime import datetime

# --- CONFIGURATION ---
# HuggingFace URL for the specific version of Samsung Notes that works with these hooks
SNOTES_APPX_URL = "https://huggingface.co/datasets/Jaimodiji/SAMSUNG-NOTES/resolve/main/snotes.Msixbundle"
APP_FILENAME = "SamsungNotes.Msixbundle"
TARGET_NOTE = "input_note.sdocx"
OUTPUT_SVG = "Final_Export.svg"
EXPORT_PDF_PATH = r"C:\Temp\dummy_export.pdf"

# Tuning for Smoothing
MIN_DISTANCE = 2.0   

# --- LOGGING HELPER ---
def log(msg):
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] {msg}", flush=True)

# --- GEOMETRY ENGINE (Python Side) ---
def get_midpoint(p1, p2):
    return ((p1[0] + p2[0]) / 2, (p1[1] + p2[1]) / 2)

def generate_smooth_path(stroke_data, base_color):
    """
    Converts raw stroke data into a smooth, tapered Bezier SVG path.
    """
    try:
        header, body = stroke_data.split("|", 1)
        raw_width = float(header)
        points_raw = body.split(" ")
        
        raw_points = []
        for p_str in points_raw:
            x, y, p = map(float, p_str.split(','))
            raw_points.append({'x': x, 'y': y, 'p': p})
    except: return ""

    if len(raw_points) < 2: return ""

    # 1. ADAPTIVE SCALING (Fixes the "Thick Line" issue)
    if raw_width > 3.0: base_width = raw_width * 0.35 # Calligraphy
    elif raw_width > 1.5: base_width = raw_width * 0.60 # Marker
    else: base_width = raw_width * 0.90 # Pen

    # 2. FILTER & SMOOTH PRESSURE
    clean_points = [raw_points[0]]
    for i in range(1, len(raw_points)):
        dist = math.hypot(raw_points[i]['x'] - clean_points[-1]['x'], 
                          raw_points[i]['y'] - clean_points[-1]['y'])
        if dist > MIN_DISTANCE:
            # Square pressure for sharper taper at ends
            p_smooth = (raw_points[i]['p'] + clean_points[-1]['p']) / 2
            raw_points[i]['p'] = p_smooth * p_smooth 
            clean_points.append(raw_points[i])
            
    if clean_points[-1] != raw_points[-1]: clean_points.append(raw_points[-1])
    if len(clean_points) < 2: return ""

    # 3. CALCULATE OUTLINE
    left_side = []
    right_side = []

    for i in range(len(clean_points)):
        p = clean_points[i]
        
        if i < len(clean_points) - 1:
            nxt = clean_points[i+1]
            dx, dy = nxt['x'] - p['x'], nxt['y'] - p['y']
        else:
            prev = clean_points[i-1]
            dx, dy = p['x'] - prev['x'], p['y'] - prev['y']

        len_v = math.hypot(dx, dy)
        if len_v == 0: nx, ny = 0, 0
        else: nx, ny = -dy / len_v, dx / len_v

        width = base_width * p['p']
        if width < 0.5: width = 0.5 

        left_side.append( (p['x'] + nx * width, p['y'] + ny * width) )
        right_side.append( (p['x'] - nx * width, p['y'] - ny * width) )

    # 4. SVG PATH (Q Bezier)
    d = f"M {left_side[0][0]:.2f} {left_side[0][1]:.2f} "
    
    for i in range(1, len(left_side)):
        p0 = left_side[i-1]
        p1 = left_side[i]
        mid = get_midpoint(p0, p1)
        d += f"Q {p0[0]:.2f} {p0[1]:.2f} {mid[0]:.2f} {mid[1]:.2f} "
    
    d += f"L {left_side[-1][0]:.2f} {left_side[-1][1]:.2f} "
    d += f"L {right_side[-1][0]:.2f} {right_side[-1][1]:.2f} "

    for i in range(len(right_side) - 2, -1, -1):
        p0 = right_side[i+1]
        p1 = right_side[i]
        mid = get_midpoint(p0, p1)
        d += f"Q {p0[0]:.2f} {p0[1]:.2f} {mid[0]:.2f} {mid[1]:.2f} "

    d += "Z"
    return f'<path d="{d}" fill="{base_color}" stroke="none" />'

# --- INSTALLATION LOGIC ---

def install_pip_deps():
    log("[SETUP] Installing Python Dependencies...")
    # Explicitly including pyautogui and pillow
    packages = ["frida", "frida-tools", "uiautomation", "requests", "pyautogui", "pillow"]
    subprocess.check_call([sys.executable, "-m", "pip", "install"] + packages)

def install_local_dependencies():
    log("[SETUP] Looking for Dependency Appx files in repo...")
    dep_files = glob.glob("*.Appx") + glob.glob("*.AppxBundle")
    
    if not dep_files:
        log("[SETUP] Warning: No dependency Appx files found in root.")
    
    for dep in dep_files:
        if "SamsungNotes" in dep: continue
        log(f"[SETUP] Installing Dependency: {dep}")
        try:
            subprocess.run(["powershell", "Add-AppxPackage", "-Path", f".\\{dep}"], check=True)
        except Exception as e:
            log(f"[SETUP] Warning: Failed to install {dep} ({e})")

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
                const pressurePtr = getPressure ? getPressure(this.stroke) : ptr(0);
                
                let dataStr = "";
                let hashSample = ""; 

                for (let i = 0; i < count; i++) {
                    let x = pointsPtr.add(i*8).readFloat().toFixed(2);
                    let y = pointsPtr.add(i*8+4).readFloat().toFixed(2);
                    let p = "0.5";
                    if (!pressurePtr.isNull()) {
                        p = pressurePtr.add(i*4).readFloat().toFixed(3);
                    }
                    let ptStr = `${x},${y},${p}`;
                    
                    if (i === 0) dataStr += ptStr;
                    else dataStr += " " + ptStr;

                    if (i < 3 || i > count - 3) hashSample += ptStr;
                }

                let color = "#000000";
                if (getColor) {
                    let fullHex = getColor(this.stroke).toString(16).padStart(8, '0');
                    color = "#" + fullHex.substring(2, 8);
                }
                const penSize = getPenSize ? getPenSize(this.stroke) : 2.0;
                
                // Hash to avoid duplicates
                const fullHash = count + "_" + color + "_" + hashSample;
                
                // Send raw data to Python for geometry processing
                send(`${fullHash}||${penSize}|${dataStr}||${color}`);

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
            hsh, stroke_data, color = message['payload'].split("||", 2)
            if hsh not in saved_hashes:
                saved_hashes.add(hsh)
                
                # Use the Geometry Engine to make it look nice
                svg = generate_smooth_path(stroke_data, color)
                if svg:
                    svg_buffer.append(svg)
                    if len(svg_buffer) % 50 == 0:
                        log(f"[FRIDA] Captured {len(svg_buffer)} strokes so far...")
        except: pass

def drive_ui():
    # Import inside thread to ensure it's loaded after install
    import pyautogui
    
    log("[UI] Thread Started.")
    log("[UI] Waiting 5 seconds for App Window to stabilize...")
    time.sleep(5) 
    
    # 1. Clear Popups
    log("[UI] Step 1: Clearing Popups (Pressing Enter)...")
    pyautogui.press('enter') 
    time.sleep(1)
    pyautogui.press('enter') 
    time.sleep(1)

    # 2. Navigate to Share Menu
    # UPDATED: 7 Tabs instead of 8 based on user feedback
    log("[UI] Step 2: Navigating to Toolbar (7x Tab)...")
    for i in range(7):
        pyautogui.press('tab')
        time.sleep(0.1)
    
    log("[UI] Opening Share Menu (Enter)...")
    pyautogui.press('enter') 
    time.sleep(1.5)
    
    # 3. Select PDF
    log("[UI] Step 3: Selecting PDF (Down -> Enter)...")
    pyautogui.press('down')
    time.sleep(0.2)
    pyautogui.press('enter')
    time.sleep(1.5)
    
    # 4. Click Done
    log("[UI] Step 4: Clicking Done (Enter)...")
    pyautogui.press('enter')
    time.sleep(1.5)
    
    # 5. Save Dialog
    log(f"[UI] Step 5: Handling Save Dialog...")
    
    if not os.path.exists("C:\\Temp"): 
        os.makedirs("C:\\Temp")

    pyautogui.write(EXPORT_PDF_PATH)
    time.sleep(0.5)
    pyautogui.press('enter')
    time.sleep(1.0)
    
    # Confirm Overwrite
    log("[UI] Handling potential Overwrite popup...")
    pyautogui.press('left')
    pyautogui.press('enter')
    
    log("[UI] Automation Sequence Complete.")

def main():
    # 1. INSTALLATION
    install_pip_deps()
    install_local_dependencies()
    install_samsung_notes()
    
    # Late import
    import frida

    if not os.path.exists(TARGET_NOTE):
        log(f"[-] FATAL: {TARGET_NOTE} not found in working directory.")
        return

    # 2. LAUNCH
    log(f"[LAUNCH] Opening {TARGET_NOTE} via Windows Shell...")
    os.startfile(TARGET_NOTE)
    
    log("[LAUNCH] Waiting 8 seconds for application startup...")
    time.sleep(8)

    # 3. FRIDA ATTACH
    try:
        log("[FRIDA] Attaching process...")
        session = frida.attach("SamsungNotes.exe")
        script = session.create_script(jscode)
        script.on("message", on_message)
        script.load()
        log("[FRIDA] Hooks injected successfully.")
    except Exception as e:
        log(f"[-] Frida Fatal Error: {e}")
        os.system("taskkill /f /im SamsungNotes.exe >nul 2>&1")
        sys.exit(1)

    # 4. DRIVE UI
    t = threading.Thread(target=drive_ui)
    t.start()
    t.join()
    
    # 5. HARVEST
    log("[HARVEST] Waiting for data stream to finish...")
    last_val = -1
    no_change = 0
    
    # Wait max 60 seconds for export to complete
    for _ in range(60):
        time.sleep(1)
        if len(svg_buffer) > 0 and len(svg_buffer) == last_val:
            no_change += 1
        else:
            no_change = 0
        last_val = len(svg_buffer)
        
        # If we have data and it hasn't changed for 5 seconds, we assume export is done
        if len(svg_buffer) > 0 and no_change > 5:
            log("[HARVEST] Data stream stabilized. Finishing.")
            break
            
    # 6. SAVE OUTPUT
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
        log("[-] FAILURE: No data was captured. The export might have failed or UI nav was blocked.")

    # 7. CLEANUP
    try:
        session.detach()
    except: pass
    os.system("taskkill /f /im SamsungNotes.exe >nul 2>&1")
    log("[EXIT] Process killed. Job done.")

if __name__ == "__main__":
    main()
