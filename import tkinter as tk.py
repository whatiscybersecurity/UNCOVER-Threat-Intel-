#01010101 01001110 01000011 01001111 01010110 01000101 01010010
#   U        N        C        O        V        E        R
#
#  ██╗   ██╗███╗   ██╗ ██████╗ ██████╗ ██╗   ██╗███████╗██████╗ 
#  ██║   ██║████╗  ██║██╔════╝██╔═══██╗██║   ██║██╔════╝██╔══██╗
#  ██║   ██║██╔██╗ ██║██║     ██║   ██║██║   ██║█████╗  ██████╔╝
#  ██║   ██║██║╚██╗██║██║     ██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗
#  ╚██████╔╝██║ ╚████║╚██████╗╚██████╔╝ ╚████╔╝ ███████╗██║  ██║
#   ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝
#
#               [ IP Threat Intelligence Tool ]
#           https://github.com/whatiscybersecurity
#                   ░▒▓█ FEATURES █▓▒░                     
#  ├─► AbuseIPDB Integration    ├─► Shodan API Lookup  
#  ├─► Nmap Port Scanning       ├─► IP Geolocation      
#  └─► Interactive Map View     └─► Dark/Light Mode   


import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import requests
import subprocess
import threading
import shutil

# Try to import tkintermapview, show message if not installed
try:
    from tkintermapview import TkinterMapView
    MAP_AVAILABLE = True
except ImportError:
    MAP_AVAILABLE = False

# Check if nmap is available
NMAP_AVAILABLE = shutil.which('nmap') is not None

# Color Schemes
LIGHT_THEME = {
    'bg': '#f8fafc',
    'card_bg': '#ffffff',
    'text': '#1e293b',
    'text_secondary': '#64748b',
    'accent': '#3b82f6',
    'accent_hover': '#2563eb',
    'success': '#10b981',
    'danger': '#ef4444',
    'warning': '#f59e0b',
    'purple': '#8b5cf6',
    'border': '#e2e8f0',
    'input_bg': '#f1f5f9',
    'result_bg': '#ffffff',
}

DARK_THEME = {
    'bg': '#0f172a',
    'card_bg': '#1e293b',
    'text': '#f1f5f9',
    'text_secondary': '#94a3b8',
    'accent': '#3b82f6',
    'accent_hover': '#60a5fa',
    'success': '#10b981',
    'danger': '#ef4444',
    'warning': '#f59e0b',
    'purple': '#a78bfa',
    'border': '#334155',
    'input_bg': '#334155',
    'result_bg': '#1e293b',
}

current_theme = LIGHT_THEME
is_dark_mode = False
current_marker = None
nmap_running = False


def apply_text_tags(text_widget):
    """Apply text tags for styling the result output."""
    theme = current_theme
    text_widget.tag_config('title', foreground=theme['accent'], font=('Segoe UI', 13, 'bold'))
    text_widget.tag_config('highlight', foreground=theme['success'], font=('Segoe UI', 11, 'bold'))
    text_widget.tag_config('default', foreground=theme['text'], font=('Segoe UI', 11))
    text_widget.tag_config('bad_score', foreground=theme['danger'], font=('Segoe UI', 12, 'bold'))
    text_widget.tag_config('good_score', foreground=theme['success'], font=('Segoe UI', 12, 'bold'))
    text_widget.tag_config('label', foreground=theme['text_secondary'], font=('Segoe UI', 10))
    text_widget.tag_config('warning', foreground=theme['warning'], font=('Segoe UI', 11, 'bold'))
    text_widget.tag_config('purple', foreground=theme['purple'], font=('Segoe UI', 11, 'bold'))
    text_widget.tag_config('port_open', foreground=theme['danger'], font=('Segoe UI', 11))
    text_widget.tag_config('service', foreground=theme['purple'], font=('Segoe UI', 11))


def apply_theme():
    """Apply the current theme to all widgets."""
    theme = current_theme
    
    # Main window
    app.configure(bg=theme['bg'])
    
    # Header
    header_frame.configure(bg=theme['card_bg'])
    title_label.configure(bg=theme['card_bg'], fg=theme['accent'])
    subtitle_label.configure(bg=theme['card_bg'], fg=theme['text_secondary'])
    
    # Input card
    input_card.configure(bg=theme['card_bg'])
    api_label.configure(bg=theme['card_bg'], fg=theme['text'])
    ip_label.configure(bg=theme['card_bg'], fg=theme['text'])
    shodan_label.configure(bg=theme['card_bg'], fg=theme['text'])
    
    # Entry styling
    api_key_entry.configure(
        bg=theme['input_bg'],
        fg=theme['text'],
        insertbackground=theme['text'],
        relief='flat',
        highlightthickness=2,
        highlightbackground=theme['border'],
        highlightcolor=theme['accent']
    )
    ip_entry.configure(
        bg=theme['input_bg'],
        fg=theme['text'],
        insertbackground=theme['text'],
        relief='flat',
        highlightthickness=2,
        highlightbackground=theme['border'],
        highlightcolor=theme['accent']
    )
    shodan_key_entry.configure(
        bg=theme['input_bg'],
        fg=theme['text'],
        insertbackground=theme['text'],
        relief='flat',
        highlightthickness=2,
        highlightbackground=theme['border'],
        highlightcolor=theme['accent']
    )
    
    # Buttons
    check_button.configure(
        bg=theme['accent'],
        activebackground=theme['accent_hover']
    )
    shodan_button.configure(
        bg=theme['purple'],
        activebackground=theme['purple']
    )
    nmap_button.configure(
        bg=theme['warning'],
        activebackground=theme['warning']
    )
    dark_mode_button.configure(
        text="☀️ Light Mode" if is_dark_mode else "🌙 Dark Mode",
        bg=theme['card_bg'],
        fg=theme['text'],
        activebackground=theme['border'],
        activeforeground=theme['text']
    )
    
    # Results area
    results_card.configure(bg=theme['card_bg'])
    results_label.configure(bg=theme['card_bg'], fg=theme['text'])
    result_text.configure(
        bg=theme['result_bg'],
        fg=theme['text'],
        insertbackground=theme['text'],
        relief='flat',
        highlightthickness=1,
        highlightbackground=theme['border'],
        highlightcolor=theme['border']
    )
    
    # Map card
    map_card.configure(bg=theme['card_bg'])
    map_label.configure(bg=theme['card_bg'], fg=theme['text'])
    map_info_label.configure(bg=theme['card_bg'], fg=theme['text_secondary'])
    
    # Content frame
    content_frame.configure(bg=theme['bg'])
    left_column.configure(bg=theme['bg'])
    right_column.configure(bg=theme['bg'])
    
    # Button frames
    button_frame.configure(bg=theme['card_bg'])
    button_frame2.configure(bg=theme['card_bg'])
    
    # Reapply text tags
    apply_text_tags(result_text)


def toggle_dark_mode():
    """Toggle between light and dark mode."""
    global current_theme, is_dark_mode
    is_dark_mode = not is_dark_mode
    current_theme = DARK_THEME if is_dark_mode else LIGHT_THEME
    apply_theme()


def get_ip_geolocation(ip_address):
    """Get latitude and longitude for an IP address using ip-api.com (free)."""
    try:
        response = requests.get(f'http://ip-api.com/json/{ip_address}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                return {
                    'lat': data.get('lat'),
                    'lon': data.get('lon'),
                    'city': data.get('city', 'Unknown'),
                    'region': data.get('regionName', 'Unknown'),
                    'country': data.get('country', 'Unknown'),
                    'isp': data.get('isp', 'Unknown')
                }
    except Exception as e:
        print(f"Geolocation error: {e}")
    return None


def update_map(ip_address, location_data=None):
    """Update the map with the IP location."""
    global current_marker
    
    if not MAP_AVAILABLE:
        map_info_label.configure(text="📍 Map unavailable - install tkintermapview")
        return
    
    if location_data and location_data.get('lat') and location_data.get('lon'):
        lat = location_data['lat']
        lon = location_data['lon']
        city = location_data.get('city', 'Unknown')
        country = location_data.get('country', 'Unknown')
        
        # Remove previous marker
        if current_marker:
            current_marker.delete()
        
        # Set map position and zoom
        map_widget.set_position(lat, lon)
        map_widget.set_zoom(10)
        
        # Add marker
        current_marker = map_widget.set_marker(
            lat, lon,
            text=f"{ip_address}\n{city}, {country}",
            marker_color_circle="#ef4444",
            marker_color_outside="#dc2626"
        )
        
        # Update info label
        map_info_label.configure(text=f"📍 {city}, {country} ({lat:.4f}, {lon:.4f})")
    else:
        map_info_label.configure(text="📍 Location data unavailable for this IP")
        # Reset map to world view
        map_widget.set_position(20, 0)
        map_widget.set_zoom(2)
        if current_marker:
            current_marker.delete()
            current_marker = None


def check_shodan():
    """Query Shodan API for open ports and services."""
    ip_address = ip_entry.get().strip()
    shodan_key = shodan_key_entry.get().strip()
    
    if not ip_address:
        messagebox.showwarning("Input Error", "Please provide an IP address.")
        return
    
    if not shodan_key:
        messagebox.showwarning("Input Error", "Please provide your Shodan API key.")
        return
    
    # Show loading state
    shodan_button.configure(text="Querying...", state='disabled')
    app.update()
    
    try:
        url = f'https://api.shodan.io/shodan/host/{ip_address}?key={shodan_key}'
        response = requests.get(url, timeout=15)
        
        if response.status_code == 404:
            result_text.insert(tk.END, "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", 'default')
            result_text.insert(tk.END, "  🔍 SHODAN RESULTS\n", 'purple')
            result_text.insert(tk.END, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n", 'default')
            result_text.insert(tk.END, "  No information available for this IP in Shodan.\n", 'default')
            result_text.see(tk.END)
            return
        
        response.raise_for_status()
        data = response.json()
        
        # Display Shodan results
        result_text.insert(tk.END, "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", 'default')
        result_text.insert(tk.END, "  🔍 SHODAN RESULTS\n", 'purple')
        result_text.insert(tk.END, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n", 'default')
        
        # General Info
        result_text.insert(tk.END, "  HOST INFORMATION\n", 'label')
        result_text.insert(tk.END, f"  IP: {data.get('ip_str', 'N/A')}\n", 'default')
        result_text.insert(tk.END, f"  Organization: {data.get('org', 'N/A')}\n", 'default')
        result_text.insert(tk.END, f"  ISP: {data.get('isp', 'N/A')}\n", 'default')
        result_text.insert(tk.END, f"  ASN: {data.get('asn', 'N/A')}\n", 'default')
        
        # OS Detection
        if data.get('os'):
            result_text.insert(tk.END, f"  OS: {data.get('os')}\n", 'warning')
        
        # Hostnames
        hostnames = data.get('hostnames', [])
        if hostnames:
            result_text.insert(tk.END, f"  Hostnames: {', '.join(hostnames)}\n", 'default')
        
        # Vulnerabilities
        vulns = data.get('vulns', [])
        if vulns:
            result_text.insert(tk.END, f"\n  ⚠️ VULNERABILITIES ({len(vulns)} found)\n", 'label')
            for vuln in vulns[:10]:  # Show first 10
                result_text.insert(tk.END, f"  • {vuln}\n", 'bad_score')
            if len(vulns) > 10:
                result_text.insert(tk.END, f"  ... and {len(vulns) - 10} more\n", 'default')
        
        # Open Ports and Services
        ports = data.get('ports', [])
        if ports:
            result_text.insert(tk.END, f"\n  🔓 OPEN PORTS ({len(ports)} found)\n", 'label')
            for item in data.get('data', []):
                port = item.get('port', 'N/A')
                transport = item.get('transport', 'tcp')
                product = item.get('product', '')
                version = item.get('version', '')
                
                service_info = f"{product} {version}".strip() if product else item.get('_shodan', {}).get('module', 'Unknown')
                
                result_text.insert(tk.END, f"  • Port ", 'default')
                result_text.insert(tk.END, f"{port}/{transport}", 'port_open')
                result_text.insert(tk.END, f" - ", 'default')
                result_text.insert(tk.END, f"{service_info}\n", 'service')
                
                # Show banner snippet if available
                banner = item.get('data', '')
                if banner and len(banner) > 0:
                    banner_preview = banner[:100].replace('\n', ' ').replace('\r', '')
                    if len(banner) > 100:
                        banner_preview += "..."
                    result_text.insert(tk.END, f"    └─ {banner_preview}\n", 'label')
        
        # Tags
        tags = data.get('tags', [])
        if tags:
            result_text.insert(tk.END, f"\n  🏷️ TAGS\n", 'label')
            result_text.insert(tk.END, f"  {', '.join(tags)}\n", 'warning')
        
        result_text.insert(tk.END, "\n", 'default')
        result_text.see(tk.END)
        
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            messagebox.showerror("Error", "Invalid Shodan API key.")
        elif e.response.status_code == 403:
            messagebox.showerror("Error", "Access denied. Check your Shodan API key permissions.")
        else:
            messagebox.showerror("Error", f"Shodan API error: {e}")
    except requests.exceptions.RequestException as e:
        messagebox.showerror("Error", f"Network error: {e}")
    except Exception as e:
        messagebox.showerror("Error", f"Error: {e}")
    finally:
        shodan_button.configure(text="🔍 Shodan Lookup", state='normal')


def run_nmap_scan():
    """Run nmap scan in a separate thread."""
    global nmap_running
    
    if nmap_running:
        messagebox.showwarning("Scan in Progress", "An Nmap scan is already running.")
        return
    
    if not NMAP_AVAILABLE:
        messagebox.showerror("Nmap Not Found", 
            "Nmap is not installed or not in PATH.\n\n"
            "Install Nmap from: https://nmap.org/download.html\n\n"
            "Make sure to add it to your system PATH.")
        return
    
    ip_address = ip_entry.get().strip()
    
    if not ip_address:
        messagebox.showwarning("Input Error", "Please provide an IP address.")
        return
    
    # Confirm scan
    confirm = messagebox.askyesno("Confirm Nmap Scan", 
        f"Run Nmap scan on {ip_address}?\n\n"
        "This will perform a service version detection scan (-sV).\n"
        "The scan may take 1-5 minutes to complete.\n\n"
        "Note: Only scan IPs you have permission to scan!")
    
    if not confirm:
        return
    
    # Start scan in background thread
    nmap_running = True
    nmap_button.configure(text="⏳ Scanning...", state='disabled')
    
    result_text.insert(tk.END, "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", 'default')
    result_text.insert(tk.END, "  🔧 NMAP SCAN\n", 'warning')
    result_text.insert(tk.END, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n", 'default')
    result_text.insert(tk.END, f"  Scanning {ip_address}... Please wait.\n", 'default')
    result_text.insert(tk.END, "  (This may take 1-5 minutes)\n\n", 'label')
    result_text.see(tk.END)
    app.update()
    
    thread = threading.Thread(target=execute_nmap, args=(ip_address,))
    thread.daemon = True
    thread.start()


def execute_nmap(ip_address):
    """Execute nmap command and display results."""
    global nmap_running
    
    try:
        # Run nmap with service version detection
        # -sV: Version detection
        # -T4: Faster timing
        # --top-ports 100: Scan top 100 ports for speed
        cmd = ['nmap', '-sV', '-T4', '--top-ports', '100', ip_address]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        # Update UI from main thread
        app.after(0, lambda: display_nmap_results(result.stdout, result.stderr))
        
    except subprocess.TimeoutExpired:
        app.after(0, lambda: display_nmap_error("Scan timed out after 5 minutes."))
    except Exception as e:
        app.after(0, lambda: display_nmap_error(str(e)))
    finally:
        nmap_running = False
        app.after(0, lambda: nmap_button.configure(text="🔧 Nmap Scan", state='normal'))


def display_nmap_results(stdout, stderr):
    """Display nmap results in the result text widget."""
    if stderr and not stdout:
        result_text.insert(tk.END, f"  ⚠️ Error: {stderr}\n", 'bad_score')
        result_text.see(tk.END)
        return
    
    # Parse and display nmap output
    lines = stdout.split('\n')
    in_ports_section = False
    
    for line in lines:
        line = line.strip()
        
        if not line:
            continue
        
        # Skip some verbose lines
        if line.startswith('Starting Nmap') or line.startswith('Nmap scan report'):
            result_text.insert(tk.END, f"  {line}\n", 'default')
        elif line.startswith('Host is'):
            result_text.insert(tk.END, f"  ✓ {line}\n", 'good_score')
        elif 'PORT' in line and 'STATE' in line and 'SERVICE' in line:
            result_text.insert(tk.END, f"\n  {line}\n", 'label')
            in_ports_section = True
        elif in_ports_section and ('open' in line or 'closed' in line or 'filtered' in line):
            if 'open' in line:
                result_text.insert(tk.END, f"  {line}\n", 'port_open')
            elif 'closed' in line:
                result_text.insert(tk.END, f"  {line}\n", 'good_score')
            else:
                result_text.insert(tk.END, f"  {line}\n", 'warning')
        elif line.startswith('Service Info'):
            result_text.insert(tk.END, f"\n  {line}\n", 'service')
        elif line.startswith('Nmap done'):
            result_text.insert(tk.END, f"\n  ✓ {line}\n", 'highlight')
    
    result_text.insert(tk.END, "\n", 'default')
    result_text.see(tk.END)


def display_nmap_error(error_msg):
    """Display nmap error in the result text widget."""
    result_text.insert(tk.END, f"  ⚠️ Scan Error: {error_msg}\n\n", 'bad_score')
    result_text.see(tk.END)


def check_ip():
    """Checks the provided IP against the AbuseIPDB API and displays the results."""
    global current_marker
    
    ip_address = ip_entry.get().strip()
    api_key = api_key_entry.get().strip()

    if not ip_address or not api_key:
        messagebox.showwarning("Input Error", "Please provide both IP address and AbuseIPDB API key.")
        return

    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90',
    }

    # Show loading state
    check_button.configure(text="Checking...", state='disabled')
    map_info_label.configure(text="📍 Locating IP...")
    app.update()

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()['data']

        # Get geolocation data for the map
        geo_data = get_ip_geolocation(ip_address)
        update_map(ip_address, geo_data)

        # Clear previous results
        result_text.delete(1.0, tk.END)

        # Display header
        result_text.insert(tk.END, f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", 'default')
        result_text.insert(tk.END, f"  Results for: {data.get('ipAddress', 'N/A')}\n", 'title')
        result_text.insert(tk.END, f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n", 'default')
        
        # Abuse Score with visual indicator
        abuse_score = data.get('abuseConfidenceScore', 'N/A')
        if isinstance(abuse_score, int):
            abuse_color = 'bad_score' if abuse_score >= 50 else 'good_score'
            score_bar = "█" * (abuse_score // 10) + "░" * (10 - abuse_score // 10)
            result_text.insert(tk.END, f"  THREAT LEVEL\n", 'label')
            result_text.insert(tk.END, f"  {score_bar}  {abuse_score}%\n\n", abuse_color)
        else:
            result_text.insert(tk.END, f"  Abuse Confidence Score: {abuse_score}\n\n", 'default')

        # Report Statistics
        result_text.insert(tk.END, f"  REPORT STATISTICS\n", 'label')
        result_text.insert(tk.END, f"  Total Reports: {data.get('totalReports', 'N/A')}\n", 'default')
        result_text.insert(tk.END, f"  Last Reported: {data.get('lastReportedAt', 'Never')}\n\n", 'default')

        # Location Info (enhanced with geo data)
        result_text.insert(tk.END, f"  LOCATION\n", 'label')
        country_name = data.get('countryName', 'N/A')
        country_code = data.get('countryCode', 'N/A')
        result_text.insert(tk.END, f"  Country: {country_name} ({country_code})\n", 'default')
        
        if geo_data:
            result_text.insert(tk.END, f"  City: {geo_data.get('city', 'N/A')}\n", 'default')
            result_text.insert(tk.END, f"  Region: {geo_data.get('region', 'N/A')}\n", 'default')
            result_text.insert(tk.END, f"  Coordinates: {geo_data.get('lat', 'N/A')}, {geo_data.get('lon', 'N/A')}\n", 'default')
        result_text.insert(tk.END, "\n", 'default')

        # Network Info
        result_text.insert(tk.END, f"  NETWORK INFORMATION\n", 'label')
        result_text.insert(tk.END, f"  ISP: {data.get('isp', 'N/A')}\n", 'default')
        result_text.insert(tk.END, f"  Domain: {data.get('domain', 'N/A')}\n", 'default')
        result_text.insert(tk.END, f"  Usage Type: {data.get('usageType', 'N/A')}\n", 'default')
        result_text.insert(tk.END, f"  ASN: {data.get('asn', 'N/A')}\n", 'default')
        
        hostnames = data.get('hostnames', [])
        if hostnames:
            result_text.insert(tk.END, f"  Hostnames: {', '.join(hostnames)}\n", 'default')
        result_text.insert(tk.END, "\n", 'default')

        # IP Properties
        result_text.insert(tk.END, f"  IP PROPERTIES\n", 'label')
        result_text.insert(tk.END, f"  Public: {'Yes' if data.get('isPublic') else 'No'}\n", 'default')
        result_text.insert(tk.END, f"  Shared: {'Yes' if data.get('isShared') else 'No'}\n", 'default')
        
        netblock = data.get('netblock')
        if netblock:
            result_text.insert(tk.END, f"  Netblock: {netblock}\n", 'default')

        if data.get('isWhitelisted', False):
            result_text.insert(tk.END, "\n  ✓ This IP is whitelisted\n", 'highlight')

        # Report Categories
        total_reports = data.get('totalReports', 0)
        if isinstance(total_reports, int) and total_reports > 0:
            result_text.insert(tk.END, f"\n  REPORT CATEGORIES\n", 'label')
            for category in data.get('reportCategories', []):
                result_text.insert(tk.END, f"  • {category}\n", 'highlight')
        else:
            result_text.insert(tk.END, "\n  ✓ No abuse reports found for this IP\n", 'good_score')

    except requests.exceptions.RequestException as e:
        messagebox.showerror("Error", f"An error occurred: {e}")
    except KeyError as e:
        messagebox.showerror("Error", f"Error parsing API response: {e}")
    finally:
        check_button.configure(text="🔍  Check IP", state='normal')


# Set up the main application window
app = tk.Tk()
app.title("IP Threat Intelligence Tool")
app.geometry('1200x900')
app.configure(bg=LIGHT_THEME['bg'])

# Make window resizable
app.minsize(1000, 800)

# Header Section
header_frame = tk.Frame(app, bg=LIGHT_THEME['card_bg'], pady=15)
header_frame.pack(fill='x', padx=0, pady=0)

title_label = tk.Label(
    header_frame,
    text="🛡️ IP Threat Intelligence Tool",
    font=('Segoe UI', 24, 'bold'),
    bg=LIGHT_THEME['card_bg'],
    fg=LIGHT_THEME['accent']
)
title_label.pack()

subtitle_label = tk.Label(
    header_frame,
    text="AbuseIPDB • Shodan • Nmap Integration",
    font=('Segoe UI', 11),
    bg=LIGHT_THEME['card_bg'],
    fg=LIGHT_THEME['text_secondary']
)
subtitle_label.pack(pady=(5, 0))

# Main Content Frame (horizontal layout)
content_frame = tk.Frame(app, bg=LIGHT_THEME['bg'])
content_frame.pack(fill='both', expand=True, padx=20, pady=15)

# Left Column (Input + Results)
left_column = tk.Frame(content_frame, bg=LIGHT_THEME['bg'])
left_column.pack(side='left', fill='both', expand=True, padx=(0, 10))

# Input Card
input_card = tk.Frame(left_column, bg=LIGHT_THEME['card_bg'], padx=25, pady=20)
input_card.pack(fill='x', pady=(0, 15))

# IP Address (moved to top for better UX)
ip_label = tk.Label(
    input_card,
    text="IP Address",
    font=('Segoe UI', 11, 'bold'),
    bg=LIGHT_THEME['card_bg'],
    fg=LIGHT_THEME['text'],
    anchor='w'
)
ip_label.pack(fill='x', pady=(0, 5))

ip_entry = tk.Entry(
    input_card,
    font=('Segoe UI', 11),
    bg=LIGHT_THEME['input_bg'],
    fg=LIGHT_THEME['text'],
    relief='flat',
    highlightthickness=2,
    highlightbackground=LIGHT_THEME['border'],
    highlightcolor=LIGHT_THEME['accent']
)
ip_entry.pack(fill='x', ipady=8, pady=(0, 12))

# AbuseIPDB API Key
api_label = tk.Label(
    input_card,
    text="AbuseIPDB API Key",
    font=('Segoe UI', 11, 'bold'),
    bg=LIGHT_THEME['card_bg'],
    fg=LIGHT_THEME['text'],
    anchor='w'
)
api_label.pack(fill='x', pady=(0, 5))

api_key_entry = tk.Entry(
    input_card,
    font=('Segoe UI', 11),
    bg=LIGHT_THEME['input_bg'],
    fg=LIGHT_THEME['text'],
    relief='flat',
    highlightthickness=2,
    highlightbackground=LIGHT_THEME['border'],
    highlightcolor=LIGHT_THEME['accent'],
    show='•'
)
api_key_entry.pack(fill='x', ipady=8, pady=(0, 12))

# Shodan API Key
shodan_label = tk.Label(
    input_card,
    text="Shodan API Key (Optional)",
    font=('Segoe UI', 11, 'bold'),
    bg=LIGHT_THEME['card_bg'],
    fg=LIGHT_THEME['text'],
    anchor='w'
)
shodan_label.pack(fill='x', pady=(0, 5))

shodan_key_entry = tk.Entry(
    input_card,
    font=('Segoe UI', 11),
    bg=LIGHT_THEME['input_bg'],
    fg=LIGHT_THEME['text'],
    relief='flat',
    highlightthickness=2,
    highlightbackground=LIGHT_THEME['border'],
    highlightcolor=LIGHT_THEME['accent'],
    show='•'
)
shodan_key_entry.pack(fill='x', ipady=8, pady=(0, 12))

# Button Frame - Row 1
button_frame = tk.Frame(input_card, bg=LIGHT_THEME['card_bg'])
button_frame.pack(fill='x', pady=(5, 5))

# Check Button (AbuseIPDB)
check_button = tk.Button(
    button_frame,
    text="🔍  Check IP",
    command=check_ip,
    font=('Segoe UI', 11, 'bold'),
    fg='white',
    bg=LIGHT_THEME['accent'],
    activebackground=LIGHT_THEME['accent_hover'],
    activeforeground='white',
    relief='flat',
    cursor='hand2',
    padx=20,
    pady=10,
    bd=0
)
check_button.pack(side='left', padx=(0, 10))

# Shodan Button
shodan_button = tk.Button(
    button_frame,
    text="🔍 Shodan Lookup",
    command=check_shodan,
    font=('Segoe UI', 11, 'bold'),
    fg='white',
    bg=LIGHT_THEME['purple'],
    activebackground=LIGHT_THEME['purple'],
    activeforeground='white',
    relief='flat',
    cursor='hand2',
    padx=20,
    pady=10,
    bd=0
)
shodan_button.pack(side='left', padx=(0, 10))

# Nmap Button
nmap_button = tk.Button(
    button_frame,
    text="🔧 Nmap Scan",
    command=run_nmap_scan,
    font=('Segoe UI', 11, 'bold'),
    fg='white',
    bg=LIGHT_THEME['warning'],
    activebackground=LIGHT_THEME['warning'],
    activeforeground='white',
    relief='flat',
    cursor='hand2',
    padx=20,
    pady=10,
    bd=0
)
nmap_button.pack(side='left')

# Button Frame - Row 2
button_frame2 = tk.Frame(input_card, bg=LIGHT_THEME['card_bg'])
button_frame2.pack(fill='x', pady=(5, 0))

# Dark Mode Button
dark_mode_button = tk.Button(
    button_frame2,
    text="🌙 Dark Mode",
    command=toggle_dark_mode,
    font=('Segoe UI', 10),
    fg=LIGHT_THEME['text'],
    bg=LIGHT_THEME['card_bg'],
    activebackground=LIGHT_THEME['border'],
    activeforeground=LIGHT_THEME['text'],
    relief='flat',
    cursor='hand2',
    padx=15,
    pady=8,
    bd=0
)
dark_mode_button.pack(side='right')

# Results Card
results_card = tk.Frame(left_column, bg=LIGHT_THEME['card_bg'], padx=25, pady=20)
results_card.pack(fill='both', expand=True)

results_label = tk.Label(
    results_card,
    text="Results",
    font=('Segoe UI', 11, 'bold'),
    bg=LIGHT_THEME['card_bg'],
    fg=LIGHT_THEME['text'],
    anchor='w'
)
results_label.pack(fill='x', pady=(0, 10))

# Result Text Area
result_text = scrolledtext.ScrolledText(
    results_card,
    width=55,
    height=22,
    wrap=tk.WORD,
    bg=LIGHT_THEME['result_bg'],
    fg=LIGHT_THEME['text'],
    font=('Consolas', 10),
    relief='flat',
    highlightthickness=1,
    highlightbackground=LIGHT_THEME['border'],
    highlightcolor=LIGHT_THEME['border'],
    padx=12,
    pady=12
)
result_text.pack(fill='both', expand=True)

# Right Column (Map)
right_column = tk.Frame(content_frame, bg=LIGHT_THEME['bg'])
right_column.pack(side='right', fill='both', expand=True, padx=(10, 0))

# Map Card
map_card = tk.Frame(right_column, bg=LIGHT_THEME['card_bg'], padx=25, pady=20)
map_card.pack(fill='both', expand=True)

map_label = tk.Label(
    map_card,
    text="🗺️ IP Location",
    font=('Segoe UI', 11, 'bold'),
    bg=LIGHT_THEME['card_bg'],
    fg=LIGHT_THEME['text'],
    anchor='w'
)
map_label.pack(fill='x', pady=(0, 5))

map_info_label = tk.Label(
    map_card,
    text="📍 Enter an IP address to view location",
    font=('Segoe UI', 10),
    bg=LIGHT_THEME['card_bg'],
    fg=LIGHT_THEME['text_secondary'],
    anchor='w'
)
map_info_label.pack(fill='x', pady=(0, 10))

# Map Widget
if MAP_AVAILABLE:
    map_widget = TkinterMapView(map_card, corner_radius=8)
    map_widget.pack(fill='both', expand=True)
    map_widget.set_position(20, 0)  # Default world view
    map_widget.set_zoom(2)
else:
    # Fallback if tkintermapview is not installed
    map_placeholder = tk.Frame(map_card, bg='#e2e8f0', height=400)
    map_placeholder.pack(fill='both', expand=True)
    map_placeholder.pack_propagate(False)
    
    install_label = tk.Label(
        map_placeholder,
        text="📦 Map feature requires tkintermapview\n\nInstall it with:\npy -m pip install tkintermapview",
        font=('Segoe UI', 11),
        bg='#e2e8f0',
        fg='#64748b',
        justify='center'
    )
    install_label.place(relx=0.5, rely=0.5, anchor='center')

# Apply initial text tags
apply_text_tags(result_text)

# Bind Enter key to check IP
ip_entry.bind('<Return>', lambda e: check_ip())

# Start the main event loop
app.mainloop()