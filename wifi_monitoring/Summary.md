# Summary of WiFi Activity Monitor Codebase

## 1. `monitor_with_ipv6.py`
This Python script is responsible for scanning and tracking devices connected to a network via both IPv4 and IPv6. Key features include:

- **Device Tracking**: Maintains `devices_combined.json` to persist known devices and their status (online/offline).
- **Event Logging**: Captures scan events into `network_events_combined.log`.
- **Dual Stack Monitoring**:
  - IPv4: Uses ARP and DNS sniffing to detect devices.
  - IPv6: Uses NDP (Neighbor Discovery Protocol) and DNS sniffing.
- **WebSocket Support**: Broadcasts device updates to clients via WebSocket.
- **Data Handling**: Periodically merges and saves data with timestamps like `last_seen`, `last_online`, `last_offline`.

## 2. `app.py`
This file defines a **Flask web server** to serve both the frontend and handle WebSocket connections for real-time device updates.

- **Flask App Setup**:
  - Hosts the static files (HTML, JS) and provides the dashboard.
- **SocketIO Integration**:
  - Listens for client connections.
  - Emits updates for IPv4 and IPv6 devices.
- **Scheduler**: Runs background tasks (e.g. calling `scan_loop`) to periodically scan the network.
- **Logging**: Outputs connection and disconnection events, device updates.

## 3. `index.html`
This is the **frontend interface** for visualizing WiFi activity.

- **UI Components**:
  - Filters by IP address and status (online/offline).
  - Two tables to display active IPv4 and IPv6 devices.
  - Export buttons to download CSV files.
  - Toggle for dark mode.
- **WebSocket Client**:
  - Connects to the backend to receive device updates.
  - Displays debug messages and updates charts/tables dynamically.
- **Device Data Display**:
  - Shows IP, MAC, interface, status, last seen, online/offline times, and source (scanned/sniffed).

## How to Run the Application

1. **Install dependencies**:
   ```bash
   pip install flask flask-socketio eventlet scapy
   python monitor_with_ipv6.py
   sudo python app.py
   
