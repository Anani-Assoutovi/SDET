
from flask import Flask, send_file, request
from flask_socketio import SocketIO
import threading
from monitor_with_ipv6 import start_monitoring, known_devices

app = Flask(__name__)
socketio = SocketIO(app, async_mode='eventlet')

@app.route("/")
def index():
    return send_file("templates/index.html")

@app.route("/download-devices")
def download_devices():
    return send_file("devices_ipv6.json", as_attachment=True)

@socketio.on("connect")
def on_connect():
    print("[Web] Client connected")
    if known_devices:
        socketio.emit("update_devices", known_devices)

@socketio.on("disconnect")
def on_disconnect():
    print("[Web] Client disconnected")

@socketio.on("ipv6_devices")
def handle_ipv6_devices(data):
    print("[Web] Received IPv6 device update:", data)

if __name__ == "__main__":
    threading.Thread(target=start_monitoring, args=(socketio,), daemon=True).start()
    port = 5000
    while True:
        try:
            socketio.run(app, host="127.0.0.1", port=port)
            break
        except OSError as e:
            if "Address already in use" in str(e):
                port += 1
            else:
                raise e
