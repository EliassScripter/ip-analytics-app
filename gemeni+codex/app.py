import os
import json
import socket
import ipaddress
import threading
import requests
from io import StringIO
from datetime import datetime
from flask import Flask, request, render_template, jsonify, Response
from flask_sqlalchemy import SQLAlchemy
import csv
from collections import Counter

app = Flask(__name__, template_folder='.')

# Configure Database
# Uses SQLite locally (ip_logs.db) and PostgreSQL if DATABASE_URL is set (Production)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///ip_logs.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Define Database Model
class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(50))
    timestamp = db.Column(db.String(50))
    user_agent = db.Column(db.String(200))
    hostname = db.Column(db.String(100))
    # JSON columns allow us to store the nested dictionaries
    network_info = db.Column(db.JSON)
    geo = db.Column(db.JSON)

# Create tables if they don't exist
with app.app_context():
    db.create_all()

def get_network_info(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        version = "IPv4" if ip_obj.version == 4 else "IPv6"
        if version == "IPv4":
            network = ipaddress.ip_network(f"{ip_str}/24", strict=False)
            cidr = "24"
        else:
            network = ipaddress.ip_network(f"{ip_str}/64", strict=False)
            cidr = "64"
        return {
            "version": version,
            "network": str(network.network_address),
            "mask": str(network.netmask),
            "cidr": cidr
        }
    except ValueError:
        return None

def get_hostname(ip_str):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_str)
        return hostname
    except Exception:
        return "N/A"

def get_geolocation(ip_str):
    """
    Fetches Lat/Lon from ip-api.com.
    Note: This API is free but rate-limited (45 requests/minute).
    """
    # Skip local addresses
    if ip_str in ["127.0.0.1", "::1"]:
        return None
        
    try:
        url = f"http://ip-api.com/json/{ip_str}"
        response = requests.get(url, timeout=5)
        data = response.json()
        
        if data.get('status') == 'success':
            return {
                "lat": data['lat'],
                "lon": data['lon'],
                "city": data['city'],
                "country": data['countryCode']
            }
    except Exception as e:
        print(f"Geo lookup failed: {e}")
    return None

def background_worker(user_ip, user_agent, timestamp):
    # We must push the app context to access the DB inside a thread
    with app.app_context():
        # 1. DNS Lookup
        hostname = get_hostname(user_ip)
        
        # 2. Network Info
        net_info = get_network_info(user_ip)

        # 3. Geolocation
        geo_info = get_geolocation(user_ip)

        # 4. Save to Database
        new_log = Log(
            ip=user_ip,
            timestamp=timestamp,
            user_agent=user_agent,
            network_info=net_info,
            hostname=hostname,
            geo=geo_info
        )
        db.session.add(new_log)
        db.session.commit()
        
        print(f"[{timestamp}] Logged: {user_ip} | Location: {geo_info.get('city') if geo_info else 'Unknown'}")

@app.route('/lookup-ip', methods=['POST'])
def lookup_ip():
    data = request.get_json(silent=True) or {}
    ip_str = data.get('ip')
    
    if not ip_str:
        return jsonify({'error': 'No IP provided'}), 400

    try:
        ipaddress.ip_address(ip_str)
    except ValueError:
        return jsonify({'error': 'Invalid IP address format'}), 400

    geo_info = get_geolocation(ip_str)
    hostname = get_hostname(ip_str)
    net_info = get_network_info(ip_str)
    
    return jsonify({
        'ip': ip_str,
        'geo': geo_info,
        'hostname': hostname,
        'network_info': net_info
    })

@app.route('/')
def index():
    if request.headers.getlist("X-Forwarded-For"):
        user_ip = request.headers.getlist("X-Forwarded-For")[0]
    else:
        user_ip = request.remote_addr

    user_agent = request.user_agent.string
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    thread = threading.Thread(
        target=background_worker, 
        args=(user_ip, user_agent, timestamp)
    )
    thread.start()

    return "<h1>Access Recorded</h1><p>Your visit is being processed.</p>"

@app.route('/favicon.ico')
def favicon():
    # Browsers request /favicon.ico automatically; return 204 to avoid noisy 404 logs.
    return ('', 204)

@app.route('/dashboard')
def dashboard():
    logs = Log.query.all()
    
    ip_counts = Counter(log.ip for log in logs)
    subnet_counts = Counter(
        log.network_info['network'] 
        for log in logs 
        if log.network_info
    )

    # Prepare Map Data
    # We group by coordinates to calculate "Magnitude" (count of visits per location)
    map_data = {}
    for log in logs:
        if log.geo:
            # Create a unique key for the location
            key = f"{log.geo['lat']},{log.geo['lon']}"
            if key not in map_data:
                map_data[key] = {
                    "lat": log.geo['lat'],
                    "lon": log.geo['lon'],
                    "city": log.geo['city'],
                    "country": log.geo['country'],
                    "count": 0
                }
            map_data[key]["count"] += 1
    
    # Convert dict to list for JSON serialization in template
    map_points = list(map_data.values())

    # Analytics: Traffic over time (Visits per Hour)
    traffic_per_hour = Counter()
    for log in logs:
        if log.timestamp:
            # Group by hour: "YYYY-MM-DD HH:00"
            # Timestamp format is "%Y-%m-%d %H:%M:%S"
            hour_key = log.timestamp[:13] + ":00"
            traffic_per_hour[hour_key] += 1
            
    sorted_traffic = sorted(traffic_per_hour.items())
    chart_labels = [item[0] for item in sorted_traffic]
    chart_data = [item[1] for item in sorted_traffic]

    return render_template(
        'dashboard.html', 
        logs=logs, 
        ip_counts=ip_counts, 
        subnet_counts=subnet_counts,
        map_points=map_points,
        chart_labels=chart_labels,
        chart_data=chart_data
    )

@app.route('/export-csv')
def export_csv():
    logs = Log.query.all()
    
    # CSV headers
    csv_headers = ['Timestamp', 'IP Address', 'Location', 'Hostname', 'Subnet', 'User Agent']
    
    # Generate CSV safely (handles None values and escaping commas/quotes).
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(csv_headers)
    for log in logs:
        geo = log.geo or {}
        network_info = log.network_info or {}
        writer.writerow([
            log.timestamp or '',
            log.ip or '',
            f"{geo.get('city', '')}, {geo.get('country', '')}",
            log.hostname or '',
            network_info.get('network', ''),
            log.user_agent or ''
        ])
    csv_string = output.getvalue()
    
    # Return CSV file
    return Response(csv_string, mimetype="text/csv", headers={"Content-disposition": "attachment; filename=ip_logs.csv"})


if __name__ == '__main__':
    app.run(debug=True, port=5000, threaded=True)
