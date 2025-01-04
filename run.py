from http.server import HTTPServer, BaseHTTPRequestHandler
import json
from wifi_scanner import WiFiInvestigator
import os
import time
import asyncio

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

class InvestigatorHandler(BaseHTTPRequestHandler):
    # Class-level shared investigator instance
    investigator = WiFiInvestigator()
    
    @classmethod
    def handle_progress(cls, progress):
        """Handle progress updates from investigator"""
        print(f"Progress: Testing '{progress['current_password']}' ({progress['attempt']}/{progress['max_attempts']})")
    
    def __init__(self, *args, **kwargs):
        # Set progress callback when instance is created
        self.__class__.investigator.set_progress_callback(self.__class__.handle_progress)
        super().__init__(*args, **kwargs)
    
    protocol_version = 'HTTP/1.1'
    
    def _send_cors_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')

    def send_json_response(self, data, status=200):
        response = json.dumps(data).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self._send_cors_headers()
        self.send_header('Content-Length', str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def do_OPTIONS(self):
        self.send_response(200)
        self._send_cors_headers()
        self.end_headers()

    def do_POST(self):
        if self.path == '/crack' or self.path == '/simulate':
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                self.send_json_response({
                    'success': False,
                    'error': 'No data received'
                }, 400)
                return

            try:
                post_data = self.rfile.read(content_length)
                data = json.loads(post_data.decode('utf-8'))
                print(f"\nStarting new investigation:")
                print(f"SSID: {data.get('ssid')}")
                print(f"Pattern: {data.get('pattern', 'dlu')}")
                print(f"Length: {data.get('min_length', 8)}-{data.get('max_length', 12)}")
                print(f"Max attempts: {data.get('max_attempts', 1000)}")
                print(f"Mode: {'Simulation' if self.path == '/simulate' else 'Real Attack'}\n")

                if 'ssid' not in data:
                    self.send_json_response({
                        'success': False,
                        'error': 'SSID is required'
                    }, 400)
                    return

                # Use class investigator instance
                result = self.investigator.crack_wifi(
                    ssid=data['ssid'],
                    pattern=data.get('pattern', 'dlu'),
                    length_range=(
                        int(data.get('min_length', 8)),
                        int(data.get('max_length', 12))
                    ),
                    max_attempts=int(data.get('max_attempts', 1000)),
                    simulation_mode=(self.path == '/simulate')
                )
                
                if result.get('success'):
                    print(f"\nSuccess! Password found: {result['password']}")
                else:
                    print(f"\nInvestigation failed: {result.get('error', 'Unknown error')}")
                
                self.send_json_response(result)
                
            except json.JSONDecodeError as e:
                print(f"Error: Invalid JSON data - {str(e)}")
                self.send_json_response({
                    'success': False,
                    'error': 'Invalid JSON data'
                }, 400)
            except Exception as e:
                print(f"Error in investigation: {str(e)}")
                self.send_json_response({
                    'success': False,
                    'error': str(e)
                }, 500)
        elif self.path == '/control':
            try:
                content_length = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_length)
                data = json.loads(post_data.decode('utf-8'))
                
                if 'action' not in data:
                    self.send_json_response({
                        'success': False,
                        'error': 'Action is required'
                    }, 400)
                    return
                
                # Use class investigator instance for control
                if data['action'] == 'pause':
                    self.investigator.pause()
                    print("Investigation paused")
                    self.send_json_response({'success': True, 'status': 'paused'})
                elif data['action'] == 'resume':
                    self.investigator.resume()
                    print("Investigation resumed")
                    self.send_json_response({'success': True, 'status': 'resumed'})
                elif data['action'] == 'stop':
                    # Force stop the investigation
                    self.investigator.stop()
                    print("Investigation stopped")
                    # Create new investigator instance to ensure clean state
                    self.investigator = WiFiInvestigator()
                    self.send_json_response({'success': True, 'status': 'stopped'})
                else:
                    self.send_json_response({
                        'success': False,
                        'error': 'Invalid action'
                    }, 400)
                
            except Exception as e:
                print(f"Error in control handler: {str(e)}")
                self.send_json_response({
                    'success': False,
                    'error': str(e)
                }, 500)
        elif self.path == '/speedtest':
            try:
                result = self.investigator.perform_speed_test()
                self.send_json_response(result)
            except Exception as e:
                print(f"Speed test error: {str(e)}")
                self.send_json_response({
                    'success': False,
                    'error': str(e)
                }, 500)
        elif self.path == '/capture':
            try:
                content_length = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_length)
                data = json.loads(post_data.decode('utf-8'))
                
                duration = int(data.get('duration', 10))
                max_packets = int(data.get('max_packets', 100))
                
                result = self.investigator.capture_packets(duration, max_packets)
                self.send_json_response(result)
            except Exception as e:
                print(f"Packet capture error: {str(e)}")
                self.send_json_response({
                    'success': False,
                    'error': str(e)
                }, 500)
        elif self.path == '/portscan':
            try:
                content_length = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_length)
                data = json.loads(post_data.decode('utf-8'))
                
                target_ip = data.get('target_ip')
                port_range = (
                    int(data.get('start_port', 1)),
                    int(data.get('end_port', 1024))
                )
                
                if not target_ip:
                    self.send_json_response({
                        'success': False,
                        'error': 'Target IP is required'
                    }, 400)
                    return
                
                result = self.investigator.scan_ports(target_ip, port_range)
                self.send_json_response(result)
            except Exception as e:
                print(f"Port scan error: {str(e)}")
                self.send_json_response({
                    'success': False,
                    'error': str(e)
                }, 500)
        elif self.path == '/dns':
            try:
                content_length = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_length)
                data = json.loads(post_data.decode('utf-8'))
                
                domain = data.get('domain')
                if not domain:
                    self.send_json_response({
                        'success': False,
                        'error': 'Domain is required'
                    }, 400)
                    return
                
                result = self.investigator.dns_lookup(domain)
                self.send_json_response(result)
            except Exception as e:
                print(f"DNS lookup error: {str(e)}")
                self.send_json_response({
                    'success': False,
                    'error': str(e)
                }, 500)
        elif self.path == '/traceroute':
            try:
                content_length = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_length)
                data = json.loads(post_data.decode('utf-8'))
                
                target = data.get('target')
                if not target:
                    self.send_json_response({
                        'success': False,
                        'error': 'Target is required'
                    }, 400)
                    return
                
                result = self.investigator.traceroute(target)
                self.send_json_response(result)
            except Exception as e:
                print(f"Traceroute error: {str(e)}")
                self.send_json_response({
                    'success': False,
                    'error': str(e)
                }, 500)
        else:
            self.send_json_response({
                'success': False,
                'error': 'Invalid endpoint'
            }, 404)

    def do_GET(self):
        try:
            # Handle scan request
            if self.path == '/scan':
                try:
                    result = self.investigator.scan()
                    self.send_json_response(result)
                except Exception as e:
                    print(f"Scan error: {str(e)}")
                    self.send_json_response({
                        'success': False,
                        'error': str(e)
                    }, 500)
                return

            # Handle file serving
            if self.path == '/' or self.path == '':
                file_path = 'index.html'
            else:
                file_path = self.path.lstrip('/')
            
            abs_path = os.path.join(BASE_DIR, file_path)
            print(f"Serving file: {abs_path}")
            
            if not os.path.exists(abs_path):
                self.send_response(404)
                self._send_cors_headers()
                self.end_headers()
                return
            
            # Read and serve file
            with open(abs_path, 'rb') as file:
                content = file.read()
                self.send_response(200)
                
                # Set content type
                if file_path.endswith('.html'):
                    content_type = 'text/html'
                elif file_path.endswith('.js'):
                    content_type = 'application/javascript'
                elif file_path.endswith('.css'):
                    content_type = 'text/css'
                else:
                    content_type = 'application/octet-stream'
                
                # Send headers and content
                self.send_header('Content-Type', content_type)
                self._send_cors_headers()
                self.send_header('Content-Length', str(len(content)))
                self.end_headers()
                self.wfile.write(content)
        except Exception as e:
            print(f"Error serving file: {str(e)}")
            self.send_response(404)
            self._send_cors_headers()
            self.end_headers()

def run(port=8000):
    try:
        print(f"Starting Law Enforcement WiFi Investigation Tool...")
        print(f"Current directory: {BASE_DIR}")
        print(f"Available files: {os.listdir(BASE_DIR)}")
        
        server = HTTPServer(('localhost', port), InvestigatorHandler)
        print(f'Server running on http://localhost:{port}')
        server.serve_forever()
    except Exception as e:
        print(f"Server error: {str(e)}")
        raise

if __name__ == '__main__':
    run()