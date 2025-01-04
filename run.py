from http.server import HTTPServer, BaseHTTPRequestHandler
import json
from wifi_scanner import WiFiScanner
import os
import traceback

# Get the directory containing the script
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

class WifiHandler(BaseHTTPRequestHandler):
    def send_json_response(self, data, status=200):
        try:
            if not isinstance(data, dict):
                data = {'success': False, 'error': 'Invalid response data'}
            
            response = json.dumps(data)
            self.send_response(status)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Content-Length', str(len(response.encode('utf-8'))))
            self.end_headers()
            self.wfile.write(response.encode('utf-8'))
        except Exception as e:
            print(f"Error sending JSON response: {str(e)}")
            self.send_error(500, str(e))

    def do_GET(self):
        print(f"Received request for path: {self.path}")
        
        if self.path == '/scan' or self.path == '/scan/':
            try:
                scanner = WiFiScanner()
                result = scanner.scan()
                if isinstance(result, dict) and not result.get('success', False):
                    self.send_json_response({
                        'success': False,
                        'error': result.get('error', 'Unknown error')
                    })
                else:
                    self.send_json_response({
                        'success': True,
                        'networks': result.get('networks', [])
                    })
            except Exception as e:
                print(f"Scan error: {str(e)}")
                self.send_json_response({
                    'success': False,
                    'error': str(e)
                })
            return
            
        try:
            # Handle file paths
            if self.path == '/':
                file_path = 'index.html'
            else:
                file_path = self.path.lstrip('/')
                
            # Construct absolute file path
            abs_path = os.path.join(BASE_DIR, file_path)
            print(f"Trying to serve file: {abs_path}")  # Debug log
            
            if not os.path.exists(abs_path):
                print(f"File not found: {abs_path}")
                self.send_error(404)
                return
                
            with open(abs_path, 'rb') as file:
                content = file.read()
                self.send_response(200)
                
                if file_path.endswith('.html'):
                    self.send_header('Content-type', 'text/html')
                elif file_path.endswith('.js'):
                    self.send_header('Content-type', 'application/javascript')
                elif file_path.endswith('.css'):
                    self.send_header('Content-type', 'text/css')
                    
                self.send_header('Content-Length', str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                
        except Exception as e:
            print(f"Error serving file: {str(e)}")
            self.send_error(404)

def run(port=8000):
    try:
        # Print current directory and files for debugging
        print(f"Current directory: {BASE_DIR}")
        print("Available files:", os.listdir(BASE_DIR))
        
        server = HTTPServer(('', port), WifiHandler)
        print(f'Server running on http://localhost:{port}')
        server.serve_forever()
    except Exception as e:
        print(f"Server error: {str(e)}")
        raise

if __name__ == '__main__':
    run()