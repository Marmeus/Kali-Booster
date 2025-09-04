import http.server
import socketserver
import argparse
from datetime import datetime

class CustomHandler(http.server.BaseHTTPRequestHandler):
    show_headers = False
    show_post_data = False

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")
        self.log_request_line(200)

        if CustomHandler.show_headers:
            print("Request Headers:")
            for key, value in self.headers.items():
                print(f"{key}: {value}")

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b''

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")
        self.log_request_line(200)

        if CustomHandler.show_headers:
            print("\nRequest Headers:")
            for key, value in self.headers.items():
                print(f"{key}: {value}")

        if CustomHandler.show_post_data:
            print("\nPOST Data:")
            try:
                print(post_data.decode('utf-8'))
            except UnicodeDecodeError:
                print(post_data)

    def log_request_line(self, status_code):
        client_ip = self.client_address[0]
        timestamp = datetime.now().strftime("%d/%b/%Y %H:%M:%S")
        request_line = f"{self.command} {self.path} {self.request_version}"
        log_entry = f'{client_ip} - - [{timestamp}] "{request_line}" {status_code} -'
        print(log_entry)

    def log_message(self, format, *args):
        # Override to silence default logging
        return

def run_server(port, show_headers, show_post_data):
    CustomHandler.show_headers = show_headers
    CustomHandler.show_post_data = show_post_data
    with socketserver.TCPServer(("", port), CustomHandler) as httpd:
        print(f"Serving HTTP on port {port} (headers: {show_headers}, post data: {show_post_data})...")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nServer stopped.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple HTTP server that always returns 200 OK.")
    parser.add_argument("-p", "--port", type=int, default=80, help="Port to listen on (default: 80)")
    parser.add_argument("-headers", action="store_true", help="Print client request headers to console")
    parser.add_argument("-post", action="store_true", help="Print POST request data to console")
    args = parser.parse_args()

    run_server(args.port, args.headers, args.post)

