import http.server
import json
from pathlib import Path

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            payload = {'ready': True}
        elif self.path == '/state':
            payload = {
                'counter': Path('/var/lib/pilot/counter').read_text().strip(),
                'bind': Path('/opt/pilot-data/message.txt').read_text().strip(),
                'setting': Path('/opt/pilot/setting.txt').read_text().strip(),
                'anonymous': Path('/var/lib/pilot-anonymous/token').read_text().strip(),
            }
        else:
            self.send_error(404)
            return
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass

http.server.ThreadingHTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
