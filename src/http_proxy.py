#!/usr/bin/env python3

import http.server

class ReqHandler(http.server.BaseHTTPRequestHandler):
    DEFAULT_RESPONSE = """<html lang="en">
<head>
    <meta charset="utf-8">
    <title>You are being proxied</title>
</head>
<body>
    <h1>You are being proxied</h1>
</body>
</html>"""

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', len(self.DEFAULT_RESPONSE))
        self.end_headers()
        self.wfile.write(bytes(self.DEFAULT_RESPONSE, encoding='utf-8'))

if __name__ == '__main__':
    http = http.server.HTTPServer(('0.0.0.0', 8080), ReqHandler)
    http.serve_forever()
