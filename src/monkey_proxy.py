"""
This script makes all headings start with emoji
"""
from mitmproxy import http


def response(flow: http.HTTPFlow) -> None:
    reflector = b"&#x1F346</a>"
    flow.response.content = flow.response.content.replace(b"</a>", reflector)
