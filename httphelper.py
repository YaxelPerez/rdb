from http import HTTPStatus

HTTP_METHODS = [
    'GET',
    'HEAD'
]

# stolen from https://en.wikipedia.org/wiki/List_of_HTTP_header_fields
# any future bugs stemming from this are the responsibility of
# whoever wrote that article
# HTTP_HEADERS = [
#     'Accept',
#     'Accept-Charset',
#     'Accept-Encoding',
#     'Accept-Language',
#     'Accept-Datetime',
#     'Access-Control-Request-Method',
#     'Access-Control-Request-Headers',
#     'Authorization',
#     'Cache-Control',
#     'Connection',
#     'Cookie',
#     'Content-MD5', # fun fact: obsolete probably
#     'Content-Type',
#     'Date',
#     'Expect',
#     'Forwarded',
#     'From',
#     'Host',
#     'If-Match',
#     'If-Modified-Since',
#     'If-None-Match',
#     'If-Range',
#     'If-Unmodified-Since',
#     'Max-Forwards',
#     'Origin',
#     'Pragma',
#     'Proxy-Authorization',
#     'Range',
#     'Referer',
#     'TE',
#     'User-Agent',
#     'Upgrade',
#     'Via',
#     'Warning'
# ]

STATUS_CODES = {
    v: (v.phrase, v.description)
    for v in HTTPStatus.__members__.values()
}

# consolidate all parsing errors under one exception
# so that the server just focuses on damage control
# (i.e closing the connection)
class HTTPParseError(Exception):
    pass

class HTTPResponse:
    def __init__(self, status, headers=dict(), body=None):
        self.status = status
        self.headers = headers
        self.body = body

    def __str__(self):
        s = 'HTTP/1.1 {} {}\r\n'.format(self.status, STATUS_CODES[self.status][0])
        for field_name, field_value in self.headers.items():
            s += '{}: {}\r\n'.format(field_name, field_value)
        s += '\r\n'
        if self.body:
            s += self.body
            s += '\r\n'
        return s

class HTTPRequest:
    def __init__(self):

        self.request_line = None

        self.method = None
        self.path = None
        self.version = None

        self.headers = dict()
        self._parsing_headers = True

        self.body = ''

        self.complete = False

    def build(self, line):
        if not self.request_line:
            # try to parse request line
            try:
                method, path, version = line.split()
            except ValueError:
                raise HTTPParseError('Invalid request line')

            if not method in HTTP_METHODS:
                raise HTTPParseError('Invalid HTTP method')

            try:
                version = tuple(int(i) for i in version.split('/')[1].split('.'))
            except (IndexError, ValueError):
                raise HTTPParseError

            self.method = method.upper()
            self.path = path
            self.version = version

            self.request_line = line

            return

        if line == '':
            self._parsing_headers = False
            self.complete = True
            # FUN FACT:
            # THIS WILL HANG IF THE HTTP REQUEST HAS A BODY
            # THIS IS A RARE EDGE CASE THOUGH. WE PROBABLY DON'T
            # NEED TO WORRY ABOUT IT
            return
            # serious todo: fix

        if self._parsing_headers:
            field_name, field_value = line.split(':', 1)
            self.headers[field_name] = field_value.strip()

    def __str__(self):
        s = self.request_line + '\n'
        for name, value in self.headers.items():
            s += '\t{}:{}\n'.format(name, value)
        return s
