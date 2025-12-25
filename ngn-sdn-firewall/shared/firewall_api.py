import json
from ryu.app.wsgi import ControllerBase, Response, route

FIREWALL_INSTANCE_NAME = 'firewall_app'


class FirewallAPIController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(FirewallAPIController, self).__init__(req, link, data, **config)
        self.app = data[FIREWALL_INSTANCE_NAME]

    @route('firewall', '/api/firewall/status', methods=['GET'])
    def status(self, req, **kwargs):
        payload = self.app.api_status()
        return Response(content_type='application/json', body=json.dumps(payload))

    @route('firewall', '/api/firewall/events', methods=['GET'])
    def events(self, req, **kwargs):
        try:
            limit = int(req.params.get('limit', 200))
        except ValueError:
            limit = 200
        limit = max(1, min(limit, 500))
        payload = self.app.api_events(limit)
        return Response(content_type='application/json', body=json.dumps(payload))

    @route('firewall', '/api/firewall/block', methods=['POST'])
    def block(self, req, **kwargs):
        try:
            body = req.json if req.body else {}
        except ValueError:
            return Response(status=400, body='Invalid JSON')
        ip = (body or {}).get('ip')
        seconds = (body or {}).get('seconds')
        if not ip:
            return Response(status=400, body='Missing ip')
        try:
            seconds = int(seconds) if seconds else None
        except (TypeError, ValueError):
            return Response(status=400, body='Invalid seconds')
        result = self.app.api_block_ip(ip, seconds)
        return Response(content_type='application/json', body=json.dumps(result))

    @route('firewall', '/api/firewall/unblock', methods=['POST'])
    def unblock(self, req, **kwargs):
        try:
            body = req.json if req.body else {}
        except ValueError:
            return Response(status=400, body='Invalid JSON')
        ip = (body or {}).get('ip')
        if not ip:
            return Response(status=400, body='Missing ip')
        result = self.app.api_unblock_ip(ip)
        status = 200 if result.get('removed') else 404
        return Response(status=status, content_type='application/json', body=json.dumps(result))

    @route('firewall', '/api/firewall/block_port', methods=['POST'])
    def block_port(self, req, **kwargs):
        try:
            body = req.json if req.body else {}
        except ValueError:
            return Response(status=400, body='Invalid JSON')
        port = (body or {}).get('port')
        scope = (body or {}).get('scope', 'mqtt')
        seconds = (body or {}).get('seconds')
        override_allow = (body or {}).get('override_allow', False)
        if port is None:
            return Response(status=400, body='Missing port')
        try:
            port = int(port)
        except (TypeError, ValueError):
            return Response(status=400, body='Invalid port')
        if scope not in ['mqtt', 'global']:
            return Response(status=400, body='Invalid scope')
        try:
            seconds = int(seconds) if seconds else None
        except (TypeError, ValueError):
            return Response(status=400, body='Invalid seconds')
        override_allow = bool(override_allow)
        result = self.app.api_block_port(port, scope, seconds, override_allow)
        return Response(content_type='application/json', body=json.dumps(result))

    @route('firewall', '/api/firewall/unblock_port', methods=['POST'])
    def unblock_port(self, req, **kwargs):
        try:
            body = req.json if req.body else {}
        except ValueError:
            return Response(status=400, body='Invalid JSON')
        port = (body or {}).get('port')
        scope = (body or {}).get('scope', 'mqtt')
        override_allow = (body or {}).get('override_allow', None)
        if port is None:
            return Response(status=400, body='Missing port')
        try:
            port = int(port)
        except (TypeError, ValueError):
            return Response(status=400, body='Invalid port')
        if scope not in ['mqtt', 'global']:
            return Response(status=400, body='Invalid scope')
        if override_allow is not None:
            override_allow = bool(override_allow)
        result = self.app.api_unblock_port(port, scope, override_allow)
        status = 200 if result.get('removed') else 404
        return Response(status=status, content_type='application/json', body=json.dumps(result))
