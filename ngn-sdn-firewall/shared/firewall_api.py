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
