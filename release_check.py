"""Bounded, advisory release checks. Never fetch assets or execute release content."""
import json
import re
import threading
import time
import urllib.request

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


API = 'https://api.github.com/repos/kiyanibehzad/HopHarbor/releases/latest'
RELEASES = 'https://github.com/kiyanibehzad/HopHarbor/releases'
INTERVAL = 24 * 3600


def version_tuple(value):
    if not isinstance(value, str) or not re.fullmatch(r'v?\d{1,6}\.\d{1,6}\.\d{1,6}', value):
        raise ValueError('Invalid stable version.')
    return tuple(map(int, value.lstrip('v').split('.')))


def interpret(document, current):
    if not isinstance(document, dict) or document.get('draft') is not False or document.get('prerelease') is not False:
        raise ValueError('Not a stable release.')
    tag = document.get('tag_name')
    latest = version_tuple(tag)
    url = RELEASES + '/tag/' + tag
    if document.get('html_url') != url:
        raise ValueError('Unexpected release location.')
    comparison = latest > version_tuple(current)
    return {'status': 'available' if comparison else 'current' if latest == version_tuple(current) else 'older',
            'latest_version': tag.lstrip('v'), 'url': url}


class ReleaseChecker:
    def __init__(self, path, current, write, opener=None, clock=time.time):
        self.path, self.current, self.write = path, current, write
        self.opener, self.clock = opener or urllib.request.build_opener(NoRedirect).open, clock
        self.lock = threading.Lock()
        self.running = False
        self.result = {'status': 'unchecked', 'url': RELEASES}
        self.last_attempt = 0
        try:
            if path.stat().st_size > 8192:
                raise ValueError('Oversized release cache.')
            cached = json.loads(path.read_text())
            stamp = cached['checked_at']
            if isinstance(stamp, (float, int)) and 0 <= clock() - stamp < INTERVAL:
                self.last_attempt = stamp
                if cached.get('document') is not None:
                    self.result = dict(interpret(cached['document'], current), checked_at=stamp)
                else:
                    self.result = {'status': 'unavailable', 'checked_at': stamp, 'url': RELEASES}
        except (OSError, ValueError, KeyError, TypeError):
            pass

    def snapshot(self):
        with self.lock:
            return dict(self.result, checking=self.running)

    def check(self, manual=False):
        with self.lock:
            elapsed = self.clock() - self.last_attempt
            if self.running or (self.last_attempt and 0 <= elapsed < (60 if manual else INTERVAL)):
                return False
            self.last_attempt = self.clock()
            self.running = True
        threading.Thread(target=self._fetch, daemon=True).start()
        return True

    def _fetch(self):
        stamp, document = self.last_attempt, None
        result = {'status': 'unavailable', 'url': RELEASES, 'checked_at': stamp}
        try:
            request = urllib.request.Request(API, headers={'Accept': 'application/vnd.github+json',
                                                          'User-Agent': 'HopHarbor-release-notice'})
            with self.opener(request, timeout=5) as response:
                if response.geturl() != API:
                    raise ValueError('Unexpected API redirect.')
                raw = response.read(65537)
            if len(raw) > 65536:
                raise ValueError('Release response too large.')
            candidate = json.loads(raw)
            result = dict(interpret(candidate, self.current), checked_at=stamp)
            document = {key: candidate[key] for key in ('draft', 'prerelease', 'tag_name', 'html_url')}
        except Exception:
            pass  # An outage is unknown, never "up to date".
        try:
            self.write(self.path, {'checked_at': stamp, 'document': document})
        except OSError:
            pass
        with self.lock:
            self.result, self.running = result, False
