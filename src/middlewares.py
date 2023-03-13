"""
X-Forwarded-For Proxy Fix
=========================
This module provides a middleware that adjusts the WSGI environ based on
``X-Forwarded-`` headers that proxies in front of an application may
set.
When an application is running behind a proxy server, WSGI may see the
request as coming from that server rather than the real client. Proxies
set various headers to track where the request actually came from.
This middleware should only be used if the application is actually
behind such a proxy, and should be configured with the number of proxies
that are chained in front of it. Not all proxies set all the headers.
Since incoming headers can be faked, you must set how many proxies are
setting each header so the middleware knows what to trust.
.. autoclass:: ProxyFix
:copyright: 2007 Pallets
:license: BSD-3-Clause

https://github.com/pallets/werkzeug/blob/8fe91b792fb7ff46af6372a7ffbe3d5a4f58598a/src/werkzeug/middleware/proxy_fix.py
"""
import typing as t

from werkzeug.http import parse_list_header


class ProxyFix:
    """
    Adjust the WSGI environ based on ``X-Forwarded-For`` that proxies in
    front of the application may set.
    """
    def __init__(self, app) -> None:
        self.app = app

    def _get_real_value(self, trusted: int, value: t.Optional[str]) -> t.Optional[str]:
        """Get the real value from a list header based on the configured
        number of trusted proxies.
        :param trusted: Number of values to trust in the header.
        :param value: Comma separated list header value to parse.
        :return: The real value, or ``None`` if there are fewer values
            than the number of trusted proxies.
        """
        if not (trusted and value):
            return None
        values = parse_list_header(value)
        if len(values) >= trusted:
            return values[-trusted]
        return None

    def __call__(self, environ, start_response) -> t.Iterable[bytes]:
        """Modify the WSGI environ based on the various ``Forwarded``
        headers before calling the wrapped application. Store the
        original environ values in ``werkzeug.proxy_fix.orig_{key}``.
        """

        x_for = self._get_real_value(1, environ.get("HTTP_X_FORWARDED_FOR"))
        if x_for:
            environ["REMOTE_ADDR"] = x_for
        else:
            raise KeyError("No X-Forwarded-For header found. Make sure to set it in your proxy.")
        return self.app(environ, start_response)