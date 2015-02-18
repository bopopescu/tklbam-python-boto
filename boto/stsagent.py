import os
import datetime
import commands

class Error(Exception):
    pass

import dateutil.parser

class Timeout(Exception):
    pass

STATUS_TIMEDOUT = 124
TIMEOUT_SECONDS = 3
TIMEOUT_RETRY = 10

def _getstatusoutput(command, timeout=TIMEOUT_SECONDS, timeout_retry=TIMEOUT_RETRY):

    def _timeout_getstatusoutput(timeout, command):
        status, output = commands.getstatusoutput("timeout %d %s" % (timeout, command))
        if os.WIFEXITED(status) and os.WEXITSTATUS(status) == STATUS_TIMEDOUT:
            raise Timeout()

        return status, output

    i = 0
    while timeout_retry == -1 or (i < timeout_retry):
        try:
            status, output = _timeout_getstatusoutput(timeout, command)
            return status, output
        except Timeout:
            pass

        i += 1

    return (STATUS_TIMEDOUT, '')

def utcnow():

    now = datetime.datetime.utcnow().replace(tzinfo=dateutil.tz.tzutc())
    return now

class STSAgent(object):
    Error = Error
    class Credentials:
        def __init__(self, access_key, secret_key, session_token, expires):
            self.access_key = access_key
            self.secret_key = secret_key
            self.session_token = session_token
            self.expires = expires

            self._expires_datetime = dateutil.parser.parse(expires)

        def __repr__(self):
            return "Credentials%s" % `(self.access_key, self.secret_key, self.session_token, self.expires)`

        def expired(self, expirationbuffer=0):
            if (utcnow() + datetime.timedelta(seconds=expirationbuffer)) > self._expires_datetime:
                return True

            return False

    def __init__(self, command, expirationbuffer=0):
        self.command = command
        self.expirationbuffer = expirationbuffer

        self.renew_credentials()

    def renew_credentials(self):
        status, output = _getstatusoutput(self.command)
        if status != 0:
            raise Error("sts agent error: " + output)

        vals = output.split()
        if len(vals) != 4:
            raise Error("expecting 4 fields from STS agent, instead received: " + output)

        ## cache renewed credentials
        self._credentials = self.Credentials(*vals)

    @property
    def credentials(self):
        if self._credentials.expired(self.expirationbuffer):
            self.renew_credentials()
        return self._credentials
