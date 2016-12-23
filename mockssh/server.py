import logging
import os
import select
import socket
import subprocess
import threading

try:
    from queue import Queue
except ImportError:  # Python 2.7
    from Queue import Queue

import paramiko

from mockssh import sftp


__all__ = [
    "Server",
]


SERVER_KEY_PATH = os.path.join(os.path.dirname(__file__), "server-key")


class Handler(paramiko.ServerInterface):

    log = logging.getLogger(__name__)

    def __init__(self, server, client_conn):
        self.server = server
        self.thread = None
        self.command_queues = {}
        client, _ = client_conn
        self.transport = t = paramiko.Transport(client)
        t.add_server_key(paramiko.RSAKey(filename=SERVER_KEY_PATH))
        t.set_subsystem_handler("sftp", sftp.SFTPServer)

    def run(self):
        self.transport.start_server(server=self)
        while True:
            channel = self.transport.accept()
            if channel is None:
                break
            self.command_queues[channel.get_id()] = Queue()
            t = threading.Thread(target=self.handle_client, args=(channel,))
            t.setDaemon(True)
            t.start()

    def handle_client(self, channel):
        try:
            command = self.command_queues[channel.get_id()].get(block=True)
            self.log.debug("Executing %s", command)
            p = subprocess.Popen(command, shell=True,
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            stdout, stderr = p.communicate()
            channel.sendall(stdout)
            channel.sendall_stderr(stderr)
            channel.send_exit_status(p.returncode)
        except Exception:
            self.log.error("Error handling client (channel: %s)", channel,
                           exc_info=True)
        finally:
            channel.close()

    def check_auth_publickey(self, username, key):
        try:
            known_public_key = self.server._users[username].k
        except KeyError:
            self.log.debug("Unknown user '%s'", username)
            return paramiko.AUTH_FAILED
        if known_public_key == key:
            self.log.debug("Accepting public key for user '%s'", username)
            return paramiko.AUTH_SUCCESSFUL
        self.log.debug("Rejecting public ley for user '%s'", username)
        return paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        if username not in self.server._users:
            self.log.debug("Unknown user '%s'", username)
            return paramiko.AUTH_FAILED
        if password == self.server._users[username].password:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_exec_request(self, channel, command):
        self.command_queues.setdefault(channel.get_id(), Queue()).put(command)
        return True

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return "publickey, password"


class User(object):
    def __init__(self, uid, password=None, private_key_path=None, private_key_password=None):
        self.uid = uid
        self.password = password
        self.private_key_path = private_key_path
        self.private_key_password = private_key_password
        self.pkey = None
        if self.private_key_path:
            self.pkey = paramiko.RSAKey.from_private_key_file(private_key_path, password=private_key_password)
            self.k = self.pkey


class Server(object):

    host = "127.0.0.1"

    log = logging.getLogger(__name__)

    def __init__(self, users):
        """
        :param users: list of User objects
        """
        self._socket = None
        self._thread = None
        # backwards compatibility
        if isinstance(users, dict):
            users = [User(uid=uid, private_key_path=key_path) for uid, key_path in users.iteritems()]
        self._users = {user.uid:user for user in users}

    def add_user(self, uid, private_key_path):
        self._users[uid] = User(uid=uid, private_key_path=private_key_path)

    def __enter__(self):
        self._socket = s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((self.host, 0))
        s.listen(5)
        self._thread = t = threading.Thread(target=self._run)
        t.setDaemon(True)
        t.start()
        return self

    def _run(self):
        sock = self._socket
        while sock.fileno() > 0:
            self.log.debug("Waiting for incoming connections ...")
            rlist, _, _ = select.select([sock], [], [], 1.0)
            if rlist:
                conn, addr = sock.accept()
                self.log.debug("... got connection %s from %s", conn, addr)
                handler = Handler(self, (conn, addr))
                t = threading.Thread(target=handler.run)
                t.setDaemon(True)
                t.start()

    def __exit__(self, *exc_info):
        try:
            self._socket.shutdown(socket.SHUT_RDWR)
            self._socket.close()
        except Exception:
            pass
        self._socket = None
        self._thread = None

    def client(self, uid):
        user = self._users[uid]
        c = paramiko.SSHClient()
        host_keys = c.get_host_keys()
        key = paramiko.RSAKey.from_private_key_file(SERVER_KEY_PATH)
        host_keys.add(self.host, "ssh-rsa", key)
        host_keys.add("[%s]:%d" % (self.host, self.port), "ssh-rsa", key)
        c.set_missing_host_key_policy(paramiko.RejectPolicy())
        c.connect(hostname=self.host,
                  port=self.port,
                  username=uid,
                  password=user.password,
                  # key_filename=user.private_key_path,
                  pkey=user.pkey,
                  allow_agent=False,
                  look_for_keys=False)
        return c

    @property
    def port(self):
        return self._socket.getsockname()[1]

    @property
    def users(self):
        return self._users.keys()
