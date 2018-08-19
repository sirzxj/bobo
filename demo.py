#!/usr/bin/env python3

import os
import random
from datetime import datetime
from calendar import timegm
from argparse import ArgumentParser
from base64 import urlsafe_b64encode, urlsafe_b64decode
from urllib.request import urlopen, Request
from hashlib import scrypt

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, SECP256R1, ECDH
from cryptography.hazmat.primitives.serialization import load_der_public_key

from bobo import Repo, encode_public_key, sign_message, format_message

ROOT = os.path.dirname(__file__)

def keygen():
    return generate_private_key(SECP256R1(), default_backend())

def feed_key_hash(shared_secret, key):
    return scrypt(key, salt=shared_secret, n=2**14, r=1, p=1)

def init_server(private_keys):
    repo = Repo(os.path.join(ROOT, 'server'))

    for key in private_keys:
        message = format_message(
            {"type": "feed",
             "timestamp": timegm(datetime.utcnow().utctimetuple())})
        message = sign_message(key, message)
        with repo.tempfile() as f:
            f.write(message)
        repo.index_object(repo.add_object(f.name))

def init_client(public_keys):
    repo = Repo(os.path.join(ROOT, 'client'))
    public_key = random.choice(public_keys)
    repo.index.get_feed_id(encode_public_key(public_key))

def demo_app():
    from wsgiref.util import FileWrapper
    repo = Repo(os.path.join(ROOT, 'server'))
    sessions = {}

    def application(environ, start_response):
        path = environ["PATH_INFO"]

        if path.startswith("/auth/"):
            peer_public_key = load_der_public_key(urlsafe_b64decode(path[6:]), default_backend())
            private_key = keygen()
            shared_secret = private_key.exchange(ECDH(), peer_public_key)
            public_key = encode_public_key(private_key.public_key())
            sessions[public_key] = {
                feed_key_hash(shared_secret, key) : key
                for key in repo.index.list_feed_keys() }
            start_response('200 OK', [('Content-type', 'application/octet-stream')])
            return [public_key]

        if path.startswith("/feed/"):
            public_key = urlsafe_b64decode(environ["HTTP_X_SESSION"])
            hash = urlsafe_b64decode(path[6:])
            key = sessions[public_key][hash]
            root = repo.index.get_feed_root(key)
            if root:
                start_response('200 OK', [('Content-type', 'application/octet-stream')])
                return [root]
        elif path.startswith("/blob/"):
            try:
                f = open(repo.full_path('cur', path[6:]), 'rb')
                start_response('200 OK', [('Content-type', 'application/octet-stream')])
                return FileWrapper(f)
            except FileNotFoundError:
                pass

        start_response('404 Not Found', [('Content-type', 'text/plain; charset=utf-8')])
        return [b"404 Not Found"]

    return application


def sync():
    repo = Repo(os.path.join(ROOT, 'client'))
    SERVER = 'http://127.0.0.1:8000'

    private_key = keygen()

    def auth():
        public_key = encode_public_key(private_key.public_key())
        response = urlopen(SERVER + '/auth/' + urlsafe_b64encode(public_key).decode())
        return response.read()

    peer_public_key = auth()
    shared_secret = private_key.exchange(ECDH(), load_der_public_key(peer_public_key, default_backend()))
    peer_public_key = urlsafe_b64encode(peer_public_key)

    def fetch_feed_root(key):
        hash = feed_key_hash(shared_secret, key)
        response = urlopen(
            Request(
                SERVER + '/feed/' + urlsafe_b64encode(hash).decode(),
                headers = {"X-Session": peer_public_key}))
        return response.read().decode()

    def fetch_blob(hash):
        response = urlopen(SERVER + '/blob/' + hash)
        with repo.tempfile() as f:
            f.write(response.read())
        repo.index_object(repo.add_object(f.name, hash))

    def pull():
        roots = [fetch_feed_root(key)
                 for key in repo.index.list_feed_keys()]

        while True:
            hashes = repo.index.find_objects_to_fetch(roots)
            if not hashes:
                break
            fetch_blob(hashes[0])

    pull()

def argument(*args, **kwargs):
    return lambda parser: parser.add_argument(*args, **kwargs)

class Command(object):

    def __init__(self):
        self._parser = ArgumentParser()
        self._subparsers = self._parser.add_subparsers(dest="COMMAND")
        self._commands = {}

    def __call__(self, *arguments):
        def decorator(func):
            name = func.__name__.replace("_", "-")
            subparser = self._subparsers.add_parser(name, help = func.__doc__)
            dests = [arg(subparser).dest for arg in arguments]
            def wrapper(args):
                return func(**{d:getattr(args, d, None) for d in dests})
            self._commands[name] = wrapper
            return func
        return decorator

    def run(self):
        args = self._parser.parse_args()
        return self._commands[args.COMMAND or "help"](args)


command = Command()

@command()
def init():
    private_keys = [keygen() for _ in range(5)]
    init_server(private_keys)
    init_client([key.public_key() for key in private_keys])

@command()
def server():
    from wsgiref.simple_server import make_server
    with make_server('', 8000, demo_app()) as httpd:
        print("Serving on port 8000...")
        httpd.serve_forever()

@command()
def client():
    sync()

@command()
def help():
    command._parser.print_help()


if __name__ == '__main__':
    command.run()
