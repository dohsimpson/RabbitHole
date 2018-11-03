#!/usr/bin/env python
# -*- coding: utf-8 -*-

import yaml
from subprocess import Popen, PIPE
import time
import socket
from contextlib import closing
import sys
import os
import traceback
import signal

# TODO support via

LOCALHOST="127.0.0.1"
BINDALL="0.0.0.0"
DEVNULL = open(os.devnull, 'wb')

FILES = ["./rabbithole.yaml", "~/rabbithole.yaml", "/etc/rabbithole.yaml"]

def parse_node_pair(s, node=False, port=False, path=False):
    """
    can parse, use localhost when NODENAME part is omitted
    * NODENAME
    * PORT
    * PATH
    * NODENAME:PORT
    * NODENAME:PATH
    """
    a = b = None
    # s cannot be empty
    if not s:
        raise Exception("Cannot parse empty node pair")
    # at most one of port and path is true
    if port and path:
        raise Exception("port and path cannot both be True")
    # at least one of node, port and path is true
    if not any([node, port, path]):
        raise Exception("Need to specify at least one keyword argument")
    if type(s) is str:
        if ":" in s:
            l = s.split(":")
            if len(l) != 2:
                raise Exception("Invalid Syntax, only one ':' expected: {}".format(s))
            a, b = [x.strip() for x in l]
            if port:
                try:
                    b = int(b)
                except ValueError:
                    raise Exception("Unable to parse port {}".format(s))
        else:
            if node:
                a = s
            elif port:
                try:
                    b = int(s)
                except ValueError:
                    raise Exception("Tried to parse port from string '{}' but failed. Port is required!".format(s))
            else:
                b = s
    elif type(s) is int:
        b = s
    else:
        raise Exception("Unparsable Type {} for {}".format(type(s), s))
    if not a:
        if node:
            raise Exception("Host part is needed in {}".format(s))
        else:
            a = 'localhost'
    if not b:
        if port:
            raise Exception("Port part is needed in {}".format(s))
        if path:
            raise Exception("Path part is needed in {}".format(s))
        b = ""
    a = Node.get_instance(a)
    return a, b

def parse_ssh_option(s):
    """
    can parse
    * SSHOPTION=VALUE
    """
    a = b = None
    # s cannot be empty
    if not s:
        raise Exception("Cannot parse empty ssh option")
    if type(s) is str:
        if "=" in s:
            l = s.split("=")
            if len(l) != 2:
                raise Exception("Invalid Syntax, only one '=' expected: {}".format(s))
            a, b = [x.strip() for x in l]
        else:
            raise Exception("Expected '=' in ssh option, got none: {}".format(s))
    else:
        raise Exception("Unparsable Type {} for {}".format(type(s), s))
    if not a:
        raise Exception("ssh option part is empty: {}".format(s))
    if not b:
        raise Exception("Missing assignment for ssh option: {}".format(s))
    return a, b


def parse_bind(bind_addr):
    if bind_addr in ("all", "*", "0.0.0.0", "0"):
        return BINDALL
    elif bind_addr in ("localhost", "127.0.0.1"):
        return LOCALHOST
    else:
        return str(bind_addr)


def shell(s):
    print(s)
    p = Popen(s, stdin=DEVNULL, stdout=PIPE, stderr=PIPE, shell=True)
    return p

def check_port(host, port, retry=3):
    for i in range(retry):
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(1)
            try:
                s.connect((host, port))
            except socket.error as e:
                # print(e)
                if i == (retry - 1):
                    break
                else:
                    time.sleep(1)
            else:
                return True
    return False

def check_mount(path, retry=3):
    for i in range(retry):
        if os.path.ismount(path):
            return True
        else:
            time.sleep(1)
    return False

def graceful_exit(signum, frame):
    print("Shutting Down")
    l = SSHCommand._instances.values()
    for i in l:
        i.stop()
    time.sleep(1)
    for i in l:
        i.kill()
    sys.exit(0)


class FromYaml(object):
    _instances = {}

    def __init__(self, d):
        self._d = d
        self.assign_attributes()

    @property
    def allowed(self):
        return self.required + self.optional

    @classmethod
    def get_instance(cls, name):
        # search node by name
        if not cls._instances.get(name):
            raise Exception("%s is not defined" % cls._node_str(name))
        return cls._instances[name]

    def is_localhost(self):
        return parse_bind(self.hostname) == LOCALHOST

    def require(self, *args):
        missing = [k for k in args if not self._d.get(k)]
        if missing:
            raise Exception("Missing required attribute(s) for {}: {}".format(str(self), " ".join(missing)))
        return list(args)

    def require_one(self, *args):
        ks = [k for k in args if self._d.get(k)]
        if not ks:
            raise Exception("One of these attribute is required for {}: {}".format(str(self), " ".join(args)))

    def require_at_most_one(self, *args):
        ks = [k for k in args if self._d.get(k)]
        if len(ks) > 1:
            raise Exception("Only One of these attribute should be specified for {}: {}".format(str(self), " ".join(args)))

    def assign_attributes(self):
        unrecognized = [k for k in self._d if not k in self.allowed]
        if unrecognized:
            raise Exception("Unknown attribute(s) '{}' for {}".format(", ".join(unrecognized), str(self)))
        for k in self.allowed:
            v = self._d.get(k)
            if v is None:
                v = self.default.get(k)
            if v is None:
                v = ""
            if k in ["from"]:
                k = k + "_"
            setattr(self, k, v)

class SSHCommand(FromYaml):
    _instances = {}  # declare it again because we want to be able to access all subclass of SSHCommand

    def __init__(self, d):
        self.proc = None
        return super(SSHCommand, self).__init__(d)

    def ssh_command0(self, command, remote_node, prefix="ssh -N ", postfix="", excluded_ssh_options=None):
        if not excluded_ssh_options:
            excluded_ssh_options = []
        options = " ".join(["-o {}".format(o) for o in remote_node.ssh_options if parse_ssh_option(o)[0] not in excluded_ssh_options])
        remote = "-p {} {}@{}".format(remote_node.port, remote_node.user, remote_node.hostname)
        if remote_node.password:
            prefix = "sshpass -p {} ".format(remote_node.password) + prefix
        return "{}{} {} {}{}".format(prefix, options, command, remote, postfix)

    def ssh_command(self):
        pass

    def check_connection(self):
        pass

    def run(self):
        self.proc = Popen(self.ssh_command(), shell=True, stdin=DEVNULL, stdout=PIPE, stderr=PIPE, bufsize=-1)
        if self.check_connection():
            print("* {} success!".format(self))
        else:
            self.proc.terminate()
            print("* {} failed!".format(self))
            print("You may want to retry this command manually: {}".format(self.ssh_command()))
        return self.proc

    def rerun(self):
        return self.run()

    def poll(self):
        if self.proc:
            return self.proc.poll()
        else:
            return False

    def stop(self):
        if self.poll() is None:
            print("Shutting down connection {}".format(self))
            self.proc.terminate()

    def kill(self):
        if self.poll() is None:
            print("Killing connection {}".format(self))
            self.proc.kill()

class Node(FromYaml):
    def __init__(self, d):
        self._d = d
        self.required = self.require('name', 'hostname')
        # assign here so that exception can print normally
        self.name = self._d.get('name')
        self.optional = ['port', 'key', 'password', 'user', 'ssh_options', 'verifyhost', 'via', 'keepalive']
        self.require_at_most_one('key', 'password')
        self.default = {'port': 22, 'user': 'root', 'verifyhost': True, 'ssh_options': [], 'keepalive': True}
        # add node to node instance list
        Node._instances[self.name] = self
        # assign attributes
        ret = super(Node, self).__init__(d)
        if not self.verifyhost:
            self.ssh_options.append('StrictHostKeyChecking=no')
            self.ssh_options.append('UserKnownHostsFile=/dev/null')
        if self.key:
            self.ssh_options.append('IdentityFile={}'.format(self.key))
        if self.keepalive:
            self.ssh_options.append('ServerAliveInterval=10')
            # self.ssh_options.append('ServerAliveCountMax=3')  # 3 is the default value
        self.ssh_options.append('ExitOnForwardFailure=yes')

    def __repr__(self):
        return str(self)

    def __str__(self):
        return self._node_str(self.name)

    @classmethod
    def _node_str(self, name):
        return "Node '%s'" % name

class Map(SSHCommand):
    """SSH Tunnel"""
    def __init__(self, d):
        self._d = d
        self.required = self.require('from', 'to')
        # assign these here so that exception can print normally
        self.from_ = self._d['from']
        self.to = self._d['to']
        self.optional = ['bind']
        self.default = {'bind': 'localhost'}
        # add map to map instance list
        Map._instances[str(self)] = self
        return super(Map, self).__init__(d)

    def ssh_command(self):
        from_node, from_port = parse_node_pair(self.from_, port=True)
        to_node, to_port = parse_node_pair(self.to, port=True)
        bind_addr = parse_bind(self.bind)
        # port forwarding (tunnel)
        if from_node.is_localhost():
            return self.ssh_command0("-L {}:{}:{}".format(from_port, bind_addr, to_port), to_node)
        # reverse tunnel
        elif to_node.is_localhost():
            return self.ssh_command0("-R :{}:{}:{}".format(from_port, bind_addr, to_port), from_node)
        else:
            raise Exception("Not Implemented: {}".format(self))

    def check_connection(self):
        from_node, from_port = parse_node_pair(self.from_, port=True)
        to_node, to_port = parse_node_pair(self.to, port=True)
        bind_addr = parse_bind(self.bind)
        x = True
        # port forwarding (tunnel)
        if from_node.is_localhost():
            x = check_port(bind_addr, from_port)
        # reverse tunnel
        elif to_node.is_localhost():
            if bind_addr == LOCALHOST:
                pass  # open to remote localhost, impossible to check
            elif bind_addr == BINDALL:
                x = check_port(from_node.hostname, from_port)
            else:
                x = check_port(bind_addr, from_port)
        else:
            raise Exception("Not Implemented: {}".format(self))
        return x

    def run(self):
        p = super(Map, self).run()
        to_node, to_port = parse_node_pair(self.to, port=True)
        # reverse tunnel
        if to_node.is_localhost() and not self.check_connection():
            print("Reverse tunnel failed: Check if your remote sshd has enabled GatewayPorts option")
        return p

    def __repr__(self):
        return str(self)

    def __str__(self):
        return "Map '%s -> %s'" % (self.from_, self.to)

class Proxy(SSHCommand):
    """SOCKS5 Proxy"""
    def __init__(self, d):
        self._d = d
        self.required = self.require('from', 'to')
        # assign these here so that exception can print normally
        self.from_ = self._d['from']
        self.to = self._d['to']
        self.optional = ['bind']
        self.default = {'bind': 'localhost'}
        # add proxy to proxy instance list
        Proxy._instances[str(self)] = self
        return super(Proxy, self).__init__(d)

    def ssh_command(self):
        from_node, from_port = parse_node_pair(self.from_, port=True)
        to_node, to_port = parse_node_pair(self.to, node=True)
        bind_addr = parse_bind(self.bind)
        if not from_node.is_localhost():
            raise Exception('The host part of "from" attribute for {} must be localhost'.format(str(self)))
        # proxy
        return self.ssh_command0("-D {}:{}".format(from_node.hostname, from_port), to_node)
        # HERE'S HOW YOU USE IT: export http_proxy=socks5://localhost:9999/ https_proxy=socks5://localhost:9999/

    def check_connection(self):
        from_node, from_port = parse_node_pair(self.from_, port=True)
        to_node, to_port = parse_node_pair(self.to, node=True)
        bind_addr = parse_bind(self.bind)
        x = check_port(bind_addr, from_port)
        return x

    def run(self):
        return super(Proxy, self).run()

    def __repr__(self):
        return str(self)

    def __str__(self):
        return "Proxy '%s -> %s'" % (self.from_, self.to)

class Mount(SSHCommand):
    """SSHFS Mount"""
    def __init__(self, d):
        self._d = d
        self.required = self.require('from', 'to')
        # assign these here so that exception can print normally
        self.from_ = self._d['from']
        self.to = self._d['to']
        self.optional = ['bind', 'mkdir']
        self.default = {'bind': 'localhost', 'mkdir': False}
        # add mount to mount instance list
        Mount._instances[str(self)] = self
        return super(Mount, self).__init__(d)

    def ssh_command(self):
        from_node, from_path = parse_node_pair(self.from_, path=True)
        to_node, to_path = parse_node_pair(self.to, node=True)
        if not from_node.is_localhost():
            raise Exception('The host part of "from" attribute for {} must be localhost'.format(str(self)))
        # mount
        return self.ssh_command0("", to_node, prefix='sshfs -f ', postfix=":{} {}".format(to_path, from_path), excluded_ssh_options=['ExitOnForwardFailure'])

    def check_connection(self):
        from_node, from_path = parse_node_pair(self.from_, path=True)
        x = check_mount(from_path)
        return x

    def run(self):
        from_node, from_path = parse_node_pair(self.from_, path=True)
        if self.mkdir:
            shell("mkdir -p {}".format(from_path))
        return super(Mount, self).run()

    def __repr__(self):
        return str(self)

    def __str__(self):
        return "Mount '%s -> %s'" % (self.from_, self.to)

def main():
    d = None
    for f in FILES:
        try:
            with open(f, "rb") as f:
                d = yaml.load(f)
                break
        except EnvironmentError as e:
            continue

    if not d:
        raise Exception("Couldn't read config file, please make sure one of these files exists: {}".format(", ".join(FILES)))

    ks = set(['node', 'map', 'proxy', 'mount'])
    ys = set(d.keys())
    if ys - ks:
        raise Exception("Unknown attribute(s) in YAML: {}".format(", ".join(ys - ks)))
    nodes = d.get('node') or []
    maps = d.get('map') or []
    proxies = d.get('proxy') or []
    mounts = d.get('mount') or []
    if not any([maps, proxies, mounts]):
        raise Exception("You need to specify at least 1 map, proxy or mount.")
    if not nodes:
        raise Exception("You need to specify node.")

    # initialize nodes
    Node({'name': 'localhost', 'hostname': 'localhost'})
    nodes = {n['name']:Node(n) for n in nodes}

    # initialize maps, proxies and mounts
    M = [Map(x) for x in maps]
    P = [Proxy(x) for x in proxies]
    MT = [Mount(x) for x in mounts]

    # check for YAML error
    syntax_check_failed = False
    for i in M + P + MT:
        try:
            i.ssh_command()
        except Exception as e:
            print(e.message)
            syntax_check_failed = True
    if syntax_check_failed:
        sys.exit(1)

    signal.signal(signal.SIGINT, graceful_exit)
    signal.signal(signal.SIGTERM, graceful_exit)

    # run forever
    try:
        for i in M + P + MT:
            i.run()

        while True:
            time.sleep(10)
            print("Checking all connections...")
            for x in M + P + MT:
                r_code = x.poll()
                if r_code is not None:
                    print("{} exited with code {}, retrying".format(x, r_code))
                    x.rerun()
    except Exception as e:
        traceback.print_exc()
    except KeyboardInterrupt:
        print("Keyboard Interruption")
    finally:
        graceful_exit(None, None)

if __name__ == "__main__":
    main()
