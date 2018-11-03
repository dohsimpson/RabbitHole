# RabbitHole

![rabbit](https://raw.githubusercontent.com/dohsimpson/rabbithole/master/alice.jpg)

> Alice started to her feet, for it flashed across her mind that she had never before seen a rabbit with either a waistcoat-pocket, or a watch to take out of it, and burning with curiosity, she ran across the field after it, and was just in time to see it pop down a large rabbit-hole under the hedge.

## Who is this for?

For anyone who uses SSH Tunnel (forward and reverse), HTTP/HTTPS proxy, or needs a remote directory mounted via SSH.

## Features

* A simple way to think about SSH tunnels
* Simple YAML syntax to define SSH tunnels
* Support Both Forward and Reverse tunnels
* Support key based and password authentication
* Support defining SSH-based Proxy
* Support mounting SSH directories
* Persistent tunnels. Broken connections are automatically recovered

## Installation

* `pip install RabbitHole-SSH`
* (Optional) To use password authentication feature, install [`sshpass`](https://linux.die.net/man/1/sshpass)
* (Optional) To use SSHFS mount feature, install [`sshfs`](https://github.com/libfuse/sshfs)

## Quick Start

1. Create a file `rabbithole.yaml` under your current directory, and paste in the following snippet, replacing HOSTNAME with the ip or hostname of an SSH server, change other attributes accordingly:

```yaml
node:
  - name: myserver
    hostname: HOSTNAME
    port: 22
    user: root
    verifyhost: false

  - name: local
    hostname: localhost

map:
  - from: 2222
    to: myserver:22
```

2. Run command `rabbithole`.

Now you have a tunnel to myserver:22 from localhost:2222. Test your access with `ssh -p 2222 root@localhost`.

See more examples in [Examples](#examples) section.

# Documentation

### Syntax Definition

```yaml
node:
  - name: NAME                 # an identifier for a SSH host
    hostname: HOSTNAME         # ip or hostname for the SSH server
    port: PORT                 # (Optional) a port number, default to 22
    key: PATH                  # (Optional) specify the private key to use
    password: PASSWORD         # (Optional) password to use for the connection
    user: USERNAME             # (Optional) username to use, default to "root"
    verifyhost: BOOL           # (Optional) whether or not to verify SSH host when connecting, default to true
    ssh_options: [OPT=VAL,...] # (Optional) Additional SSH options when connecting

map:
  - from: NODE_NAME:PORT       # This is the entry point of the tunnel, NODE_NAME default to localhost if omitted, PORT is required
    to: NODE_NAME:PORT         # This is the exit of the tunnel, NODE_NAME default to localhost if omitted, PORT is required
    bind: IP                   # (Optional) which ip to bind the tunnel to. IP default to 'localhost'. Use 'all' to bind to all interfaces.

proxy:
  - from: PORT                 # This is the entry point of the proxy
    to: NODE_NAME              # This is the proxy SSH node
    bind: IP                   # (Optional) which ip to bind the proxy to. IP default to 'localhost'. Use 'all' to bind to all interfaces.

mount:
  - from: PATH                 # This is the entry point of the SSHFS mount
    to: NODE_NAME:PATH         # This is the exit of the SSHFS mount, PATH default to home directory if omitted, NODE_NAME is required
    mkdir: BOOL                # (Optional) Whether to create the mount point if does not exist, default to false
```

### Configuration File

The YAML configuration file for RabbitHole need to be placed under current directory, `~/rabbithole.yaml`, or `/etc/rabbithole.yaml`. Files are tried in that order and the first one is used.

## Examples

* Node Definition

```yaml
node:
  - name: server1
    hostname: server1

  - name: password_only_server
    hostname: password.example.org
    password: "notmypassword!"
    user: user

  - name: an_aws_server
    hostname: 123.123.123.123
    key: ~/.ssh/ec2_key.pem
    user: ec2-user
    verifyhost: no

  - name: hidden_ssh_server
    hostname: not22.example.org
    port: 2222
```

* A Forward Tunnel

```yaml
map:
  # localhost:1234 tunneled to myserver:22
  - from: 1234  # NODE_NAME default to localhost
    to: myserver:22

  # localhost:8080 tunneled to nginx:80
  - from: localhost:8080
    to: nginx:80
```

* A Reverse Tunnel

```yaml
map:
  # SSH access bypassing a firewall
  - from: myserver:2222
    to: 22  # NODE_NAME default to localhost

  # exposing a test server to the world
  - from: www_server:80
    to: localhost:8080
```

* SOCKS5 Proxy

```yaml
proxy:
  - from: 9000
    to: uk_server
    bind: all  # open port 9000 to all interfaces

  - from: 9001
    to: us_server
    # default bind to localhost

# Test the proxy: `export http_proxy=socks5://localhost:9000/ https_proxy=socks5://localhost:9000/; curl https://ipinfo.io`
```

* SSHFS Mount

```yaml
mount:
  - from: /mnt/server1_home
    to: server1  # PATH default to home directory

  - from: /mnt/server2_root
    to: server2:/
    mkdir: true  # create /mnt/server2_root directory if it does not exist
```

## TODO

* Add support for forward tunnel through an intermediate host
* Add init script to run at startup
* Add verbose mode to print useful debug messages
* Anything else that makes sense ;)

## Bugs or Feature requests

Finding bugs and fix them, that is how software evolves. I need your help to make this software better for everyone. Feel free to open an issue or pull request and I will review it and respond.

A good software should be intuitive. I consider anything that is unintuitive about RabbitHole to be a bug too.
