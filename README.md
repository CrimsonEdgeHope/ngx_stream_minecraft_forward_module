# Nginx Stream Module ngx_stream_minecraft_forward_module

The `ngx_stream_minecraft_forward_module` module attempts to modify [Handshake](https://wiki.vg/Protocol#Handshake) packet and inspect [Login Start](https://wiki.vg/Protocol#Login_Start) packet that's sent from client to server.

> [!IMPORTANT]
> - This module relies on [stream module](https://nginx.org/en/docs/stream/ngx_stream_core_module.html).
> - Only suitable for Minecraft Java protocol since Netty rewrite.
> - Nginx no earlier than 1.11.5 can pass compilation with this module.

## Compilation

```shell
NGINX_VER=1.24.0
wget -O "nginx.tar.gz" "https://nginx.org/download/nginx-${NGINX_VER}.tar.gz"
tar -xf nginx.tar.gz
cd nginx-${NGINX_VER}
chmod +x configure
./configure --add-module=/path/to/ngx_stream_minecraft_forward_module --with-stream
make
```

## Directives

- Syntax: `minecraft_server_forward  off|on;` <br/>
  Default: `minecraft_server_forward  off;` <br/>
  Context: server <br/>

  Indicate a server block that proxies Minecraft Java tcp connections.

> [!CAUTION]
> Set to `on` only when upstream server is a Minecraft Java server, otherwise proxy won't function properly.

- Syntax: `minecraft_server_hostname  hostname.to.be.replaced  new.hostname  [arbitrary];` <br/>
  Default: None <br/>
  Context: stream, server <br/>

  When a client starts logging process, replace client-provided server hostname with a new hostname before proxying to remote Minecraft server.

  If Nginx is compiled with PCRE, the module applies a simple validation against `hostname.to.be.replaced` and `new.hostname`. Set `arbitrary` option to bypass the validation.

> [!TIP]
> Due to differences in Minecraft Java protocol specification, should there be a SRV record `_minecraft._tcp.a.domain.for.example.com` that points to `another.domain.for.example.com`, consider define two replacements:

```
minecraft_server_hostname  a.domain.for.example.com        new.domain.for.example.com;
minecraft_server_hostname  another.domain.for.example.com  new.domain.for.example.com;
```

- Syntax: `minecraft_server_hostname_hash_max_size  size;` <br/>
  Default: `minecraft_server_hostname_hash_max_size  512;` <br/>
  Context: stream, server <br/>

  Set the maximum size of hash tables used by `minecraft_server_hostname` directive.

- Syntax: `minecraft_server_hostname_hash_bucket_size  size;` <br/>
  Default: `minecraft_server_hostname_hash_bucket_size  64;` <br/>
  Context: stream, server <br/>

  Set the bucket size for hash tables used by `minecraft_server_hostname` directive.

- Syntax: `minecraft_server_hostname_disconnect_on_nomatch  off|on;` <br/>
  Default: `minecraft_server_hostname_disconnect_on_nomatch  off;` <br/>
  Context: stream, server <br/>

  Close connection if client-provided server hostname matches no replacement.

- Syntax: `minecraft_server_hostname_replace_on_ping  off|on;` <br/>
  Default: `minecraft_server_hostname_replace_on_ping  on;` <br/>
  Context: stream, server <br/>

  When a client starts pinging, replace client-provided server hostname with a new hostname before proxying to remote Minecraft server. This option is recommended pinging servers behind third-party services (e.g. TCPShield.com) that impose inspection of pinging packets.
