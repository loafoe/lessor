# lessor

Caddy based plugin to dynamically inject `X-Scope-OrgID` header values into Loki bound requests.

## Building

You first need to build a new caddy executable with this plugin. The easiest way is to do this with xcaddy.

Install xcaddy :

```shell
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
```

After xcaddy installation you can build caddy with this plugin by executing:

```shell
xcaddy build v2.6.4 --with github.com/loafoe/lessor
```

## Configuration

**TODO**

## License

Apache 2.0
