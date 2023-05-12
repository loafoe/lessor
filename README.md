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

### Helm

Use the included `Helm` chart to deploy. Example `values.yaml`

```yaml
issuer: https://dex.hsp.hostedzonehere.com/

loki:
  url: loki-gateway.observability.svc
  
ingress:
  enabled: true
  className: "nginx"
  hosts:
    - host: lessor.test.hostedzonehere.com
      paths:
        - path: /
          pathType: ImplementationSpecific
```

Then deploy:

```shell
helm template lessor charts/lessor --skip-tests --values values.yaml|kubectl apply -f - -n lessor
```

Once deployed you can configure your Grafana Data source to point to `https://lessor.test.hostedzonehere.com`.
Make sure you enable the `Forward OAuth Identity` option so lessor can extract tenant claims and inject the `X-Scope-OrgID`

## License

Apache 2.0
