# vpol-rs

Evaluates Kyverno `ValidatingPolicy`'s againt plain JSON.
The JSON is bound to `object` in expressions.

## Build

```sh
cargo build --release
```

## Example policy

`policy.yaml`:

```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: max-replicas
spec:
  validations:
    - expression: object.spec.replicas <= 5
```

`-p` takes a file or a directory of `.yaml`/`.yml`/`.json` files, and can be repeated.

## `eval`: evaluate one object

```sh
vpol-rs eval -p policy.yaml --json '{"spec": {"replicas": 10}}'
```

```json
{
  "allowed": false,
  "results": [{ "policy": "max-replicas", "outcome": "fail" }]
}
```

## `serve`: evaluate over HTTP

```sh
vpol-rs serve -p policy.yaml --addr 127.0.0.1:8080
```

```sh
curl -X POST localhost:8080/evaluate \
  -H 'Content-Type: application/json' \
  -d '{"spec": {"replicas": 3}}'
```

```json
{
  "allowed": true,
  "results": [{ "policy": "max-replicas", "outcome": "pass" }]
}
```

`GET /healthz` returns `ok`.
