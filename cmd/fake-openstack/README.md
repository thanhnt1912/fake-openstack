## Fake OpenStack API guide

This mock service keeps everything in memory and exposes a tiny subset of common OpenStack APIs so you can test client integrations without a real cloud.

### Run locally

```bash
cd /Users/mkgr3/Downloads/code/vnpost/mock-go-openstack
go build ./cmd/fake-openstack
./fake-openstack -addr :5000
```

### Run with Docker

```bash
cd /Users/mkgr3/Downloads/code/vnpost/mock-go-openstack
docker build -t mock-openstack .
docker run --rm -p 5000:5000 mock-openstack
```

**Note:** The server includes integrated Swagger UI for API documentation:
- **API Server**: http://localhost:5000
- **Swagger UI**: http://localhost:5000/swagger/ (interactive API documentation)

### Auth and token usage

1. Request a token (no credentials required):

   ```bash
   curl -i -X POST http://localhost:5000/v3/auth/tokens
   ```

2. Copy the `X-Subject-Token` header and reuse it as `X-Auth-Token` for subsequent calls (the server does not verify it, but this mirrors the real workflow).

### Core API checks

Flavors and images:

```bash
curl http://localhost:5000/v2.1/flavors/detail
curl http://localhost:5000/v2.1/images
```

Volumes and floating IP pools:

```bash
curl http://localhost:5000/v2.1/volumes
curl http://localhost:5000/v2.1/floatingips
```

Create a VM:

```bash
curl -X POST http://localhost:5000/v2.1/servers \
  -H "Content-Type: application/json" \
  -d '{
    "server": {
      "name": "demo",
      "imageRef": "img-ubuntu",
      "flavorRef": "1"
    }
  }'
```

List and inspect VMs:

```bash
curl http://localhost:5000/v2.1/servers
curl http://localhost:5000/v2.1/servers/srv-xxxx
```

Delete a VM:

```bash
curl -X DELETE http://localhost:5000/v2.1/servers/srv-xxxx
```

### Server actions

The server action endpoint accepts one action per request:

```bash
curl -X POST http://localhost:5000/v2.1/servers/srv-xxxx/action \
  -H "Content-Type: application/json" \
  -d '{ "os-stop": null }'
```

Supported payloads:

| Purpose | Payload |
| --- | --- |
| Start | `{ "os-start": null }` |
| Stop | `{ "os-stop": null }` |
| Reboot | `{ "reboot": { "type": "SOFT" } }` *(type is ignored but accepted)* |
| Attach volume | `{ "attach_volume": { "volumeId": "vol-1" } }` |
| Detach volume | `{ "detach_volume": { "volumeId": "vol-1" } }` |
| Associate floating IP | `{ "associate_floating_ip": { "floatingIpId": "fip-1" } }` |
| Disassociate floating IP | `{ "disassociate_floating_ip": { "floatingIpId": "fip-1" } }` |

Each action returns the updated server representation so you can verify status, attached volumes, and floating IP metadata.

