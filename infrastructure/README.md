# Infrastructure Configuration

This directory contains OpenTofu configuration for managing infrastructure on Scaleway.

### Alternative: Environment Variables

You can also provide backend configuration via environment variables:

```bash
export SCW_ACCESS_KEY="…"
export SCW_SECRET_KEY="…"
export SCW_DEFAULT_REGION="fr-par"

# Verify & Plan infrastructure
$ > tofu plan

# Create & Update infrastructure
$ > tofu apply

Outputs:

container_hostname = "9a6XIl4RPa-jwkserve.functions.fnc.fr-par.scw.cloud"
container_id = "c26d4964-a3cc-4d59-92f1-db669a7fcab0"
container_registry = "rg.fr-par.scw.cloud/funcscw9a6XIl4RPa"
```

## Publish Containers

The container running at `jwkserve.com` is based on the initial `sbstjn/jwkserve` containers, but has a customer `--issuer` argument in use.

```bash
# Builder docker container with jwkserve.com defaults
docker build \
    --platform linux/amd64 \
    -f Dockerfile . \
    -t rg.fr-par.scw.cloud/funcscw9a6XIl4RPa/jwkserve:latest

# Push to internal registry for Scaleway Serverless Containers
docker push rg.fr-par.scw.cloud/funcscw9a6XIl4RPa/jwkserve:latest
```

## Deploy New Version

```bash
# Trigger new deployment of container
$ > scw container container deploy c26d4964-a3cc-4d59-92f1-db669a7fcab0

ID                                         c26d4964-a3cc-4d59-92f1-db669a7fcab0
Name                                       jwkserve
NamespaceID                                be9ea5b1-1e24-42e6-a0f8-5e3796c145d6
Status                                     pending
[…]

# Verify deployment
$ > scw container container get c26d4964-a3cc-4d59-92f1-db669a7fcab0

ID                                         c26d4964-a3cc-4d59-92f1-db669a7fcab0
Name                                       jwkserve
NamespaceID                                be9ea5b1-1e24-42e6-a0f8-5e3796c145d6
Status                                     ready
```