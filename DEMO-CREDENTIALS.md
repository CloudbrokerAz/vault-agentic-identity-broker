# Demo Credentials

Quick reference for all usernames and passwords needed to run the demo.

## Keycloak Users (Human Login)

| User  | Password             | Groups                         |
|-------|----------------------|--------------------------------|
| alice | `alice-demo-password` | data-analysts, trading-team   |
| bob   | `bob-demo-password`   | engineering                   |

## Keycloak Admin Console

| URL                          | Username | Password |
|------------------------------|----------|----------|
| http://localhost:8080/admin   | admin    | `admin`  |

## PostgreSQL

| User      | Password                 | Notes                                      |
|-----------|--------------------------|---------------------------------------------|
| postgres  | `postgres-root-password` | Root superuser                              |
| vault_admin | (rotated at bootstrap) | Initial: `vault-admin-initial-password`, invalidated after Vault rotates it |

## Vault

| URL                    | Token                          |
|------------------------|--------------------------------|
| http://localhost:8200   | See `.vault-root-token` file  |

Unseal key is in `.vault-unseal-key`. Both files are created by `bootstrap.sh`.

## Token Exchange Service

| Setting              | Value                                             |
|----------------------|---------------------------------------------------|
| Vault token          | See `.gateway.env` (`GATEWAY_VAULT_TOKEN`)        |
| Token signing secret | `token-exchange-secret-change-in-production`      |

## Demo UI

| URL                    | Notes                            |
|------------------------|----------------------------------|
| http://localhost:8500   | No login required for the UI itself. Use alice/bob credentials above for the auth steps. |

## OAuth Clients (Keycloak)

| Client ID          | Type         | Secret                      |
|--------------------|--------------|-----------------------------|
| demo-cli           | Public       | (none)                      |
| ai-agent-service   | Confidential | `ai-agent-service-secret`   |
