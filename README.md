# Akeyless BuildKite Plugin

Integration between Akeyless and BuildKite with JWT authentication. Allows for secrets retrieval into environment variables.

## Requirements

1. The environment should have `python3` in $PATH
2. A JWT Auth method is created in Akeyless. See: <https://docs.akeyless.io/docs/oauth20jwt>
3. The access-id of the auth method created in (2)

## Example

Add the following to your `pipeline.yml`:

```yml
steps:
  - command: echo "Hello World"
    plugins:
      - dropbox/akeyless-buildkite-plugin:
          auth_access_id: "p-myid1729"
          secrets:
            MY_ENV_VAR1: path/to/secret/var1
            MY_ENV_VAR2: path/to/secret/var2
```

or to not expose auth access id:
```yml
steps:
  - command: echo "Hello World"
    plugins:
      - dropbox/akeyless-buildkite-plugin:
          auth_secret_name: "AUTH_ID_SECRET" # See: https://buildkite.com/docs/pipelines/security/secrets/buildkite-secrets
          secrets:
            MY_ENV_VAR1: path/to/secret/var1
            MY_ENV_VAR2: path/to/secret/var2
```

## Configuration

### `audience` (Optional, string)

The audience for the Akeyless token. Defaults to 'buildkite'. Should match the audience configured when creating the Akeyless Auth Method

### `akeyless_url` (Optional, string)

The URL of the Akeyless API server. Defaults to '<https://api.akeyless.io>'.

### `auth_access_id` (Required, string)

The Akeyless access ID for authentication. This can be retrieved either via Akeyless CLI, Console, or UI. See: <https://docs.akeyless.io/docs/oauth20jwt>.

### `auth_secret_name` (Required, string)

Use an agent secret to get `auth_access_id` instead of inputting it directly. See: https://buildkite.com/docs/pipelines/security/secrets/buildkite-secrets

### `secrets` (Required, object)

Mapping of env var to Akeyless paths - where each env var will receive the value of the Akeyless path. Invalid paths (insufficient permissions, non-existent) will be ignored.

### `store_token` (Optional, boolean)

Whether to store the Akeyless token in an environment variable. If true, the access token will be stored (and redacted) in the `AKEYLESS_TOKEN` env var. 

When used, be mindful that there is a TTL on this oken (Default: 15m).

## License

Unless otherwise noted:

```
Copyright (c) 2025 Dropbox, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
