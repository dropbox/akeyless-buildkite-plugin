import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

from subprocess import PIPE, Popen, STDOUT

AKEYLESS_AUTH_METHOD = "jwt"
AKEYLESS_TOKEN_ENV_VAR = "AKEYLESS_TOKEN"

BUILDKITE_PLUGIN_CONFIGURATION = "BUILDKITE_PLUGIN_CONFIGURATION"
BUILDKITE_PLUGIN_AUDIENCE_PROPERTY = "audience"
BUILDKITE_PLUGIN_AKEYLESS_URL_PROPERTY = "akeyless_url"
BUILDKITE_PLUGIN_AUTH_ACCESS_ID_PROPERTY = "auth_access_id"
BUILDKITE_PLUGIN_AUTH_SECRET_NAME_PROPERTY = "auth_secret_name"
BUILDKITE_PLUGIN_SECRETS_PROPERTY = "secrets"
BUILDKITE_STORE_TOKEN_PROPERTY = "store_token"

DEFAULT_AUDIENCE = "buildkite"
DEFAULT_AKEYLESS_URL = "https://api.akeyless.io"

def load_plugin_config() -> None:
    cfg = os.environ.get(BUILDKITE_PLUGIN_CONFIGURATION)
    if not cfg:
        print(
            f"Error: {BUILDKITE_PLUGIN_CONFIGURATION} is not set",
            file=sys.stderr,
        )
        sys.exit(1)
    try:
        return json.loads(cfg)
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON: {e}", file=sys.stderr)
        sys.exit(1)


def make_secret_dict(config, property_name) -> dict:
    entries = config.get(property_name, [])
    if not isinstance(entries, dict):
        print(
            f"Error: `{property_name}` is not a dict in plugin configuration",
            file=sys.stderr,
        )
        sys.exit(1)

    return entries


def main() -> None:
    cfg = load_plugin_config()

    secret_dict = make_secret_dict(cfg, BUILDKITE_PLUGIN_SECRETS_PROPERTY)
    if not secret_dict:
        print("No secrets found in plugin configuration", file=sys.stderr)
        sys.exit(1)
    audience = cfg.get(BUILDKITE_PLUGIN_AUDIENCE_PROPERTY, DEFAULT_AUDIENCE)
    akeyless_url = cfg.get(BUILDKITE_PLUGIN_AKEYLESS_URL_PROPERTY, DEFAULT_AKEYLESS_URL)
    auth_access_id = cfg.get(BUILDKITE_PLUGIN_AUTH_ACCESS_ID_PROPERTY)
    store_token = cfg.get(BUILDKITE_STORE_TOKEN_PROPERTY, False)
    if not auth_access_id:
        print(
            f"Warning: {BUILDKITE_PLUGIN_AUTH_ACCESS_ID_PROPERTY} \
            is not set in plugin configuration, retrieving auth access id from agent secret..."
        )
        auth_secret_name = cfg.get(BUILDKITE_PLUGIN_AUTH_SECRET_NAME_PROPERTY)
        if not auth_secret_name:
            print(
                f"Error: {BUILDKITE_PLUGIN_AUTH_ACCESS_ID_PROPERTY} \
                or {BUILDKITE_PLUGIN_AUTH_SECRET_NAME_PROPERTY} must be set in plugin configuration",
                file=sys.stderr,
            )
            sys.exit(1)
        
        try:
            auth_access_id = subprocess.check_output(
                ["buildkite-agent", "secret", "get", auth_secret_name],
                text=True,
            )
        except subprocess.CalledProcessError as e:
            print(
                f"Error retrieving auth access ID from BuildKite agent: {e}",
                file=sys.stderr,
            )
            sys.exit(1)
        
    # First retrieve the signed OIDC JWT from BuildKite agent
    # Reference: https://buildkite.com/docs/agent/v3/cli-oidc
    print("Retrieving JWT from BuildKite...")

    try:
        # Execute buildkite-agent command to get JWT
        out = subprocess.check_output(
            ["buildkite-agent", "oidc", "request-token", "--audience", audience],
            text=True,
        )
        jwt = out.strip()

        if not jwt:
            print("Failed to retrieve OIDC JWT from BuildKite agent")
            sys.exit(1)

        print("Got JWT")
    except subprocess.CalledProcessError as e:
        print(f"Error executing buildkite-agent command: {e}", file=sys.stderr)
        sys.exit(1)

    # Present this JWT to Akeyless to get our access token
    # Reference: https://docs.akeyless.io/reference/auth
    print("Trading BuildKite's JWT for Akeyless access token...")

    auth_data = {
        "access-type": AKEYLESS_AUTH_METHOD,
        "json": True,
        "access-id": auth_access_id,
        "jwt": jwt,
    }

    try:
        auth_request = urllib.request.Request(
            "{}/auth".format(akeyless_url),
            data=json.dumps(auth_data).encode("utf-8"),
            headers={"accept": "application/json", "content-type": "application/json"},
        )

        with urllib.request.urlopen(auth_request) as response:
            auth_response_data = response.read().decode("utf-8")
            token_json = json.loads(auth_response_data)
    except urllib.error.HTTPError as e:
        print(
            f"HTTP error communicating with Akeyless API: {e}", file=sys.stderr
        )
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"Error communicating with Akeyless API: {e}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON response: {e}", file=sys.stderr)
        sys.exit(1)

    token = token_json.get("token")

    if not token:
        print("Failed to retrieve access token from Akeyless")
        sys.exit(1)

    print("Got access token")

    print("Retrieving secrets...")
    # Get the secret from Akeyless
    secret_data = {
        "json": False,
        "token": token,
        "names": list(secret_dict.values()),
    }

    try:
        secret_request = urllib.request.Request(
            "{}/get-secret-value".format(akeyless_url),
            data=json.dumps(secret_data).encode("utf-8"),
            headers={"accept": "application/json", "content-type": "application/json"},
        )

        with urllib.request.urlopen(secret_request) as response:
            secret_response_data = response.read().decode("utf-8")
            secret_result = json.loads(secret_response_data)
    except urllib.error.HTTPError as e:
        print(
            f"HTTP error communicating with Akeyless API: {e}", file=sys.stderr
        )
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"Error communicating with Akeyless API: {e}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON response: {e}", file=sys.stderr)
        sys.exit(1)

    assert isinstance(secret_result, dict), (
        "Expected Akeyless response to be a dictionary"
    )
    # Convert all secret values into the required form to redact them: {"key":"secret1","key":"secret2"}

    # Store all secrets in the environment (using buildkite-agent env) and add them to redactor
    print("Storing secrets in environment variables...")

    # Register retrieved secrets with the redactor and set in BuildKite environment
    final_mapping = dict()
    for secret_name in secret_dict:
        secret_path = secret_dict[secret_name]
        secret_value = secret_result.get(secret_path)
        if secret_value is None:
            print(
                f"Warning: Secret `{secret_name}` not found in Akeyless response",
                file=sys.stderr,
            )
            continue

        final_mapping[secret_name] = secret_value

    if not final_mapping:
        print("No valid secrets found in Akeyless response", file=sys.stderr)
        sys.exit(1)

    if store_token:
        if AKEYLESS_TOKEN_ENV_VAR in final_mapping:
            print(
                f"Warning: {AKEYLESS_TOKEN_ENV_VAR} already exists in the environment, overwriting it",
                file=sys.stderr,
            )

        print(f"Storing Akeyless token in {AKEYLESS_TOKEN_ENV_VAR}")
        final_mapping[AKEYLESS_TOKEN_ENV_VAR] = token

    # First add to redactor to ensure sensitive data is properly redacted
    print("Adding secrets to redactor...")
    
    # Ensure all secret values are properly handled as strings
    # Some secrets may contain JSON as string values, so we need to ensure
    # they are treated as strings and not parsed as nested JSON
    safe_mapping = {}
    for key, value in final_mapping.items():
        if isinstance(value, str):
            # Value is already a string, keep it as is
            safe_mapping[key] = value
        else:
            # Convert non-string values to strings
            safe_mapping[key] = str(value)
    
    # The redactor expects a flat JSON object with key-value pairs
    # as per https://buildkite.com/docs/agent/v3/cli-redactor
    try:
        redactor_json = json.dumps(
            safe_mapping,
            indent=None,
            separators=(",", ":"),
            ensure_ascii=True,
        )
    except (TypeError, ValueError) as e:
        print(
            f"Error: Failed to serialize secrets for redactor: {e}",
            file=sys.stderr,
        )
        print("Skipping redactor setup due to serialization error")
        redactor_json = None
    
    redactor_cmd = ["buildkite-agent", "redactor", "add", "--format=json"]
    
    if redactor_json:
        try:
            redactor_process = Popen(
                redactor_cmd, stdin=PIPE, stdout=PIPE, stderr=STDOUT, text=True
            )
            redactor_stdout, _ = redactor_process.communicate(input=redactor_json)
            if redactor_process.returncode != 0:
                print(
                    f"Warning: Redactor command failed with return code "
                    f"{redactor_process.returncode}: {redactor_stdout}",
                    file=sys.stderr,
                )
                # Log the JSON for debugging (but be careful not to expose secrets)
                print(
                    f"Warning: Failed to parse JSON with "
                    f"{len(final_mapping)} secrets",
                    file=sys.stderr,
                )
            else:
                print("Successfully added secrets to redactor")
        except (OSError, subprocess.SubprocessError) as e:
            print(
                f"Warning: Exception running redactor command: {e}",
                file=sys.stderr,
            )
    else:
        print("Warning: Skipping redactor due to JSON serialization failure")

    # Then set environment variables
    print("Setting environment variables...")
    
    # The env set command expects key-value pairs as an object
    # Use the same safe mapping to ensure consistency
    try:
        env_json = json.dumps(
            safe_mapping, indent=None, separators=(",", ":"), ensure_ascii=True
        )
    except (TypeError, ValueError) as e:
        print(
            f"Error: Failed to serialize secrets for environment: {e}",
            file=sys.stderr,
        )
        sys.exit(1)
    
    env_set_cmd = [
        "buildkite-agent",
        "env",
        "set",
        "--input-format=json",
        "--output-format=quiet",
        "-",
    ]
    env_process = Popen(
        env_set_cmd, stdin=PIPE, stdout=PIPE, stderr=STDOUT, text=True
    )
    env_stdout, _ = env_process.communicate(input=env_json)
    if env_process.returncode != 0:
        print(
            f"Warning: Environment setting command failed: {env_stdout}",
            file=sys.stderr,
        )
    else:
        print("Successfully set environment variables")


if __name__ == "__main__":
    main()