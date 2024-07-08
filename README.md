## Running the Application with Docker

To run the application using Docker, follow these steps:

1. Ensure Docker is installed on your system. If not, download and install Docker from [here](https://www.docker.com/get-started).

2. Navigate to the directory containing the `docker-compose.yml` file.

3. Build and run the Docker containers:

```bash
docker-compose up --build
```
To stop the containers, run:
```bash
docker-compose down
```

# User Service

This repository contains backend services and API service for users and user-related services in Muimi-Chat.

## Directory Structure

<details>
<summary><strong>.github/workflows</strong> - Click to expand/collapse</summary>

- `deploy-vm.yml`: GitHub Actions workflow for deploying to VM.
</details>

<details>
<summary><strong>redisdata</strong> - Click to expand/collapse</summary>

- `.gitkeep`: Placeholder to ensure the directory is tracked by git.
</details>

<details>
<summary><strong>src</strong> - Click to expand/collapse</summary>

  <details>
  <summary><strong>muimi_user_api</strong> - Click to expand/collapse</summary>
    
  - `__init__.py`: Initialization script for Muimi User API.
  - `asgi.py`: ASGI config for Muimi User API.
  - `settings.py`: Settings for Muimi User API.
  - `urls.py`: URL config for Muimi User API.
  - `wsgi.py`: WSGI config for Muimi User API.

  </details>

  <details>
  <summary><strong>static</strong> - Click to expand/collapse</summary>
    
  - `xato-net-10-million-passwords-100000.txt`: Static text file containing passwords.
    
  </details>

  <details>
  <summary><strong>userapi</strong> - Click to expand/collapse</summary>

  - **enums**: Enumerations used across the APIs.
    - `account_status.py`: Enum defining account statuses.
    - `email_token_purpose.py`: Enum defining purposes for email tokens.
    - `log_severity.py`: Enum defining log severity levels.
  - **migrations**: Database migration scripts.
    - `0001_initial.py`: Initial database migration script.
    - `0002_alter_account_hashed_password_and_more.py`: Alteration to account hashed password.
    - `0003_alter_sessiontoken_expiry_date.py`: Alteration to session token expiry date.
    - `0004_account_authenticated_account_status.py`: Adding authenticated account status.
    - `0005_sessiontoken_encrypted_country_and_more.py`: Adding encrypted country to session token.
    - `0006_alter_sessiontoken_encrypted_country.py`: Alteration to encrypted country in session token.
    - `0007_alter_sessiontoken_hashed_token.py`: Alteration to session token hashed token.
    - `0008_commonpasswords.py`: Adding common passwords.
    - `0009_emailauthenticationtoken_consumed_and_more.py`: Adding email authentication token consumption.
    - `0010_emailhistorylog.py`: Adding email history log.
    - `0011_remove_twofasecret_account_and_more.py`: Removing 2FA secret from account.
    - `0012_delete_emailauthenticationtoken.py`: Deleting email authentication token.
    - `0013_account_totp_enabled.py`: Adding TOTP enabled flag to account.
    - `__init__.py`: Initialization script for migrations.
  - **services**: Business logic services.
    - `generate_email_verification_token.py`: Service for generating email verification tokens.
    - `generate_recovery_codes.py`: Service for generating recovery codes.
    - `generate_totp_token.py`: Service for generating TOTP tokens.
    - `get_country_from_ip.py`: Service for retrieving country from IP address.
    - `request_decrypt.py`: Service for decrypting requests.
    - `request_encrypt.py`: Service for encrypting requests.
    - `send_email_with_content.py`: Service for sending emails with content.
    - `validate_cloudflare_token.py`: Service for validating Cloudflare tokens.
    - `verify_email_verification_token.py`: Service for verifying email verification tokens.
    - `verify_recovery_code.py`: Service for verifying recovery codes.
    - `verify_totp_code.py`: Service for verifying TOTP codes.
  - **utils**: Utility modules.
    - `encrypt_email.py`: Utility for encrypting email addresses.
    - `generate_email_change_confirm_url.py`: Utility for generating email change confirmation URLs.
    - `generate_password_reset_url.py`: Utility for generating password reset URLs.
    - `generate_verification_url.py`: Utility for generating verification URLs.
    - `hash_email.py`: Utility for hashing email addresses.
    - `hash_password.py`: Utility for hashing passwords.
    - `is_valid_email.py`: Utility for validating email addresses.
    - `is_valid_password.py`: Utility for validating passwords.
    - `verify_password.py`: Utility for verifying passwords.
  - `__init__.py`: Initialization script for utilities.
  - `admin.py`: Django admin configuration (if applicable).
  - `apps.py`: Django app configuration (if applicable).
  - `controllers.py`: Controllers for handling business logic.
  - `forgot_password_routers.py`: Routers for handling forgot password requests.
  - `models.py`: Database models (if applicable).
  - `routers.py`: Main router configuration.
  - `totp_routers.py`: Routers for handling TOTP operations.
  - `urls.py`: URL configuration.
  - `user_routers.py`: Routers for handling user operations.
  </details>

- `manage.py`: Django management script (if applicable).
</details>

- `.env.example`: Example environment variable configuration file.
- `.gitignore`: Git ignore file.
- `Dockerfile`: Dockerfile for containerization.
- `LICENSE`: License information for the repository.
- `README.md`: This file, providing an overview of the repository structure and contents.
- `docker-compose.yml`: Docker Compose file for multi-container applications.
- `migration-helper.sh`: Script to assist with database migrations.
- `requirements.txt`: List of Python dependencies for the project.
