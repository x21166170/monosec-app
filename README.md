# monosec-app
This is a test project for NCI Dublin - Web Application Security Project


# Usage
Code is built on Python3 and Flask Framework (linux-ubuntu20)

# Usage
1. Install python3.8
2. Install Python3 PIP - sudo apt-get install python3-pip
3. Install python virtual environment - sudo apt install python3-virtualenv
4. Clone the repository
5. Get inside the repository - cd monosec-app
6. Create a virtual environment - python3 -m venv .venv
7. Execute the virtual environment - source .venv/bin/activate
8. Install all dependencies in requirements.txt using PIP3
9. Create a google account or use an existing account for getting "RECAPTCHA keys" and "EMAIL CREDS"
10. Configure the environment variables
  * SECRET_KEY - A key that would be used by flask for securing the application - generate a secure randon key using python3-secrets (secrets.token_hex(16))
  * RECAPTCHA_PUBLIC_KEY - From google
  * RECAPTCHA_PUBLIC_KEY - From google
  * EMAIL_SENDER - From google
  * EMAIL_PASSWORD - From google
10. Run the module using python3 run.py
