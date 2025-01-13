FROM python:3.12-slim

WORKDIR /connector

# Clone the repository from GitHub
RUN apt-get update && apt-get install -y git \
    && git clone https://github.com/your-username/mncert-connector.git .

# Install Python dependencies
RUN pip install -r mncert-connector/requirements.txt

# Set the working directory
WORKDIR /connector/mncert-connector

ENTRYPOINT ["python3", "mncert_connector.py"]
