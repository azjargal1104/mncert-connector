FROM python:3.12-slim

# Set working directory
WORKDIR /connector

# Install Git to clone your repository
RUN apt-get update && apt-get install -y git

# Clone your GitHub repository (replace with your actual repo URL)
RUN git clone https://github.com/azjargal1104/mncert-connector.git .

# Install Python dependencies
RUN pip install -r requirements.txt

# Run the connector script
ENTRYPOINT ["python3", "mncert_connector.py"]
