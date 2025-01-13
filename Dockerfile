FROM python:3.12-slim

WORKDIR /connector

COPY . .

RUN pip install -r requirements.txt

ENTRYPOINT ["python3", "mncert_connector.py"]
