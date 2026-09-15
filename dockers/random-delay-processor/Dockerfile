FROM python:3.10-slim

RUN apt-get update && apt-get install -y iputils-ping && \
    pip install --upgrade pip && \
    pip install nats-py scapy matplotlib pandas numpy

WORKDIR /code/random-delay-processor