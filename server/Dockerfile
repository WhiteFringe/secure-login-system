FROM python:3.12-slim

WORKDIR /app
COPY . .

RUN apt-get update && apt-get install -y net-tools iproute2 iputils-ping \
    && pip install --no-cache-dir pycryptodome bcrypt

CMD ["/bin/bash"]
