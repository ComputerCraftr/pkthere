FROM alpine:latest

RUN apk add --no-cache \
    iputils \
    iptables \
    libcap \
    py3-pip \
    python3 \
    su-exec \
    && pip3 install --break-system-packages --no-cache-dir scapy \
    && addgroup -S pkthere \
    && adduser -S -G pkthere pkthere

COPY .artifacts/alpine/ /usr/local/libexec/pkthere/
COPY docker/__init__.py /opt/pkthere/docker/__init__.py
COPY docker/alpine/__init__.py /opt/pkthere/docker/alpine/__init__.py
COPY docker/alpine/harness.py /opt/pkthere/docker/alpine/harness.py
COPY docker/alpine/pkthere_harness/ /opt/pkthere/docker/alpine/pkthere_harness/

ENV PKTHERE_ALLOW_RAW_ICMP=1

WORKDIR /opt/pkthere
ENTRYPOINT ["python3", "-m", "docker.alpine.harness"]
