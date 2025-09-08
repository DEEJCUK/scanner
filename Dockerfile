FROM python:3.11-slim

WORKDIR /opt/scanner

# install minimal packages (ping)
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    iputils-ping \
  && rm -rf /var/lib/apt/lists/*

# copy requirements and install
COPY requirements.txt /opt/scanner/requirements.txt
RUN pip install --no-cache-dir -r /opt/scanner/requirements.txt

# copy app and templates
COPY network_scanner_app.py /opt/scanner/network_scanner_app.py
COPY templates/ /opt/scanner/templates/

# create data directory (mounted by compose)
RUN mkdir -p /data && chown -R root:root /data

EXPOSE 8888

# run as foreground service (no tty)
CMD ["python", "/opt/scanner/network_scanner_app.py", "--host", "0.0.0.0", "--port", "8888"]