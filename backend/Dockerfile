FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONPATH=/work

RUN apt-get update && apt-get install -y \
    python3 \
    tree \
    jq \
    vim \
    python3-pip \
    libpcap-dev \
    libssl-dev \
    curl \
    wget \
    build-essential \
    nmap \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN npm install -g @google/gemini-cli

RUN npm i -g @openai/codex

RUN wget https://go.dev/dl/go1.23.0.linux-amd64.tar.gz && \
    rm -rf /usr/local/go && \
    tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz && \
    rm go1.23.0.linux-amd64.tar.gz


ENV GOPATH=/go
ENV PATH=$PATH:/usr/local/go/bin:$GOPATH/bin
RUN mkdir -p /go/bin

RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

WORKDIR /work

COPY requirements.txt /work/
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

COPY . /work
COPY core/bins/ /usr/local/bin
RUN chmod +x /usr/local/bin/* 2>/dev/null || true

RUN mkdir -p /opt/js-analyzer && \
    cp /work/core/js_analysis/tools/JavaScript-Sinks-Analyzer/package*.json /opt/js-analyzer/ && \
    cd /opt/js-analyzer && npm install

ENV NODE_PATH=/opt/js-analyzer/node_modules

EXPOSE 8000

CMD ["python3", "backend/manage.py", "runserver", "0.0.0.0:8000"]