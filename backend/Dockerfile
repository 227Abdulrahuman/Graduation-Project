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
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN wget https://go.dev/dl/go1.23.0.linux-amd64.tar.gz && \
    rm -rf /usr/local/go && \
    tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz && \
    rm go1.23.0.linux-amd64.tar.gz


ENV GOPATH=/go
ENV PATH=$PATH:/usr/local/go/bin:$GOPATH/bin
RUN mkdir -p /go/bin

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/ffuf/ffuf/v2@latest

WORKDIR /work

COPY requirements.txt /work/
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

COPY . /work
COPY core/bins/ /usr/local/bin
RUN chmod +x /usr/local/bin/* 2>/dev/null || true

EXPOSE 8000

CMD ["python3", "backend/manage.py", "runserver", "0.0.0.0:8000"]