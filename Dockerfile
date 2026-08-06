FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc-mingw-w64-i686 \
    gcc-mingw-w64-x86-64 \
    curl \
    wget \
    unzip \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt

RUN wget -qO /tmp/openjdk-21.tar.gz https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.4%2B7/OpenJDK21U-jdk_x64_linux_hotspot_21.0.4_7.tar.gz \
    && tar -xzf /tmp/openjdk-21.tar.gz -C /opt/ \
    && rm /tmp/openjdk-21.tar.gz

ENV JAVA_HOME=/opt/jdk-21.0.4+7
ENV PATH="${JAVA_HOME}/bin:${PATH}"

# Download and extract Ghidra to /opt/ghidra
RUN wget -q https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.2_build/ghidra_12.1.2_PUBLIC_20260605.zip \
    && unzip -q ghidra_12.1.2_PUBLIC_20260605.zip \
    && mv ghidra_*_PUBLIC /opt/ghidra \
    && rm ghidra_12.1.2_PUBLIC_20260605.zip

ENV GHIDRA_INSTALL_DIR=/opt/ghidra

WORKDIR /app

COPY ./requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "./src/entry.py"]