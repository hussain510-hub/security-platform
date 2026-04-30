FROM mcr.microsoft.com/devcontainers/base:ubuntu

# System packages
RUN apt-get update && apt-get install -y \
    python3-pip \
    curl \
    unzip \
    git \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip
RUN pip3 install --upgrade pip

# =========================
# Python DevSecOps Tools
# =========================
RUN pip3 install \
    prowler \
    scoutsuite \
    c7n \
    ansible \
    awscli \
    azure-cli

# =========================
# Terraform
# =========================
RUN curl -fsSL https://releases.hashicorp.com/terraform/1.7.5/terraform_1.7.5_linux_amd64.zip -o tf.zip \
    && unzip tf.zip \
    && mv terraform /usr/local/bin/ \
    && rm tf.zip

# =========================
# Open Policy Agent (OPA)
# =========================
RUN curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static \
    && chmod +x opa \
    && mv opa /usr/local/bin/

# Set working directory
WORKDIR /workspace
