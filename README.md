# NixForge - Secure Manager Node with k3s + Data Services

A secure, production-ready NixOS configuration for managing a k3s Kubernetes cluster with PostgreSQL, monitoring, and observability tools.

## Security Notice

This repository is designed to be **safe for public hosting**. Sensitive information like SSH keys and IP addresses are abstracted and loaded from external sources.

## Prerequisites

- Nix with flakes enabled
- Age key for sops-nix (for secrets encryption)
- SSH access to target server

## Setup Instructions

### 1. Clone and Configure Environment

```bash
git clone <your-repo-url>
cd NixForge

# Set environment variables for your deployment
export SERVER_IP="your.server.ip.address"
export SERVER_GATEWAY="your.gateway.ip"
export SERVER_INTERFACE="your.network.interface"
```

### 2. Set Up Secrets

Create the secrets directory and age key:

```bash
mkdir -p secrets
# Generate age key (keep this secure!)
age-keygen -o secrets/key.txt
```

Create your encrypted secrets file:

```bash
# Create secrets.yaml with your SSH keys and other secrets
cat > secrets/secrets.yaml << EOF
ssh_keys:
  root: |
    ssh-ed25519 ...
  ruud: |
    ssh-ed25519 ...

# Add other secrets as needed
# server_ip: "192.168.1.0"
# server_gateway: "192.164.22.33"
EOF

# Encrypt the secrets
sops --encrypt --in-place secrets/secrets.yaml
```

### 3. Deploy

Using Colmena:

```bash
# First build to check for errors
colmena build

# Deploy to server
colmena apply
```

## Architecture

- **k3s**: Lightweight Kubernetes distribution
- **PostgreSQL 16**: With PostGIS, pgvector, and TimescaleDB extensions
- **Prometheus + Grafana**: Observability stack
- **Nginx Ingress**: For service exposure
- **sops-nix**: Secrets management
- **Disko**: Declarative disk partitioning

## Security Features

- SSH key-only authentication
- Encrypted secrets with sops-nix
- Firewall with minimal open ports
- fail2ban for intrusion prevention
- System auto-upgrades
- Kernel hardening

## Environment Variables

- `SERVER_IP`: Server's public IP address
- `SERVER_GATEWAY`: Network gateway IP
- `SERVER_INTERFACE`: Network interface name (default: enp10s0f1np1)

## Development

For local development with macOS builder:

```bash
# Build macOS configuration
darwin-rebuild build --flake .#builder
```

## Ports

- 22: SSH
- 80/443: HTTP/HTTPS (for ingress)
- 6443: k3s API
- 5432: PostgreSQL
- 3000: Grafana
- 9090: Prometheus

## License

MIT