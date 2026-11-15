# CyberRed tool image: the sandbox external tools run in.
# NOTE: not yet built or tested in CI. Treat as a starting point; pin versions/digests before relying on it.
#   docker build -t cyberred/tools:latest docker/
FROM kalilinux/kali-rolling

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates nmap ffuf sqlmap exploitdb nuclei \
 && rm -rf /var/lib/apt/lists/*

# Fetch nuclei templates at build time so scans don't update themselves at runtime.
RUN nuclei -update-templates -silent || true

# Run as an unprivileged user by default; the runner adds only NET_RAW and sets memory/pid limits.
RUN useradd -m -u 1000 cyberred
USER cyberred
WORKDIR /work
