# Playwright base ships Chromium + system deps, avoiding a fragile manual install.
FROM mcr.microsoft.com/playwright/python:v1.44.0-jammy

WORKDIR /app

# Install deps first for layer caching.
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir --break-system-packages ".[judge]"

# Run as non-root: a scanner should not need root, and dropping privileges
# limits blast radius if a dependency is compromised.
RUN useradd -m scanner && chown -R scanner:scanner /app
USER scanner

ENTRYPOINT ["aisploit"]
CMD ["--help"]
