# QuantumPulse Docker Container
FROM python:3.12-slim

WORKDIR /app

# Install system dependencies for build tools and fonts
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency definition
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy source tree
COPY . .

# Expose Streamlit dashboard port
EXPOSE 8501

# Healthcheck
HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health || exit 1

# Default command: launch the Streamlit Web GUI
ENTRYPOINT ["streamlit", "run", "gui/dashboard.py", "--server.port=8501", "--server.address=0.0.0.0", "--server.headless=true"]

