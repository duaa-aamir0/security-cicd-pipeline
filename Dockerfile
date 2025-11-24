FROM python:3.11-slim
LABEL description="Security CI/CD Application"

WORKDIR /app

# Set environment variables
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

# create a non-root user to prevent app from running as root
RUN groupadd -r appuser && useradd -r -g appuser appuser

# install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# change app code ownership to non-root user
COPY app/ /app/app/
RUN chown -R appuser:appuser /app
# switch user
USER appuser

# run app using gunicorn, check health
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')" || exit 1
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "60", "--access-logfile", "-", "--error-logfile", "-", "app.app:app"]