FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

# libvirt0 = biblioteka uruchomieniowa (zostaje); reszta tylko do zbudowania libvirt-python
RUN apt-get update \
    && apt-get install -y --no-install-recommends libvirt0 libvirt-dev gcc libc6-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && apt-get purge -y --auto-remove gcc libc6-dev libvirt-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY . .

# Dostęp do socketu libvirt daje grupa hosta (group_add w docker-compose.yml)
RUN useradd --create-home --uid 1000 app \
    && mkdir -p /data/extensions && chown app:app /data/extensions
USER app

EXPOSE 5000

# gthread + długi timeout: wgrywanie ISO (kilka GB) trwa minuty i nie może blokować całego workera
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--worker-class", "gthread", "--threads", "4", "--timeout", "3600", "app:app"]
