# Runner skryptów: Playwright BEZ przeglądarki - łączy się z Chromium sesji przez CDP.
# Uruchamiany jako jednorazowy kontener we wspólnej przestrzeni sieciowej kontenera sesji
# (network_mode=container:<sesja>), więc widzi tylko 127.0.0.1:9222 tej jednej sesji.
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 HOME=/tmp PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
RUN pip install --no-cache-dir "playwright>=1.48,<2"
COPY runner.py /runner.py
USER 1000
CMD ["python", "/runner.py"]
