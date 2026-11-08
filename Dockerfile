FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
RUN useradd --create-home --uid 10001 app
WORKDIR /app
COPY pura ./pura
COPY web ./web
COPY results/results.json results/comparacao.png results/serie_temporal.png ./results/
USER app
EXPOSE 8000
# A porta vem de $PORT (nuvem). O bind externo exige senha separada para o dashboard.
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import os,urllib.request as u; u.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('PORT','8000'))"
CMD ["python", "-m", "pura.server", "--host", "0.0.0.0"]
