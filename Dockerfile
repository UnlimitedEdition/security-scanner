FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y gcc && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Non-root runtime. HF Spaces ocekuje UID 1000 i da app cita/pise u /app.
# Ide POSLE svih apt-get/pip/COPY koraka (oni traze root), a PRE CMD-a.
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
ENV HOME=/home/appuser
USER appuser

EXPOSE 7860

# --host 0.0.0.0 ostaje NAMERNO (audit nalaz 7 = svesno prihvacen):
# HF Spaces rutira saobracaj spolja u kontejner, bind na 127.0.0.1 bi
# ucinio app nedostupnim. Izlozenost kontrolise platforma, ne proces.
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "7860"]
