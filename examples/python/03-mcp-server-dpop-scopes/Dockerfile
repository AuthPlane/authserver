FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml ./
RUN pip install --no-cache-dir .

COPY server.py agent.py ./

EXPOSE 8080

CMD ["python", "server.py"]
