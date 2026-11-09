FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY promptshield ./promptshield
COPY data ./data
RUN pip install --no-cache-dir ".[ml]"
ENV PROMPTSHIELD_UPSTREAM_URL=https://api.openai.com
EXPOSE 8080
CMD ["promptshield", "serve", "--host", "0.0.0.0", "--port", "8080"]
