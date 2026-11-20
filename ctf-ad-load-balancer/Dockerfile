FROM python:3.12-slim
WORKDIR /app
COPY balancer ./balancer
ENV PYTHONUNBUFFERED=1 LB_RULES=/rules LB_POLL=5 LB_TCP_TIMEOUT=180
CMD ["python", "-m", "balancer"]
