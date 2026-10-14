# Host the board online so any device can open it from anywhere.
FROM python:3.12-slim
WORKDIR /app
COPY f1live.py ./
COPY static ./static
ENV PYTHONUNBUFFERED=1
EXPOSE 8000
# Override the command for replay, e.g.:
#   docker run -p 8000:8000 f1-live replay --year 2025 --gp Monaco --speed 8
ENTRYPOINT ["python", "f1live.py"]
CMD ["live"]
