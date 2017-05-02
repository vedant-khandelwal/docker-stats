
FROM python:2.7-alpine

# Install prerequisites.
RUN pip install docker

# Copy the monitor scripts.
COPY start.py /start.py

# Run the monitor script.
ENTRYPOINT ["/start.py"]
