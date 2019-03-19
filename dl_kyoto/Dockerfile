FROM python:3
RUN mkdir -p /app
COPY requirments.txt /app
WORKDIR /app
RUN pip install -r requirments.txt
COPY . /app
EXPOSE 5000
CMD ["python", "server.py"]
