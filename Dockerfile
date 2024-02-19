FROM python:3.10.4

WORKDIR /app

COPY . /app

RUN pip --default-timeout=5000 install -r requirements.txt

CMD uvicorn main:app --reload --port=8000 --host=0.0.0.0
