FROM python:3.8-slim-buster

# LABEL maintainer="jesus.ramos.atos@gmail.com"

RUN apt-get update -y && \
    apt-get install -y netcat-openbsd

EXPOSE 3001

COPY ./requirements.txt /app/requirements.txt

WORKDIR /app

RUN pip3 install -r requirements.txt

COPY ./app.py /app

COPY ./templates/* /app/templates/

CMD [ "sh", "-c", "gunicorn -w ${GUNICORN_WORKERS} -b :${GRAFANA_REGISTRY_PORT} app:app" ]