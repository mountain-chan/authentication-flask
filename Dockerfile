FROM continuumio/miniconda3
ENV INSTALL_PATH /app
RUN mkdir -p $INSTALL_PATH
WORKDIR $INSTALL_PATH

RUN conda install python=3.6.5 -y
RUN apt-get update && apt-get install -y build-essential
RUN apt install gunicorn -y
RUN apt-get install -y default-libmysqlclient-dev
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt
COPY . .
