FROM python:3.7

RUN mkdir /app
WORKDIR /
ADD . /
RUN pip3 install -r requirements.txt
RUN pip3 install requests

EXPOSE 5000
CMD ["python", "main.py"]
