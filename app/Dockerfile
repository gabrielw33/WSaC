FROM python:3.7

RUN mkdir /app
WORKDIR /
ADD . /
RUN pip3 install -r requirements.txt



EXPOSE 5000
CMD ["python3", "admin.py"]
