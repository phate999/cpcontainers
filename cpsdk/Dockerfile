FROM alpine:3.10
ENV PYTHONUNBUFFERED 1
# install python
RUN apk add python3 && pip3 install --upgrade pip setuptools
# copy the application into the container
COPY cs.py print_status.py /usr/local/bin/
# use the following entrypoint when running the container
ENTRYPOINT ["python3", "/usr/local/bin/print_status.py"]  
