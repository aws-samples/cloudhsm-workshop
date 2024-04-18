FROM --platform=linux/amd64 public.ecr.aws/lambda/python:3.11

RUN yum update -y \
    && yum install zip -y

RUN pip3 --version
    
RUN pip3 install boto3
   
RUN pip3 \
    install \
    --platform manylinux2014_x86_64 \
    --implementation cp \
    --only-binary=:all: --upgrade \
    --target /var/task \
    cryptography

COPY lambda_function.py /var/task

CMD [ "lambda_function.handler" ] 