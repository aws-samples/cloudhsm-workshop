FROM public.ecr.aws/lambda/python:3.9

RUN yum update -y \
    && yum install zip -y \
    && python3 -m pip install --upgrade pip
    
RUN pip3 install boto3
   
RUN pip3 \
    install \
    --platform manylinux2010_x86_64 \
    --implementation cp \
    --only-binary=:all: --upgrade \
    --target /var/task \
    cryptography

COPY lambda_function.py /var/task

CMD [ "lambda_function.handler" ] 