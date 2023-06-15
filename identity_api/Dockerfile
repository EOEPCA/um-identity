FROM python:alpine
WORKDIR /app
COPY identity_api/conf conf
COPY identity_api/src src
COPY identity_api/requirements.txt requirements.txt
COPY utils/ src/utils/
RUN pip install -r requirements.txt
EXPOSE 5566
CMD [ "python", "-m" , "flask", "run", "--host=0.0.0.0"]
