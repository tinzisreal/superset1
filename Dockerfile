FROM apache/superset:4.0.1

USER root

# Cài Authlib thay vì flask-openid
RUN pip install --no-cache-dir authlib

USER superset
