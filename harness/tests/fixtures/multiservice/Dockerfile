FROM python:3.12-slim
RUN python -m pip install --no-cache-dir \
    --index-url https://pkg.pjlab.org.cn/repository/pypi-proxy/simple/ pytest
WORKDIR /opt/pilot
COPY server.py /opt/pilot/server.py
COPY entrypoint.sh /opt/pilot/entrypoint.sh
RUN printf 'anonymous-volume-preserved\n' > /opt/pilot/seed-anonymous
VOLUME ["/var/lib/pilot-anonymous"]
CMD ["sh", "/opt/pilot/entrypoint.sh"]
