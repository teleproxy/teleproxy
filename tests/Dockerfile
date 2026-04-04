FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
ENV PYTHONUNBUFFERED=1
COPY test_proxy.py test_tls_e2e.py test_tls_fingerprint.py test_multi_secret_tls.py test_ip_acl.py test_direct_e2e.py test_secret_limit.py test_secret_quota.py test_rate_limit.py test_drs_delays_e2e.py test_cdn_dc.py test_ipv6_direct.py test_bind_address.py test_config_reload.py test_socks5.py test_link_ip.py test_proxy_protocol.py ./
CMD ["python", "test_proxy.py"]

