FROM sbstjn/jwkserve:latest AS jwkserve

COPY fixtures/*.key /fixtures/

CMD ["jwkserve", "serve", "--port", "3000", "--key", "/fixtures/rsa4096.key", "--key", "/fixtures/ecdsa256.key", "--key", "/fixtures/ecdsa384.key", "--key", "/fixtures/ecdsa521.key", "--bind", "0.0.0.0", "--issuer", "https://jwkserve.com"]