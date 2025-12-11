FROM sbstjn/jwkserve:latest AS jwkserve

COPY private.key /private.key

CMD ["jwkserve", "serve", "--algorithm", "RS256", "--algorithm", "RS384", "--port", "3000", "--key", "/private.key", "--bind", "0.0.0.0", "--issuer", "https://jwkserve.com"]