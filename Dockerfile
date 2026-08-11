FROM hexpm/elixir:1.16.3-erlang-26.2.5-alpine-3.19.1

RUN apk add --no-cache build-base git postgresql-client imagemagick

WORKDIR /app

ENV MIX_ENV=dev

COPY mix.exs mix.lock ./
COPY apps apps
COPY config config
COPY .formatter.exs ./
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN chmod +x /usr/local/bin/docker-entrypoint.sh \
  && mix local.hex --force \
  && mix local.rebar --force \
  && mix deps.get \
  && mix deps.compile

EXPOSE 4000

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["mix", "phx.server"]
