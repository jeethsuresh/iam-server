FROM hexpm/elixir:1.18.5-erlang-27.3.4.17-alpine-3.21.7

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
  && mix deps.compile \
  && mix compile \
  && MIX_ENV=test mix deps.get \
  && MIX_ENV=test mix deps.compile \
  && MIX_ENV=test mix compile

EXPOSE 4000

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["mix", "phx.server"]
