[
  import_deps: [:ecto, :phoenix],
  inputs: [
    "{mix,.formatter}.exs",
    "{config,lib,test}/**/*.{ex,exs}",
    "apps/*/{config,lib,test}/**/*.{ex,exs}"
  ],
  subdirectories: ["apps/*"]
]
