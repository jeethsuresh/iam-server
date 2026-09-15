browser_excluded? =
  case System.get_env("WALLABY_SKIP") do
    v when v in ["1", "true", "yes"] -> true
    _ -> false
  end

exclude = if browser_excluded?, do: [:browser], else: []

ExUnit.start(exclude: [:pending | exclude])
Ecto.Adapters.SQL.Sandbox.mode(LakehouseIam.Repo, :manual)

{:ok, _} = Application.ensure_all_started(:lakehouse_web)
{:ok, _} = Application.ensure_all_started(:lakehouse_app_demo)

unless browser_excluded? do
  chrome = System.get_env("CHROME_PATH")
  chromedriver = System.get_env("CHROMEDRIVER_PATH")

  chromedriver_cfg =
    []
    |> then(fn cfg ->
      if is_binary(chromedriver) and chromedriver != "", do: Keyword.put(cfg, :path, chromedriver), else: cfg
    end)
    |> then(fn cfg ->
      if is_binary(chrome) and chrome != "", do: Keyword.put(cfg, :binary, chrome), else: cfg
    end)

  if chromedriver_cfg != [] do
    Application.put_env(:wallaby, :chromedriver, chromedriver_cfg)
  end

  {:ok, _} = Application.ensure_all_started(:wallaby)
end

Cucumber.compile_features!(
  features: ["test/features/**/*.feature"],
  steps: ["test/features/step_definitions/**/*.exs"],
  support: ["test/features/support/**/*.exs"]
)
