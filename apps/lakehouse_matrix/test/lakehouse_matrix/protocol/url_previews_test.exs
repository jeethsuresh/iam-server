defmodule LakehouseMatrix.UrlPreviewsTest do
  use LakehouseMatrix.DataCase, async: false
  alias LakehouseMatrix.{ClientStore, Fixtures, UrlPreviews}
  setup do: %{alice: Fixtures.user_fixture("alice")}

  test "HTML previews use bounded metadata, avoid active content and fetch outside transactions",
       ctx do
    fetch = fn url ->
      refute Repo.in_transaction?()
      assert url == "https://example.org/page?q=one"

      {:ok,
       %{
         headers: %{"content-type" => ["text/html; charset=utf-8"]},
         body: """
         <html><head><title>Fallback title</title>
         <meta property="og:title" content="One &amp; Two">
         <meta name="description" content="Summary">
         <meta property="og:image" content="http://127.0.0.1/secret">
         <meta property="og:url" content="javascript:alert(1)">
         <script>never return executable content</script></head></html>
         """
       }}
    end

    assert {:ok, response} =
             UrlPreviews.preview(
               ctx.alice.id,
               %{"url" => "https://example.org/page?q=one#fragment"},
               fetch
             )

    assert response == %{
             "og:title" => "One & Two",
             "og:description" => "Summary",
             "og:url" => "https://example.org/page?q=one"
           }

    assert {:ok, ^response} =
             UrlPreviews.preview(
               ctx.alice.id,
               %{"url" => "https://example.org/page?q=one", "ts" => "1"},
               fn _ -> flunk("cached summary fetched again") end
             )
  end

  test "untrusted URLs, private literal addresses and invalid timestamps cannot reach HTTP",
       ctx do
    for url <- [
          nil,
          [],
          "file:///etc/passwd",
          "http://example.org",
          "https://user:password@example.org",
          "https://example.org:70000"
        ] do
      assert {:error, :invalid_param} =
               UrlPreviews.preview(ctx.alice.id, %{"url" => url}, fn _ ->
                 flunk("unsafe URL fetched")
               end)
    end

    for url <- [
          "https://127.0.0.1/private",
          "https://[::1]/private",
          "https://169.254.169.254/latest/meta-data"
        ] do
      assert {:error, :forbidden} =
               UrlPreviews.preview(ctx.alice.id, %{"url" => url}, fn _ ->
                 flunk("private address fetched")
               end)
    end

    assert {:error, :forbidden} =
             UrlPreviews.preview(ctx.alice.id, %{"url" => "https://localhost/private"})

    assert {:error, :invalid_param} =
             UrlPreviews.preview(
               ctx.alice.id,
               %{"url" => "https://example.org", "ts" => "bad"},
               fn _ -> flunk("invalid timestamp fetched") end
             )
  end

  test "private/no-store responses are not cached and non-HTML bodies are never exposed", ctx do
    for directive <- ["private, max-age=300", "no-store", "no-cache", "max-age=0"] do
      url = "https://example.org/" <> URI.encode_www_form(directive)

      fetch = fn _ ->
        {:ok,
         %{
           headers: %{"content-type" => "text/html", "cache-control" => directive},
           body: "<title>First</title>"
         }}
      end

      assert {:ok, %{"og:title" => "First"}} =
               UrlPreviews.preview(ctx.alice.id, %{"url" => url}, fetch)

      assert {:ok, %{"og:title" => "Second"}} =
               UrlPreviews.preview(ctx.alice.id, %{"url" => url}, fn _ ->
                 {:ok,
                  %{headers: %{"content-type" => "text/html"}, body: "<title>Second</title>"}}
               end)
    end

    assert {:ok, %{}} =
             UrlPreviews.preview(
               ctx.alice.id,
               %{"url" => "https://example.org/private.json"},
               fn _ ->
                 {:ok,
                  %{headers: %{"content-type" => "application/json"}, body: "secret contents"}}
               end
             )

    assert {:error, :unavailable} =
             UrlPreviews.preview(ctx.alice.id, %{"url" => "https://example.org/huge"}, fn _ ->
               {:ok, %{headers: %{}, body: String.duplicate("x", 1_048_577)}}
             end)
  end

  test "preview budgets are bounded even when the requested URL is already cached", ctx do
    fetch = fn _ ->
      {:ok, %{headers: %{"content-type" => "text/html"}, body: "<title>Cached</title>"}}
    end

    for _ <- 1..30,
        do:
          assert(
            {:ok, _} = UrlPreviews.preview(ctx.alice.id, %{"url" => "https://example.org"}, fetch)
          )

    assert {:error, :rate_limited} =
             UrlPreviews.preview(ctx.alice.id, %{"url" => "https://example.org"}, fetch)

    Repo.update_all(from(r in "matrix_preview_requests"),
      set: [requested_at: DateTime.add(ClientStore.now(), -61, :second)]
    )

    assert {:ok, _} = UrlPreviews.preview(ctx.alice.id, %{"url" => "https://example.org"}, fetch)
  end

  @tag timeout: 15_000
  test "fetches have an absolute deadline and disconnected callers retain their concurrency slots",
       ctx do
    parent = self()

    fetch = fn _ ->
      send(parent, {:preview_started, self()})

      receive do
        :never -> {:error, :unavailable}
      end
    end

    callers =
      for index <- 1..4 do
        caller =
          spawn(fn ->
            send(
              parent,
              {:preview_done,
               UrlPreviews.preview(
                 ctx.alice.id,
                 %{"url" => "https://example.org/stall/#{index}"},
                 fetch
               )}
            )
          end)

        assert_receive {:preview_started, worker}, 2000
        {caller, Process.monitor(worker)}
      end

    Process.exit(elem(hd(callers), 0), :kill)

    assert {:error, :rate_limited} =
             UrlPreviews.preview(ctx.alice.id, %{"url" => "https://example.org/overflow"}, fn _ ->
               flunk("concurrency limit was bypassed")
             end)

    for {_, monitor} <- callers do
      assert_receive {:DOWN, ^monitor, :process, _, :killed}, 11_000
    end

    assert_receive {:preview_done, {:error, :unavailable}}, 1000
  end
end
