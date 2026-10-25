defmodule LakehouseMatrix.ImageSafetyTest do
  use ExUnit.Case, async: false
  alias LakehouseMatrix.Media.Image

  @png Base.decode64!(
         "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jRZkAAAAASUVORK5CYII="
       )

  test "vector, document and indirect inputs are never passed to the image converter" do
    for bytes <- [
          "<svg xmlns='http://www.w3.org/2000/svg'><image href='file:///etc/passwd'/></svg>",
          "%PDF-1.7",
          "@/etc/passwd",
          "push graphic-context\nimage over 0,0 1,1 'https://example.org/image'\npop graphic-context"
        ] do
      assert {:error, :unsupported_image} = Image.compress(bytes)
      assert {:error, :unsupported_image} = Image.thumbnail(bytes, 64, 64, "scale")
    end
  end

  @tag timeout: 30_000
  test "a disconnected caller cannot free the bounded conversion slot or leave an unbounded decoder" do
    root = Path.join(System.tmp_dir!(), "matrix-converter-test-" <> Ecto.UUID.generate())
    File.mkdir!(root)
    old_path = System.fetch_env!("PATH")
    binary = Path.join(root, "magick")
    started = Path.join(root, "started")
    File.write!(binary, "#!/bin/sh\nprintf ready > '" <> started <> "'\nexec sleep 60\n")
    File.chmod!(binary, 0o700)
    System.put_env("PATH", root <> ":" <> old_path)

    on_exit(fn ->
      System.put_env("PATH", old_path)
      File.rm_rf!(root)
    end)

    parent = self()
    caller = spawn(fn -> send(parent, {:converted, Image.compress(@png)}) end)
    wait_started(started, 100)
    Process.exit(caller, :kill)
    assert {:error, :rate_limited} = Image.compress(@png)
    assert {:error, :rate_limited} = Image.thumbnail(@png, 32, 32, "scale")
    # The independent supervisor keeps the slot until the external deadline,
    # even though the original request process has gone away.
    wait_finished(250)
    assert Task.Supervisor.children(LakehouseMatrix.ImageTasks) == []
  end

  defp wait_started(_, 0), do: flunk("converter did not start")

  defp wait_started(path, left) do
    if File.exists?(path),
      do: :ok,
      else:
        (
          Process.sleep(10)
          wait_started(path, left - 1)
        )
  end

  defp wait_finished(0), do: flunk("decoder outlived its deadline")

  defp wait_finished(left) do
    if Task.Supervisor.children(LakehouseMatrix.ImageTasks) == [],
      do: :ok,
      else:
        (
          Process.sleep(100)
          wait_finished(left - 1)
        )
  end
end
