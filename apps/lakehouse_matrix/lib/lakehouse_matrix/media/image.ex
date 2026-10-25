defmodule LakehouseMatrix.Media.Image do
  @moduledoc "Bounded raster previews. Original uploads survive unavailable or unsupported conversion."
  @limits ~w(-limit thread 1 -limit memory 32MiB -limit map 64MiB -limit disk 128MiB)

  def compress(body) when is_binary(body) do
    convert(body, ["-auto-orient", "-resize", "1280x1280>"])
  end

  def thumbnail(body, width, height, method)
      when width in 1..4096 and height in 1..4096 and method in ["scale", "crop"] do
    geometry = "#{width}x#{height}" <> if(method == "crop", do: "^>", else: ">")

    crop =
      if method == "crop",
        do: ["-gravity", "center", "-crop", "#{width}x#{height}+0+0", "+repage"],
        else: []

    convert(body, ["-auto-orient", "-resize", geometry] ++ crop)
  end

  defp convert(body, options) do
    if raster?(body) do
      parent = self()
      ref = make_ref()
      # A supervisor, rather than the HTTP process, owns the converter. A
      # disconnected client cannot release the slot while its decoder lives.
      if Process.whereis(LakehouseMatrix.ImageTasks) do
        case Task.Supervisor.start_child(LakehouseMatrix.ImageTasks, fn ->
               send(parent, {ref, run(body, options)})
             end) do
          {:ok, pid} ->
            monitor = Process.monitor(pid)

            receive do
              {^ref, result} ->
                Process.demonitor(monitor, [:flush])
                result

              {:DOWN, ^monitor, _, _, _} ->
                {:error, :unavailable}
            after
              25_000 ->
                Process.demonitor(monitor, [:flush])
                {:error, :unavailable}
            end

          {:error, :max_children} ->
            {:error, :rate_limited}

          _ ->
            {:error, :unavailable}
        end
      else
        {:error, :unavailable}
      end
    else
      {:error, :unsupported_image}
    end
  end

  defp run(body, options) do
    with bin when is_binary(bin) <-
           System.find_executable("magick") || System.find_executable("convert"),
         timeout when is_binary(timeout) <- System.find_executable("timeout") do
      root =
        Path.join(
          System.tmp_dir!(),
          "lakehouse-image-" <> Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)
        )

      File.mkdir!(root)
      File.chmod!(root, 0o700)
      source = Path.join(root, "input")
      target = Path.join(root, "output.jpg")

      try do
        File.write!(source, body)

        args =
          ["-k", "1", "20", "/bin/sh", "-c", ~S(exec "$@" >/dev/null 2>&1), "matrix-image", bin] ++
            @limits ++
            [source <> "[0]"] ++ options ++ ["-strip", "-quality", "82", "jpeg:" <> target]

        env = [
          {"MAGICK_CONFIGURE_PATH", Application.app_dir(:lakehouse_matrix, "priv/media-policy")},
          {"MAGICK_TEMPORARY_PATH", root}
        ]

        case System.cmd(timeout, args, env: env, stderr_to_stdout: true) do
          {_, 0} ->
            case File.read(target) do
              {:ok, <<0xFF, 0xD8, 0xFF, _::binary>> = bytes} -> {:ok, bytes}
              _ -> {:error, :invalid_image}
            end

          _ ->
            {:error, :invalid_image}
        end
      after
        File.rm_rf!(root)
      end
    else
      _ -> {:error, :unavailable}
    end
  rescue
    _ -> {:error, :unavailable}
  end

  defp raster?(<<0x89, "PNG", 13, 10, 26, 10, _::binary>>), do: true
  defp raster?(<<0xFF, 0xD8, 0xFF, _::binary>>), do: true
  defp raster?(<<"GIF8", version, "a", _::binary>>) when version in [?7, ?9], do: true
  defp raster?(<<"RIFF", _::binary-size(4), "WEBP", _::binary>>), do: true

  defp raster?(<<_::32, "ftyp", brand::binary-size(4), _::binary>>)
       when brand in ["avif", "avis", "heic", "heix", "mif1", "msf1"],
       do: true

  defp raster?(_), do: false
end
