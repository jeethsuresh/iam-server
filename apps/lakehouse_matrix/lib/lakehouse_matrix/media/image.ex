defmodule LakehouseMatrix.Media.Image do
  @moduledoc false

  @max_edge 1280

  @doc """
  Compresses an image binary into a smaller JPEG preview.
  Returns `{:ok, jpeg_binary}` or `{:error, reason}`.
  """
  @spec compress(binary()) :: {:ok, binary()} | {:error, term()}
  def compress(body) when is_binary(body) do
    case find_magick() do
      nil ->
        {:error, :no_imagemagick}

      bin ->
        in_path = tmp("in")
        out_path = tmp("out.jpg")

        try do
          File.write!(in_path, body)

          args = [
            in_path,
            "-auto-orient",
            "-resize",
            "#{@max_edge}x#{@max_edge}>",
            "-strip",
            "-quality",
            "82",
            "jpeg:" <> out_path
          ]

          case System.cmd(bin, args, stderr_to_stdout: true) do
            {_, 0} ->
              case File.read(out_path) do
                {:ok, <<0xFF, 0xD8, 0xFF, _::binary>> = data} -> {:ok, data}
                {:ok, data} when byte_size(data) > 0 -> {:error, :invalid_jpeg}
                {:ok, _} -> {:error, :empty_output}
                {:error, reason} -> {:error, reason}
              end

            {output, code} ->
              {:error, {:magick_failed, code, output}}
          end
        after
          File.rm(in_path)
          File.rm(out_path)
        end
    end
  end

  def thumbnail(body, width, height, method)
      when width in 1..4096 and height in 1..4096 and method in ["scale", "crop"] do
    bin = find_magick()

    if is_nil(bin) do
      {:error, :unavailable}
    else
      source = tmp("source")
      target = tmp("thumbnail.jpg")

      try do
        File.write!(source, body)
        geometry = "#{width}x#{height}" <> if(method == "crop", do: "^>", else: ">")

        crop =
          if method == "crop",
            do: ["-gravity", "center", "-crop", "#{width}x#{height}+0+0", "+repage"],
            else: []

        args =
          [
            bin,
            "-limit",
            "memory",
            "128MiB",
            "-limit",
            "map",
            "256MiB",
            "-limit",
            "disk",
            "256MiB",
            source <> "[0]",
            "-auto-orient",
            "-resize",
            geometry
          ] ++ crop ++ ["-strip", "-quality", "82", "jpeg:" <> target]

        case System.cmd("timeout", ["20" | args], stderr_to_stdout: true) do
          {_, 0} -> File.read(target)
          _ -> {:error, :invalid_param}
        end
      after
        File.rm(source)
        File.rm(target)
      end
    end
  end

  defp find_magick do
    System.find_executable("magick") || System.find_executable("convert")
  end

  defp tmp(suffix) do
    Path.join(
      System.tmp_dir!(),
      "lakehouse-img-#{System.unique_integer([:positive])}-#{suffix}"
    )
  end
end
