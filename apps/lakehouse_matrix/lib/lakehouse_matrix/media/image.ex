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
