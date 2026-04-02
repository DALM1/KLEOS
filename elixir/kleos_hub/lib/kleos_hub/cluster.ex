defmodule KleosHub.Cluster do
  @moduledoc false

  def connect_from_env do
    case System.get_env("KLEOS_HUB_CLUSTER") do
      nil ->
        :ok

      "" ->
        :ok

      csv ->
        csv
        |> String.split(",", trim: true)
        |> Enum.map(&String.trim/1)
        |> Enum.reject(&(&1 == ""))
        |> Enum.each(fn node_name ->
          case safe_to_atom(node_name) do
            {:ok, node} -> Node.connect(node)
            :error -> :ok
          end
        end)

        :ok
    end
  end

  defp safe_to_atom(str) do
    try do
      {:ok, String.to_atom(str)}
    rescue
      _ -> :error
    end
  end
end

