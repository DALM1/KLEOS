defmodule KleosHub.Application do
  @moduledoc false

  use Application

  @offline_table :kleos_offline
  @rel_table :kleos_rel
  @user_table :kleos_user

  @impl true
  def start(_type, _args) do
    port = Application.get_env(:kleos_hub, :port, 7000)
    bind = Application.get_env(:kleos_hub, :bind, {127, 0, 0, 1})

    :net_kernel.monitor_nodes(true, node_type: :visible)
    KleosHub.Cluster.connect_from_env()

    init_storage!()

    children = [
      {Task.Supervisor, name: KleosHub.TaskSupervisor},
      {KleosHub.Acceptor, %{bind: bind, port: port}}
    ]

    opts = [strategy: :one_for_one, name: KleosHub.Supervisor]
    Supervisor.start_link(children, opts)
  end

  defp init_storage! do
    base_dir =
      System.get_env("KLEOS_HUB_MNESIA_DIR") ||
        Path.join([System.user_home!(), ".kleos_hub", "mnesia"])

    base_dir =
      case File.mkdir_p(base_dir) do
        :ok ->
          base_dir

        {:error, _} ->
          fallback = Path.join([File.cwd!(), ".mnesia"])
          File.mkdir_p!(fallback)
          fallback
      end

    node_dir = Path.join(base_dir, Atom.to_string(node()))
    File.mkdir_p!(node_dir)

    Application.put_env(:mnesia, :dir, String.to_charlist(node_dir), persistent: true)

    schema_path = Path.join(node_dir, "schema.DAT")

    if not File.exists?(schema_path) do
      _ = :mnesia.stop()
      :ok = :mnesia.create_schema([node()])
    end

    :ok = :mnesia.start()

    _ =
      case :mnesia.create_table(@offline_table,
             attributes: [:to, :from, :b64, :ts],
             type: :bag,
             disc_copies: [node()]
           ) do
        {:atomic, :ok} -> :ok
        {:aborted, {:already_exists, @offline_table}} -> :ok
        other -> other
      end

    _ =
      case :mnesia.create_table(@rel_table,
             attributes: [:user, :peer, :kind, :ts],
             type: :bag,
             disc_copies: [node()]
           ) do
        {:atomic, :ok} -> :ok
        {:aborted, {:already_exists, @rel_table}} -> :ok
        other -> other
      end

    _ =
      case :mnesia.create_table(@user_table,
             attributes: [:handle, :secret_hash, :ts],
             type: :set,
             disc_copies: [node()]
           ) do
        {:atomic, :ok} -> :ok
        {:aborted, {:already_exists, @user_table}} -> :ok
        other -> other
      end

    _ =
      case :mnesia.wait_for_tables([@offline_table, @rel_table], 30_000) do
        :ok -> :ok
        {:timeout, _} -> :ok
      end

    _ =
      case :mnesia.wait_for_tables([@user_table], 30_000) do
        :ok -> :ok
        {:timeout, _} -> :ok
      end
    :ok
  end
end
