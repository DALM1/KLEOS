defmodule KleosHub.Acceptor do
  use GenServer

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(%{bind: bind, port: port}) do
    {:ok, listen} =
      :gen_tcp.listen(port, [
        :binary,
        packet: :line,
        active: false,
        reuseaddr: true,
        ip: bind,
        backlog: 4096
      ])

    state = %{listen: listen}
    send(self(), :accept)
    {:ok, state}
  end

  @impl true
  def handle_info(:accept, %{listen: listen} = state) do
    case :gen_tcp.accept(listen) do
      {:ok, socket} ->
        Task.Supervisor.start_child(KleosHub.TaskSupervisor, fn -> KleosHub.RelayConn.run(socket) end)
        send(self(), :accept)
        {:noreply, state}

      {:error, _} ->
        Process.send_after(self(), :accept, 1000)
        {:noreply, state}
    end
  end
end
