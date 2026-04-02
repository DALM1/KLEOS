defmodule KleosHub.RelayConn do
  @moduledoc false

  @offline_table :kleos_offline
  @rel_table :kleos_rel
  @user_table :kleos_user
  @offline_limit 100

  def run(socket) do
    :ok = :inet.setopts(socket, active: :once)

    state = %{
      socket: socket,
      relay: nil,
      handles: MapSet.new()
    }

    loop(state)
  end

  defp loop(state) do
    receive do
      {:tcp, socket, data} when socket == state.socket ->
        state =
          data
          |> String.trim_trailing()
          |> handle_line(state)

        :ok = :inet.setopts(state.socket, active: :once)
        loop(state)

      {:tcp_closed, socket} when socket == state.socket ->
        cleanup(state)
        :ok

      {:tcp_error, socket, _} when socket == state.socket ->
        cleanup(state)
        :ok

      {:deliver, to, from, b64} ->
        send_line(state.socket, "DELIVER #{to} #{from} #{b64}\n")
        loop(state)
    end
  end

  defp handle_line("RELAY " <> rest, state) do
    case String.split(rest, " ", parts: 2) do
      [host, port_s] ->
        port =
          case Integer.parse(port_s) do
            {p, _} when p > 0 and p < 65536 -> p
            _ -> nil
          end

        if port do
          %{state | relay: %{host: host, port: port}}
        else
          state
        end

      _ ->
        state
    end
  end

  defp handle_line("ONLINE " <> handle, state) do
    handle = String.trim(handle)

    if valid_handle?(handle) do
      if user_exists?(handle) do
        :global.register_name({:kleos_handle, handle}, self())
        flush_offline(state.socket, handle)
        %{state | handles: MapSet.put(state.handles, handle)}
      else
        state
      end
    else
      state
    end
  end

  defp handle_line("OFFLINE " <> handle, state) do
    handle = String.trim(handle)
    :global.unregister_name({:kleos_handle, handle})
    %{state | handles: MapSet.delete(state.handles, handle)}
  end

  defp handle_line("ROUTE " <> rest, state) do
    parts = String.split(rest, " ", parts: 4)

    case parts do
      [msgid, to, from, b64] ->
        to = String.trim(to)
        from = String.trim(from)
        b64 = String.trim(b64)

        cond do
          not user_exists?(to) ->
            send_line(state.socket, "NOUSER #{msgid}\n")

          blocked?(to, from) ->
            send_line(state.socket, "BLOCKED #{msgid}\n")

          true ->
            dest = :global.whereis_name({:kleos_handle, to})

            if is_pid(dest) do
              send(dest, {:deliver, to, from, b64})
              send_line(state.socket, "FOUND #{msgid}\n")
            else
              store_offline(to, from, b64)
              send_line(state.socket, "NOTFOUND #{msgid}\n")
            end
        end

        state

      _ ->
        state
    end
  end

  defp handle_line("REL " <> rest, state) do
    parts = String.split(rest, " ", parts: 4)

    case parts do
      [reqid, op, user, peer_or_empty] ->
        user = String.trim(user)
        op = String.trim(op)
        peer_or_empty = String.trim(peer_or_empty)

        case op do
          "LIST" ->
            if valid_handle?(user) and user_exists?(user) do
              list = list_relations(user)
              b64 = Base.encode64(list)
              send_line(state.socket, "REL_LIST #{reqid} #{b64}\n")
            else
              send_line(state.socket, "REL_ERR #{reqid} invalid\n")
            end

          "ADD" ->
            if valid_handle?(user) and valid_handle?(peer_or_empty) and user_exists?(user) and user_exists?(peer_or_empty) do
              rel_add_friend(user, peer_or_empty)
              send_line(state.socket, "REL_OK #{reqid}\n")
            else
              send_line(state.socket, "REL_ERR #{reqid} invalid\n")
            end

          "DEL" ->
            if valid_handle?(user) and valid_handle?(peer_or_empty) and user_exists?(user) and user_exists?(peer_or_empty) do
              rel_del_friend(user, peer_or_empty)
              send_line(state.socket, "REL_OK #{reqid}\n")
            else
              send_line(state.socket, "REL_ERR #{reqid} invalid\n")
            end

          "BLOCK" ->
            if valid_handle?(user) and valid_handle?(peer_or_empty) and user_exists?(user) and user_exists?(peer_or_empty) do
              rel_block(user, peer_or_empty)
              send_line(state.socket, "REL_OK #{reqid}\n")
            else
              send_line(state.socket, "REL_ERR #{reqid} invalid\n")
            end

          "UNBLOCK" ->
            if valid_handle?(user) and valid_handle?(peer_or_empty) and user_exists?(user) and user_exists?(peer_or_empty) do
              rel_unblock(user, peer_or_empty)
              send_line(state.socket, "REL_OK #{reqid}\n")
            else
              send_line(state.socket, "REL_ERR #{reqid} invalid\n")
            end

          _ ->
            send_line(state.socket, "REL_ERR #{reqid} unknown\n")
        end

        state

      _ ->
        state
    end
  end

  defp handle_line("AUTH " <> rest, state) do
    parts = String.split(rest, " ", parts: 5)

    case parts do
      ["REG", reqid, handle, hash_hex] ->
        handle = String.trim(handle)
        hash_hex = String.trim(hash_hex)

        if valid_handle?(handle) do
          with {:ok, hash_bin} <- decode_hex(hash_hex),
               true <- byte_size(hash_bin) == 32 do
            ts = System.system_time(:millisecond)

            res =
              :mnesia.transaction(fn ->
                case :mnesia.read({@user_table, handle}) do
                  [] ->
                    :mnesia.write({@user_table, handle, hash_bin, ts})
                    :ok

                  _ ->
                    {:error, :exists}
                end
              end)

            case res do
              {:atomic, :ok} -> send_line(state.socket, "AUTH_OK #{reqid}\n")
              {:atomic, {:error, :exists}} -> send_line(state.socket, "AUTH_ERR #{reqid} exists\n")
              _ -> send_line(state.socket, "AUTH_ERR #{reqid} failed\n")
            end
          else
            _ -> send_line(state.socket, "AUTH_ERR #{reqid} invalid\n")
          end
        else
          send_line(state.socket, "AUTH_ERR #{reqid} invalid\n")
        end

        state

      ["VERIFY", reqid, handle, nonce_b64, hmac_hex] ->
        handle = String.trim(handle)
        nonce_b64 = String.trim(nonce_b64)
        hmac_hex = String.trim(hmac_hex)

        with true <- valid_handle?(handle),
             {:ok, nonce} <- Base.decode64(nonce_b64),
             {:ok, hmac_bin} <- decode_hex(hmac_hex),
             true <- byte_size(hmac_bin) == 32 do
          res =
            :mnesia.transaction(fn ->
              case :mnesia.read({@user_table, handle}) do
                [{@user_table, ^handle, secret_hash, _ts}] ->
                  expected = :crypto.mac(:hmac, :sha256, secret_hash, nonce)
                  if :crypto.secure_compare(expected, hmac_bin), do: :ok, else: {:error, :bad_password}

                _ ->
                  {:error, :no_user}
              end
            end)

          case res do
            {:atomic, :ok} -> send_line(state.socket, "AUTH_OK #{reqid}\n")
            {:atomic, {:error, :no_user}} -> send_line(state.socket, "AUTH_FAIL #{reqid} no_user\n")
            {:atomic, {:error, :bad_password}} -> send_line(state.socket, "AUTH_FAIL #{reqid} bad_password\n")
            _ -> send_line(state.socket, "AUTH_FAIL #{reqid} failed\n")
          end
        else
          _ -> send_line(state.socket, "AUTH_FAIL #{reqid} invalid\n")
        end

        state

      _ ->
        state
    end
  end

  defp handle_line(_other, state) do
    state
  end

  defp send_line(socket, data) do
    :gen_tcp.send(socket, data)
    :ok
  end

  defp cleanup(state) do
    Enum.each(state.handles, fn h ->
      :global.unregister_name({:kleos_handle, h})
    end)

    :ok
  end

  defp store_offline(to, from, b64) do
    if valid_handle?(to) and valid_handle?(from) do
      ts = System.system_time(:millisecond)

      _ =
        :mnesia.transaction(fn ->
          :mnesia.write({@offline_table, to, from, b64, ts})
          enforce_offline_limit(to)
        end)
    end

    :ok
  end

  defp flush_offline(socket, handle) do
    records =
      case :mnesia.transaction(fn ->
             recs = :mnesia.read({@offline_table, handle})
             Enum.each(recs, &:mnesia.delete_object/1)
             recs
           end) do
        {:atomic, recs} when is_list(recs) -> recs
        _ -> []
      end

    records
    |> Enum.sort_by(fn {_, _to, _from, _b64, ts} -> ts end, :asc)
    |> Enum.each(fn
      {@offline_table, to, from, b64, _ts} when is_binary(to) and is_binary(from) and is_binary(b64) ->
        send_line(socket, "DELIVER #{to} #{from} #{b64}\n")

      _ ->
        :ok
    end)

    :ok
  end

  defp enforce_offline_limit(to) do
    recs = :mnesia.read({@offline_table, to})

    if length(recs) > @offline_limit do
      recs
      |> Enum.sort_by(fn {_, _to, _from, _b64, ts} -> ts end, :desc)
      |> Enum.drop(@offline_limit)
      |> Enum.each(&:mnesia.delete_object/1)
    end

    :ok
  end

  defp blocked?(to, from) do
    case :mnesia.transaction(fn ->
           recs = :mnesia.read({@rel_table, to})
           Enum.any?(recs, fn
             {@rel_table, ^to, ^from, :blocked, _ts} -> true
             _ -> false
           end)
         end) do
      {:atomic, v} when is_boolean(v) -> v
      _ -> false
    end
  end

  defp rel_add_friend(user, peer) do
    ts = System.system_time(:millisecond)

    _ =
      :mnesia.transaction(fn ->
        rel_unblock_tx(user, peer)
        rel_unblock_tx(peer, user)
        :mnesia.write({@rel_table, user, peer, :friend, ts})
        :mnesia.write({@rel_table, peer, user, :friend, ts})
      end)

    :ok
  end

  defp rel_del_friend(user, peer) do
    _ =
      :mnesia.transaction(fn ->
        rel_del_friend_tx(user, peer)
      end)

    :ok
  end

  defp rel_block(user, peer) do
    ts = System.system_time(:millisecond)

    _ =
      :mnesia.transaction(fn ->
        rel_del_friend_tx(user, peer)
        rel_unblock_tx(user, peer)
        :mnesia.write({@rel_table, user, peer, :blocked, ts})
      end)

    :ok
  end

  defp rel_unblock(user, peer) do
    _ =
      :mnesia.transaction(fn ->
        rel_unblock_tx(user, peer)
      end)

    :ok
  end

  defp rel_del_friend_tx(user, peer) do
    recs = :mnesia.read({@rel_table, user})

    Enum.each(recs, fn
      {@rel_table, ^user, ^peer, :friend, _ts} = r -> :mnesia.delete_object(r)
      _ -> :ok
    end)

    recs2 = :mnesia.read({@rel_table, peer})

    Enum.each(recs2, fn
      {@rel_table, ^peer, ^user, :friend, _ts} = r -> :mnesia.delete_object(r)
      _ -> :ok
    end)

    :ok
  end

  defp rel_unblock_tx(user, peer) do
    recs = :mnesia.read({@rel_table, user})

    Enum.each(recs, fn
      {@rel_table, ^user, ^peer, :blocked, _ts} = r -> :mnesia.delete_object(r)
      _ -> :ok
    end)

    :ok
  end

  defp list_relations(user) do
    case :mnesia.transaction(fn ->
           recs = :mnesia.read({@rel_table, user})

           recs
           |> Enum.reduce(%{}, fn
             {@rel_table, ^user, peer, kind, ts}, acc when is_binary(peer) and kind in [:friend, :blocked] ->
               cur = Map.get(acc, peer)
               if is_nil(cur) or elem(cur, 1) < ts do
                 Map.put(acc, peer, {kind, ts})
               else
                 acc
               end

             _, acc ->
               acc
           end)
           |> Enum.map(fn {peer, {kind, _ts}} -> "#{peer}\t#{kind}\n" end)
           |> Enum.join()
         end) do
      {:atomic, s} when is_binary(s) -> s
      _ -> ""
    end
  end

  defp user_exists?(handle) do
    case :mnesia.transaction(fn ->
           case :mnesia.read({@user_table, handle}) do
             [] -> false
             _ -> true
           end
         end) do
      {:atomic, v} when is_boolean(v) -> v
      _ -> false
    end
  end

  defp decode_hex(hex) do
    try do
      Base.decode16(hex, case: :mixed)
    rescue
      _ -> :error
    end
  end

  defp valid_handle?(handle) do
    byte_size(handle) > 0 and byte_size(handle) <= 32 and
      String.match?(handle, ~r/^[A-Za-z0-9_-]+$/)
  end
end
