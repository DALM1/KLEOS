defmodule KleosHubTest do
  use ExUnit.Case
  doctest KleosHub

  test "greets the world" do
    assert KleosHub.hello() == :world
  end
end
