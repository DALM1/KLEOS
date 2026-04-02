# KLEOS

Kleos est un backend de chat robuste (Elixir + C++), avec un client C++ optionnel. L’architecture combine:
- Hub Elixir (OTP) avec persistance Mnesia: comptes, relations (amis/bloqués), messages offline, présence, routage inter‑relays.
- Relays C++ ultra‑performants (kqueue, non‑bloquant) servant d’edge.
- Client C++ (optionnel) basé sur Dear ImGui, buildable uniquement si les sources ImGui sont disponibles localement.

## Build
- Prérequis: CMake, GLFW, Elixir/Mix, CommandLineTools macOS.
- Optionnel (client): définir KLEOS_IMGUI_DIR vers un dossier Dear ImGui contenant:
  - imgui.cpp, imgui_draw.cpp, imgui_tables.cpp, imgui_widgets.cpp
  - backends/imgui_impl_glfw.cpp, backends/imgui_impl_opengl3.cpp
- Commande:
  - ./build.sh
  - Si KLEOS_IMGUI_DIR est défini, KleosClient sera construit; sinon seul KleosRelay sera produit.

## Run
- Backend complet:
  - ./run_backend.sh
  - Variables utiles:
    - KLEOS_RELAY_PORT (default: 5555)
    - KLEOS_RELAY_BIND (default: 127.0.0.1)
    - KLEOS_HUB (default: 127.0.0.1:7000)
    - KLEOS_RELAY_PUBLIC_HOST (annonce au hub)
    - KLEOS_COOKIE / KLEOS_HUB_NODE (pour le nœud Elixir)
- Relay seul:
  - KLEOS_HUB=127.0.0.1:7000 ./build/KleosRelay <port> <max_payload> <bind>
- Client (si buildé):
  - KLEOS_SERVER_HOST=127.0.0.1 KLEOS_SERVER_PORT=5555 ./run_frontend.sh

## Persistance (Hub)
- Tables Mnesia:
  - :kleos_user(handle, secret_hash, ts)
  - :kleos_rel(user, peer, kind[:friend|:blocked], ts)
  - :kleos_offline(to, from, b64, ts)
- Répertoire:
  - par défaut ~/.kleos_hub/mnesia/<node_name>/
  - configurable via KLEOS_HUB_MNESIA_DIR

## Protocole (client ↔ relay)
- Auth: Register, LoginBegin, LoginChallenge, LoginResponse, LoginOk
- Chat: SendMessage, DeliverMessage, Error, Ok
- Relations: FriendAdd, FriendRemove, FriendListReq, FriendListResp, Block, Unblock
- Présence: Presence(handle, online=1/0)
- Hub ↔ relay (texte): REL, ROUTE, DELIVER, ONLINE/OFFLINE, PRESENCE, AUTH

## Notes
- Les sources ImGui ne sont pas dans le repo. Pour construire le client, définir   KLEOS_IMGUI_DIR vers une installation ou un checkout local d’ImGui.
