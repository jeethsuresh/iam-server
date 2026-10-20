defmodule LakehouseWeb.Layouts do
  @moduledoc false
  use Phoenix.Component

  import Phoenix.Controller, only: [get_csrf_token: 0]

  use Phoenix.VerifiedRoutes,
    endpoint: LakehouseWeb.Endpoint,
    router: LakehouseWeb.Router,
    statics: LakehouseWeb.StaticPaths.paths()

  attr :username, :string, required: true
  attr :admin, :boolean, default: false
  attr :active, :atom, default: :services
  slot :inner_block, required: true

  def shell(assigns) do
    assigns = assign(assigns, :identifier, LakehouseIam.Identifier.format(assigns.username))

    ~H"""
    <div class="gravitas-shell">
      <aside class="global-sidebar">
        <a href={~p"/dashboard"} class="brand"><span class="brand-mark" aria-hidden="true">g</span> gravitas<span class="brand-dot">.</span></a>
        <div class="workspace-label">YOUR WORKSPACE</div>
        <nav aria-label="Main navigation" class="main-nav">
          <a href={~p"/dashboard"} class={@active == :services && "is-active"} aria-current={@active == :services && "page"}><span aria-hidden="true">◈</span> Services</a>
          <a href={~p"/groups"} class={@active == :groups && "is-active"} aria-current={@active == :groups && "page"}><span aria-hidden="true">◎</span> Groups</a>
          <a href={~p"/settings"} class={@active == :settings && "is-active"} aria-current={@active == :settings && "page"}><span aria-hidden="true">⚙</span> Settings</a>
        </nav>
        <%= if @admin do %>
          <div class="workspace-label admin-label">ADMINISTRATION</div>
          <nav aria-label="Administration" class="main-nav"><a href={~p"/services/manage"} class={@active == :catalog && "is-active"}><span aria-hidden="true">⊞</span> Service catalog</a></nav>
        <% end %>
        <div class="sidebar-bottom"><div class="account-avatar"><%= String.upcase(String.first(@username)) %></div><div class="account-copy"><strong><%= @username %></strong><span title={@identifier}><%= @identifier %></span></div><a href={~p"/logout"} aria-label="Sign out" title="Sign out">↗</a></div>
      </aside>
      <main class={["workspace", @active == :groups && "workspace--groups"]} id="main-content"><%= render_slot(@inner_block) %></main>
    </div>
    """
  end

  embed_templates "layouts/*"
end
