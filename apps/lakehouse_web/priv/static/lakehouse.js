(function () {
  function initSessionRenewal() {
    if (document.body.dataset.gravitasAuthenticated !== "true") return
    let pending = false
    async function renew() {
      if (pending || document.visibilityState !== "visible") return
      pending = true
      try {
        const response = await fetch("/web/session", {
          credentials: "same-origin", cache: "no-store", headers: {Accept: "application/json"}
        })
        if (response.status === 401) window.location.reload()
      } catch (_) {
        // Offline or temporarily unavailable: preserve the current page.
      } finally {
        pending = false
      }
    }
    document.addEventListener("visibilitychange", renew)
    window.setInterval(renew, 5 * 60 * 1000)
  }

  function initLiveSocket() {
    const csrfToken = document.querySelector("meta[name='csrf-token']")?.getAttribute("content")

    const Hooks = {
      ScrollMessages: {
        mounted() {
          this.scrollToBottom()
        },
        updated() {
          this.scrollToBottom()
        },
        scrollToBottom() {
          this.el.scrollTop = this.el.scrollHeight
        }
      },
      ClearComposer: {
        mounted() {
          this.handleEvent("composer_cleared", () => {
            this.el.value = ""
          })
        }
      }
    }

    if (typeof LiveView === "undefined" || typeof Phoenix === "undefined" || !csrfToken) {
      return
    }

    const liveSocket = new LiveView.LiveSocket("/live", Phoenix.Socket, {
      // The endpoint enables WebSockets only. Keep reconnecting after restarts
      // instead of switching to an unsupported polling transport.
      params: {_csrf_token: csrfToken},
      hooks: Hooks
    })

    liveSocket.connect()
    window.liveSocket = liveSocket
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => { initLiveSocket(); initSessionRenewal() })
  } else {
    initLiveSocket()
    initSessionRenewal()
  }
})()
