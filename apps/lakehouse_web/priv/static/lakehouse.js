(function () {
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
      longPollFallbackMs: 2500,
      params: {_csrf_token: csrfToken},
      hooks: Hooks
    })

    liveSocket.connect()
    window.liveSocket = liveSocket
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initLiveSocket)
  } else {
    initLiveSocket()
  }
})()
