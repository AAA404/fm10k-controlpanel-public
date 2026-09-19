import { ref, watch, type WatchSource } from 'vue'

export function useAutoDismiss(source: WatchSource<unknown>, duration: () => number, dismiss: () => void) {
  const hovered = ref(false), focused = ref(false)
  watch([source, duration, hovered, focused], ([key, milliseconds, pointerInside, controlFocused], _, onCleanup) => {
    if (key == null) { hovered.value = false; focused.value = false; return }
    if (milliseconds <= 0 || pointerInside || controlFocused) return
    const timer = setTimeout(dismiss, milliseconds)
    onCleanup(() => clearTimeout(timer))
  }, { flush: 'post' })

  return {
    mouseenter: () => { hovered.value = true },
    mouseleave: () => { hovered.value = false },
    focusin: (event: FocusEvent) => {
      // Focusing the status region after an action must not pin its notification.
      focused.value = event.target !== event.currentTarget
    },
    focusout: (event: FocusEvent) => {
      focused.value = event.relatedTarget instanceof Node && event.relatedTarget !== event.currentTarget &&
        (event.currentTarget as HTMLElement).contains(event.relatedTarget)
    },
  }
}
