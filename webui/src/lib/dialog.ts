import { nextTick, onUnmounted, ref, watch } from 'vue'

// Keep keyboard navigation inside the open dialog and restore the invoking control on close.
export function useDialog(isOpen: () => boolean, close: () => void) {
  const dialog = ref<HTMLElement | null>(null)
  let previous: HTMLElement | null = null
  const controls = () =>
    Array.from(
      dialog.value?.querySelectorAll<HTMLElement>(
        'button:not(:disabled), input:not(:disabled), select:not(:disabled), [href], [tabindex="0"]'
      ) || []
    )
  function onKey(event: KeyboardEvent) {
    if (!isOpen()) return
    if (event.key === 'Escape') {
      event.preventDefault()
      close()
    }
    if (event.key !== 'Tab') return
    const elements = controls(),
      first = elements[0],
      last = elements[elements.length - 1]
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault()
      last?.focus()
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault()
      first?.focus()
    }
  }
  watch(isOpen, async (open) => {
    if (open) {
      previous = document.activeElement as HTMLElement | null
      document.addEventListener('keydown', onKey)
      await nextTick()
      ;(dialog.value?.querySelector<HTMLElement>('input:not(:disabled)') || controls()[0])?.focus()
    } else {
      document.removeEventListener('keydown', onKey)
      previous?.focus()
    }
  })
  onUnmounted(() => document.removeEventListener('keydown', onKey))
  return dialog
}
