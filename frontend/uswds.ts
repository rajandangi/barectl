import type { Htmx } from "htmx.org";
import navigation from "@uswds/uswds/js/usa-header";
import skipnav from "@uswds/uswds/js/usa-skipnav";
import table from "@uswds/uswds/js/usa-table";

/**
 * Elements that HTMX replaces as a whole and whose USWDS components need their own setup.
 * Swap these roots with `outerHTML`; replacing only their children is not supported.
 */
const FRAGMENT_ROOT = "[data-uswds-fragment]";

// Page-shell components are rendered once per document and never swapped.
const pageBehaviors: readonly UswdsBehavior[] = [skipnav, navigation];
// Fragment components are bound to each fragment root, never to the body, so
// delegated listeners cannot run twice for one event.
const fragmentBehaviors: readonly UswdsBehavior[] = [table];
const activeRoots = new Set<HTMLElement>();

function fragmentRootsWithin(elt: Element): HTMLElement[] {
  const roots = [...elt.querySelectorAll(FRAGMENT_ROOT)];
  if (elt.matches(FRAGMENT_ROOT)) {
    roots.unshift(elt);
  }
  return roots.filter((root) => root instanceof HTMLElement);
}

function initializeFragments(elt: Element): void {
  for (const root of fragmentRootsWithin(elt)) {
    if (activeRoots.has(root)) {
      continue;
    }
    for (const behavior of fragmentBehaviors) {
      behavior.on(root);
    }
    activeRoots.add(root);
  }
}

function releaseDetachedFragments(): void {
  for (const root of activeRoots) {
    if (!root.isConnected) {
      for (const behavior of fragmentBehaviors) {
        behavior.off(root);
      }
      activeRoots.delete(root);
    }
  }
}

/** Starts USWDS once, then follows HTMX 4 processing and swap events. */
export function startUswds(htmx: Pick<Htmx, "onLoad">): void {
  for (const behavior of pageBehaviors) {
    behavior.on(document.body);
  }
  // `htmx:after:process` fires for the initial body and for each swapped-in element.
  htmx.onLoad(initializeFragments);
  document.addEventListener("htmx:after:swap", releaseDetachedFragments);
}
