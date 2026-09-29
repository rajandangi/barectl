import type { Htmx } from "htmx.org";
import navigation from "@uswds/uswds/js/usa-header";
import skipnav from "@uswds/uswds/js/usa-skipnav";
import table from "@uswds/uswds/js/usa-table";

/** docs/frontend-assets.md#components-and-htmx-lifecycle */
const FRAGMENT_ROOT = "[data-uswds-fragment]";

const pageBehaviors: readonly UswdsBehavior[] = [skipnav, navigation];
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

export function startUswds(htmx: Pick<Htmx, "onLoad">): void {
  for (const behavior of pageBehaviors) {
    behavior.on(document.body);
  }
  htmx.onLoad(initializeFragments);
  document.addEventListener("htmx:after:swap", releaseDetachedFragments);
}
