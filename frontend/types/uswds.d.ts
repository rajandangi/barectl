// USWDS publishes its component behaviors as untyped CommonJS modules.
// Barectl uses only these lifecycle methods; see packages/uswds-core/src/js/utils/behavior.js.
interface UswdsBehavior {
  on(target: HTMLElement): void;
  off(target: HTMLElement): void;
}

declare module "@uswds/uswds/js/usa-header" {
  const behavior: UswdsBehavior;
  export default behavior;
}

declare module "@uswds/uswds/js/usa-skipnav" {
  const behavior: UswdsBehavior;
  export default behavior;
}

declare module "@uswds/uswds/js/usa-table" {
  const behavior: UswdsBehavior;
  export default behavior;
}

interface Window {
  /** Read by the USWDS initializer to end its loading state. */
  uswdsPresent?: boolean;
}
