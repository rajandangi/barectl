// USWDS initializer: the page counts as loading until main.ts sets `window.uswdsPresent`,
// so JavaScript-dependent components do not flash. Production loads this as a classic,
// render-blocking script in <head>, as the USWDS installation guidance requires.
import "@uswds/uswds/uswds-core/src/js/uswds-init.js";
