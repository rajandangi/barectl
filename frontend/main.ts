import "./styles/main.scss";
import htmx from "htmx.org";
import { startFirstAccess } from "./wordpress-first-access.ts";
import { startUswds } from "./uswds.ts";

// docs/frontend-assets.md#htmx-4
htmx.config.history = "reload";

startUswds(htmx);
startFirstAccess();
window.uswdsPresent = true;
