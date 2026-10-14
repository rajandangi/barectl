import "./styles/main.scss";
import "./site-identifier.ts";
import htmx from "htmx.org";
import { startUswds } from "./uswds.ts";

// docs/frontend-assets.md#htmx-4
htmx.config.history = "reload";

startUswds(htmx);
window.uswdsPresent = true;
