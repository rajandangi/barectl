import "./styles/main.scss";
import htmx from "htmx.org";
import { startUswds } from "./uswds.ts";

// Back and forward navigation reloads the page, so every restored page passes Django's
// authentication checks and initializes USWDS from a complete server response.
htmx.config.history = "reload";

startUswds(htmx);
// Tells the USWDS initializer from uswds-init.ts that component behaviors are ready.
window.uswdsPresent = true;
