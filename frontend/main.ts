import "./styles/main.scss";
import "./site-create.ts";
import "./site-identifier.ts";
import "./secret-generate.ts";
import "./credential-choice.ts";
import htmx from "htmx.org";
import { startUswds } from "./uswds.ts";

// docs/frontend-assets.md#htmx-4
htmx.config.history = "reload";

startUswds(htmx);
window.uswdsPresent = true;
