/** @type {import("stylelint").Config} */
export default {
  extends: ["stylelint-config-standard-scss"],
  reportDescriptionlessDisables: true,
  reportInvalidScopeDisables: true,
  reportNeedlessDisables: true,
  rules: {
    // Barectl classes follow the USWDS BEM convention: block__element--modifier.
    "selector-class-pattern": [
      "^[a-z][a-z0-9]*(?:-[a-z0-9]+)*(?:__[a-z0-9]+(?:-[a-z0-9]+)*)?(?:--[a-z0-9]+(?:-[a-z0-9]+)*)?$",
      { message: "Expected class selector to use kebab-case BEM: block__element--modifier" },
    ],
  },
};
