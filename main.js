! function() {
  "use strict";
  var t, e, n, a, r, s = {
      32195: function(t, e, n) {
        var a = n(87537),
          r = n.n(a),
          s = n(23645),
          i = n.n(s)()(r());
        i.push([t.id, ".App{text-align:center}.App-logo{height:40vmin;pointer-events:none}@media(prefers-reduced-motion: no-preference){.App-logo{-webkit-animation:App-logo-spin infinite 20s linear;animation:App-logo-spin infinite 20s linear}}.App-header{background-color:#282c34;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;font-size:calc(10px + 2vmin);color:#fff}.App-link{color:#61dafb}@-webkit-keyframes App-logo-spin{from{-webkit-transform:rotate(0deg);transform:rotate(0deg)}to{-webkit-transform:rotate(360deg);transform:rotate(360deg)}}@keyframes App-logo-spin{from{-webkit-transform:rotate(0deg);transform:rotate(0deg)}to{-webkit-transform:rotate(360deg);transform:rotate(360deg)}}", "", {
          version: 3,
          sources: ["webpack://./src/App.css"],
          names: [],
          mappings: "AAAA,KACE,iBAAA,CAGF,UACE,aAAA,CACA,mBAAA,CAGF,8CACE,UACE,mDAAA,CAAA,2CAAA,CAAA,CAIJ,YACE,wBAAA,CACA,gBAAA,CACA,YAAA,CACA,qBAAA,CACA,kBAAA,CACA,sBAAA,CACA,4BAAA,CACA,UAAA,CAGF,UACE,aAAA,CAGF,iCACE,KACE,8BAAA,CAAA,sBAAA,CAEF,GACE,gCAAA,CAAA,wBAAA,CAAA,CALJ,yBACE,KACE,8BAAA,CAAA,sBAAA,CAEF,GACE,gCAAA,CAAA,wBAAA,CAAA",
          sourcesContent: [".App {\n  text-align: center;\n}\n\n.App-logo {\n  height: 40vmin;\n  pointer-events: none;\n}\n\n@media (prefers-reduced-motion: no-preference) {\n  .App-logo {\n    animation: App-logo-spin infinite 20s linear;\n  }\n}\n\n.App-header {\n  background-color: #282c34;\n  min-height: 100vh;\n  display: flex;\n  flex-direction: column;\n  align-items: center;\n  justify-content: center;\n  font-size: calc(10px + 2vmin);\n  color: white;\n}\n\n.App-link {\n  color: #61dafb;\n}\n\n@keyframes App-logo-spin {\n  from {\n    transform: rotate(0deg);\n  }\n  to {\n    transform: rotate(360deg);\n  }\n}\n"],
          sourceRoot: ""
        }]), e.Z = i
      },
      77291: function(t, e, n) {
        var a = n(87537),
          r = n.n(a),
          s = n(23645),
          i = n.n(s)()(r());
        i.push([t.id, ".zai-chatbot-window{box-shadow:none !important;border:none !important;background-color:rgba(0,0,0,0) !important}", "", {
          version: 3,
          sources: ["webpack://./src/components/ZaiChatBot/ZaiChatBot.css"],
          names: [],
          mappings: "AAAA,oBACE,0BAAA,CACA,sBAAA,CACA,yCAAA",
          sourcesContent: [".zai-chatbot-window {\n  box-shadow: none !important;\n  border: none !important;\n  background-color: transparent !important;\n}\n"],
          sourceRoot: ""
        }]), e.Z = i
      },
      46552: function(t, e, n) {
        var a = n(87537),
          r = n.n(a),
          s = n(23645),
          i = n.n(s)()(r());
        i.push([t.id, '/*\n! tailwindcss v3.3.2 | MIT License | https://tailwindcss.com\n*//*\n1. Prevent padding and border from affecting element width. (https://github.com/mozdevs/cssremedy/issues/4)\n2. Allow adding a border to an element by just adding a border-width. (https://github.com/tailwindcss/tailwindcss/pull/116)\n*/\n\n*,\n::before,\n::after {\n  box-sizing: border-box; /* 1 */\n  border-width: 0; /* 2 */\n  border-style: solid; /* 2 */\n  border-color: #e5e7eb; /* 2 */\n}\n\n::before,\n::after {\n  --tw-content: \'\';\n}\n\n/*\n1. Use a consistent sensible line-height in all browsers.\n2. Prevent adjustments of font size after orientation changes in iOS.\n3. Use a more readable tab size.\n4. Use the user\'s configured `sans` font-family by default.\n5. Use the user\'s configured `sans` font-feature-settings by default.\n6. Use the user\'s configured `sans` font-variation-settings by default.\n*/\n\nhtml {\n  line-height: 1.5; /* 1 */\n  -webkit-text-size-adjust: 100%; /* 2 */ /* 3 */\n  tab-size: 4; /* 3 */\n  font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, "Noto Sans", sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol", "Noto Color Emoji"; /* 4 */\n  -webkit-font-feature-settings: normal;\n          font-feature-settings: normal; /* 5 */\n  font-variation-settings: normal; /* 6 */\n}\n\n/*\n1. Remove the margin in all browsers.\n2. Inherit line-height from `html` so users can set them as a class directly on the `html` element.\n*/\n\nbody {\n  margin: 0; /* 1 */\n  line-height: inherit; /* 2 */\n}\n\n/*\n1. Add the correct height in Firefox.\n2. Correct the inheritance of border color in Firefox. (https://bugzilla.mozilla.org/show_bug.cgi?id=190655)\n3. Ensure horizontal rules are visible by default.\n*/\n\nhr {\n  height: 0; /* 1 */\n  color: inherit; /* 2 */\n  border-top-width: 1px; /* 3 */\n}\n\n/*\nAdd the correct text decoration in Chrome, Edge, and Safari.\n*/\n\nabbr:where([title]) {\n  -webkit-text-decoration: underline dotted;\n          text-decoration: underline dotted;\n}\n\n/*\nRemove the default font size and weight for headings.\n*/\n\nh1,\nh2,\nh3,\nh4,\nh5,\nh6 {\n  font-size: inherit;\n  font-weight: inherit;\n}\n\n/*\nReset links to optimize for opt-in styling instead of opt-out.\n*/\n\na {\n  color: inherit;\n  text-decoration: inherit;\n}\n\n/*\nAdd the correct font weight in Edge and Safari.\n*/\n\nb,\nstrong {\n  font-weight: bolder;\n}\n\n/*\n1. Use the user\'s configured `mono` font family by default.\n2. Correct the odd `em` font sizing in all browsers.\n*/\n\ncode,\nkbd,\nsamp,\npre {\n  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; /* 1 */\n  font-size: 1em; /* 2 */\n}\n\n/*\nAdd the correct font size in all browsers.\n*/\n\nsmall {\n  font-size: 80%;\n}\n\n/*\nPrevent `sub` and `sup` elements from affecting the line height in all browsers.\n*/\n\nsub,\nsup {\n  font-size: 75%;\n  line-height: 0;\n  position: relative;\n  vertical-align: baseline;\n}\n\nsub {\n  bottom: -0.25em;\n}\n\nsup {\n  top: -0.5em;\n}\n\n/*\n1. Remove text indentation from table contents in Chrome and Safari. (https://bugs.chromium.org/p/chromium/issues/detail?id=999088, https://bugs.webkit.org/show_bug.cgi?id=201297)\n2. Correct table border color inheritance in all Chrome and Safari. (https://bugs.chromium.org/p/chromium/issues/detail?id=935729, https://bugs.webkit.org/show_bug.cgi?id=195016)\n3. Remove gaps between table borders by default.\n*/\n\ntable {\n  text-indent: 0; /* 1 */\n  border-color: inherit; /* 2 */\n  border-collapse: collapse; /* 3 */\n}\n\n/*\n1. Change the font styles in all browsers.\n2. Remove the margin in Firefox and Safari.\n3. Remove default padding in all browsers.\n*/\n\nbutton,\ninput,\noptgroup,\nselect,\ntextarea {\n  font-family: inherit; /* 1 */\n  font-size: 100%; /* 1 */\n  font-weight: inherit; /* 1 */\n  line-height: inherit; /* 1 */\n  color: inherit; /* 1 */\n  margin: 0; /* 2 */\n  padding: 0; /* 3 */\n}\n\n/*\nRemove the inheritance of text transform in Edge and Firefox.\n*/\n\nbutton,\nselect {\n  text-transform: none;\n}\n\n/*\n1. Correct the inability to style clickable types in iOS and Safari.\n2. Remove default button styles.\n*/\n\nbutton,\n[type=\'button\'],\n[type=\'reset\'],\n[type=\'submit\'] {\n  -webkit-appearance: button; /* 1 */\n  background-color: transparent; /* 2 */\n  background-image: none; /* 2 */\n}\n\n/*\nUse the modern Firefox focus style for all focusable elements.\n*/\n\n:-moz-focusring {\n  outline: auto;\n}\n\n/*\nRemove the additional `:invalid` styles in Firefox. (https://github.com/mozilla/gecko-dev/blob/2f9eacd9d3d995c937b4251a5557d95d494c9be1/layout/style/res/forms.css#L728-L737)\n*/\n\n:-moz-ui-invalid {\n  box-shadow: none;\n}\n\n/*\nAdd the correct vertical alignment in Chrome and Firefox.\n*/\n\nprogress {\n  vertical-align: baseline;\n}\n\n/*\nCorrect the cursor style of increment and decrement buttons in Safari.\n*/\n\n::-webkit-inner-spin-button,\n::-webkit-outer-spin-button {\n  height: auto;\n}\n\n/*\n1. Correct the odd appearance in Chrome and Safari.\n2. Correct the outline style in Safari.\n*/\n\n[type=\'search\'] {\n  -webkit-appearance: textfield; /* 1 */\n  outline-offset: -2px; /* 2 */\n}\n\n/*\nRemove the inner padding in Chrome and Safari on macOS.\n*/\n\n::-webkit-search-decoration {\n  -webkit-appearance: none;\n}\n\n/*\n1. Correct the inability to style clickable types in iOS and Safari.\n2. Change font properties to `inherit` in Safari.\n*/\n\n::-webkit-file-upload-button {\n  -webkit-appearance: button; /* 1 */\n  font: inherit; /* 2 */\n}\n\n/*\nAdd the correct display in Chrome and Safari.\n*/\n\nsummary {\n  display: list-item;\n}\n\n/*\nRemoves the default spacing and border for appropriate elements.\n*/\n\nblockquote,\ndl,\ndd,\nh1,\nh2,\nh3,\nh4,\nh5,\nh6,\nhr,\nfigure,\np,\npre {\n  margin: 0;\n}\n\nfieldset {\n  margin: 0;\n  padding: 0;\n}\n\nlegend {\n  padding: 0;\n}\n\nol,\nul,\nmenu {\n  list-style: none;\n  margin: 0;\n  padding: 0;\n}\n\n/*\nPrevent resizing textareas horizontally by default.\n*/\n\ntextarea {\n  resize: vertical;\n}\n\n/*\n1. Reset the default placeholder opacity in Firefox. (https://github.com/tailwindlabs/tailwindcss/issues/3300)\n2. Set the default placeholder color to the user\'s configured gray 400 color.\n*/\n\ninput::-webkit-input-placeholder, textarea::-webkit-input-placeholder {\n  opacity: 1; /* 1 */\n  color: #9ca3af; /* 2 */\n}\n\ninput::placeholder,\ntextarea::placeholder {\n  opacity: 1; /* 1 */\n  color: #9ca3af; /* 2 */\n}\n\n/*\nSet the default cursor for buttons.\n*/\n\nbutton,\n[role="button"] {\n  cursor: pointer;\n}\n\n/*\nMake sure disabled buttons don\'t get the pointer cursor.\n*/\n:disabled {\n  cursor: default;\n}\n\n/*\n1. Make replaced elements `display: block` by default. (https://github.com/mozdevs/cssremedy/issues/14)\n2. Add `vertical-align: middle` to align replaced elements more sensibly by default. (https://github.com/jensimmons/cssremedy/issues/14#issuecomment-634934210)\n   This can trigger a poorly considered lint error in some tools but is included by design.\n*/\n\nimg,\nsvg,\nvideo,\ncanvas,\naudio,\niframe,\nembed,\nobject {\n  display: block; /* 1 */\n  vertical-align: middle; /* 2 */\n}\n\n/*\nConstrain images and videos to the parent width and preserve their intrinsic aspect ratio. (https://github.com/mozdevs/cssremedy/issues/14)\n*/\n\nimg,\nvideo {\n  max-width: 100%;\n  height: auto;\n}\n\n/* Make elements with the HTML hidden attribute stay hidden by default */\n[hidden] {\n  display: none;\n}\n\n*, ::before, ::after {\n  --tw-border-spacing-x: 0;\n  --tw-border-spacing-y: 0;\n  --tw-translate-x: 0;\n  --tw-translate-y: 0;\n  --tw-rotate: 0;\n  --tw-skew-x: 0;\n  --tw-skew-y: 0;\n  --tw-scale-x: 1;\n  --tw-scale-y: 1;\n  --tw-pan-x:  ;\n  --tw-pan-y:  ;\n  --tw-pinch-zoom:  ;\n  --tw-scroll-snap-strictness: proximity;\n  --tw-gradient-from-position:  ;\n  --tw-gradient-via-position:  ;\n  --tw-gradient-to-position:  ;\n  --tw-ordinal:  ;\n  --tw-slashed-zero:  ;\n  --tw-numeric-figure:  ;\n  --tw-numeric-spacing:  ;\n  --tw-numeric-fraction:  ;\n  --tw-ring-inset:  ;\n  --tw-ring-offset-width: 0px;\n  --tw-ring-offset-color: #fff;\n  --tw-ring-color: rgb(59 130 246 / 0.5);\n  --tw-ring-offset-shadow: 0 0 #0000;\n  --tw-ring-shadow: 0 0 #0000;\n  --tw-shadow: 0 0 #0000;\n  --tw-shadow-colored: 0 0 #0000;\n  --tw-blur:  ;\n  --tw-brightness:  ;\n  --tw-contrast:  ;\n  --tw-grayscale:  ;\n  --tw-hue-rotate:  ;\n  --tw-invert:  ;\n  --tw-saturate:  ;\n  --tw-sepia:  ;\n  --tw-drop-shadow:  ;\n  --tw-backdrop-blur:  ;\n  --tw-backdrop-brightness:  ;\n  --tw-backdrop-contrast:  ;\n  --tw-backdrop-grayscale:  ;\n  --tw-backdrop-hue-rotate:  ;\n  --tw-backdrop-invert:  ;\n  --tw-backdrop-opacity:  ;\n  --tw-backdrop-saturate:  ;\n  --tw-backdrop-sepia:  ;\n}\n\n::-webkit-backdrop {\n  --tw-border-spacing-x: 0;\n  --tw-border-spacing-y: 0;\n  --tw-translate-x: 0;\n  --tw-translate-y: 0;\n  --tw-rotate: 0;\n  --tw-skew-x: 0;\n  --tw-skew-y: 0;\n  --tw-scale-x: 1;\n  --tw-scale-y: 1;\n  --tw-pan-x:  ;\n  --tw-pan-y:  ;\n  --tw-pinch-zoom:  ;\n  --tw-scroll-snap-strictness: proximity;\n  --tw-gradient-from-position:  ;\n  --tw-gradient-via-position:  ;\n  --tw-gradient-to-position:  ;\n  --tw-ordinal:  ;\n  --tw-slashed-zero:  ;\n  --tw-numeric-figure:  ;\n  --tw-numeric-spacing:  ;\n  --tw-numeric-fraction:  ;\n  --tw-ring-inset:  ;\n  --tw-ring-offset-width: 0px;\n  --tw-ring-offset-color: #fff;\n  --tw-ring-color: rgb(59 130 246 / 0.5);\n  --tw-ring-offset-shadow: 0 0 #0000;\n  --tw-ring-shadow: 0 0 #0000;\n  --tw-shadow: 0 0 #0000;\n  --tw-shadow-colored: 0 0 #0000;\n  --tw-blur:  ;\n  --tw-brightness:  ;\n  --tw-contrast:  ;\n  --tw-grayscale:  ;\n  --tw-hue-rotate:  ;\n  --tw-invert:  ;\n  --tw-saturate:  ;\n  --tw-sepia:  ;\n  --tw-drop-shadow:  ;\n  --tw-backdrop-blur:  ;\n  --tw-backdrop-brightness:  ;\n  --tw-backdrop-contrast:  ;\n  --tw-backdrop-grayscale:  ;\n  --tw-backdrop-hue-rotate:  ;\n  --tw-backdrop-invert:  ;\n  --tw-backdrop-opacity:  ;\n  --tw-backdrop-saturate:  ;\n  --tw-backdrop-sepia:  ;\n}\n\n::backdrop {\n  --tw-border-spacing-x: 0;\n  --tw-border-spacing-y: 0;\n  --tw-translate-x: 0;\n  --tw-translate-y: 0;\n  --tw-rotate: 0;\n  --tw-skew-x: 0;\n  --tw-skew-y: 0;\n  --tw-scale-x: 1;\n  --tw-scale-y: 1;\n  --tw-pan-x:  ;\n  --tw-pan-y:  ;\n  --tw-pinch-zoom:  ;\n  --tw-scroll-snap-strictness: proximity;\n  --tw-gradient-from-position:  ;\n  --tw-gradient-via-position:  ;\n  --tw-gradient-to-position:  ;\n  --tw-ordinal:  ;\n  --tw-slashed-zero:  ;\n  --tw-numeric-figure:  ;\n  --tw-numeric-spacing:  ;\n  --tw-numeric-fraction:  ;\n  --tw-ring-inset:  ;\n  --tw-ring-offset-width: 0px;\n  --tw-ring-offset-color: #fff;\n  --tw-ring-color: rgb(59 130 246 / 0.5);\n  --tw-ring-offset-shadow: 0 0 #0000;\n  --tw-ring-shadow: 0 0 #0000;\n  --tw-shadow: 0 0 #0000;\n  --tw-shadow-colored: 0 0 #0000;\n  --tw-blur:  ;\n  --tw-brightness:  ;\n  --tw-contrast:  ;\n  --tw-grayscale:  ;\n  --tw-hue-rotate:  ;\n  --tw-invert:  ;\n  --tw-saturate:  ;\n  --tw-sepia:  ;\n  --tw-drop-shadow:  ;\n  --tw-backdrop-blur:  ;\n  --tw-backdrop-brightness:  ;\n  --tw-backdrop-contrast:  ;\n  --tw-backdrop-grayscale:  ;\n  --tw-backdrop-hue-rotate:  ;\n  --tw-backdrop-invert:  ;\n  --tw-backdrop-opacity:  ;\n  --tw-backdrop-saturate:  ;\n  --tw-backdrop-sepia:  ;\n}.tw-pointer-events-none {\n  pointer-events: none;\n}.tw-pointer-events-auto {\n  pointer-events: auto;\n}.tw-fixed {\n  position: fixed;\n}.tw-absolute {\n  position: absolute;\n}.tw-relative {\n  position: relative;\n}.tw-inset-0 {\n  inset: 0px;\n}.tw-inset-y-0 {\n  top: 0px;\n  bottom: 0px;\n}.tw-left-0 {\n  left: 0px;\n}.tw-left-1\\/2 {\n  left: 50%;\n}.tw-left-2 {\n  left: 0.5rem;\n}.tw-left-3 {\n  left: 0.75rem;\n}.tw-right-0 {\n  right: 0px;\n}.tw-right-1 {\n  right: 0.25rem;\n}.tw-right-4 {\n  right: 1rem;\n}.tw-top-0 {\n  top: 0px;\n}.tw-top-1\\/2 {\n  top: 50%;\n}.tw-top-4 {\n  top: 1rem;\n}.tw-top-\\[72px\\] {\n  top: 72px;\n}.tw-top-full {\n  top: 100%;\n}.tw-z-0 {\n  z-index: 0;\n}.tw-z-10 {\n  z-index: 10;\n}.tw-z-20 {\n  z-index: 20;\n}.tw-z-40 {\n  z-index: 40;\n}.tw-z-50 {\n  z-index: 50;\n}.tw-z-\\[60\\] {\n  z-index: 60;\n}.tw-col-span-12 {\n  grid-column: span 12 / span 12;\n}.tw-col-start-2 {\n  grid-column-start: 2;\n}.tw-row-span-2 {\n  grid-row: span 2 / span 2;\n}.tw-row-start-1 {\n  grid-row-start: 1;\n}.tw-m-0 {\n  margin: 0px;\n}.tw-mx-0 {\n  margin-left: 0px;\n  margin-right: 0px;\n}.tw-mx-0\\.5 {\n  margin-left: 0.125rem;\n  margin-right: 0.125rem;\n}.tw-mx-4 {\n  margin-left: 1rem;\n  margin-right: 1rem;\n}.tw-mx-6 {\n  margin-left: 1.5rem;\n  margin-right: 1.5rem;\n}.tw-mx-auto {\n  margin-left: auto;\n  margin-right: auto;\n}.tw-my-2 {\n  margin-top: 0.5rem;\n  margin-bottom: 0.5rem;\n}.tw--mb-1 {\n  margin-bottom: -0.25rem;\n}.tw--mt-1 {\n  margin-top: -0.25rem;\n}.tw-mb-1 {\n  margin-bottom: 0.25rem;\n}.tw-mb-1\\.5 {\n  margin-bottom: 0.375rem;\n}.tw-mb-2 {\n  margin-bottom: 0.5rem;\n}.tw-mb-2\\.5 {\n  margin-bottom: 0.625rem;\n}.tw-mb-3 {\n  margin-bottom: 0.75rem;\n}.tw-mb-4 {\n  margin-bottom: 1rem;\n}.tw-mb-5 {\n  margin-bottom: 1.25rem;\n}.tw-ml-1 {\n  margin-left: 0.25rem;\n}.tw-ml-1\\.5 {\n  margin-left: 0.375rem;\n}.tw-ml-4 {\n  margin-left: 1rem;\n}.tw-ml-auto {\n  margin-left: auto;\n}.tw-mr-1 {\n  margin-right: 0.25rem;\n}.tw-mr-1\\.5 {\n  margin-right: 0.375rem;\n}.tw-mt-0 {\n  margin-top: 0px;\n}.tw-mt-0\\.5 {\n  margin-top: 0.125rem;\n}.tw-mt-1 {\n  margin-top: 0.25rem;\n}.tw-mt-1\\.5 {\n  margin-top: 0.375rem;\n}.tw-mt-2 {\n  margin-top: 0.5rem;\n}.tw-mt-3 {\n  margin-top: 0.75rem;\n}.tw-mt-4 {\n  margin-top: 1rem;\n}.tw-mt-5 {\n  margin-top: 1.25rem;\n}.tw-mt-6 {\n  margin-top: 1.5rem;\n}.tw-line-clamp-2 {\n  overflow: hidden;\n  display: -webkit-box;\n  -webkit-box-orient: vertical;\n  -webkit-line-clamp: 2;\n}.tw-block {\n  display: block;\n}.tw-inline-block {\n  display: inline-block;\n}.tw-flex {\n  display: flex;\n}.tw-inline-flex {\n  display: inline-flex;\n}.tw-grid {\n  display: grid;\n}.tw-hidden {\n  display: none;\n}.tw-aspect-\\[3\\/1\\] {\n  aspect-ratio: 3/1;\n}.tw-aspect-\\[9\\/16\\] {\n  aspect-ratio: 9/16;\n}.tw-h-1 {\n  height: 0.25rem;\n}.tw-h-1\\.5 {\n  height: 0.375rem;\n}.tw-h-10 {\n  height: 2.5rem;\n}.tw-h-12 {\n  height: 3rem;\n}.tw-h-16 {\n  height: 4rem;\n}.tw-h-2 {\n  height: 0.5rem;\n}.tw-h-2\\.5 {\n  height: 0.625rem;\n}.tw-h-20 {\n  height: 5rem;\n}.tw-h-3 {\n  height: 0.75rem;\n}.tw-h-3\\.5 {\n  height: 0.875rem;\n}.tw-h-4 {\n  height: 1rem;\n}.tw-h-5 {\n  height: 1.25rem;\n}.tw-h-6 {\n  height: 1.5rem;\n}.tw-h-7 {\n  height: 1.75rem;\n}.tw-h-8 {\n  height: 2rem;\n}.tw-h-9 {\n  height: 2.25rem;\n}.tw-h-\\[120px\\] {\n  height: 120px;\n}.tw-h-\\[180px\\] {\n  height: 180px;\n}.tw-h-\\[18px\\] {\n  height: 18px;\n}.tw-h-\\[220px\\] {\n  height: 220px;\n}.tw-h-\\[4px\\] {\n  height: 4px;\n}.tw-h-\\[550px\\] {\n  height: 550px;\n}.tw-h-\\[80vh\\] {\n  height: 80vh;\n}.tw-h-full {\n  height: 100%;\n}.tw-h-screen {\n  height: 100vh;\n}.tw-max-h-0 {\n  max-height: 0px;\n}.tw-max-h-60 {\n  max-height: 15rem;\n}.tw-max-h-64 {\n  max-height: 16rem;\n}.tw-max-h-\\[196px\\] {\n  max-height: 196px;\n}.tw-max-h-\\[80vh\\] {\n  max-height: 80vh;\n}.tw-min-h-0 {\n  min-height: 0px;\n}.tw-min-h-\\[56px\\] {\n  min-height: 56px;\n}.tw-min-h-\\[60vh\\] {\n  min-height: 60vh;\n}.tw-w-1 {\n  width: 0.25rem;\n}.tw-w-1\\.5 {\n  width: 0.375rem;\n}.tw-w-1\\/4 {\n  width: 25%;\n}.tw-w-10 {\n  width: 2.5rem;\n}.tw-w-12 {\n  width: 3rem;\n}.tw-w-14 {\n  width: 3.5rem;\n}.tw-w-16 {\n  width: 4rem;\n}.tw-w-2 {\n  width: 0.5rem;\n}.tw-w-2\\.5 {\n  width: 0.625rem;\n}.tw-w-2\\/5 {\n  width: 40%;\n}.tw-w-20 {\n  width: 5rem;\n}.tw-w-24 {\n  width: 6rem;\n}.tw-w-28 {\n  width: 7rem;\n}.tw-w-3 {\n  width: 0.75rem;\n}.tw-w-3\\.5 {\n  width: 0.875rem;\n}.tw-w-32 {\n  width: 8rem;\n}.tw-w-36 {\n  width: 9rem;\n}.tw-w-4 {\n  width: 1rem;\n}.tw-w-4\\/5 {\n  width: 80%;\n}.tw-w-40 {\n  width: 10rem;\n}.tw-w-44 {\n  width: 11rem;\n}.tw-w-48 {\n  width: 12rem;\n}.tw-w-5 {\n  width: 1.25rem;\n}.tw-w-52 {\n  width: 13rem;\n}.tw-w-6 {\n  width: 1.5rem;\n}.tw-w-64 {\n  width: 16rem;\n}.tw-w-7 {\n  width: 1.75rem;\n}.tw-w-72 {\n  width: 18rem;\n}.tw-w-8 {\n  width: 2rem;\n}.tw-w-80 {\n  width: 20rem;\n}.tw-w-9 {\n  width: 2.25rem;\n}.tw-w-\\[120px\\] {\n  width: 120px;\n}.tw-w-\\[18px\\] {\n  width: 18px;\n}.tw-w-\\[200px\\] {\n  width: 200px;\n}.tw-w-\\[280px\\] {\n  width: 280px;\n}.tw-w-\\[330px\\] {\n  width: 330px;\n}.tw-w-\\[3px\\] {\n  width: 3px;\n}.tw-w-\\[400px\\] {\n  width: 400px;\n}.tw-w-\\[425px\\] {\n  width: 425px;\n}.tw-w-\\[90vw\\] {\n  width: 90vw;\n}.tw-w-fit {\n  width: -webkit-fit-content;\n  width: -moz-fit-content;\n  width: fit-content;\n}.tw-w-full {\n  width: 100%;\n}.tw-w-px {\n  width: 1px;\n}.tw-min-w-0 {\n  min-width: 0px;\n}.tw-max-w-\\[1120px\\] {\n  max-width: 1120px;\n}.tw-max-w-\\[1200px\\] {\n  max-width: 1200px;\n}.tw-max-w-\\[1220px\\] {\n  max-width: 1220px;\n}.tw-max-w-full {\n  max-width: 100%;\n}.tw-max-w-sm {\n  max-width: 24rem;\n}.tw-flex-1 {\n  flex: 1 1 0%;\n}.tw-flex-shrink-0 {\n  flex-shrink: 0;\n}.tw-shrink-0 {\n  flex-shrink: 0;\n}.tw--translate-x-1\\/2 {\n  --tw-translate-x: -50%;\n  -webkit-transform: translate(var(--tw-translate-x), var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y));\n          transform: translate(var(--tw-translate-x), var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y));\n}.tw--translate-x-full {\n  --tw-translate-x: -100%;\n  -webkit-transform: translate(var(--tw-translate-x), var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y));\n          transform: translate(var(--tw-translate-x), var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y));\n}.tw--translate-y-1\\/2 {\n  --tw-translate-y: -50%;\n  -webkit-transform: translate(var(--tw-translate-x), var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y));\n          transform: translate(var(--tw-translate-x), var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y));\n}.tw-translate-x-0 {\n  --tw-translate-x: 0px;\n  -webkit-transform: translate(var(--tw-translate-x), var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y));\n          transform: translate(var(--tw-translate-x), var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y));\n}.tw-translate-x-4 {\n  --tw-translate-x: 1rem;\n  -webkit-transform: translate(var(--tw-translate-x), var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y));\n          transform: translate(var(--tw-translate-x), var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y));\n}.tw-translate-x-full {\n  --tw-translate-x: 100%;\n  -webkit-transform: translate(var(--tw-translate-x), var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y));\n          transform: translate(var(--tw-translate-x), var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y));\n}.tw-rotate-180 {\n  --tw-rotate: 180deg;\n  -webkit-transform: translate(var(--tw-translate-x), var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y));\n          transform: translate(var(--tw-translate-x), var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y));\n}.tw-animate-\\[sweep_4s_linear_infinite\\] {\n  -webkit-animation: sweep 4s linear infinite;\n          animation: sweep 4s linear infinite;\n}@-webkit-keyframes tw-bounce {\n\n  0%, 100% {\n    -webkit-transform: translateY(-25%);\n            transform: translateY(-25%);\n    -webkit-animation-timing-function: cubic-bezier(0.8,0,1,1);\n            animation-timing-function: cubic-bezier(0.8,0,1,1);\n  }\n\n  50% {\n    -webkit-transform: none;\n            transform: none;\n    -webkit-animation-timing-function: cubic-bezier(0,0,0.2,1);\n            animation-timing-function: cubic-bezier(0,0,0.2,1);\n  }\n}@keyframes tw-bounce {\n\n  0%, 100% {\n    -webkit-transform: translateY(-25%);\n            transform: translateY(-25%);\n    -webkit-animation-timing-function: cubic-bezier(0.8,0,1,1);\n            animation-timing-function: cubic-bezier(0.8,0,1,1);\n  }\n\n  50% {\n    -webkit-transform: none;\n            transform: none;\n    -webkit-animation-timing-function: cubic-bezier(0,0,0.2,1);\n            animation-timing-function: cubic-bezier(0,0,0.2,1);\n  }\n}.tw-animate-bounce {\n  -webkit-animation: tw-bounce 1s infinite;\n          animation: tw-bounce 1s infinite;\n}@-webkit-keyframes tw-pulse {\n\n  50% {\n    opacity: .5;\n  }\n}@keyframes tw-pulse {\n\n  50% {\n    opacity: .5;\n  }\n}.tw-animate-pulse {\n  -webkit-animation: tw-pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;\n          animation: tw-pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;\n}@-webkit-keyframes tw-spin {\n\n  to {\n    -webkit-transform: rotate(360deg);\n            transform: rotate(360deg);\n  }\n}@keyframes tw-spin {\n\n  to {\n    -webkit-transform: rotate(360deg);\n            transform: rotate(360deg);\n  }\n}.tw-animate-spin {\n  -webkit-animation: tw-spin 1s linear infinite;\n          animation: tw-spin 1s linear infinite;\n}.tw-cursor-not-allowed {\n  cursor: not-allowed;\n}.tw-cursor-pointer {\n  cursor: pointer;\n}.tw-list-none {\n  list-style-type: none;\n}.tw-appearance-none {\n  -webkit-appearance: none;\n          appearance: none;\n}.tw-auto-rows-min {\n  grid-auto-rows: -webkit-min-content;\n  grid-auto-rows: min-content;\n}.tw-grid-cols-1 {\n  grid-template-columns: repeat(1, minmax(0, 1fr));\n}.tw-grid-cols-12 {\n  grid-template-columns: repeat(12, minmax(0, 1fr));\n}.tw-grid-cols-3 {\n  grid-template-columns: repeat(3, minmax(0, 1fr));\n}.tw-grid-cols-4 {\n  grid-template-columns: repeat(4, minmax(0, 1fr));\n}.tw-grid-rows-\\[0fr\\] {\n  grid-template-rows: 0fr;\n}.tw-grid-rows-\\[1fr\\] {\n  grid-template-rows: 1fr;\n}.tw-flex-col {\n  flex-direction: column;\n}.tw-flex-wrap {\n  flex-wrap: wrap;\n}.tw-items-start {\n  align-items: flex-start;\n}.tw-items-center {\n  align-items: center;\n}.tw-items-baseline {\n  align-items: baseline;\n}.tw-items-stretch {\n  align-items: stretch;\n}.tw-justify-start {\n  justify-content: flex-start;\n}.tw-justify-end {\n  justify-content: flex-end;\n}.tw-justify-center {\n  justify-content: center;\n}.tw-justify-between {\n  justify-content: space-between;\n}.tw-gap-0 {\n  gap: 0px;\n}.tw-gap-0\\.5 {\n  gap: 0.125rem;\n}.tw-gap-1 {\n  gap: 0.25rem;\n}.tw-gap-1\\.5 {\n  gap: 0.375rem;\n}.tw-gap-2 {\n  gap: 0.5rem;\n}.tw-gap-2\\.5 {\n  gap: 0.625rem;\n}.tw-gap-3 {\n  gap: 0.75rem;\n}.tw-gap-4 {\n  gap: 1rem;\n}.tw-gap-5 {\n  gap: 1.25rem;\n}.tw-gap-6 {\n  gap: 1.5rem;\n}.tw-gap-x-3 {\n  -webkit-column-gap: 0.75rem;\n          column-gap: 0.75rem;\n}.tw-gap-x-4 {\n  -webkit-column-gap: 1rem;\n          column-gap: 1rem;\n}.tw-gap-y-1 {\n  row-gap: 0.25rem;\n}.tw-space-y-0 > :not([hidden]) ~ :not([hidden]) {\n  --tw-space-y-reverse: 0;\n  margin-top: calc(0px * calc(1 - var(--tw-space-y-reverse)));\n  margin-bottom: calc(0px * var(--tw-space-y-reverse));\n}.tw-space-y-0\\.5 > :not([hidden]) ~ :not([hidden]) {\n  --tw-space-y-reverse: 0;\n  margin-top: calc(0.125rem * calc(1 - var(--tw-space-y-reverse)));\n  margin-bottom: calc(0.125rem * var(--tw-space-y-reverse));\n}.tw-space-y-3 > :not([hidden]) ~ :not([hidden]) {\n  --tw-space-y-reverse: 0;\n  margin-top: calc(0.75rem * calc(1 - var(--tw-space-y-reverse)));\n  margin-bottom: calc(0.75rem * var(--tw-space-y-reverse));\n}.tw-divide-x > :not([hidden]) ~ :not([hidden]) {\n  --tw-divide-x-reverse: 0;\n  border-right-width: calc(1px * var(--tw-divide-x-reverse));\n  border-left-width: calc(1px * calc(1 - var(--tw-divide-x-reverse)));\n}.tw-divide-y > :not([hidden]) ~ :not([hidden]) {\n  --tw-divide-y-reverse: 0;\n  border-top-width: calc(1px * calc(1 - var(--tw-divide-y-reverse)));\n  border-bottom-width: calc(1px * var(--tw-divide-y-reverse));\n}.tw-divide-\\[rgba\\(255\\,255\\,255\\,0\\.06\\)\\] > :not([hidden]) ~ :not([hidden]) {\n  border-color: rgba(255,255,255,0.06);\n}.tw-self-start {\n  align-self: flex-start;\n}.tw-justify-self-end {\n  justify-self: end;\n}.tw-overflow-auto {\n  overflow: auto;\n}.tw-overflow-hidden {\n  overflow: hidden;\n}.tw-overflow-x-auto {\n  overflow-x: auto;\n}.tw-overflow-y-auto {\n  overflow-y: auto;\n}.tw-overflow-x-hidden {\n  overflow-x: hidden;\n}.tw-overflow-y-hidden {\n  overflow-y: hidden;\n}.tw-truncate {\n  overflow: hidden;\n  text-overflow: ellipsis;\n  white-space: nowrap;\n}.tw-whitespace-nowrap {\n  white-space: nowrap;\n}.tw-rounded {\n  border-radius: 0.25rem;\n}.tw-rounded-2xl {\n  border-radius: 1rem;\n}.tw-rounded-\\[inherit\\] {\n  border-radius: inherit;\n}.tw-rounded-full {\n  border-radius: 9999px;\n}.tw-rounded-lg {\n  border-radius: 0.5rem;\n}.tw-rounded-md {\n  border-radius: 0.375rem;\n}.tw-rounded-sm {\n  border-radius: 0.125rem;\n}.tw-rounded-xl {\n  border-radius: 0.75rem;\n}.tw-rounded-l-lg {\n  border-top-left-radius: 0.5rem;\n  border-bottom-left-radius: 0.5rem;\n}.tw-rounded-r-full {\n  border-top-right-radius: 9999px;\n  border-bottom-right-radius: 9999px;\n}.tw-border {\n  border-width: 1px;\n}.tw-border-0 {\n  border-width: 0px;\n}.tw-border-2 {\n  border-width: 2px;\n}.tw-border-\\[3px\\] {\n  border-width: 3px;\n}.tw-border-b {\n  border-bottom-width: 1px;\n}.tw-border-l {\n  border-left-width: 1px;\n}.tw-border-r {\n  border-right-width: 1px;\n}.tw-border-t {\n  border-top-width: 1px;\n}.tw-border-dashed {\n  border-style: dashed;\n}.tw-border-\\[\\#00CCBD\\] {\n  --tw-border-opacity: 1;\n  border-color: rgb(0 204 189 / var(--tw-border-opacity));\n}.tw-border-\\[rgba\\(0\\,204\\,189\\,0\\.2\\)\\] {\n  border-color: rgba(0,204,189,0.2);\n}.tw-border-\\[rgba\\(0\\,204\\,189\\,0\\.3\\)\\] {\n  border-color: rgba(0,204,189,0.3);\n}.tw-border-\\[rgba\\(0\\,204\\,189\\,0\\.35\\)\\] {\n  border-color: rgba(0,204,189,0.35);\n}.tw-border-\\[rgba\\(0\\,204\\,189\\,0\\.4\\)\\] {\n  border-color: rgba(0,204,189,0.4);\n}.tw-border-\\[rgba\\(244\\,114\\,182\\,0\\.2\\)\\] {\n  border-color: rgba(244,114,182,0.2);\n}.tw-border-\\[rgba\\(248\\,113\\,113\\,0\\.2\\)\\] {\n  border-color: rgba(248,113,113,0.2);\n}.tw-border-\\[rgba\\(251\\,146\\,60\\,0\\.2\\)\\] {\n  border-color: rgba(251,146,60,0.2);\n}.tw-border-\\[rgba\\(251\\,191\\,36\\,0\\.2\\)\\] {\n  border-color: rgba(251,191,36,0.2);\n}.tw-border-\\[rgba\\(255\\,255\\,255\\,0\\.06\\)\\] {\n  border-color: rgba(255,255,255,0.06);\n}.tw-border-\\[rgba\\(255\\,255\\,255\\,0\\.08\\)\\] {\n  border-color: rgba(255,255,255,0.08);\n}.tw-border-\\[rgba\\(255\\,255\\,255\\,0\\.15\\)\\] {\n  border-color: rgba(255,255,255,0.15);\n}.tw-border-\\[rgba\\(52\\,211\\,153\\,0\\.2\\)\\] {\n  border-color: rgba(52,211,153,0.2);\n}.tw-border-\\[rgba\\(96\\,165\\,250\\,0\\.2\\)\\] {\n  border-color: rgba(96,165,250,0.2);\n}.tw-border-amber-400\\/20 {\n  border-color: rgb(251 191 36 / 0.2);\n}.tw-border-blue-400\\/20 {\n  border-color: rgb(96 165 250 / 0.2);\n}.tw-border-green-200 {\n  --tw-border-opacity: 1;\n  border-color: rgb(187 247 208 / var(--tw-border-opacity));\n}.tw-border-purple-400\\/20 {\n  border-color: rgb(192 132 252 / 0.2);\n}.tw-border-red-200 {\n  --tw-border-opacity: 1;\n  border-color: rgb(254 202 202 / var(--tw-border-opacity));\n}.tw-border-slate-200 {\n  --tw-border-opacity: 1;\n  border-color: rgb(226 232 240 / var(--tw-border-opacity));\n}.tw-border-transparent {\n  border-color: transparent;\n}.tw-border-white\\/10 {\n  border-color: rgb(255 255 255 / 0.1);\n}.tw-border-t-blue-500 {\n  --tw-border-opacity: 1;\n  border-top-color: rgb(59 130 246 / var(--tw-border-opacity));\n}.tw-bg-\\[\\#000614\\] {\n  --tw-bg-opacity: 1;\n  background-color: rgb(0 6 20 / var(--tw-bg-opacity));\n}.tw-bg-\\[\\#00081C\\] {\n  --tw-bg-opacity: 1;\n  background-color: rgb(0 8 28 / var(--tw-bg-opacity));\n}.tw-bg-\\[\\#000D26\\] {\n  --tw-bg-opacity: 1;\n  background-color: rgb(0 13 38 / var(--tw-bg-opacity));\n}.tw-bg-\\[\\#00CCBD\\] {\n  --tw-bg-opacity: 1;\n  background-color: rgb(0 204 189 / var(--tw-bg-opacity));\n}.tw-bg-\\[\\#00CCBD\\]\\/80 {\n  background-color: rgb(0 204 189 / 0.8);\n}.tw-bg-\\[\\#0a1021\\] {\n  --tw-bg-opacity: 1;\n  background-color: rgb(10 16 33 / var(--tw-bg-opacity));\n}.tw-bg-\\[\\#0a1224\\] {\n  --tw-bg-opacity: 1;\n  background-color: rgb(10 18 36 / var(--tw-bg-opacity));\n}.tw-bg-\\[\\#0d1a2d\\] {\n  --tw-bg-opacity: 1;\n  background-color: rgb(13 26 45 / var(--tw-bg-opacity));\n}.tw-bg-\\[\\#1a2332\\] {\n  --tw-bg-opacity: 1;\n  background-color: rgb(26 35 50 / var(--tw-bg-opacity));\n}.tw-bg-\\[\\#e07a2f\\] {\n  --tw-bg-opacity: 1;\n  background-color: rgb(224 122 47 / var(--tw-bg-opacity));\n}.tw-bg-\\[rgba\\(0\\,0\\,0\\,0\\.7\\)\\] {\n  background-color: rgba(0,0,0,0.7);\n}.tw-bg-\\[rgba\\(0\\,204\\,189\\,0\\.05\\)\\] {\n  background-color: rgba(0,204,189,0.05);\n}.tw-bg-\\[rgba\\(0\\,204\\,189\\,0\\.06\\)\\] {\n  background-color: rgba(0,204,189,0.06);\n}.tw-bg-\\[rgba\\(0\\,204\\,189\\,0\\.08\\)\\] {\n  background-color: rgba(0,204,189,0.08);\n}.tw-bg-\\[rgba\\(0\\,204\\,189\\,0\\.1\\)\\] {\n  background-color: rgba(0,204,189,0.1);\n}.tw-bg-\\[rgba\\(0\\,204\\,189\\,0\\.12\\)\\] {\n  background-color: rgba(0,204,189,0.12);\n}.tw-bg-\\[rgba\\(110\\,231\\,183\\,0\\.1\\)\\] {\n  background-color: rgba(110,231,183,0.1);\n}.tw-bg-\\[rgba\\(122\\,162\\,255\\,0\\.1\\)\\] {\n  background-color: rgba(122,162,255,0.1);\n}.tw-bg-\\[rgba\\(16\\,185\\,129\\,0\\.1\\)\\] {\n  background-color: rgba(16,185,129,0.1);\n}.tw-bg-\\[rgba\\(167\\,139\\,250\\,0\\.1\\)\\] {\n  background-color: rgba(167,139,250,0.1);\n}.tw-bg-\\[rgba\\(168\\,85\\,247\\,0\\.1\\)\\] {\n  background-color: rgba(168,85,247,0.1);\n}.tw-bg-\\[rgba\\(236\\,72\\,153\\,0\\.1\\)\\] {\n  background-color: rgba(236,72,153,0.1);\n}.tw-bg-\\[rgba\\(244\\,114\\,182\\,0\\.1\\)\\] {\n  background-color: rgba(244,114,182,0.1);\n}.tw-bg-\\[rgba\\(244\\,63\\,94\\,0\\.1\\)\\] {\n  background-color: rgba(244,63,94,0.1);\n}.tw-bg-\\[rgba\\(245\\,158\\,11\\,0\\.1\\)\\] {\n  background-color: rgba(245,158,11,0.1);\n}.tw-bg-\\[rgba\\(248\\,113\\,113\\,0\\.08\\)\\] {\n  background-color: rgba(248,113,113,0.08);\n}.tw-bg-\\[rgba\\(249\\,115\\,22\\,0\\.1\\)\\] {\n  background-color: rgba(249,115,22,0.1);\n}.tw-bg-\\[rgba\\(250\\,204\\,21\\,0\\.1\\)\\] {\n  background-color: rgba(250,204,21,0.1);\n}.tw-bg-\\[rgba\\(251\\,146\\,60\\,0\\.1\\)\\] {\n  background-color: rgba(251,146,60,0.1);\n}.tw-bg-\\[rgba\\(251\\,191\\,36\\,0\\.08\\)\\] {\n  background-color: rgba(251,191,36,0.08);\n}.tw-bg-\\[rgba\\(251\\,191\\,36\\,0\\.1\\)\\] {\n  background-color: rgba(251,191,36,0.1);\n}.tw-bg-\\[rgba\\(255\\,255\\,255\\,0\\.03\\)\\] {\n  background-color: rgba(255,255,255,0.03);\n}.tw-bg-\\[rgba\\(255\\,255\\,255\\,0\\.04\\)\\] {\n  background-color: rgba(255,255,255,0.04);\n}.tw-bg-\\[rgba\\(255\\,255\\,255\\,0\\.05\\)\\] {\n  background-color: rgba(255,255,255,0.05);\n}.tw-bg-\\[rgba\\(255\\,255\\,255\\,0\\.06\\)\\] {\n  background-color: rgba(255,255,255,0.06);\n}.tw-bg-\\[rgba\\(255\\,255\\,255\\,0\\.08\\)\\] {\n  background-color: rgba(255,255,255,0.08);\n}.tw-bg-\\[rgba\\(255\\,255\\,255\\,0\\.1\\)\\] {\n  background-color: rgba(255,255,255,0.1);\n}.tw-bg-\\[rgba\\(255\\,255\\,255\\,0\\.15\\)\\] {\n  background-color: rgba(255,255,255,0.15);\n}.tw-bg-\\[rgba\\(255\\,255\\,255\\,0\\.2\\)\\] {\n  background-color: rgba(255,255,255,0.2);\n}.tw-bg-\\[rgba\\(255\\,255\\,255\\,0\\.25\\)\\] {\n  background-color: rgba(255,255,255,0.25);\n}.tw-bg-\\[rgba\\(34\\,211\\,238\\,0\\.1\\)\\] {\n  background-color: rgba(34,211,238,0.1);\n}.tw-bg-\\[rgba\\(52\\,211\\,153\\,0\\.1\\)\\] {\n  background-color: rgba(52,211,153,0.1);\n}.tw-bg-\\[rgba\\(59\\,130\\,246\\,0\\.1\\)\\] {\n  background-color: rgba(59,130,246,0.1);\n}.tw-bg-\\[rgba\\(59\\,130\\,246\\,0\\.15\\)\\] {\n  background-color: rgba(59,130,246,0.15);\n}.tw-bg-\\[rgba\\(94\\,234\\,212\\,0\\.1\\)\\] {\n  background-color: rgba(94,234,212,0.1);\n}.tw-bg-\\[rgba\\(96\\,165\\,250\\,0\\.08\\)\\] {\n  background-color: rgba(96,165,250,0.08);\n}.tw-bg-\\[rgba\\(96\\,165\\,250\\,0\\.1\\)\\] {\n  background-color: rgba(96,165,250,0.1);\n}.tw-bg-amber-400 {\n  --tw-bg-opacity: 1;\n  background-color: rgb(251 191 36 / var(--tw-bg-opacity));\n}.tw-bg-amber-400\\/10 {\n  background-color: rgb(251 191 36 / 0.1);\n}.tw-bg-amber-400\\/70 {\n  background-color: rgb(251 191 36 / 0.7);\n}.tw-bg-amber-500 {\n  --tw-bg-opacity: 1;\n  background-color: rgb(245 158 11 / var(--tw-bg-opacity));\n}.tw-bg-black\\/40 {\n  background-color: rgb(0 0 0 / 0.4);\n}.tw-bg-black\\/50 {\n  background-color: rgb(0 0 0 / 0.5);\n}.tw-bg-blue-400 {\n  --tw-bg-opacity: 1;\n  background-color: rgb(96 165 250 / var(--tw-bg-opacity));\n}.tw-bg-blue-400\\/10 {\n  background-color: rgb(96 165 250 / 0.1);\n}.tw-bg-blue-500 {\n  --tw-bg-opacity: 1;\n  background-color: rgb(59 130 246 / var(--tw-bg-opacity));\n}.tw-bg-blue-600 {\n  --tw-bg-opacity: 1;\n  background-color: rgb(37 99 235 / var(--tw-bg-opacity));\n}.tw-bg-emerald-400 {\n  --tw-bg-opacity: 1;\n  background-color: rgb(52 211 153 / var(--tw-bg-opacity));\n}.tw-bg-emerald-500 {\n  --tw-bg-opacity: 1;\n  background-color: rgb(16 185 129 / var(--tw-bg-opacity));\n}.tw-bg-green-400 {\n  --tw-bg-opacity: 1;\n  background-color: rgb(74 222 128 / var(--tw-bg-opacity));\n}.tw-bg-green-400\\/70 {\n  background-color: rgb(74 222 128 / 0.7);\n}.tw-bg-green-50 {\n  --tw-bg-opacity: 1;\n  background-color: rgb(240 253 244 / var(--tw-bg-opacity));\n}.tw-bg-green-500 {\n  --tw-bg-opacity: 1;\n  background-color: rgb(34 197 94 / var(--tw-bg-opacity));\n}.tw-bg-green-500\\/10 {\n  background-color: rgb(34 197 94 / 0.1);\n}.tw-bg-green-600 {\n  --tw-bg-opacity: 1;\n  background-color: rgb(22 163 74 / var(--tw-bg-opacity));\n}.tw-bg-purple-400\\/10 {\n  background-color: rgb(192 132 252 / 0.1);\n}.tw-bg-purple-600 {\n  --tw-bg-opacity: 1;\n  background-color: rgb(147 51 234 / var(--tw-bg-opacity));\n}.tw-bg-red-400 {\n  --tw-bg-opacity: 1;\n  background-color: rgb(248 113 113 / var(--tw-bg-opacity));\n}.tw-bg-red-400\\/70 {\n  background-color: rgb(248 113 113 / 0.7);\n}.tw-bg-red-50 {\n  --tw-bg-opacity: 1;\n  background-color: rgb(254 242 242 / var(--tw-bg-opacity));\n}.tw-bg-red-500 {\n  --tw-bg-opacity: 1;\n  background-color: rgb(239 68 68 / var(--tw-bg-opacity));\n}.tw-bg-red-600 {\n  --tw-bg-opacity: 1;\n  background-color: rgb(220 38 38 / var(--tw-bg-opacity));\n}.tw-bg-slate-50 {\n  --tw-bg-opacity: 1;\n  background-color: rgb(248 250 252 / var(--tw-bg-opacity));\n}.tw-bg-transparent {\n  background-color: transparent;\n}.tw-bg-white {\n  --tw-bg-opacity: 1;\n  background-color: rgb(255 255 255 / var(--tw-bg-opacity));\n}.tw-bg-white\\/10 {\n  background-color: rgb(255 255 255 / 0.1);\n}.tw-bg-white\\/5 {\n  background-color: rgb(255 255 255 / 0.05);\n}.tw-bg-yellow-400 {\n  --tw-bg-opacity: 1;\n  background-color: rgb(250 204 21 / var(--tw-bg-opacity));\n}.tw-bg-gradient-to-br {\n  background-image: linear-gradient(to bottom right, var(--tw-gradient-stops));\n}.tw-from-\\[\\#00CCBD\\] {\n  --tw-gradient-from: #00CCBD var(--tw-gradient-from-position);\n  --tw-gradient-to: rgb(0 204 189 / 0) var(--tw-gradient-to-position);\n  --tw-gradient-stops: var(--tw-gradient-from), var(--tw-gradient-to);\n}.tw-to-\\[\\#00E5D4\\] {\n  --tw-gradient-to: #00E5D4 var(--tw-gradient-to-position);\n}.tw-to-\\[rgba\\(0\\,204\\,189\\,0\\.7\\)\\] {\n  --tw-gradient-to: rgba(0,204,189,0.7) var(--tw-gradient-to-position);\n}.tw-object-cover {\n  object-fit: cover;\n}.tw-p-0 {\n  padding: 0px;\n}.tw-p-0\\.5 {\n  padding: 0.125rem;\n}.tw-p-1 {\n  padding: 0.25rem;\n}.tw-p-4 {\n  padding: 1rem;\n}.tw-p-5 {\n  padding: 1.25rem;\n}.tw-p-6 {\n  padding: 1.5rem;\n}.tw-px-1 {\n  padding-left: 0.25rem;\n  padding-right: 0.25rem;\n}.tw-px-1\\.5 {\n  padding-left: 0.375rem;\n  padding-right: 0.375rem;\n}.tw-px-2 {\n  padding-left: 0.5rem;\n  padding-right: 0.5rem;\n}.tw-px-2\\.5 {\n  padding-left: 0.625rem;\n  padding-right: 0.625rem;\n}.tw-px-3 {\n  padding-left: 0.75rem;\n  padding-right: 0.75rem;\n}.tw-px-3\\.5 {\n  padding-left: 0.875rem;\n  padding-right: 0.875rem;\n}.tw-px-4 {\n  padding-left: 1rem;\n  padding-right: 1rem;\n}.tw-px-5 {\n  padding-left: 1.25rem;\n  padding-right: 1.25rem;\n}.tw-px-6 {\n  padding-left: 1.5rem;\n  padding-right: 1.5rem;\n}.tw-px-8 {\n  padding-left: 2rem;\n  padding-right: 2rem;\n}.tw-py-0 {\n  padding-top: 0px;\n  padding-bottom: 0px;\n}.tw-py-0\\.5 {\n  padding-top: 0.125rem;\n  padding-bottom: 0.125rem;\n}.tw-py-1 {\n  padding-top: 0.25rem;\n  padding-bottom: 0.25rem;\n}.tw-py-1\\.5 {\n  padding-top: 0.375rem;\n  padding-bottom: 0.375rem;\n}.tw-py-16 {\n  padding-top: 4rem;\n  padding-bottom: 4rem;\n}.tw-py-2 {\n  padding-top: 0.5rem;\n  padding-bottom: 0.5rem;\n}.tw-py-2\\.5 {\n  padding-top: 0.625rem;\n  padding-bottom: 0.625rem;\n}.tw-py-3 {\n  padding-top: 0.75rem;\n  padding-bottom: 0.75rem;\n}.tw-py-3\\.5 {\n  padding-top: 0.875rem;\n  padding-bottom: 0.875rem;\n}.tw-py-4 {\n  padding-top: 1rem;\n  padding-bottom: 1rem;\n}.tw-py-5 {\n  padding-top: 1.25rem;\n  padding-bottom: 1.25rem;\n}.tw-py-6 {\n  padding-top: 1.5rem;\n  padding-bottom: 1.5rem;\n}.tw-pb-0 {\n  padding-bottom: 0px;\n}.tw-pb-0\\.5 {\n  padding-bottom: 0.125rem;\n}.tw-pb-1 {\n  padding-bottom: 0.25rem;\n}.tw-pb-2 {\n  padding-bottom: 0.5rem;\n}.tw-pb-3 {\n  padding-bottom: 0.75rem;\n}.tw-pb-4 {\n  padding-bottom: 1rem;\n}.tw-pl-6 {\n  padding-left: 1.5rem;\n}.tw-pl-7 {\n  padding-left: 1.75rem;\n}.tw-pl-9 {\n  padding-left: 2.25rem;\n}.tw-pr-5 {\n  padding-right: 1.25rem;\n}.tw-pt-1 {\n  padding-top: 0.25rem;\n}.tw-pt-2 {\n  padding-top: 0.5rem;\n}.tw-pt-3 {\n  padding-top: 0.75rem;\n}.tw-pt-4 {\n  padding-top: 1rem;\n}.tw-pt-5 {\n  padding-top: 1.25rem;\n}.tw-pt-6 {\n  padding-top: 1.5rem;\n}.tw-text-left {\n  text-align: left;\n}.tw-text-center {\n  text-align: center;\n}.tw-text-right {\n  text-align: right;\n}.tw-text-2xl {\n  font-size: 1.5rem;\n  line-height: 2rem;\n}.tw-text-3xl {\n  font-size: 1.875rem;\n  line-height: 2.25rem;\n}.tw-text-\\[10px\\] {\n  font-size: 10px;\n}.tw-text-\\[11px\\] {\n  font-size: 11px;\n}.tw-text-\\[12px\\] {\n  font-size: 12px;\n}.tw-text-\\[13px\\] {\n  font-size: 13px;\n}.tw-text-\\[15px\\] {\n  font-size: 15px;\n}.tw-text-\\[8px\\] {\n  font-size: 8px;\n}.tw-text-\\[9px\\] {\n  font-size: 9px;\n}.tw-text-base {\n  font-size: 1rem;\n  line-height: 1.5rem;\n}.tw-text-lg {\n  font-size: 1.125rem;\n  line-height: 1.75rem;\n}.tw-text-sm {\n  font-size: 0.875rem;\n  line-height: 1.25rem;\n}.tw-text-xl {\n  font-size: 1.25rem;\n  line-height: 1.75rem;\n}.tw-text-xs {\n  font-size: 0.75rem;\n  line-height: 1rem;\n}.tw-font-bold {\n  font-weight: 700;\n}.tw-font-medium {\n  font-weight: 500;\n}.tw-font-semibold {\n  font-weight: 600;\n}.tw-uppercase {\n  text-transform: uppercase;\n}.tw-leading-\\[1\\.5\\] {\n  line-height: 1.5;\n}.tw-leading-none {\n  line-height: 1;\n}.tw-leading-relaxed {\n  line-height: 1.625;\n}.tw-leading-snug {\n  line-height: 1.375;\n}.tw-leading-tight {\n  line-height: 1.25;\n}.tw-tracking-tight {\n  letter-spacing: -0.025em;\n}.tw-tracking-wide {\n  letter-spacing: 0.025em;\n}.tw-tracking-wider {\n  letter-spacing: 0.05em;\n}.tw-tracking-widest {\n  letter-spacing: 0.1em;\n}.tw-text-\\[\\#00CCBD\\] {\n  --tw-text-opacity: 1;\n  color: rgb(0 204 189 / var(--tw-text-opacity));\n}.tw-text-\\[\\#0678FF\\] {\n  --tw-text-opacity: 1;\n  color: rgb(6 120 255 / var(--tw-text-opacity));\n}.tw-text-\\[\\#0A1526\\] {\n  --tw-text-opacity: 1;\n  color: rgb(10 21 38 / var(--tw-text-opacity));\n}.tw-text-\\[\\#4da3ff\\] {\n  --tw-text-opacity: 1;\n  color: rgb(77 163 255 / var(--tw-text-opacity));\n}.tw-text-\\[\\#5eead4\\] {\n  --tw-text-opacity: 1;\n  color: rgb(94 234 212 / var(--tw-text-opacity));\n}.tw-text-\\[\\#6ee7b7\\] {\n  --tw-text-opacity: 1;\n  color: rgb(110 231 183 / var(--tw-text-opacity));\n}.tw-text-\\[\\#7aa2ff\\] {\n  --tw-text-opacity: 1;\n  color: rgb(122 162 255 / var(--tw-text-opacity));\n}.tw-text-\\[\\#EBEBF0\\] {\n  --tw-text-opacity: 1;\n  color: rgb(235 235 240 / var(--tw-text-opacity));\n}.tw-text-\\[\\#a78bfa\\] {\n  --tw-text-opacity: 1;\n  color: rgb(167 139 250 / var(--tw-text-opacity));\n}.tw-text-\\[\\#bebebe\\] {\n  --tw-text-opacity: 1;\n  color: rgb(190 190 190 / var(--tw-text-opacity));\n}.tw-text-\\[\\#dadee4\\] {\n  --tw-text-opacity: 1;\n  color: rgb(218 222 228 / var(--tw-text-opacity));\n}.tw-text-\\[\\#e6eaf2\\] {\n  --tw-text-opacity: 1;\n  color: rgb(230 234 242 / var(--tw-text-opacity));\n}.tw-text-\\[\\#f472b6\\] {\n  --tw-text-opacity: 1;\n  color: rgb(244 114 182 / var(--tw-text-opacity));\n}.tw-text-\\[\\#facc15\\] {\n  --tw-text-opacity: 1;\n  color: rgb(250 204 21 / var(--tw-text-opacity));\n}.tw-text-\\[\\#fb923c\\] {\n  --tw-text-opacity: 1;\n  color: rgb(251 146 60 / var(--tw-text-opacity));\n}.tw-text-\\[rgba\\(255\\,255\\,255\\,0\\.2\\)\\] {\n  color: rgba(255,255,255,0.2);\n}.tw-text-\\[rgba\\(255\\,255\\,255\\,0\\.25\\)\\] {\n  color: rgba(255,255,255,0.25);\n}.tw-text-\\[rgba\\(255\\,255\\,255\\,0\\.3\\)\\] {\n  color: rgba(255,255,255,0.3);\n}.tw-text-\\[rgba\\(255\\,255\\,255\\,0\\.35\\)\\] {\n  color: rgba(255,255,255,0.35);\n}.tw-text-\\[rgba\\(255\\,255\\,255\\,0\\.5\\)\\] {\n  color: rgba(255,255,255,0.5);\n}.tw-text-\\[rgba\\(255\\,255\\,255\\,0\\.6\\)\\] {\n  color: rgba(255,255,255,0.6);\n}.tw-text-\\[rgba\\(255\\,255\\,255\\,0\\.7\\)\\] {\n  color: rgba(255,255,255,0.7);\n}.tw-text-\\[rgba\\(59\\,130\\,246\\,0\\.8\\)\\] {\n  color: rgba(59,130,246,0.8);\n}.tw-text-amber-400 {\n  --tw-text-opacity: 1;\n  color: rgb(251 191 36 / var(--tw-text-opacity));\n}.tw-text-amber-500 {\n  --tw-text-opacity: 1;\n  color: rgb(245 158 11 / var(--tw-text-opacity));\n}.tw-text-amber-800 {\n  --tw-text-opacity: 1;\n  color: rgb(146 64 14 / var(--tw-text-opacity));\n}.tw-text-blue-400 {\n  --tw-text-opacity: 1;\n  color: rgb(96 165 250 / var(--tw-text-opacity));\n}.tw-text-cyan-400 {\n  --tw-text-opacity: 1;\n  color: rgb(34 211 238 / var(--tw-text-opacity));\n}.tw-text-emerald-400 {\n  --tw-text-opacity: 1;\n  color: rgb(52 211 153 / var(--tw-text-opacity));\n}.tw-text-emerald-500 {\n  --tw-text-opacity: 1;\n  color: rgb(16 185 129 / var(--tw-text-opacity));\n}.tw-text-green-400 {\n  --tw-text-opacity: 1;\n  color: rgb(74 222 128 / var(--tw-text-opacity));\n}.tw-text-green-700 {\n  --tw-text-opacity: 1;\n  color: rgb(21 128 61 / var(--tw-text-opacity));\n}.tw-text-orange-400 {\n  --tw-text-opacity: 1;\n  color: rgb(251 146 60 / var(--tw-text-opacity));\n}.tw-text-pink-400 {\n  --tw-text-opacity: 1;\n  color: rgb(244 114 182 / var(--tw-text-opacity));\n}.tw-text-purple-400 {\n  --tw-text-opacity: 1;\n  color: rgb(192 132 252 / var(--tw-text-opacity));\n}.tw-text-red-400 {\n  --tw-text-opacity: 1;\n  color: rgb(248 113 113 / var(--tw-text-opacity));\n}.tw-text-red-500 {\n  --tw-text-opacity: 1;\n  color: rgb(239 68 68 / var(--tw-text-opacity));\n}.tw-text-red-600 {\n  --tw-text-opacity: 1;\n  color: rgb(220 38 38 / var(--tw-text-opacity));\n}.tw-text-rose-400 {\n  --tw-text-opacity: 1;\n  color: rgb(251 113 133 / var(--tw-text-opacity));\n}.tw-text-slate-300 {\n  --tw-text-opacity: 1;\n  color: rgb(203 213 225 / var(--tw-text-opacity));\n}.tw-text-slate-400 {\n  --tw-text-opacity: 1;\n  color: rgb(148 163 184 / var(--tw-text-opacity));\n}.tw-text-slate-500 {\n  --tw-text-opacity: 1;\n  color: rgb(100 116 139 / var(--tw-text-opacity));\n}.tw-text-slate-600 {\n  --tw-text-opacity: 1;\n  color: rgb(71 85 105 / var(--tw-text-opacity));\n}.tw-text-white {\n  --tw-text-opacity: 1;\n  color: rgb(255 255 255 / var(--tw-text-opacity));\n}.tw-text-white\\/50 {\n  color: rgb(255 255 255 / 0.5);\n}.tw-text-white\\/80 {\n  color: rgb(255 255 255 / 0.8);\n}.tw-text-white\\/95 {\n  color: rgb(255 255 255 / 0.95);\n}.tw-no-underline {\n  text-decoration-line: none;\n}.tw-underline-offset-4 {\n  text-underline-offset: 4px;\n}.tw-opacity-0 {\n  opacity: 0;\n}.tw-opacity-100 {\n  opacity: 1;\n}.tw-opacity-40 {\n  opacity: 0.4;\n}.tw-shadow {\n  --tw-shadow: 0 1px 3px 0 rgb(0 0 0 / 0.1), 0 1px 2px -1px rgb(0 0 0 / 0.1);\n  --tw-shadow-colored: 0 1px 3px 0 var(--tw-shadow-color), 0 1px 2px -1px var(--tw-shadow-color);\n  box-shadow: var(--tw-ring-offset-shadow, 0 0 #0000), var(--tw-ring-shadow, 0 0 #0000), var(--tw-shadow);\n}.tw-shadow-2xl {\n  --tw-shadow: 0 25px 50px -12px rgb(0 0 0 / 0.25);\n  --tw-shadow-colored: 0 25px 50px -12px var(--tw-shadow-color);\n  box-shadow: var(--tw-ring-offset-shadow, 0 0 #0000), var(--tw-ring-shadow, 0 0 #0000), var(--tw-shadow);\n}.tw-shadow-\\[0_0_20px_rgba\\(0\\,204\\,189\\,0\\.15\\)\\] {\n  --tw-shadow: 0 0 20px rgba(0,204,189,0.15);\n  --tw-shadow-colored: 0 0 20px var(--tw-shadow-color);\n  box-shadow: var(--tw-ring-offset-shadow, 0 0 #0000), var(--tw-ring-shadow, 0 0 #0000), var(--tw-shadow);\n}.tw-shadow-\\[0_10px_30px_rgba\\(0\\,0\\,0\\,0\\.35\\)\\] {\n  --tw-shadow: 0 10px 30px rgba(0,0,0,0.35);\n  --tw-shadow-colored: 0 10px 30px var(--tw-shadow-color);\n  box-shadow: var(--tw-ring-offset-shadow, 0 0 #0000), var(--tw-ring-shadow, 0 0 #0000), var(--tw-shadow);\n}.tw-shadow-\\[0_8px_30px_rgba\\(0\\,0\\,0\\,0\\.25\\)\\] {\n  --tw-shadow: 0 8px 30px rgba(0,0,0,0.25);\n  --tw-shadow-colored: 0 8px 30px var(--tw-shadow-color);\n  box-shadow: var(--tw-ring-offset-shadow, 0 0 #0000), var(--tw-ring-shadow, 0 0 #0000), var(--tw-shadow);\n}.tw-shadow-\\[0_8px_30px_rgba\\(0\\,0\\,0\\,0\\.4\\)\\] {\n  --tw-shadow: 0 8px 30px rgba(0,0,0,0.4);\n  --tw-shadow-colored: 0 8px 30px var(--tw-shadow-color);\n  box-shadow: var(--tw-ring-offset-shadow, 0 0 #0000), var(--tw-ring-shadow, 0 0 #0000), var(--tw-shadow);\n}.tw-shadow-\\[0_8px_40px_rgba\\(0\\,0\\,0\\,0\\.4\\)\\] {\n  --tw-shadow: 0 8px 40px rgba(0,0,0,0.4);\n  --tw-shadow-colored: 0 8px 40px var(--tw-shadow-color);\n  box-shadow: var(--tw-ring-offset-shadow, 0 0 #0000), var(--tw-ring-shadow, 0 0 #0000), var(--tw-shadow);\n}.tw-shadow-lg {\n  --tw-shadow: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);\n  --tw-shadow-colored: 0 10px 15px -3px var(--tw-shadow-color), 0 4px 6px -4px var(--tw-shadow-color);\n  box-shadow: var(--tw-ring-offset-shadow, 0 0 #0000), var(--tw-ring-shadow, 0 0 #0000), var(--tw-shadow);\n}.tw-shadow-sm {\n  --tw-shadow: 0 1px 2px 0 rgb(0 0 0 / 0.05);\n  --tw-shadow-colored: 0 1px 2px 0 var(--tw-shadow-color);\n  box-shadow: var(--tw-ring-offset-shadow, 0 0 #0000), var(--tw-ring-shadow, 0 0 #0000), var(--tw-shadow);\n}.tw-shadow-xl {\n  --tw-shadow: 0 20px 25px -5px rgb(0 0 0 / 0.1), 0 8px 10px -6px rgb(0 0 0 / 0.1);\n  --tw-shadow-colored: 0 20px 25px -5px var(--tw-shadow-color), 0 8px 10px -6px var(--tw-shadow-color);\n  box-shadow: var(--tw-ring-offset-shadow, 0 0 #0000), var(--tw-ring-shadow, 0 0 #0000), var(--tw-shadow);\n}.tw-outline-none {\n  outline: 2px solid transparent;\n  outline-offset: 2px;\n}.tw-backdrop-blur-\\[10px\\] {\n  --tw-backdrop-blur: blur(10px);\n  -webkit-backdrop-filter: var(--tw-backdrop-blur) var(--tw-backdrop-brightness) var(--tw-backdrop-contrast) var(--tw-backdrop-grayscale) var(--tw-backdrop-hue-rotate) var(--tw-backdrop-invert) var(--tw-backdrop-opacity) var(--tw-backdrop-saturate) var(--tw-backdrop-sepia);\n          backdrop-filter: var(--tw-backdrop-blur) var(--tw-backdrop-brightness) var(--tw-backdrop-contrast) var(--tw-backdrop-grayscale) var(--tw-backdrop-hue-rotate) var(--tw-backdrop-invert) var(--tw-backdrop-opacity) var(--tw-backdrop-saturate) var(--tw-backdrop-sepia);\n}.tw-transition-\\[filter\\,box-shadow\\] {\n  transition-property: box-shadow,-webkit-filter;\n  transition-property: filter,box-shadow;\n  transition-property: filter,box-shadow,-webkit-filter;\n  transition-timing-function: cubic-bezier(0.4, 0, 0.2, 1);\n  transition-duration: 150ms;\n}.tw-transition-all {\n  transition-property: all;\n  transition-timing-function: cubic-bezier(0.4, 0, 0.2, 1);\n  transition-duration: 150ms;\n}.tw-transition-colors {\n  transition-property: color, background-color, border-color, text-decoration-color, fill, stroke;\n  transition-timing-function: cubic-bezier(0.4, 0, 0.2, 1);\n  transition-duration: 150ms;\n}.tw-transition-opacity {\n  transition-property: opacity;\n  transition-timing-function: cubic-bezier(0.4, 0, 0.2, 1);\n  transition-duration: 150ms;\n}.tw-transition-transform {\n  transition-property: -webkit-transform;\n  transition-property: transform;\n  transition-property: transform, -webkit-transform;\n  transition-timing-function: cubic-bezier(0.4, 0, 0.2, 1);\n  transition-duration: 150ms;\n}.tw-duration-150 {\n  transition-duration: 150ms;\n}.tw-duration-200 {\n  transition-duration: 200ms;\n}.tw-duration-300 {\n  transition-duration: 300ms;\n}.tw-duration-500 {\n  transition-duration: 500ms;\n}.tw-ease-in-out {\n  transition-timing-function: cubic-bezier(0.4, 0, 0.2, 1);\n}.tw-ease-out {\n  transition-timing-function: cubic-bezier(0, 0, 0.2, 1);\n}.\\[writing-mode\\:vertical-lr\\] {\n  -webkit-writing-mode: vertical-lr;\n          writing-mode: vertical-lr;\n}:root{color-scheme:light}body{background-color:#fff;margin:0}*{scrollbar-width:thin;scrollbar-color:rgba(56,74,98,.5) rgba(0,0,0,0)}*::-webkit-scrollbar{width:6px;height:6px}*::-webkit-scrollbar-track{background:rgba(0,0,0,0)}*::-webkit-scrollbar-thumb{background-color:rgba(56,74,98,.5);border-radius:9999px}*::-webkit-scrollbar-thumb:hover{background-color:rgba(56,74,98,.8)}.editor .ql-container{border-bottom-left-radius:.25em;border-bottom-right-radius:.25em;font-size:16px;border:1px solid #6f7880 !important;border-top:none !important}.editor .ql-snow.ql-toolbar{display:block;border-top-left-radius:.25em;border-top-right-radius:.25em;opacity:40 !important;border-bottom:none !important;border:1px solid #6f7880 !important}.editor .ql-editor{min-height:2.5rem}.custom-input{font-size:16px}.custom-input::-webkit-input-placeholder{color:#585f67}.custom-input::placeholder{color:#585f67}.custom-constraint-text{font-family:"Amazon Ember","Amazon Ember Arabic",Arial,sans-serif;color:#575f67;font-size:14px;font-weight:400;line-height:20px;cursor:default;margin-top:4px}.card-lit{position:relative;border-color:rgba(0,204,189,.15) !important;background-image:radial-gradient(500px at 0% 0%, rgba(0, 204, 189, 0.06), rgba(60, 40, 140, 0.05) 40%, transparent 70%);box-shadow:0 4px 24px rgba(0,0,0,.3),inset 0 1px 0 0 rgba(255,255,255,.1),0 0 30px rgba(0,204,189,.08)}.glass-surface{background:rgba(255,255,255,.05);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);border:1px solid rgba(255,255,255,.1);box-shadow:0 8px 30px rgba(0,0,0,.25)}.card-surface{background-color:#000d26;border:1px solid rgba(255,255,255,.08);border-radius:16px;padding:16px;background-image:radial-gradient(500px at 0% 0%, rgba(0, 204, 189, 0.06), rgba(60, 40, 140, 0.05) 40%, transparent 70%);box-shadow:0 4px 24px rgba(0,0,0,.3),inset 0 1px 0 0 rgba(255,255,255,.1)}.card-surface:hover{background-color:#001232}@-webkit-keyframes shimmer{0%{background-position:-200% 0}100%{background-position:200% 0}}@keyframes shimmer{0%{background-position:-200% 0}100%{background-position:200% 0}}.animate-shimmer{background:linear-gradient(90deg, #4ade80 0%, #4ade80 35%, #d1fae5 50%, #4ade80 65%, #4ade80 100%);background-size:200% 100%;-webkit-animation:shimmer 2.5s ease-in-out infinite;animation:shimmer 2.5s ease-in-out infinite;-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:rgba(0,0,0,0)}@-webkit-keyframes dots{0%,20%{content:"."}40%{content:".."}60%,100%{content:"..."}}@keyframes dots{0%,20%{content:"."}40%{content:".."}60%,100%{content:"..."}}.animate-dots::after{content:".";-webkit-animation:dots 1.5s steps(3, end) infinite;animation:dots 1.5s steps(3, end) infinite}@-webkit-keyframes glow-pulse{0%,100%{opacity:.35;-webkit-transform:translate(-50%, 0) scale(1);transform:translate(-50%, 0) scale(1)}50%{opacity:.6;-webkit-transform:translate(-50%, 0) scale(1.1);transform:translate(-50%, 0) scale(1.1)}}@keyframes glow-pulse{0%,100%{opacity:.35;-webkit-transform:translate(-50%, 0) scale(1);transform:translate(-50%, 0) scale(1)}50%{opacity:.6;-webkit-transform:translate(-50%, 0) scale(1.1);transform:translate(-50%, 0) scale(1.1)}}.animate-glow-pulse{-webkit-animation:glow-pulse 3s ease-in-out infinite;animation:glow-pulse 3s ease-in-out infinite}.text-body{font-size:13px;line-height:1.5;color:#bebebe}.scrollbar-auto-hide [data-slot=scroll-area-viewport]{overflow-y:overlay !important;scrollbar-width:thin;scrollbar-color:rgba(0,0,0,0) rgba(0,0,0,0)}.scrollbar-auto-hide [data-slot=scroll-area-viewport]::-webkit-scrollbar{width:6px}.scrollbar-auto-hide [data-slot=scroll-area-viewport]::-webkit-scrollbar-track{background:rgba(0,0,0,0)}.scrollbar-auto-hide [data-slot=scroll-area-viewport]::-webkit-scrollbar-thumb{background-color:rgba(0,0,0,0);border-radius:9999px}.scrollbar-auto-hide [data-slot=scroll-area-viewport].is-scrolling::-webkit-scrollbar-thumb{background-color:rgba(255,255,255,.15)}.scrollbar-auto-hide [data-slot=scroll-area-viewport].is-scrolling::-webkit-scrollbar-thumb:hover{background-color:rgba(255,255,255,.25)}.placeholder\\:tw-text-\\[rgba\\(255\\2c 255\\2c 255\\2c 0\\.25\\)\\]::-webkit-input-placeholder {\n  color: rgba(255,255,255,0.25);\n}.placeholder\\:tw-text-\\[rgba\\(255\\2c 255\\2c 255\\2c 0\\.25\\)\\]::placeholder {\n  color: rgba(255,255,255,0.25);\n}.placeholder\\:tw-text-\\[rgba\\(255\\2c 255\\2c 255\\2c 0\\.35\\)\\]::-webkit-input-placeholder {\n  color: rgba(255,255,255,0.35);\n}.placeholder\\:tw-text-\\[rgba\\(255\\2c 255\\2c 255\\2c 0\\.35\\)\\]::placeholder {\n  color: rgba(255,255,255,0.35);\n}.first\\:tw-pl-0:first-child {\n  padding-left: 0px;\n}.last\\:tw-pr-0:last-child {\n  padding-right: 0px;\n}.focus-within\\:tw-border-\\[\\#00CCBD\\]\\/40:focus-within {\n  border-color: rgb(0 204 189 / 0.4);\n}.focus-within\\:tw-ring-1:focus-within {\n  --tw-ring-offset-shadow: var(--tw-ring-inset) 0 0 0 var(--tw-ring-offset-width) var(--tw-ring-offset-color);\n  --tw-ring-shadow: var(--tw-ring-inset) 0 0 0 calc(1px + var(--tw-ring-offset-width)) var(--tw-ring-color);\n  box-shadow: var(--tw-ring-offset-shadow), var(--tw-ring-shadow), var(--tw-shadow, 0 0 #0000);\n}.focus-within\\:tw-ring-\\[\\#00CCBD\\]\\/20:focus-within {\n  --tw-ring-color: rgb(0 204 189 / 0.2);\n}.hover\\:-tw-translate-y-0:hover {\n  --tw-translate-y: -0px;\n  -webkit-transform: translate(var(--tw-translate-x), var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y));\n          transform: translate(var(--tw-translate-x), var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y));\n}.hover\\:-tw-translate-y-0\\.5:hover {\n  --tw-translate-y: -0.125rem;\n  -webkit-transform: translate(var(--tw-translate-x), var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y));\n          transform: translate(var(--tw-translate-x), var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y));\n}.hover\\:tw-border-\\[\\#00CCBD\\]\\/30:hover {\n  border-color: rgb(0 204 189 / 0.3);\n}.hover\\:tw-border-\\[rgba\\(0\\2c 204\\2c 189\\2c 0\\.35\\)\\]:hover {\n  border-color: rgba(0,204,189,0.35);\n}.hover\\:tw-border-\\[rgba\\(255\\2c 255\\2c 255\\2c 0\\.06\\)\\]:hover {\n  border-color: rgba(255,255,255,0.06);\n}.hover\\:tw-border-slate-300:hover {\n  --tw-border-opacity: 1;\n  border-color: rgb(203 213 225 / var(--tw-border-opacity));\n}.hover\\:tw-border-white\\/20:hover {\n  border-color: rgb(255 255 255 / 0.2);\n}.hover\\:tw-bg-\\[\\#000D26\\]:hover {\n  --tw-bg-opacity: 1;\n  background-color: rgb(0 13 38 / var(--tw-bg-opacity));\n}.hover\\:tw-bg-\\[\\#00173D\\]:hover {\n  --tw-bg-opacity: 1;\n  background-color: rgb(0 23 61 / var(--tw-bg-opacity));\n}.hover\\:tw-bg-\\[\\#00E5D4\\]:hover {\n  --tw-bg-opacity: 1;\n  background-color: rgb(0 229 212 / var(--tw-bg-opacity));\n}.hover\\:tw-bg-\\[rgba\\(0\\2c 204\\2c 189\\2c 0\\.1\\)\\]:hover {\n  background-color: rgba(0,204,189,0.1);\n}.hover\\:tw-bg-\\[rgba\\(0\\2c 204\\2c 189\\2c 0\\.12\\)\\]:hover {\n  background-color: rgba(0,204,189,0.12);\n}.hover\\:tw-bg-\\[rgba\\(0\\2c 204\\2c 189\\2c 0\\.9\\)\\]:hover {\n  background-color: rgba(0,204,189,0.9);\n}.hover\\:tw-bg-\\[rgba\\(244\\2c 114\\2c 182\\2c 0\\.15\\)\\]:hover {\n  background-color: rgba(244,114,182,0.15);\n}.hover\\:tw-bg-\\[rgba\\(251\\2c 146\\2c 60\\2c 0\\.15\\)\\]:hover {\n  background-color: rgba(251,146,60,0.15);\n}.hover\\:tw-bg-\\[rgba\\(251\\2c 191\\2c 36\\2c 0\\.15\\)\\]:hover {\n  background-color: rgba(251,191,36,0.15);\n}.hover\\:tw-bg-\\[rgba\\(255\\2c 255\\2c 255\\2c 0\\.02\\)\\]:hover {\n  background-color: rgba(255,255,255,0.02);\n}.hover\\:tw-bg-\\[rgba\\(255\\2c 255\\2c 255\\2c 0\\.03\\)\\]:hover {\n  background-color: rgba(255,255,255,0.03);\n}.hover\\:tw-bg-\\[rgba\\(255\\2c 255\\2c 255\\2c 0\\.04\\)\\]:hover {\n  background-color: rgba(255,255,255,0.04);\n}.hover\\:tw-bg-\\[rgba\\(255\\2c 255\\2c 255\\2c 0\\.05\\)\\]:hover {\n  background-color: rgba(255,255,255,0.05);\n}.hover\\:tw-bg-\\[rgba\\(255\\2c 255\\2c 255\\2c 0\\.06\\)\\]:hover {\n  background-color: rgba(255,255,255,0.06);\n}.hover\\:tw-bg-\\[rgba\\(255\\2c 255\\2c 255\\2c 0\\.1\\)\\]:hover {\n  background-color: rgba(255,255,255,0.1);\n}.hover\\:tw-bg-\\[rgba\\(52\\2c 211\\2c 153\\2c 0\\.15\\)\\]:hover {\n  background-color: rgba(52,211,153,0.15);\n}.hover\\:tw-bg-\\[rgba\\(96\\2c 165\\2c 250\\2c 0\\.15\\)\\]:hover {\n  background-color: rgba(96,165,250,0.15);\n}.hover\\:tw-bg-blue-600:hover {\n  --tw-bg-opacity: 1;\n  background-color: rgb(37 99 235 / var(--tw-bg-opacity));\n}.hover\\:tw-bg-blue-700:hover {\n  --tw-bg-opacity: 1;\n  background-color: rgb(29 78 216 / var(--tw-bg-opacity));\n}.hover\\:tw-bg-red-600:hover {\n  --tw-bg-opacity: 1;\n  background-color: rgb(220 38 38 / var(--tw-bg-opacity));\n}.hover\\:tw-bg-red-700:hover {\n  --tw-bg-opacity: 1;\n  background-color: rgb(185 28 28 / var(--tw-bg-opacity));\n}.hover\\:tw-bg-slate-50:hover {\n  --tw-bg-opacity: 1;\n  background-color: rgb(248 250 252 / var(--tw-bg-opacity));\n}.hover\\:tw-bg-transparent:hover {\n  background-color: transparent;\n}.hover\\:tw-bg-white\\/10:hover {\n  background-color: rgb(255 255 255 / 0.1);\n}.hover\\:tw-bg-white\\/5:hover {\n  background-color: rgb(255 255 255 / 0.05);\n}.hover\\:tw-text-\\[\\#00CCBD\\]:hover {\n  --tw-text-opacity: 1;\n  color: rgb(0 204 189 / var(--tw-text-opacity));\n}.hover\\:tw-text-\\[\\#00E5D4\\]:hover {\n  --tw-text-opacity: 1;\n  color: rgb(0 229 212 / var(--tw-text-opacity));\n}.hover\\:tw-text-\\[\\#3b8ef5\\]:hover {\n  --tw-text-opacity: 1;\n  color: rgb(59 142 245 / var(--tw-text-opacity));\n}.hover\\:tw-text-\\[\\#e6eaf2\\]:hover {\n  --tw-text-opacity: 1;\n  color: rgb(230 234 242 / var(--tw-text-opacity));\n}.hover\\:tw-text-\\[rgba\\(255\\2c 255\\2c 255\\2c 0\\.5\\)\\]:hover {\n  color: rgba(255,255,255,0.5);\n}.hover\\:tw-text-\\[rgba\\(255\\2c 255\\2c 255\\2c 0\\.6\\)\\]:hover {\n  color: rgba(255,255,255,0.6);\n}.hover\\:tw-text-\\[rgba\\(255\\2c 255\\2c 255\\2c 0\\.8\\)\\]:hover {\n  color: rgba(255,255,255,0.8);\n}.hover\\:tw-text-slate-300:hover {\n  --tw-text-opacity: 1;\n  color: rgb(203 213 225 / var(--tw-text-opacity));\n}.hover\\:tw-text-white:hover {\n  --tw-text-opacity: 1;\n  color: rgb(255 255 255 / var(--tw-text-opacity));\n}.hover\\:tw-underline:hover {\n  text-decoration-line: underline;\n}.hover\\:tw-shadow-\\[0_12px_36px_rgba\\(0\\2c 0\\2c 0\\2c 0\\.4\\)\\]:hover {\n  --tw-shadow: 0 12px 36px rgba(0,0,0,0.4);\n  --tw-shadow-colored: 0 12px 36px var(--tw-shadow-color);\n  box-shadow: var(--tw-ring-offset-shadow, 0 0 #0000), var(--tw-ring-shadow, 0 0 #0000), var(--tw-shadow);\n}.hover\\:tw-shadow-md:hover {\n  --tw-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);\n  --tw-shadow-colored: 0 4px 6px -1px var(--tw-shadow-color), 0 2px 4px -2px var(--tw-shadow-color);\n  box-shadow: var(--tw-ring-offset-shadow, 0 0 #0000), var(--tw-ring-shadow, 0 0 #0000), var(--tw-shadow);\n}.hover\\:tw-shadow-sm:hover {\n  --tw-shadow: 0 1px 2px 0 rgb(0 0 0 / 0.05);\n  --tw-shadow-colored: 0 1px 2px 0 var(--tw-shadow-color);\n  box-shadow: var(--tw-ring-offset-shadow, 0 0 #0000), var(--tw-ring-shadow, 0 0 #0000), var(--tw-shadow);\n}.hover\\:tw-brightness-\\[1\\.03\\]:hover {\n  --tw-brightness: brightness(1.03);\n  -webkit-filter: var(--tw-blur) var(--tw-brightness) var(--tw-contrast) var(--tw-grayscale) var(--tw-hue-rotate) var(--tw-invert) var(--tw-saturate) var(--tw-sepia) var(--tw-drop-shadow);\n          filter: var(--tw-blur) var(--tw-brightness) var(--tw-contrast) var(--tw-grayscale) var(--tw-hue-rotate) var(--tw-invert) var(--tw-saturate) var(--tw-sepia) var(--tw-drop-shadow);\n}.hover\\:tw-brightness-\\[1\\.15\\]:hover {\n  --tw-brightness: brightness(1.15);\n  -webkit-filter: var(--tw-blur) var(--tw-brightness) var(--tw-contrast) var(--tw-grayscale) var(--tw-hue-rotate) var(--tw-invert) var(--tw-saturate) var(--tw-sepia) var(--tw-drop-shadow);\n          filter: var(--tw-blur) var(--tw-brightness) var(--tw-contrast) var(--tw-grayscale) var(--tw-hue-rotate) var(--tw-invert) var(--tw-saturate) var(--tw-sepia) var(--tw-drop-shadow);\n}.focus\\:tw-border-\\[\\#00CCBD\\]:focus {\n  --tw-border-opacity: 1;\n  border-color: rgb(0 204 189 / var(--tw-border-opacity));\n}.focus\\:tw-border-\\[rgba\\(0\\2c 204\\2c 189\\2c 0\\.4\\)\\]:focus {\n  border-color: rgba(0,204,189,0.4);\n}.focus\\:tw-ring-1:focus {\n  --tw-ring-offset-shadow: var(--tw-ring-inset) 0 0 0 var(--tw-ring-offset-width) var(--tw-ring-offset-color);\n  --tw-ring-shadow: var(--tw-ring-inset) 0 0 0 calc(1px + var(--tw-ring-offset-width)) var(--tw-ring-color);\n  box-shadow: var(--tw-ring-offset-shadow), var(--tw-ring-shadow), var(--tw-shadow, 0 0 #0000);\n}.focus\\:tw-ring-\\[rgba\\(0\\2c 204\\2c 189\\2c 0\\.2\\)\\]:focus {\n  --tw-ring-color: rgba(0,204,189,0.2);\n}.focus-visible\\:tw-border-\\[\\#00CCBD\\]:focus-visible {\n  --tw-border-opacity: 1;\n  border-color: rgb(0 204 189 / var(--tw-border-opacity));\n}.focus-visible\\:tw-ring-\\[rgba\\(0\\2c 204\\2c 189\\2c 0\\.2\\)\\]:focus-visible {\n  --tw-ring-color: rgba(0,204,189,0.2);\n}.active\\:tw-translate-y-0:active {\n  --tw-translate-y: 0px;\n  -webkit-transform: translate(var(--tw-translate-x), var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y));\n          transform: translate(var(--tw-translate-x), var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y));\n}.active\\:tw-scale-95:active {\n  --tw-scale-x: .95;\n  --tw-scale-y: .95;\n  -webkit-transform: translate(var(--tw-translate-x), var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y));\n          transform: translate(var(--tw-translate-x), var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y));\n}.active\\:tw-scale-\\[0\\.97\\]:active {\n  --tw-scale-x: 0.97;\n  --tw-scale-y: 0.97;\n  -webkit-transform: translate(var(--tw-translate-x), var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y));\n          transform: translate(var(--tw-translate-x), var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y));\n}.disabled\\:tw-pointer-events-none:disabled {\n  pointer-events: none;\n}.disabled\\:tw-cursor-not-allowed:disabled {\n  cursor: not-allowed;\n}.disabled\\:tw-opacity-50:disabled {\n  opacity: 0.5;\n}.tw-group:hover .group-hover\\:tw-bg-\\[rgba\\(255\\2c 255\\2c 255\\2c 0\\.08\\)\\] {\n  background-color: rgba(255,255,255,0.08);\n}@media (min-width: 640px) {\n\n  .sm\\:tw-hidden {\n    display: none;\n  }\n\n  .sm\\:tw-h-9 {\n    height: 2.25rem;\n  }\n\n  .sm\\:tw-w-9 {\n    width: 2.25rem;\n  }\n\n  .sm\\:tw-w-\\[480px\\] {\n    width: 480px;\n  }\n\n  .sm\\:tw-max-w-\\[480px\\] {\n    max-width: 480px;\n  }\n\n  .sm\\:tw-max-w-md {\n    max-width: 28rem;\n  }\n\n  .sm\\:tw-flex-row {\n    flex-direction: row;\n  }\n\n  .sm\\:tw-items-center {\n    align-items: center;\n  }\n\n  .sm\\:tw-justify-start {\n    justify-content: flex-start;\n  }\n\n  .sm\\:tw-justify-between {\n    justify-content: space-between;\n  }\n\n  .sm\\:tw-gap-4 {\n    gap: 1rem;\n  }\n\n  .sm\\:tw-gap-6 {\n    gap: 1.5rem;\n  }\n\n  .sm\\:tw-p-5 {\n    padding: 1.25rem;\n  }\n\n  .sm\\:tw-p-6 {\n    padding: 1.5rem;\n  }\n\n  .sm\\:tw-px-4 {\n    padding-left: 1rem;\n    padding-right: 1rem;\n  }\n\n  .sm\\:tw-text-lg {\n    font-size: 1.125rem;\n    line-height: 1.75rem;\n  }\n\n  .sm\\:tw-text-sm {\n    font-size: 0.875rem;\n    line-height: 1.25rem;\n  }\n}@media (min-width: 768px) {\n\n  .md\\:tw-col-span-4 {\n    grid-column: span 4 / span 4;\n  }\n\n  .md\\:tw-col-span-6 {\n    grid-column: span 6 / span 6;\n  }\n\n  .md\\:tw-grid-cols-2 {\n    grid-template-columns: repeat(2, minmax(0, 1fr));\n  }\n\n  .md\\:tw-grid-cols-3 {\n    grid-template-columns: repeat(3, minmax(0, 1fr));\n  }\n}.\\[\\&\\:\\:-webkit-scrollbar-thumb\\:hover\\]\\:tw-bg-\\[rgba\\(255\\2c 255\\2c 255\\2c 0\\.25\\)\\]::-webkit-scrollbar-thumb:hover {\n  background-color: rgba(255,255,255,0.25);\n}.\\[\\&\\:\\:-webkit-scrollbar-thumb\\]\\:tw-rounded-full::-webkit-scrollbar-thumb {\n  border-radius: 9999px;\n}.\\[\\&\\:\\:-webkit-scrollbar-thumb\\]\\:tw-bg-\\[rgba\\(255\\2c 255\\2c 255\\2c 0\\.15\\)\\]::-webkit-scrollbar-thumb {\n  background-color: rgba(255,255,255,0.15);\n}.\\[\\&\\:\\:-webkit-scrollbar-track\\]\\:tw-bg-transparent::-webkit-scrollbar-track {\n  background-color: transparent;\n}.\\[\\&\\:\\:-webkit-scrollbar\\]\\:tw-w-1\\.5::-webkit-scrollbar {\n  width: 0.375rem;\n}.\\[\\&\\:\\:-webkit-scrollbar\\]\\:tw-w-2::-webkit-scrollbar {\n  width: 0.5rem;\n}.\\[\\&\\>button\\]\\:tw-hidden>button {\n  display: none;\n}', "", {
          version: 3,
          sources: ["webpack://./src/index.css"],
          names: [],
          mappings: "AAAA;;CAAA,CAAA;;;CAAA;;AAAA;;;EAAA,sBAAA,EAAA,MAAA;EAAA,eAAA,EAAA,MAAA;EAAA,mBAAA,EAAA,MAAA;EAAA,qBAAA,EAAA,MAAA;AAAA;;AAAA;;EAAA,gBAAA;AAAA;;AAAA;;;;;;;CAAA;;AAAA;EAAA,gBAAA,EAAA,MAAA;EAAA,8BAAA,EAAA,MAAA,EAAA,MAAA;EAAA,WAAA,EAAA,MAAA;EAAA,4NAAA,EAAA,MAAA;EAAA,qCAAA;UAAA,6BAAA,EAAA,MAAA;EAAA,+BAAA,EAAA,MAAA;AAAA;;AAAA;;;CAAA;;AAAA;EAAA,SAAA,EAAA,MAAA;EAAA,oBAAA,EAAA,MAAA;AAAA;;AAAA;;;;CAAA;;AAAA;EAAA,SAAA,EAAA,MAAA;EAAA,cAAA,EAAA,MAAA;EAAA,qBAAA,EAAA,MAAA;AAAA;;AAAA;;CAAA;;AAAA;EAAA,yCAAA;UAAA,iCAAA;AAAA;;AAAA;;CAAA;;AAAA;;;;;;EAAA,kBAAA;EAAA,oBAAA;AAAA;;AAAA;;CAAA;;AAAA;EAAA,cAAA;EAAA,wBAAA;AAAA;;AAAA;;CAAA;;AAAA;;EAAA,mBAAA;AAAA;;AAAA;;;CAAA;;AAAA;;;;EAAA,+GAAA,EAAA,MAAA;EAAA,cAAA,EAAA,MAAA;AAAA;;AAAA;;CAAA;;AAAA;EAAA,cAAA;AAAA;;AAAA;;CAAA;;AAAA;;EAAA,cAAA;EAAA,cAAA;EAAA,kBAAA;EAAA,wBAAA;AAAA;;AAAA;EAAA,eAAA;AAAA;;AAAA;EAAA,WAAA;AAAA;;AAAA;;;;CAAA;;AAAA;EAAA,cAAA,EAAA,MAAA;EAAA,qBAAA,EAAA,MAAA;EAAA,yBAAA,EAAA,MAAA;AAAA;;AAAA;;;;CAAA;;AAAA;;;;;EAAA,oBAAA,EAAA,MAAA;EAAA,eAAA,EAAA,MAAA;EAAA,oBAAA,EAAA,MAAA;EAAA,oBAAA,EAAA,MAAA;EAAA,cAAA,EAAA,MAAA;EAAA,SAAA,EAAA,MAAA;EAAA,UAAA,EAAA,MAAA;AAAA;;AAAA;;CAAA;;AAAA;;EAAA,oBAAA;AAAA;;AAAA;;;CAAA;;AAAA;;;;EAAA,0BAAA,EAAA,MAAA;EAAA,6BAAA,EAAA,MAAA;EAAA,sBAAA,EAAA,MAAA;AAAA;;AAAA;;CAAA;;AAAA;EAAA,aAAA;AAAA;;AAAA;;CAAA;;AAAA;EAAA,gBAAA;AAAA;;AAAA;;CAAA;;AAAA;EAAA,wBAAA;AAAA;;AAAA;;CAAA;;AAAA;;EAAA,YAAA;AAAA;;AAAA;;;CAAA;;AAAA;EAAA,6BAAA,EAAA,MAAA;EAAA,oBAAA,EAAA,MAAA;AAAA;;AAAA;;CAAA;;AAAA;EAAA,wBAAA;AAAA;;AAAA;;;CAAA;;AAAA;EAAA,0BAAA,EAAA,MAAA;EAAA,aAAA,EAAA,MAAA;AAAA;;AAAA;;CAAA;;AAAA;EAAA,kBAAA;AAAA;;AAAA;;CAAA;;AAAA;;;;;;;;;;;;;EAAA,SAAA;AAAA;;AAAA;EAAA,SAAA;EAAA,UAAA;AAAA;;AAAA;EAAA,UAAA;AAAA;;AAAA;;;EAAA,gBAAA;EAAA,SAAA;EAAA,UAAA;AAAA;;AAAA;;CAAA;;AAAA;EAAA,gBAAA;AAAA;;AAAA;;;CAAA;;AAAA;EAAA,UAAA,EAAA,MAAA;EAAA,cAAA,EAAA,MAAA;AAAA;;AAAA;;EAAA,UAAA,EAAA,MAAA;EAAA,cAAA,EAAA,MAAA;AAAA;;AAAA;;CAAA;;AAAA;;EAAA,eAAA;AAAA;;AAAA;;CAAA;AAAA;EAAA,eAAA;AAAA;;AAAA;;;;CAAA;;AAAA;;;;;;;;EAAA,cAAA,EAAA,MAAA;EAAA,sBAAA,EAAA,MAAA;AAAA;;AAAA;;CAAA;;AAAA;;EAAA,eAAA;EAAA,YAAA;AAAA;;AAAA,wEAAA;AAAA;EAAA,aAAA;AAAA;;AAAA;EAAA,wBAAA;EAAA,wBAAA;EAAA,mBAAA;EAAA,mBAAA;EAAA,cAAA;EAAA,cAAA;EAAA,cAAA;EAAA,eAAA;EAAA,eAAA;EAAA,aAAA;EAAA,aAAA;EAAA,kBAAA;EAAA,sCAAA;EAAA,8BAAA;EAAA,6BAAA;EAAA,4BAAA;EAAA,eAAA;EAAA,oBAAA;EAAA,sBAAA;EAAA,uBAAA;EAAA,wBAAA;EAAA,kBAAA;EAAA,2BAAA;EAAA,4BAAA;EAAA,sCAAA;EAAA,kCAAA;EAAA,2BAAA;EAAA,sBAAA;EAAA,8BAAA;EAAA,YAAA;EAAA,kBAAA;EAAA,gBAAA;EAAA,iBAAA;EAAA,kBAAA;EAAA,cAAA;EAAA,gBAAA;EAAA,aAAA;EAAA,mBAAA;EAAA,qBAAA;EAAA,2BAAA;EAAA,yBAAA;EAAA,0BAAA;EAAA,2BAAA;EAAA,uBAAA;EAAA,wBAAA;EAAA,yBAAA;EAAA;AAAA;;AAAA;EAAA,wBAAA;EAAA,wBAAA;EAAA,mBAAA;EAAA,mBAAA;EAAA,cAAA;EAAA,cAAA;EAAA,cAAA;EAAA,eAAA;EAAA,eAAA;EAAA,aAAA;EAAA,aAAA;EAAA,kBAAA;EAAA,sCAAA;EAAA,8BAAA;EAAA,6BAAA;EAAA,4BAAA;EAAA,eAAA;EAAA,oBAAA;EAAA,sBAAA;EAAA,uBAAA;EAAA,wBAAA;EAAA,kBAAA;EAAA,2BAAA;EAAA,4BAAA;EAAA,sCAAA;EAAA,kCAAA;EAAA,2BAAA;EAAA,sBAAA;EAAA,8BAAA;EAAA,YAAA;EAAA,kBAAA;EAAA,gBAAA;EAAA,iBAAA;EAAA,kBAAA;EAAA,cAAA;EAAA,gBAAA;EAAA,aAAA;EAAA,mBAAA;EAAA,qBAAA;EAAA,2BAAA;EAAA,yBAAA;EAAA,0BAAA;EAAA,2BAAA;EAAA,uBAAA;EAAA,wBAAA;EAAA,yBAAA;EAAA;AAAA;;AAAA;EAAA,wBAAA;EAAA,wBAAA;EAAA,mBAAA;EAAA,mBAAA;EAAA,cAAA;EAAA,cAAA;EAAA,cAAA;EAAA,eAAA;EAAA,eAAA;EAAA,aAAA;EAAA,aAAA;EAAA,kBAAA;EAAA,sCAAA;EAAA,8BAAA;EAAA,6BAAA;EAAA,4BAAA;EAAA,eAAA;EAAA,oBAAA;EAAA,sBAAA;EAAA,uBAAA;EAAA,wBAAA;EAAA,kBAAA;EAAA,2BAAA;EAAA,4BAAA;EAAA,sCAAA;EAAA,kCAAA;EAAA,2BAAA;EAAA,sBAAA;EAAA,8BAAA;EAAA,YAAA;EAAA,kBAAA;EAAA,gBAAA;EAAA,iBAAA;EAAA,kBAAA;EAAA,cAAA;EAAA,gBAAA;EAAA,aAAA;EAAA,mBAAA;EAAA,qBAAA;EAAA,2BAAA;EAAA,yBAAA;EAAA,0BAAA;EAAA,2BAAA;EAAA,uBAAA;EAAA,wBAAA;EAAA,yBAAA;EAAA;AAAA,CAEA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA,QAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA,gBAAA;EAAA;AAAA,CAAA;EAAA,qBAAA;EAAA;AAAA,CAAA;EAAA,iBAAA;EAAA;AAAA,CAAA;EAAA,mBAAA;EAAA;AAAA,CAAA;EAAA,iBAAA;EAAA;AAAA,CAAA;EAAA,kBAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA,gBAAA;EAAA,oBAAA;EAAA,4BAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA,0BAAA;EAAA,uBAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA,sBAAA;EAAA,uMAAA;UAAA;AAAA,CAAA;EAAA,uBAAA;EAAA,uMAAA;UAAA;AAAA,CAAA;EAAA,sBAAA;EAAA,uMAAA;UAAA;AAAA,CAAA;EAAA,qBAAA;EAAA,uMAAA;UAAA;AAAA,CAAA;EAAA,sBAAA;EAAA,uMAAA;UAAA;AAAA,CAAA;EAAA,sBAAA;EAAA,uMAAA;UAAA;AAAA,CAAA;EAAA,mBAAA;EAAA,uMAAA;UAAA;AAAA,CAAA;EAAA,2CAAA;UAAA;AAAA,CAAA;;EAAA;IAAA,mCAAA;YAAA,2BAAA;IAAA,0DAAA;YAAA;EAAA;;EAAA;IAAA,uBAAA;YAAA,eAAA;IAAA,0DAAA;YAAA;EAAA;AAAA,CAAA;;EAAA;IAAA,mCAAA;YAAA,2BAAA;IAAA,0DAAA;YAAA;EAAA;;EAAA;IAAA,uBAAA;YAAA,eAAA;IAAA,0DAAA;YAAA;EAAA;AAAA,CAAA;EAAA,wCAAA;UAAA;AAAA,CAAA;;EAAA;IAAA;EAAA;AAAA,CAAA;;EAAA;IAAA;EAAA;AAAA,CAAA;EAAA,oEAAA;UAAA;AAAA,CAAA;;EAAA;IAAA,iCAAA;YAAA;EAAA;AAAA,CAAA;;EAAA;IAAA,iCAAA;YAAA;EAAA;AAAA,CAAA;EAAA,6CAAA;UAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA,wBAAA;UAAA;AAAA,CAAA;EAAA,mCAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA,2BAAA;UAAA;AAAA,CAAA;EAAA,wBAAA;UAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA,uBAAA;EAAA,2DAAA;EAAA;AAAA,CAAA;EAAA,uBAAA;EAAA,gEAAA;EAAA;AAAA,CAAA;EAAA,uBAAA;EAAA,+DAAA;EAAA;AAAA,CAAA;EAAA,wBAAA;EAAA,0DAAA;EAAA;AAAA,CAAA;EAAA,wBAAA;EAAA,kEAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA,gBAAA;EAAA,uBAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA,8BAAA;EAAA;AAAA,CAAA;EAAA,+BAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA,sBAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA,sBAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA,sBAAA;EAAA;AAAA,CAAA;EAAA,sBAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA,sBAAA;EAAA;AAAA,CAAA;EAAA,kBAAA;EAAA;AAAA,CAAA;EAAA,kBAAA;EAAA;AAAA,CAAA;EAAA,kBAAA;EAAA;AAAA,CAAA;EAAA,kBAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA,kBAAA;EAAA;AAAA,CAAA;EAAA,kBAAA;EAAA;AAAA,CAAA;EAAA,kBAAA;EAAA;AAAA,CAAA;EAAA,kBAAA;EAAA;AAAA,CAAA;EAAA,kBAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA,kBAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA,kBAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA,kBAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA,kBAAA;EAAA;AAAA,CAAA;EAAA,kBAAA;EAAA;AAAA,CAAA;EAAA,kBAAA;EAAA;AAAA,CAAA;EAAA,kBAAA;EAAA;AAAA,CAAA;EAAA,kBAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA,kBAAA;EAAA;AAAA,CAAA;EAAA,kBAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA,kBAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA,kBAAA;EAAA;AAAA,CAAA;EAAA,kBAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA,kBAAA;EAAA;AAAA,CAAA;EAAA,kBAAA;EAAA;AAAA,CAAA;EAAA,kBAAA;EAAA;AAAA,CAAA;EAAA,kBAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA,kBAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA,kBAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA,4DAAA;EAAA,mEAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA,qBAAA;EAAA;AAAA,CAAA;EAAA,sBAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA,sBAAA;EAAA;AAAA,CAAA;EAAA,qBAAA;EAAA;AAAA,CAAA;EAAA,sBAAA;EAAA;AAAA,CAAA;EAAA,kBAAA;EAAA;AAAA,CAAA;EAAA,qBAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA,kBAAA;EAAA;AAAA,CAAA;EAAA,gBAAA;EAAA;AAAA,CAAA;EAAA,qBAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA,qBAAA;EAAA;AAAA,CAAA;EAAA,iBAAA;EAAA;AAAA,CAAA;EAAA,mBAAA;EAAA;AAAA,CAAA;EAAA,qBAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA,qBAAA;EAAA;AAAA,CAAA;EAAA,iBAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA,mBAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA,iBAAA;EAAA;AAAA,CAAA;EAAA,mBAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA,eAAA;EAAA;AAAA,CAAA;EAAA,mBAAA;EAAA;AAAA,CAAA;EAAA,mBAAA;EAAA;AAAA,CAAA;EAAA,kBAAA;EAAA;AAAA,CAAA;EAAA,kBAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA,oBAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA,0EAAA;EAAA,8FAAA;EAAA;AAAA,CAAA;EAAA,gDAAA;EAAA,6DAAA;EAAA;AAAA,CAAA;EAAA,0CAAA;EAAA,oDAAA;EAAA;AAAA,CAAA;EAAA,yCAAA;EAAA,uDAAA;EAAA;AAAA,CAAA;EAAA,wCAAA;EAAA,sDAAA;EAAA;AAAA,CAAA;EAAA,uCAAA;EAAA,sDAAA;EAAA;AAAA,CAAA;EAAA,uCAAA;EAAA,sDAAA;EAAA;AAAA,CAAA;EAAA,+EAAA;EAAA,mGAAA;EAAA;AAAA,CAAA;EAAA,0CAAA;EAAA,uDAAA;EAAA;AAAA,CAAA;EAAA,gFAAA;EAAA,oGAAA;EAAA;AAAA,CAAA;EAAA,8BAAA;EAAA;AAAA,CAAA;EAAA,8BAAA;EAAA,+QAAA;UAAA;AAAA,CAAA;EAAA,8CAAA;EAAA,sCAAA;EAAA,qDAAA;EAAA,wDAAA;EAAA;AAAA,CAAA;EAAA,wBAAA;EAAA,wDAAA;EAAA;AAAA,CAAA;EAAA,+FAAA;EAAA,wDAAA;EAAA;AAAA,CAAA;EAAA,4BAAA;EAAA,wDAAA;EAAA;AAAA,CAAA;EAAA,sCAAA;EAAA,8BAAA;EAAA,iDAAA;EAAA,wDAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA;AAAA,CAAA;EAAA,iCAAA;UAAA;AAAA,CAKA,MACE,kBAAA,CAGF,KACE,qBAAA,CACA,QAAA,CAKF,EACE,oBAAA,CACA,+CAAA,CAIF,qBACE,SAAA,CACA,UAAA,CAGF,2BACE,wBAAA,CAGF,2BACE,kCAAA,CACA,oBAAA,CAGF,iCACE,kCAAA,CAgBF,sBACE,+BAAA,CACA,gCAAA,CACA,cAAA,CACA,mCAAA,CACA,0BAAA,CAIF,4BACE,aAAA,CACA,4BAAA,CACA,6BAAA,CACA,qBAAA,CACA,6BAAA,CACA,mCAAA,CAQF,mBACE,iBAAA,CAGF,cACE,cAAA,CAGF,yCACE,aAAA,CADF,2BACE,aAAA,CAGF,wBACE,iEAAA,CAIA,aAAA,CACA,cAAA,CACA,eAAA,CACA,gBAAA,CACA,cAAA,CACA,cAAA,CAMF,UACE,iBAAA,CACA,2CAAA,CACA,uHAAA,CACA,sGACE,CAKJ,eACE,gCAAA,CACA,yBAAA,CACA,iCAAA,CACA,qCAAA,CACA,qCAAA,CAGF,cACE,wBAAA,CACA,sCAAA,CACA,kBAAA,CACA,YAAA,CACA,uHAAA,CACA,yEACE,CAIJ,oBACE,wBAAA,CAGF,2BACE,GAAA,2BAAA,CACA,KAAA,0BAAA,CAAA,CAFF,mBACE,GAAA,2BAAA,CACA,KAAA,0BAAA,CAAA,CAGF,iBACE,kGAAA,CACA,yBAAA,CACA,mDAAA,CAAA,2CAAA,CACA,4BAAA,CACA,oBAAA,CACA,qCAAA,CAGF,wBACE,OAAA,WAAA,CACA,IAAA,YAAA,CACA,SAAA,aAAA,CAAA,CAHF,gBACE,OAAA,WAAA,CACA,IAAA,YAAA,CACA,SAAA,aAAA,CAAA,CAGF,qBACE,WAAA,CACA,kDAAA,CAAA,0CAAA,CAGF,8BACE,QAAA,WAAA,CAAA,6CAAA,CAAA,qCAAA,CACA,IAAA,UAAA,CAAA,+CAAA,CAAA,uCAAA,CAAA,CAFF,sBACE,QAAA,WAAA,CAAA,6CAAA,CAAA,qCAAA,CACA,IAAA,UAAA,CAAA,+CAAA,CAAA,uCAAA,CAAA,CAGF,oBACE,oDAAA,CAAA,4CAAA,CAGF,WACE,cAAA,CACA,eAAA,CACA,aAAA,CAKF,sDACE,6BAAA,CACA,oBAAA,CACA,2CAAA,CAEF,yEACE,SAAA,CAEF,+EACE,wBAAA,CAEF,+EACE,8BAAA,CACA,oBAAA,CAEF,4FACE,sCAAA,CAEF,kGACE,sCAAA,CAxMF;EAAA;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA,2GAwME;EAxMF,yGAwME;EAxMF;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA,sBAwME;EAxMF,uMAwME;UAxMF;AAwME,CAxMF;EAAA,2BAwME;EAxMF,uMAwME;UAxMF;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA,sBAwME;EAxMF;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA,kBAwME;EAxMF;AAwME,CAxMF;EAAA,kBAwME;EAxMF;AAwME,CAxMF;EAAA,kBAwME;EAxMF;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA,kBAwME;EAxMF;AAwME,CAxMF;EAAA,kBAwME;EAxMF;AAwME,CAxMF;EAAA,kBAwME;EAxMF;AAwME,CAxMF;EAAA,kBAwME;EAxMF;AAwME,CAxMF;EAAA,kBAwME;EAxMF;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA,oBAwME;EAxMF;AAwME,CAxMF;EAAA,oBAwME;EAxMF;AAwME,CAxMF;EAAA,oBAwME;EAxMF;AAwME,CAxMF;EAAA,oBAwME;EAxMF;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA,oBAwME;EAxMF;AAwME,CAxMF;EAAA,oBAwME;EAxMF;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA,wCAwME;EAxMF,uDAwME;EAxMF;AAwME,CAxMF;EAAA,6EAwME;EAxMF,iGAwME;EAxMF;AAwME,CAxMF;EAAA,0CAwME;EAxMF,uDAwME;EAxMF;AAwME,CAxMF;EAAA,iCAwME;EAxMF,yLAwME;UAxMF;AAwME,CAxMF;EAAA,iCAwME;EAxMF,yLAwME;UAxMF;AAwME,CAxMF;EAAA,sBAwME;EAxMF;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA,2GAwME;EAxMF,yGAwME;EAxMF;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA,sBAwME;EAxMF;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA,qBAwME;EAxMF,uMAwME;UAxMF;AAwME,CAxMF;EAAA,iBAwME;EAxMF,iBAwME;EAxMF,uMAwME;UAxMF;AAwME,CAxMF;EAAA,kBAwME;EAxMF,kBAwME;EAxMF,uMAwME;UAxMF;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA;AAwME,CAxMF;;EAAA;IAAA;EAwME;;EAxMF;IAAA;EAwME;;EAxMF;IAAA;EAwME;;EAxMF;IAAA;EAwME;;EAxMF;IAAA;EAwME;;EAxMF;IAAA;EAwME;;EAxMF;IAAA;EAwME;;EAxMF;IAAA;EAwME;;EAxMF;IAAA;EAwME;;EAxMF;IAAA;EAwME;;EAxMF;IAAA;EAwME;;EAxMF;IAAA;EAwME;;EAxMF;IAAA;EAwME;;EAxMF;IAAA;EAwME;;EAxMF;IAAA,kBAwME;IAxMF;EAwME;;EAxMF;IAAA,mBAwME;IAxMF;EAwME;;EAxMF;IAAA,mBAwME;IAxMF;EAwME;AAAA,CAxMF;;EAAA;IAAA;EAwME;;EAxMF;IAAA;EAwME;;EAxMF;IAAA;EAwME;;EAxMF;IAAA;EAwME;AAAA,CAxMF;EAAA;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA;AAwME,CAxMF;EAAA;AAwME",
          sourcesContent: ["@tailwind base;\n@tailwind components;\n@tailwind utilities;\n\n/* Light color scheme for native browser controls so MFE editor inputs render correctly.\n   The Zai chatbot panel applies its own dark backgrounds via inline styles / darkTheme tokens.\n   Custom scrollbar CSS below overrides native scrollbar appearance independently. */\n:root {\n  color-scheme: light;\n}\n\nbody {\n  background-color: #ffffff;\n  margin: 0;\n}\n\n/* ââ Thin dark scrollbar for dark theme ââ */\n/* Firefox */\n* {\n  scrollbar-width: thin;\n  scrollbar-color: rgba(56, 74, 98, 0.5) transparent;\n}\n\n/* WebKit (Chrome, Safari, Edge) */\n*::-webkit-scrollbar {\n  width: 6px;\n  height: 6px;\n}\n\n*::-webkit-scrollbar-track {\n  background: transparent;\n}\n\n*::-webkit-scrollbar-thumb {\n  background-color: rgba(56, 74, 98, 0.5);\n  border-radius: 9999px;\n}\n\n*::-webkit-scrollbar-thumb:hover {\n  background-color: rgba(56, 74, 98, 0.8);\n}\n\n/* body {\n  margin: 0;\n  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen',\n    'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue',\n    sans-serif;\n  -webkit-font-smoothing: antialiased;\n  -moz-osx-font-smoothing: grayscale;\n}\n\ncode {\n  font-family: source-code-pro, Menlo, Monaco, Consolas, 'Courier New',\n    monospace;\n} */\n.editor .ql-container {\n  border-bottom-left-radius: 0.25em;\n  border-bottom-right-radius: 0.25em;\n  font-size: 16px;\n  border: 1px solid #6F7880!important;\n  border-top: none!important;\n}\n\n/* Snow Theme */\n.editor .ql-snow.ql-toolbar {\n  display: block;\n  border-top-left-radius: 0.25em;\n  border-top-right-radius: 0.25em;\n  opacity: 40!important;\n  border-bottom: none!important;\n  border: 1px solid #6F7880!important;\n}\n\n.editor {\n  /* display: flex;\n  flex-direction: column-reverse; */\n}\n\n.editor .ql-editor {\n  min-height: 2.5rem;\n}\n\n.custom-input {\n  font-size: 16px;\n}\n\n.custom-input::placeholder {\n  color: #585f67\n}\n\n.custom-constraint-text {\n  font-family: \"Amazon Ember\",\"Amazon Ember Arabic\",Arial,sans-serif;\n  font-size: 16px;\n  font-weight: 400;\n  line-height: 24px;\n  color: #575F67;\n  font-size: 14px;\n  font-weight: 400;\n  line-height: 20px;\n  cursor: default;\n  margin-top: 4px;\n}\n\n\n/* ââ Dark theme utility classes (from demoAppNew) ââ */\n\n.card-lit {\n  position: relative;\n  border-color: rgba(0, 204, 189, 0.15) !important;\n  background-image: radial-gradient(500px at 0% 0%, rgba(0, 204, 189, 0.06), rgba(60, 40, 140, 0.05) 40%, transparent 70%);\n  box-shadow:\n    0 4px 24px rgba(0, 0, 0, 0.3),\n    inset 0 1px 0 0 rgba(255, 255, 255, 0.10),\n    0 0 30px rgba(0, 204, 189, 0.08);\n}\n\n.glass-surface {\n  background: rgba(255, 255, 255, 0.05);\n  backdrop-filter: blur(8px);\n  -webkit-backdrop-filter: blur(8px);\n  border: 1px solid rgba(255, 255, 255, 0.1);\n  box-shadow: 0 8px 30px rgba(0, 0, 0, 0.25);\n}\n\n.card-surface {\n  background-color: #000D26;\n  border: 1px solid rgba(255, 255, 255, 0.08);\n  border-radius: 16px;\n  padding: 16px;\n  background-image: radial-gradient(500px at 0% 0%, rgba(0, 204, 189, 0.06), rgba(60, 40, 140, 0.05) 40%, transparent 70%);\n  box-shadow:\n    0 4px 24px rgba(0, 0, 0, 0.3),\n    inset 0 1px 0 0 rgba(255, 255, 255, 0.10);\n}\n\n.card-surface:hover {\n  background-color: #001232;\n}\n\n@keyframes shimmer {\n  0% { background-position: -200% 0; }\n  100% { background-position: 200% 0; }\n}\n\n.animate-shimmer {\n  background: linear-gradient(90deg, #4ade80 0%, #4ade80 35%, #d1fae5 50%, #4ade80 65%, #4ade80 100%);\n  background-size: 200% 100%;\n  animation: shimmer 2.5s ease-in-out infinite;\n  -webkit-background-clip: text;\n  background-clip: text;\n  -webkit-text-fill-color: transparent;\n}\n\n@keyframes dots {\n  0%, 20% { content: '.'; }\n  40% { content: '..'; }\n  60%, 100% { content: '...'; }\n}\n\n.animate-dots::after {\n  content: '.';\n  animation: dots 1.5s steps(3, end) infinite;\n}\n\n@keyframes glow-pulse {\n  0%, 100% { opacity: 0.35; transform: translate(-50%, 0) scale(1); }\n  50% { opacity: 0.6; transform: translate(-50%, 0) scale(1.1); }\n}\n\n.animate-glow-pulse {\n  animation: glow-pulse 3s ease-in-out infinite;\n}\n\n.text-body {\n  font-size: 13px;\n  line-height: 1.5;\n  color: #bebebe;\n}\n\n\n/* Scrollbar visible only while actively scrolling (macOS-native overlay behavior) */\n.scrollbar-auto-hide [data-slot=\"scroll-area-viewport\"] {\n  overflow-y: overlay !important;\n  scrollbar-width: thin;\n  scrollbar-color: transparent transparent;\n}\n.scrollbar-auto-hide [data-slot=\"scroll-area-viewport\"]::-webkit-scrollbar {\n  width: 6px;\n}\n.scrollbar-auto-hide [data-slot=\"scroll-area-viewport\"]::-webkit-scrollbar-track {\n  background: transparent;\n}\n.scrollbar-auto-hide [data-slot=\"scroll-area-viewport\"]::-webkit-scrollbar-thumb {\n  background-color: transparent;\n  border-radius: 9999px;\n}\n.scrollbar-auto-hide [data-slot=\"scroll-area-viewport\"].is-scrolling::-webkit-scrollbar-thumb {\n  background-color: rgba(255, 255, 255, 0.15);\n}\n.scrollbar-auto-hide [data-slot=\"scroll-area-viewport\"].is-scrolling::-webkit-scrollbar-thumb:hover {\n  background-color: rgba(255, 255, 255, 0.25);\n}\n\n\n\n"],
          sourceRoot: ""
        }]), e.Z = i
      },
      80170: function(t, e, n) {
        var a = n(85893),
          r = n(93379),
          s = n.n(r),
          i = n(7795),
          o = n.n(i),
          l = n(90569),
          A = n.n(l),
          c = n(3565),
          d = n.n(c),
          w = n(19216),
          g = n.n(w),
          u = n(44589),
          p = n.n(u),
          b = n(46552),
          h = {};
        h.styleTagTransform = p(), h.setAttributes = d(), h.insert = A().bind(null, "head"), h.domAPI = o(), h.insertStyleElement = g(), s()(b.Z, h), b.Z && b.Z.locals && b.Z.locals, n(7390);
        var m = n(69809),
          x = n(87679),
          f = n(53993),
          v = n(50242),
          j = n(75166),
          E = n.n(j),
          y = n(20745),
          C = n(4511),
          O = n(88767),
          N = n(60377),
          S = n(29323),
          k = (n(1508), n(87261), n(32195)),
          I = {};
        I.styleTagTransform = p(), I.setAttributes = d(), I.insert = A().bind(null, "head"), I.domAPI = o(), I.insertStyleElement = g(), s()(k.Z, I), k.Z && k.Z.locals && k.Z.locals, n(68033), n(40797);
        var M = n(55736),
          T = n(46564),
          R = n(82440),
          B = n(25881),
          _ = n(43773),
          D = n(76465),
          L = n(31955),
          F = n(55678),
          P = n(15208),
          z = n(9078),
          U = n(1890),
          G = n(91128),
          Z = n(88835),
          H = n(1572),
          Y = n(64755),
          W = n(73905),
          K = n(68863),
          V = n(86541),
          $ = n(81717),
          q = n(62759);
        const Q = {
            sellerAppGooglePlayStore: "https://play.google.com/store/apps/details?id=com.amazon.sft.rangoli.seller.app",
            faqPage: "https://smartbiz-support.zendesk.com/hc/en-us/sections/15674324808593-Select-a-Section",
            howToGuide: "https://smartbiz-support.zendesk.com/hc/en-us",
            frequentlyAsked: "https://help.smartbiz.in/hc/en-us/sections/18491586242321-FAQs",
            termsAndConditionUrl: "https://smartcommerce.amazon.in/terms-of-use",
            privacyPolicyUrl: "https://smartcommerce.amazon.in/privacy-policy"
          },
          X = new Set(["azai", "sessionId", "origin", "program"]),
          J = "smartbiz.amazon.in",
          tt = {
            "localhost.amazon.com": "DEVELOPMENT",
            "alpha-smartbiz-seller.corp.amazon.com": "ALPHA",
            "beta-smartbiz-seller.corp.amazon.com": "BETA",
            "gamma-smartbiz-seller.corp.amazon.com": "GAMMA",
            "smartbiz.amazon.in": "PROD"
          },
          et = ["aneeshna+demo", "agarwash+demo", "simsamda+demo", "ggyani+demo"],
          nt = [],
          at = [],
          rt = (t, e) => (t => et.some((e => t.startsWith(e))) && t.endsWith("@amazon.com") || nt.includes(t))(t) || !!e && (t => 10 === t.length && t.startsWith("99000000") || at.includes(t))(e);
        var st = n(68949);
        const it = new class {
          constructor() {
            this.helpMenuToggle = !1, this.isProfileDetailsActive = !1, this.isChatBotMessengerActive = !1, this.isWhatsAppChatBotFeatureEnabled = !1, this.setIsChatBotMessengerActive = t => {
              this.isChatBotMessengerActive = t
            }, this.setIsWhatsAppChatBotFeatureEnabled = t => {
              this.isWhatsAppChatBotFeatureEnabled = t
            }, this.setHelpMenuToggle = () => {
              this.helpMenuToggle = !this.helpMenuToggle
            }, this.handleChangeActiveProfileDetails = t => {
              this.isProfileDetailsActive = t
            }, (0, st.rC)(this, {
              helpMenuToggle: st.LO,
              setHelpMenuToggle: st.aD,
              isProfileDetailsActive: st.LO,
              handleChangeActiveProfileDetails: st.aD,
              isChatBotMessengerActive: st.LO,
              setIsChatBotMessengerActive: st.aD,
              isWhatsAppChatBotFeatureEnabled: st.LO,
              setIsWhatsAppChatBotFeatureEnabled: st.aD
            })
          }
        };
        var ot;
        ! function(t) {
          t.TURQUOISE_GREEN = "#18A395", t.MEDIUM_AQUAMARINE = "#58c3b8", t.LIGHT_TURQUOISE = "#d9f4f1", t.DARK_GRAY = "#434C54", t.ANTI_FLASH_WHITE = "#F0F1F2", t.BLACK = "#000000", t.SILVER_SAND_GREY = "#BBC0C1", t.PASTEL_BLUE = "#AED2CE", t.DARK_BLUE = "#25303E", t.DARK_NAVY_BLUE = "#0C1521", t.LIGHT_GRAY = "#BEBEC4"
        }(ot || (ot = {}));
        const {
          TURQUOISE_GREEN: lt,
          LIGHT_GRAY: At
        } = ot, ct = (0, D.css)({
          height: "56px",
          border: "none !important",
          backgroundColor: "white !important",
          padding: "none !important",
          margin: "0 !important",
          "&:hover": {
            boxShadow: "none"
          }
        }), dt = (0, D.css)({
          position: "absolute",
          backgroundColor: "white",
          zIndex: 52,
          top: "49px"
        }), wt = (0, D.css)({
          color: "#000000 !important"
        }), gt = (0, D.css)({
          borderRadius: "8px"
        }), ut = (0, D.css)({
          borderRadius: "50%",
          color: "white",
          fontWeight: "bold"
        }), pt = (0, D.css)({
          borderRadius: "50%",
          color: "white",
          fontWeight: "bold",
          border: "2px solid #18A395",
          padding: "2px"
        }), bt = (0, D.css)({
          color: "#AF1F18 !important"
        }), ht = (0, D.css)({
          position: "fixed",
          top: "56px",
          left: 0,
          width: "100%",
          height: "100%",
          backgroundColor: "rgba(0, 0, 0, 0.5)",
          zIndex: 20
        }), mt = (0, D.css)({
          position: "fixed",
          top: "63px",
          right: "7px",
          borderRadius: "5px",
          zIndex: 20,
          margin: "0 !important",
          height: "calc(100% - 70px)",
          overflowY: "auto",
          "&::-webkit-scrollbar": {
            display: "none"
          },
          scrollbarHeight: "none",
          scrollbarWidth: "none"
        }), xt = (0, D.css)({
          whiteSpace: "nowrap",
          width: "100%",
          overflow: "hidden",
          textOverflow: "ellipsis"
        }), ft = (0, D.css)({
          padding: "0 8px !important"
        }), vt = (0, D.css)({
          boxShadow: "0px 2px 4px 0px #0B0C0C29",
          left: 0,
          right: 0,
          top: 0,
          position: "sticky",
          zIndex: 52,
          height: "56px",
          backgroundColor: "white"
        }), jt = (0, D.css)({
          borderLeft: "1px solid #E7E9E9",
          borderRight: "1px solid #E7E9E9"
        }), Et = (0, D.css)({
          borderRight: "1px solid #E7E9E9"
        }), yt = (0, D.css)({
          borderRadius: "5px"
        }), Ct = (0, D.css)({
          height: "56px"
        }), Ot = (0, D.css)({
          color: "#077398"
        }), Nt = (0, D.css)({
          fontStyle: "italic"
        }), St = (0, D.css)({
          color: lt
        }), kt = (0, D.css)({
          color: K.colorGray400
        }), It = (0, D.css)({
          color: `${At} !important`
        }), Mt = (0, D.css)("\noverflow-y : auto !important\n"), Tt = (0, D.css)({
          color: "#62EDE4"
        }), Rt = (0, D.css)({
          marginLeft: "-25px"
        }), Bt = ((0, D.css)({
          color: "#575F67"
        }), (0, D.css)({
          padding: "2px 6px"
        })), _t = (0, D.css)({
          color: "#E7FAF6",
          ":hover": {
            color: "#E7FAF6"
          }
        }), Dt = (0, D.css)({
          cursor: "pointer"
        }), Lt = ((0, D.css)({
          width: "65px",
          background: " #69b9ff",
          borderRadius: "70%",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          color: "white",
          fontSize: "44px",
          margin: "2rem auto",
          aspectRatio: "1/1"
        }), (0, D.css)({
          color: lt,
          paddingLeft: "auto"
        })), Ft = ((0, D.css)({
          borderRadius: "50%",
          color: "white",
          fontWeight: "bold"
        }), (0, D.css)({
          width: "4rem",
          height: "4rem",
          background: "#17494d",
          right: "1rem",
          position: "absolute",
          top: "-9.37rem",
          zIndex: "999999",
          borderRadius: "100%",
          display: "flex",
          justifyContent: "center",
          alignItems: "center",
          cursor: "pointer"
        })), Pt = (0, D.css)({
          position: "fixed",
          width: "100%",
          height: "100%",
          zIndex: 99,
          opacity: .5,
          background: K.colorGray600,
          top: 0,
          left: 0
        }), zt = (0, D.css)({
          position: "fixed",
          width: "100%",
          height: "100%",
          zIndex: 100,
          top: 0,
          left: 0,
          pointerEvents: "none"
        }), Ut = (0, D.css)({
          borderRadius: "22px",
          position: "absolute",
          right: "2rem",
          pointerEvents: "auto"
        }), Gt = (0, D.css)([Ut, {
          bottom: "14rem"
        }]), Zt = (0, D.css)([Ut, {
          bottom: "10rem"
        }]), Ht = (0, D.css)({
          borderRadius: "100%"
        });
        var Yt = JSON.parse('{"helpAndSupport":{"title":"Help & Support","boxHeader":"Reach out to us at","mailId":"support@smartbiz-support.zendesk.com","contactNo":"1800-233-321","FAQTitle":"Frequently Asked Question","HowToGuideTitle":"How To Guide","ChatWithUs":"Chat with Us","MessageOnWA":"Message on WhatsApp"}}');
        const Wt = {
            iconData: '\n<svg width="36" height="36" viewBox="0 0 9 8" fill="none" xmlns="http://www.w3.org/2000/svg">\n<rect x="0.102539" y="0.26593" width="8.40384" height="5.0423" rx="2.52115" fill="#E9EBEF"/>\n<path d="M5.00488 5.86853H6.68565V7.5493L5.00488 5.86853Z" fill="#E9EBEF"/>\n</svg>\n',
            iconHeight: 24,
            iconWidth: 24
          },
          Kt = {
            iconData: '<svg width="16" height="16" viewBox="0 0 9 8" fill="none" xmlns="http://www.w3.org/2000/svg">\n<rect x="0.102539" y="0.26593" width="8.40384" height="5.0423" rx="2.52115" fill="#E9EBEF"/>\n<path d="M5.00488 5.86853H6.68565V7.5493L5.00488 5.86853Z" fill="#E9EBEF"/>\n</svg>',
            iconHeight: 16,
            iconWidth: 16
          },
          Vt = {
            iconData: '\n<svg width="36" height="36" viewBox="0 0 23 23" fill="none" xmlns="http://www.w3.org/2000/svg">\n<path fill-rule="evenodd" clip-rule="evenodd" d="M12.0578 2.86495C14.1018 2.96541 16.0064 3.8083 17.4611 5.26401C19.0128 6.81669 19.8669 8.88062 19.8661 11.0755C19.8643 15.6049 16.177 19.2902 11.6473 19.2902C9.94394 19.2902 8.59034 18.7668 7.71632 18.2903L3.35938 19.4327L4.52539 15.1758C3.80616 13.93 3.4277 12.5169 3.42829 11.069C3.43011 6.53974 7.11708 2.8548 11.6472 2.8548L12.0578 2.86495ZM7.91816 16.8032L8.16765 16.9511C9.21648 17.5732 10.4187 17.9024 11.6445 17.9029H11.6473C15.4125 17.9029 18.4769 14.8399 18.4784 11.075C18.4791 9.25067 17.7692 7.53521 16.4795 6.24466C15.1897 4.95402 13.4746 4.24285 11.65 4.24225C7.88194 4.24225 4.81746 7.30494 4.81596 11.0695C4.81545 12.3596 5.17659 13.6161 5.8604 14.7031L6.02282 14.9615L5.33272 17.481L7.91816 16.8032ZM15.7879 13.029C15.7366 12.9433 15.5997 12.8919 15.3943 12.7892C15.1889 12.6865 14.1793 12.1899 13.9911 12.1213C13.8028 12.0529 13.6659 12.0187 13.529 12.2241C13.3921 12.4296 12.9986 12.8919 12.8787 13.029C12.759 13.1659 12.6392 13.1831 12.4339 13.0803C12.2285 12.9776 11.5668 12.7608 10.7824 12.0615C10.1719 11.5173 9.75973 10.8451 9.63993 10.6396C9.52017 10.4342 9.62716 10.323 9.72996 10.2207C9.82236 10.1287 9.93536 9.98098 10.038 9.86112C10.1407 9.7413 10.1749 9.65562 10.2434 9.51869C10.3118 9.38168 10.2776 9.26186 10.2263 9.15911C10.1749 9.05632 9.76424 8.04599 9.59312 7.635C9.42638 7.23479 9.25708 7.28897 9.13103 7.28265C9.01139 7.27672 8.87435 7.27542 8.73747 7.27542C8.60055 7.27542 8.37807 7.32675 8.18983 7.53229C8.00159 7.73774 7.47107 8.23438 7.47107 9.24463C7.47107 10.255 8.20695 11.2309 8.30963 11.368C8.41231 11.505 9.75771 13.5781 11.8178 14.4673C12.3077 14.6788 12.6903 14.8051 12.9885 14.8997C13.4805 15.0559 13.9281 15.0339 14.282 14.981C14.6765 14.9221 15.497 14.4845 15.6681 14.0051C15.8392 13.5255 15.8392 13.1146 15.7879 13.029Z" fill="white"/>\n<mask id="mask0_220_16612" style="mask-type:alpha" maskUnits="userSpaceOnUse" x="4" y="4" width="15" height="14">\n<path fill-rule="evenodd" clip-rule="evenodd" d="M7.91812 16.8032L8.16761 16.9511C9.21643 17.5732 10.4187 17.9024 11.6445 17.9029H11.6472C15.4124 17.9029 18.4769 14.8399 18.4784 11.075C18.4791 9.25067 17.7692 7.53521 16.4795 6.24465C15.1897 4.95402 13.4746 4.24284 11.65 4.24225C7.8819 4.24225 4.81742 7.30493 4.81592 11.0695C4.8154 12.3596 5.17655 13.6161 5.86036 14.7031L6.02278 14.9615L5.33268 17.481L7.91812 16.8032ZM15.7878 13.029C15.7365 12.9433 15.5996 12.8919 15.3943 12.7892C15.1889 12.6864 14.1793 12.1899 13.991 12.1213C13.8028 12.0529 13.6659 12.0187 13.529 12.2241C13.3921 12.4296 12.9985 12.8919 12.8787 13.029C12.7589 13.1659 12.6391 13.1831 12.4338 13.0803C12.2285 12.9776 11.5667 12.7608 10.7823 12.0615C10.1718 11.5173 9.75969 10.8451 9.63989 10.6396C9.52013 10.4342 9.62712 10.323 9.72992 10.2207C9.82232 10.1287 9.93532 9.98097 10.038 9.86111C10.1407 9.74129 10.1749 9.65561 10.2434 9.51868C10.3118 9.38167 10.2776 9.26185 10.2262 9.1591C10.1749 9.05632 9.7642 8.04598 9.59307 7.63499C9.42634 7.23479 9.25704 7.28897 9.13099 7.28265C9.01135 7.27672 8.87431 7.27541 8.73743 7.27541C8.60051 7.27541 8.37803 7.32675 8.18979 7.53228C8.00154 7.73774 7.47102 8.23437 7.47102 9.24462C7.47102 10.255 8.20691 11.2309 8.30959 11.368C8.41227 11.505 9.75767 13.5781 11.8177 14.4673C12.3077 14.6788 12.6902 14.8051 12.9885 14.8997C13.4804 15.0559 13.9281 15.0339 14.2819 14.981C14.6765 14.9221 15.4969 14.4845 15.6681 14.0051C15.8392 13.5255 15.8392 13.1146 15.7878 13.029Z" fill="black"/>\n</mask>\n<g mask="url(#mask0_220_16612)">\n<path d="M22.9332 -0.306702H-0.158936V22.7855H22.9332V-0.306702Z" fill="url(#paint0_linear_220_16612)"/>\n</g>\n<defs>\n<linearGradient id="paint0_linear_220_16612" x1="11.3872" y1="22.7855" x2="11.3872" y2="-0.306702" gradientUnits="userSpaceOnUse">\n<stop stop-color="#25CF43"/>\n<stop offset="1" stop-color="#61FD7D"/>\n</linearGradient>\n</defs>\n</svg>\n',
            iconHeight: 24,
            iconWidth: 24
          };
        var $t = n(44194);
        const {
          config: qt
        } = (0, $t.R6)(), Qt = {
          url: qt.smartPosUrl
        }, Xt = {
          url: qt.marketingPageUrl
        }, Jt = {
          url: qt.chatScript
        }, te = {
          url: qt.smartbizUrl
        }, ee = {
          url: qt.storeFrontUrl
        }, ne = {
          phoneNumber: qt.whatsAppChatBotNumber
        }, ae = {
          url: qt.smartPosUrl
        }, re = {
          url: qt.smartbizRenBaseUrl
        }, se = new $t.Sl(Qt), ie = new $t.Sl(te), oe = new $t.Sl(ae), le = new $t.Sl(re), Ae = se.api(), ce = Xt.url, de = Jt.url, we = ee.url, ge = ne.phoneNumber, ue = ie.api(), pe = oe.api(), be = le.api(), he = (t, e) => {
          window.open(t, e, "noopener, noreferrer")
        }, {
          helpAndSupport: me
        } = Yt, {
          title: xe,
          FAQTitle: fe,
          HowToGuideTitle: ve,
          ChatWithUs: je,
          MessageOnWA: Ee
        } = me, {
          FAQ_CLICK: ye,
          HOW_TO_GUIDE_CLICK: Ce
        } = f.MixPanelEventName, {
          howToGuide: Oe,
          frequentlyAsked: Ne
        } = Q;
        var Se = (0, v.Pi)((() => {
            const {
              helpMenuToggle: t,
              setHelpMenuToggle: e
            } = it, n = () => {
              f.mE.track(ye), window.open(Ne, "_blank")
            }, r = () => {
              f.mE.track(Ce), window.open(Oe, "_blank")
            }, s = () => {
              it.isChatBotMessengerActive || (null === window || void 0 === window || window.zE("messenger", "open"), it.setIsChatBotMessengerActive(!0)), e()
            }, i = () => {
              he(`https://api.whatsapp.com/send?phone=${ge}`, "_blank")
            };
            return (0, a.jsx)(R.default, Object.assign({
              query: "max-width",
              props: {
                showMobileView: {
                  default: !1,
                  [f._G._720]: !0
                }
              }
            }, {
              children: ({
                showMobileView: o
              }) => (0, a.jsx)(Y.default, Object.assign({
                type: "overlay",
                side: o ? "bottom" : "end",
                open: t
              }, {
                children: (0, a.jsxs)(z.Z, Object.assign({
                  spacing: "400",
                  heights: "fit",
                  width: !o && "42rem"
                }, {
                  children: [(0, a.jsxs)(H.default, Object.assign({
                    alignmentHorizontal: "justify"
                  }, {
                    children: [(0, a.jsx)(W.default, Object.assign({
                      type: "h400"
                    }, {
                      children: xe
                    })), (0, a.jsx)(P.default, Object.assign({
                      type: "icon",
                      onClick: e,
                      "data-testid": "closeMenu"
                    }, {
                      children: (0, a.jsx)(G.default, {
                        tokens: V.default
                      })
                    }))]
                  })), (0, a.jsx)(U.Z, {}), (0, a.jsx)(T.default, Object.assign({
                    backgroundColor: K.colorGray100,
                    type: "fill",
                    spacingInset: "400"
                  }, {
                    children: (0, a.jsxs)(z.Z, Object.assign({
                      spacingInset: "300"
                    }, {
                      children: [(0, a.jsxs)(H.default, {
                        children: [(0, a.jsx)(G.default, {
                          className: Tt,
                          tokens: q.Z
                        }), (0, a.jsx)(Z.Z, Object.assign({
                          onClick: n,
                          type: "secondary"
                        }, {
                          children: (0, a.jsx)(W.default, Object.assign({
                            className: Tt,
                            type: "h300"
                          }, {
                            children: fe
                          }))
                        }))]
                      }), (0, a.jsx)(U.Z, {}), (0, a.jsxs)(H.default, {
                        children: [(0, a.jsx)(G.default, {
                          className: Tt,
                          tokens: $.Z
                        }), (0, a.jsx)(Z.Z, Object.assign({
                          onClick: r,
                          type: "secondary"
                        }, {
                          children: (0, a.jsx)(W.default, Object.assign({
                            className: Tt,
                            type: "h300"
                          }, {
                            children: ve
                          }))
                        }))]
                      }), it.isWhatsAppChatBotFeatureEnabled && (0, a.jsxs)(a.Fragment, {
                        children: [(0, a.jsx)(U.Z, {}), (0, a.jsxs)(H.default, {
                          children: [(0, a.jsx)(H.default, Object.assign({
                            backgroundColor: "#62EDE4",
                            alignmentHorizontal: "center",
                            alignmentVertical: "center",
                            height: 24,
                            width: 24,
                            className: (0, D.css)({
                              borderRadius: "100%"
                            })
                          }, {
                            children: (0, a.jsx)(G.default, {
                              tokens: Kt
                            })
                          })), (0, a.jsx)(Z.Z, Object.assign({
                            onClick: s,
                            type: "secondary"
                          }, {
                            children: (0, a.jsx)(W.default, Object.assign({
                              className: Tt,
                              type: "h300"
                            }, {
                              children: je
                            }))
                          }))]
                        }), (0, a.jsx)(U.Z, {}), (0, a.jsxs)(H.default, {
                          children: [(0, a.jsx)(G.default, {
                            tokens: Vt
                          }), (0, a.jsx)(Z.Z, Object.assign({
                            onClick: i,
                            type: "secondary"
                          }, {
                            children: (0, a.jsx)(W.default, Object.assign({
                              className: Tt,
                              type: "h300"
                            }, {
                              children: Ee
                            }))
                          }))]
                        })]
                      })]
                    }))
                  }))]
                }))
              }))
            }))
          })),
          ke = n(55613),
          Ie = n(93287),
          Me = n(8297),
          Te = n(67480),
          Re = n(75635),
          Be = n.p + "13d8b41d30df55c7a1ed.svg",
          _e = n.p + "caf34c2def70d4e7c6bc.svg",
          De = n.p + "7f3f16babcf1cb7fa282.svg";
        const Le = "sidebarCollapsed",
          Fe = new class {
            constructor() {
              this.logoutToggle = !1, this.sidebarToggle = !1, this.scannerToggle = !1, this.showSideBar = !0, this.isCollapsed = "false" !== localStorage.getItem(Le), this.parentRoute = "", this.childRoute = "", this.isUserManagementEnabled = !1, this.isCustomerSegmentsEnabled = !1, this.isReviewsEnabled = !1, this.isBasketBuildingEnabled = !1, this.isSalesAndOrdersAnalyticsFeatureEnabled = !1, this.isTrafficAnalyticsFeatureEnabled = !1, this.isOperationsAnalyticsFeatureEnabled = !1, this.isReportsAnalyticsFeatureEnabled = !1, this.setIsUserManagementEnabled = t => {
                this.isUserManagementEnabled = t
              }, this.setIsCustomerSegmentsEnabled = t => {
                this.isCustomerSegmentsEnabled = t
              }, this.setIsReviewsEnabled = t => {
                this.isReviewsEnabled = t
              }, this.setIsBasketBuildingEnabled = t => {
                this.isBasketBuildingEnabled = t
              }, this.setParentRoute = t => {
                this.parentRoute = t
              }, this.setIsSalesAndOrdersAnalyticsFeatureEnabled = t => {
                this.isSalesAndOrdersAnalyticsFeatureEnabled = t
              }, this.setIsTrafficAnalyticsFeatureEnabled = t => {
                this.isTrafficAnalyticsFeatureEnabled = t
              }, this.setIsOperationsAnalyticsFeatureEnabled = t => {
                this.isOperationsAnalyticsFeatureEnabled = t
              }, this.setIsReportsAnalyticsFeatureEnabled = t => {
                this.isReportsAnalyticsFeatureEnabled = t
              }, this.setChildRoute = t => {
                this.childRoute = t
              }, this.setSidebarToggle = () => {
                this.sidebarToggle = !this.sidebarToggle
              }, this.handleScannerToggle = () => {
                this.scannerToggle = !this.scannerToggle
              }, this.setShowSideBar = t => {
                this.showSideBar = t
              }, this.toggleCollapsed = () => {
                this.isCollapsed = !this.isCollapsed, localStorage.setItem(Le, String(this.isCollapsed))
              }, this.setIsCollapsed = t => {
                this.isCollapsed = t, localStorage.setItem(Le, String(t))
              }, (0, st.rC)(this, {
                logoutToggle: st.LO,
                sidebarToggle: st.LO,
                scannerToggle: st.LO,
                parentRoute: st.LO,
                childRoute: st.LO,
                isUserManagementEnabled: st.LO,
                isCustomerSegmentsEnabled: st.LO,
                isReviewsEnabled: st.LO,
                isBasketBuildingEnabled: st.LO,
                isSalesAndOrdersAnalyticsFeatureEnabled: st.LO,
                isTrafficAnalyticsFeatureEnabled: st.LO,
                isOperationsAnalyticsFeatureEnabled: st.LO,
                isReportsAnalyticsFeatureEnabled: st.LO,
                isCollapsed: st.LO,
                setSidebarToggle: st.aD,
                toggleCollapsed: st.aD,
                setIsCollapsed: st.aD,
                setLogoutToggleTrue: st.aD,
                setLogoutToggleFalse: st.aD,
                handleLogout: st.aD,
                handleScannerToggle: st.aD,
                showSideBar: st.LO,
                setShowSideBar: st.aD,
                setParentRoute: st.aD,
                setChildRoute: st.aD,
                setIsUserManagementEnabled: st.aD,
                setIsReviewsEnabled: st.aD,
                setIsBasketBuildingEnabled: st.aD,
                setIsSalesAndOrdersAnalyticsFeatureEnabled: st.aD,
                setIsTrafficAnalyticsFeatureEnabled: st.aD,
                setIsOperationsAnalyticsFeatureEnabled: st.aD,
                setIsReportsAnalyticsFeatureEnabled: st.aD
              })
            }
            handleLogout() {
              localStorage.clear()
            }
            setLogoutToggleTrue() {
              this.logoutToggle = !0
            }
            setLogoutToggleFalse() {
              this.logoutToggle = !1
            }
          };
        var Pe = n(64647),
          ze = n(28630),
          Ue = n(59890),
          Ge = n(68565),
          Ze = n(71890),
          He = n(51361),
          Ye = n(26235),
          We = n(97603),
          Ke = () => (0, a.jsxs)("svg", Object.assign({
            width: "24",
            height: "24",
            viewBox: "0 0 24 24",
            fill: "none",
            xmlns: "http://www.w3.org/2000/svg"
          }, {
            children: [(0, a.jsx)("g", Object.assign({
              clipPath: "url(#clip0_6707_340385)"
            }, {
              children: (0, a.jsx)("path", {
                d: "M10 2C10.5523 2 11 2.44772 11 3C11 3.55228 10.5523 4 10 4H5.116C5.05228 4 5 4.05228 5 4.116V19.884C5 19.9477 5.05228 20 5.116 20H10C10.5523 20 11 20.4477 11 21C11 21.5523 10.5523 22 10 22H5.116C3.94772 22 3 21.0523 3 19.884V4.116C3 2.94772 3.94772 2 5.116 2H10ZM16.2919 7.29189C16.6824 6.90137 17.3156 6.90137 17.7061 7.29189L21.7061 11.2919C21.7346 11.3204 21.7613 11.3505 21.7862 11.3822C21.7917 11.3892 21.7972 11.3964 21.8027 11.4037C21.8205 11.4279 21.8373 11.4527 21.8529 11.4783C21.8604 11.4904 21.8675 11.5026 21.8743 11.5149C21.8852 11.5347 21.8956 11.5551 21.9053 11.5759C21.9133 11.5929 21.9208 11.6102 21.9278 11.6277C21.9357 11.6474 21.9429 11.6672 21.9495 11.6873C21.9543 11.7021 21.9589 11.7175 21.9632 11.733C21.9692 11.7546 21.9744 11.7763 21.9788 11.7982C21.9823 11.8156 21.9854 11.8331 21.988 11.8505C21.9952 11.8986 21.999 11.9484 21.999 11.999L21.9954 11.9138C21.9969 11.9311 21.9979 11.9484 21.9985 11.9658L21.999 11.999C21.999 12.0101 21.9988 12.0212 21.9985 12.0322C21.9979 12.0493 21.9968 12.0673 21.9953 12.0852C21.9935 12.1069 21.991 12.1275 21.988 12.148C21.9854 12.1649 21.9823 12.1824 21.9788 12.1997C21.9744 12.2217 21.9692 12.2434 21.9633 12.2648C21.9589 12.2805 21.9543 12.2959 21.9493 12.3111C21.9429 12.3308 21.9357 12.3506 21.9279 12.3701C21.9208 12.3878 21.9133 12.4051 21.9053 12.4222C21.8956 12.4429 21.8852 12.4633 21.8741 12.4833C21.8675 12.4954 21.8604 12.5076 21.853 12.5197C21.8373 12.5453 21.8205 12.5701 21.8027 12.5942C21.7737 12.6333 21.7415 12.6707 21.7061 12.7061L21.7862 12.6158C21.7839 12.6187 21.7816 12.6216 21.7793 12.6244L21.7061 12.7061L17.7061 16.7061C17.3156 17.0966 16.6824 17.0966 16.2919 16.7061C15.9014 16.3156 15.9014 15.6824 16.2919 15.2919L18.584 12.998L10.001 12.999C9.48816 12.999 9.06549 12.613 9.00773 12.1156L9.001 11.999C9.001 11.4467 9.44872 10.999 10.001 10.999L18.584 10.998L16.2919 8.70611C15.9314 8.34562 15.9037 7.77839 16.2087 7.3861L16.2919 7.29189Z",
                fill: "#AF1F18"
              })
            })), (0, a.jsx)("defs", {
              children: (0, a.jsx)("clipPath", Object.assign({
                id: "clip0_6707_340385"
              }, {
                children: (0, a.jsx)("rect", {
                  width: "24",
                  height: "24",
                  fill: "white"
                })
              }))
            })]
          })),
          Ve = ({
            color: t
          }) => (0, a.jsx)("svg", Object.assign({
            width: "20",
            height: "20",
            viewBox: "0 0 20 20",
            fill: "none",
            xmlns: "http://www.w3.org/2000/svg"
          }, {
            children: (0, a.jsx)("path", {
              d: "M6.7002 8.69687L13.3002 5.29688M6.7002 11.2969L13.3002 14.6969M1 10C1 10.7956 1.31607 11.5587 1.87868 12.1213C2.44129 12.6839 3.20435 13 4 13C4.79565 13 5.55871 12.6839 6.12132 12.1213C6.68393 11.5587 7 10.7956 7 10C7 9.20435 6.68393 8.44129 6.12132 7.87868C5.55871 7.31607 4.79565 7 4 7C3.20435 7 2.44129 7.31607 1.87868 7.87868C1.31607 8.44129 1 9.20435 1 10ZM13 4C13 4.79565 13.3161 5.55871 13.8787 6.12132C14.4413 6.68393 15.2044 7 16 7C16.7956 7 17.5587 6.68393 18.1213 6.12132C18.6839 5.55871 19 4.79565 19 4C19 3.20435 18.6839 2.44129 18.1213 1.87868C17.5587 1.31607 16.7956 1 16 1C15.2044 1 14.4413 1.31607 13.8787 1.87868C13.3161 2.44129 13 3.20435 13 4ZM13 16C13 16.7956 13.3161 17.5587 13.8787 18.1213C14.4413 18.6839 15.2044 19 16 19C16.7956 19 17.5587 18.6839 18.1213 18.1213C18.6839 17.5587 19 16.7956 19 16C19 15.2044 18.6839 14.4413 18.1213 13.8787C17.5587 13.3161 16.7956 13 16 13C15.2044 13 14.4413 13.3161 13.8787 13.8787C13.3161 14.4413 13 15.2044 13 16Z",
              stroke: t,
              strokeWidth: "2",
              strokeLinecap: "round",
              strokeLinejoin: "round"
            })
          }));
        const {
          LIGHT_TURQUOISE: $e,
          MEDIUM_AQUAMARINE: qe,
          TURQUOISE_GREEN: Qe,
          DARK_GRAY: Xe,
          DARK_BLUE: Je,
          DARK_NAVY_BLUE: tn,
          LIGHT_GRAY: en,
          ANTI_FLASH_WHITE: nn
        } = ot;
        var an;
        ! function(t) {
          t.QR_CODE_MESSAGE = "Invite your customers to visit your webstore by putting a printout of the QR code in your shop or on your order packaging", t.QR_CODE_ERROR = "Currently unable to download QR", t.SHARE = "Share", t.SHARE_LINK = "Share Link", t.SHARE_QR_CODE = "Share QR Code", t.VISIT_ONLINE_STORE = "Visit the online store", t.DOWNLOAD_QR_CODE = "Download QR Code", t.QR_FILE_NAME = "qr_code.svg", t.QR_BLOB_FILE_TYPE = "image/svg+xml;charset=utf-8", t.QR_DOCUMENT_ID = "12345", t.QR_CREATE_ELEMENT = "a", t.CATEGORIES = "Categories", t.CATEGORIES_ERROR = "Unable to find your categories!", t.STORE_ADDRESS = "Store Address", t.STORE_NUMBER = "Store Number", t.PREFIX_STORE_NUMBER = "+91", t.ACCEPT_ORDER = "Accept Orders", t.STORE_ACTIVE = "storeActive", t.DELIVERY = "Delivery", t.PICK_UP = "Pickup", t.BOPIS_SUPPORTED = "bopisSupported", t.DELIVERY_SUPPORTED = "deliverySupported", t.EDIT_PROFILE = "Edit Profile", t.SHARE_STORE = "Share store", t.LOGOUT = "Logout", t.STORE_TIMINGS = "Store Timings", t.STORE_STATUS = "Store Status", t.FAILED_TO_ADD_CHANGES = "Failed to add changes.", t.FAILED_TO_LOGOUT = "Failed to logout!", t.YES = "Yes", t.NO = "No", t.OFF = "Off", t.ON = "On", t.CLOSED = "Closed", t.HTTPS = "https://", t.ACTIVE = "ACTIVE", t.MANAGE = "Manage", t.STORES = "Stores"
        }(an || (an = {}));
        const rn = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"],
          sn = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
          on = {
            loaderIndicatorBackgroundColor: Xe,
            toggleTrackBackgroundColorSelectedDefault: Qe,
            toggleTrackBackgroundColorSelectedHover: qe,
            toggleTrackBackgroundColorSelectedPressed: qe,
            toggleTrackBackgroundColorUnselectedHover: $e,
            dividerColor: K.colorGray200,
            buttonBackgroundColorPrimaryDefault: Je,
            buttonBackgroundColorPrimaryHover: tn,
            buttonBackgroundColorPrimaryDisabled: en,
            buttonBackgroundColorPrimaryPressed: tn,
            buttonForegroundColorPrimaryDisabled: nn,
            linkForegroundColorDefault: Qe,
            linkForegroundColorHover: qe,
            linkForegroundColorPressed: qe
          },
          ln = new class {
            constructor() {
              this.shopSelectionResponse = {
                shopDetailsList: [],
                userRole: "",
                error: "",
                statusCode: 0
              }, this.isLoggedIn = !1, this.videoCommerceOnboardingStatus = "", this.isGetShopLoader = !1, this.currentStoreDetails = null, this.allStoreDetails = [], this.isZaiChatBotEnabled = !1, this.isZAIOrchestratorEnabled = !1, this.isZaiEnabledForOnboarding = !1, this.agreementAccepted = !0, this.isLogged = () => {
                this.isLoggedIn = !0
              }, this.isLoggedOut = () => {
                this.isLoggedIn = !1, localStorage.clear()
              }, this.handleIsGetShopLoader = t => {
                this.isGetShopLoader = t
              }, this.handleCurrentStoreDetails = t => {
                this.currentStoreDetails = t
              }, this.handleAllStoreDetails = t => {
                this.allStoreDetails = t
              }, this.setIsZaiChatBotEnabled = t => {
                this.isZaiChatBotEnabled = t
              }, this.setIsZAIOrchestratorEnabled = t => {
                this.isZAIOrchestratorEnabled = t
              }, this.setIsZaiEnabledForOnboarding = t => {
                this.isZaiEnabledForOnboarding = t, this.isZAIOrchestratorEnabled = t
              }, this.setAgreementAccepted = t => {
                this.agreementAccepted = t
              }, (0, st.rC)(this, {
                root: !1,
                isLoggedIn: st.LO,
                isGetShopLoader: st.LO,
                isLogged: st.aD,
                isLoggedOut: st.aD,
                shopSelectionResponse: st.LO,
                videoCommerceOnboardingStatus: st.LO,
                handleIsGetShopLoader: st.aD,
                currentStoreDetails: st.LO,
                handleCurrentStoreDetails: st.aD,
                allStoreDetails: st.LO,
                handleAllStoreDetails: st.aD,
                isZaiChatBotEnabled: st.LO,
                setIsZaiChatBotEnabled: st.aD,
                isZAIOrchestratorEnabled: st.LO,
                setIsZAIOrchestratorEnabled: st.aD,
                isZaiEnabledForOnboarding: st.LO,
                setIsZaiEnabledForOnboarding: st.aD,
                agreementAccepted: st.LO,
                setAgreementAccepted: st.aD
              })
            }
          },
          An = "720px";
        var cn = n(9174),
          dn = n(52113),
          wn = n(84059);
        const {
          QR_CODE_MESSAGE: gn,
          DOWNLOAD_QR_CODE: un,
          QR_CODE_ERROR: pn,
          SHARE: bn,
          SHARE_LINK: hn,
          SHARE_QR_CODE: mn,
          VISIT_ONLINE_STORE: xn,
          QR_FILE_NAME: fn,
          QR_BLOB_FILE_TYPE: vn,
          QR_CREATE_ELEMENT: jn,
          QR_DOCUMENT_ID: En
        } = an, {
          SHARE_STORE_BUTTON_CLICK: yn,
          SHARE_STORE_LINK: Cn
        } = f.MixPanelEventName;
        var On = (0, v.Pi)((({
            isShareStoreOpen: t,
            handleOnCloseShareStore: e,
            domainLink: n
          }) => {
            const [r, s] = (0, j.useState)(!1), {
              currentStoreDetails: i
            } = ln, o = () => {
              const t = document.getElementById(En);
              if (!t) return void(0, f.LT)(Object.assign(Object.assign({}, f.ar), {
                text: pn
              }));
              const e = (new XMLSerializer).serializeToString(t),
                n = new Blob([e], {
                  type: vn
                }),
                a = URL.createObjectURL(n),
                r = document.createElement(jn);
              r.href = a, r.download = fn, document.body.appendChild(r), r.click(), document.body.removeChild(r), URL.revokeObjectURL(a)
            }, l = () => {
              s(!0), f.mE.track(yn, {
                store_url: n
              })
            }, A = () => {
              f.mE.track(Cn, {
                store_url: n
              }), window.open(n, "_blank")
            }, c = t => (0, a.jsxs)(z.Z, Object.assign({
              width: "100%"
            }, {
              children: [(0, a.jsx)(cn.Z, Object.assign({
                level: 6
              }, {
                children: hn
              })), (0, a.jsxs)(H.default, Object.assign({
                alignmentHorizontal: t ? "center" : "justify",
                alignmentVertical: "center",
                wrap: "down",
                spacingInset: "300"
              }, {
                children: [(0, a.jsx)(Z.Z, Object.assign({
                  onClick: A,
                  type: "secondary"
                }, {
                  children: n
                })), (0, a.jsx)(P.default, Object.assign({
                  size: "small",
                  onClick: l,
                  minWidth: t && "60%"
                }, {
                  children: bn
                }))]
              })), (0, a.jsx)(cn.Z, Object.assign({
                level: 6
              }, {
                children: mn
              })), (0, a.jsx)(W.default, Object.assign({
                type: "b200",
                className: Nt
              }, {
                children: gn
              })), (0, a.jsxs)(z.Z, Object.assign({
                width: "100%",
                alignmentHorizontal: "center",
                spacing: "none"
              }, {
                children: [(0, a.jsx)(W.default, Object.assign({
                  type: "b200"
                }, {
                  children: null == i ? void 0 : i.storeName
                })), (0, a.jsx)(wn.tv, {
                  value: n,
                  id: En,
                  includeMargin: !0
                }), (0, a.jsx)(W.default, Object.assign({
                  type: "b200"
                }, {
                  children: xn
                }))]
              })), (0, a.jsx)(H.default, Object.assign({
                width: "100%",
                alignmentHorizontal: "center",
                alignmentVertical: "center"
              }, {
                children: (0, a.jsx)(Z.Z, Object.assign({
                  onClick: o,
                  type: "secondary"
                }, {
                  children: un
                }))
              }))]
            }));
            return (0, a.jsxs)(a.Fragment, {
              children: [(0, a.jsx)(R.default, Object.assign({
                query: "max-width",
                props: {
                  showMobileView: {
                    default: !1,
                    [f._G._720]: !0
                  },
                  showShareButtonFullWidth: {
                    default: !1,
                    [f._G._425]: !0
                  }
                }
              }, {
                children: ({
                  showMobileView: n,
                  showShareButtonFullWidth: r
                }) => n ? (0, a.jsxs)(Y.default, Object.assign({
                  type: "overlay",
                  side: "bottom",
                  open: t,
                  onClose: e
                }, {
                  children: [(0, a.jsx)(H.default, Object.assign({
                    alignmentHorizontal: "end",
                    width: "100%"
                  }, {
                    children: (0, a.jsx)(P.default, Object.assign({
                      onClick: e,
                      type: "icon"
                    }, {
                      children: (0, a.jsx)(G.default, {
                        tokens: V.default
                      })
                    }))
                  })), c(r)]
                })) : (0, a.jsx)(dn.ZP, Object.assign({
                  open: t,
                  onClose: e,
                  width: "450px",
                  bodySpacingInset: "400 none 400 400"
                }, {
                  children: c(r)
                }))
              })), (0, a.jsx)(f.mS, {
                isSocialMediaLinkOpen: r,
                handleCloseSocialMediaLink: () => s(!1),
                domainLink: n,
                shareModalTitle: hn,
                mobileNumber: Number(null == i ? void 0 : i.mobileNumber),
                storeName: null == i ? void 0 : i.storeName
              })]
            })
          })),
          Nn = n(58258);
        const Sn = JSON.parse('{"localStorage":["ADDRESS_DATA","Bulk","Collections","Custom Domain","GoogleAnalytics","META","Offers and Discounts","Return Data","StorePolicyData","allCustomersTableCount","bulkType","customerAnalyticsDates","easyCatalogProcessHalted","isBulkEditDownloadInProgress","isCodePresent","isCustomerAnalyticsDates","isReviewFeatureWarningModalOpen","isSellerAppModalRendered","isStoreOnboarded","isSignUpEventTracked","isUserLoggedInEventTracked","jobId","onboardingData","openShipOrderSheet","ordersData","performance marketing","rzpAuthCode","shipOrderId","startWorkFlowTimeStamp","startWorkFlowStartDate","startWorkFlowEndDate","status","storeURI"],"sessionStorage":["IsGoogleMerchantAccounts","googleAdsData","isGoogleAdsConnected","sellingPartnerId","spapiOauthCode"],"cookies":["posSessionId"]}'),
          kn = () => {
            Sn.localStorage.forEach((t => {
              t.trim() && localStorage.removeItem(t)
            })), Sn.sessionStorage.forEach((t => {
              t.trim() && sessionStorage.removeItem(t)
            })), Sn.cookies.forEach((t => {
              t.trim() && (document.cookie = `${t}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;`)
            }))
          };
        var In = n(70389),
          Mn = function(t, e, n, a) {
            return new(n || (n = Promise))((function(r, s) {
              function i(t) {
                try {
                  l(a.next(t))
                } catch (t) {
                  s(t)
                }
              }

              function o(t) {
                try {
                  l(a.throw(t))
                } catch (t) {
                  s(t)
                }
              }

              function l(t) {
                var e;
                t.done ? r(t.value) : (e = t.value, e instanceof n ? e : new n((function(t) {
                  t(e)
                }))).then(i, o)
              }
              l((a = a.apply(t, e || [])).next())
            }))
          };
        const {
          CATEGORIES: Tn,
          CATEGORIES_ERROR: Rn,
          STORE_ADDRESS: Bn,
          STORE_NUMBER: _n,
          PREFIX_STORE_NUMBER: Dn,
          ACCEPT_ORDER: Ln,
          BOPIS_SUPPORTED: Fn,
          DELIVERY: Pn,
          DELIVERY_SUPPORTED: zn,
          PICK_UP: Un,
          STORE_ACTIVE: Gn,
          SHARE_STORE: Zn,
          LOGOUT: Hn,
          STORE_STATUS: Yn,
          STORE_TIMINGS: Wn,
          FAILED_TO_ADD_CHANGES: Kn,
          FAILED_TO_LOGOUT: Vn,
          NO: $n,
          OFF: qn,
          ON: Qn,
          YES: Xn,
          CLOSED: Jn,
          HTTPS: ta,
          ACTIVE: ea,
          MANAGE: na,
          STORES: aa
        } = an, {
          LIGHT_GRAY: ra,
          BLACK: sa
        } = ot, ia = f.ErrorMessages.ERROR_BLOCKER;
        var oa = (0, v.Pi)((({
            isLoading: t,
            CategoriesList: e,
            isCategoryError: n,
            isMenuEnable: r
          }) => {
            var s, i, o, l;
            const [A, c] = (0, j.useState)(!1), [d, w] = (0, j.useState)(!1), g = t => c(t), u = (0, N.useNavigate)(), {
              allStoreDetails: p,
              isGetShopLoader: b,
              currentStoreDetails: h,
              handleCurrentStoreDetails: m,
              handleAllStoreDetails: x
            } = ln, {
              storeConfig: v,
              storeAddress: E,
              mobileNumber: y,
              categoryIds: C,
              storeName: O,
              storeURI: S,
              onboarded: k
            } = h || {}, {
              address: I,
              postalCode: M,
              state: B,
              city: D
            } = E || {}, {
              storeClosingTime: L,
              storeOpeningTime: F,
              storeActive: Z,
              bopisSupported: H,
              storeOperationalDaysList: Y
            } = v || {}, {
              isProfileDetailsActive: V,
              handleChangeActiveProfileDetails: $
            } = it, q = null == h ? void 0 : h.storeImageUrl, Q = null === (i = null === (s = null == h ? void 0 : h.storeName) || void 0 === s ? void 0 : s.charAt(0)) || void 0 === i ? void 0 : i.toUpperCase(), X = (0, _.g0)(), {
              mutateAsync: J
            } = X, {
              isOpen: tt,
              toggle: et
            } = (0, In.b_)(), {
              data: nt,
              isLoading: at
            } = (0, Re.hQ)(S), rt = null == nt ? void 0 : nt.customDomainAttributes, st = (null == rt ? void 0 : rt.length) > 0 && (null === (o = rt[0]) || void 0 === o ? void 0 : o.status) === ea ? `${ta}${null===(l=null==rt?void 0:rt[0])||void 0===l?void 0:l.domain}` : we + (null == h ? void 0 : h.storeURI), {
              mutateAsync: ot
            } = (0, Re.DK)(), lt = (t, e) => Mn(void 0, void 0, void 0, (function*() {
              if (t !== Fn || !e || (null == Y ? void 0 : Y.length)) {
                m(Object.assign(Object.assign({}, h), {
                  storeConfig: Object.assign(Object.assign({}, v), {
                    [t]: e
                  })
                }));
                try {
                  const n = {
                    [t]: e
                  };
                  yield ot(n)
                } catch (n) {
                  m(Object.assign(Object.assign({}, h), {
                    storeConfig: Object.assign(Object.assign({}, v), {
                      [t]: !e
                    })
                  })), (0, f.LT)(Object.assign(Object.assign({}, f.ar), {
                    text: Kn
                  }))
                }
              } else(0, f.LT)(Object.assign(Object.assign({}, f.ar), {
                text: "This change does not apply to individual days. Please adjust day-wise pickup availability from the Settings page."
              }))
            })), At = t => t ? "35px" : "39px", dt = {
              address: I,
              state: B,
              city: D,
              postalCode: M
            }, vt = [{
              name: Tn,
              value: n ? Rn : (0, f.nu)(e, C)
            }, {
              name: Bn,
              value: (0, f.lX)(dt)
            }, {
              name: _n,
              value: `${Dn}${y}`
            }], jt = t => {
              if (!(null == t ? void 0 : t.length)) return Jn;
              const e = new Set(t.map((t => t.toUpperCase()))),
                n = rn.filter((t => e.has(t.toUpperCase()))),
                a = [];
              let r = rn.indexOf(n[0]),
                s = r;
              return n.forEach(((t, e) => {
                if (e > 0) {
                  const e = rn.indexOf(t);
                  e === s + 1 ? s++ : (r === s ? a.push(sn[r]) : a.push(`${sn[r]}-${sn[s]}`), r = e, s = e)
                }
              })), r === s ? a.push(sn[r]) : a.push(`${sn[r]}-${sn[s]}`), a.join(", ")
            }, Et = [{
              title: Ln,
              toggleStatus: Z,
              onClick: () => lt(Gn, !Z)
            }, {
              title: Pn,
              toggleStatus: null == v ? void 0 : v.deliverySupported,
              onClick: () => lt(zn, !(null == v ? void 0 : v.deliverySupported))
            }, {
              title: Un,
              toggleStatus: H,
              onClick: () => lt(Fn, !H)
            }], Ct = [{
              name: Zn,
              image: (0, a.jsx)(Ve, {
                color: k ? sa : ra
              }),
              onClick: () => {
                c(!0), $(!1)
              },
              disable: !k,
              className: It
            }, {
              name: Hn,
              image: (0, a.jsx)(Ke, {}),
              onClick: () => Mn(void 0, void 0, void 0, (function*() {
                w(!0);
                try {
                  const t = yield J();
                  ln.isLoggedOut(), window.location.replace(null == t ? void 0 : t.redirectUrl)
                } catch (t) {
                  w(!1), (0, f.LT)(Object.assign(Object.assign({}, f.ar), {
                    text: Vn
                  }))
                }
              }))
            }], Ot = () => {
              u(`/${f.gq.SETTINGS}${f.gq.PROFILE}`), $(!1)
            }, Nt = () => {
              u((0, f.wq)(f.gq.STORE_TIMINGS)), $(!1)
            }, Mt = t => {
              const e = t.detail,
                {
                  storeClosingTime: n,
                  storeOpeningTime: a,
                  storeOperationalDaysList: r
                } = e;
              m(Object.assign(Object.assign({}, h), {
                storeConfig: Object.assign(Object.assign({}, v), {
                  storeClosingTime: n,
                  storeOpeningTime: a,
                  storeOperationalDaysList: r
                })
              }))
            }, Tt = t => {
              const e = t.detail,
                {
                  categoryIds: n,
                  mobileNumber: a,
                  address: r,
                  state: s,
                  postalCode: i,
                  storeImageUrl: o
                } = e;
              m(Object.assign(Object.assign({}, h), {
                categoryIds: n,
                storeImageUrl: o,
                storeAddress: Object.assign(Object.assign({}, E), {
                  address: r,
                  state: s,
                  postalCode: i
                }),
                mobileNumber: a
              }))
            }, Rt = t => {
              const e = t.detail;
              m(Object.assign(Object.assign({}, h), {
                storeConfig: Object.assign(Object.assign({}, v), e)
              }))
            }, Bt = t => {
              const {
                storeName: e
              } = t.detail;
              e && (m(Object.assign(Object.assign({}, h), {
                storeName: e
              })), x(p.map((t => t.storeId === Pt ? Object.assign(Object.assign({}, t), {
                storeName: e
              }) : t))))
            }, _t = t => {
              const {
                storeURI: e
              } = t.detail;
              e && m(Object.assign(Object.assign({}, h), {
                storeURI: e
              }))
            };
            (0, j.useEffect)((() => (window.addEventListener("UPDATE_STORE_TIMING_DETAILS", Mt), window.addEventListener("UPDATE_PROFILE_DETAILS", Tt), window.addEventListener("UPDATE_STORE_DETAILS", Ft), window.addEventListener("UPDATE_STORE_CONFIG_DETAILS", Rt), window.addEventListener("UPDATE_STORE_NAME", Bt), window.addEventListener("UPDATE_STORE_URI", _t), () => {
              window.removeEventListener("UPDATE_STORE_TIMING_DETAILS", Mt), window.removeEventListener("UPDATE_PROFILE_DETAILS", Tt), window.removeEventListener("UPDATE_STORE_DETAILS", Ft), window.removeEventListener("UPDATE_STORE_CONFIG_DETAILS", Rt), window.removeEventListener("UPDATE_STORE_NAME", Bt), window.removeEventListener("UPDATE_STORE_URI", _t)
            })));
            const Ft = t => Mn(void 0, void 0, void 0, (function*() {
                const e = t.detail;
                x(e);
                const n = (0, _.NU)(e);
                n.storeId !== Pt && (yield Ut(n))
              })),
              [Pt, zt] = (0, j.useState)(localStorage.getItem("shopId")),
              Ut = t => Mn(void 0, void 0, void 0, (function*() {
                if (localStorage.setItem("shopId", t.storeId), kn(), zt(t.storeId), m(t), yield(0, Nn._)(), "undefined" != typeof window) {
                  const e = new CustomEvent("CHANGE_SELECTED_SHOP", {
                    detail: {
                      shopId: t.storeId,
                      storeName: t.storeName
                    }
                  });
                  window.dispatchEvent(e), window.location.reload()
                }
              }));
            return (0, a.jsx)(a.Fragment, {
              children: (0, a.jsx)(R.default, Object.assign({
                query: "max-width",
                props: {
                  showMobileView: {
                    default: !1,
                    [An]: !0
                  }
                }
              }, {
                children: ({
                  showMobileView: e
                }) => (0, a.jsxs)(Ue.default, Object.assign({
                  tokens: on
                }, {
                  children: [r && (0, a.jsx)(P.default, Object.assign({
                    onClick: () => (tt && et(), void $(!V)),
                    className: ct
                  }, {
                    children: (0, a.jsxs)(ze.default, Object.assign({
                      alignmentHorizontal: "end",
                      alignmentVertical: "center",
                      minWidth: "100px"
                    }, {
                      children: [q ? (0, a.jsx)("img", {
                        src: q,
                        alt: "Profile",
                        className: ut,
                        height: At(e),
                        width: At(e)
                      }) : (0, a.jsx)(ze.default, Object.assign({
                        className: ut,
                        height: At(e),
                        width: At(e),
                        backgroundColor: Q && "#F26222",
                        alignmentHorizontal: "center",
                        alignmentVertical: "center"
                      }, {
                        children: t ? (0, a.jsx)(ke.Z, {
                          size: "small"
                        }) : Q
                      })), !e && (b ? (0, a.jsx)(ke.Z, {
                        type: "linear",
                        size: "small"
                      }) : (0, a.jsx)(W.default, Object.assign({
                        type: "b200"
                      }, {
                        children: null == h ? void 0 : h.storeName
                      }))), d ? (0, a.jsx)(ke.Z, {
                        size: "small"
                      }) : (0, a.jsx)(G.default, {
                        tokens: V ? We.Z : He.Z,
                        className: wt
                      })]
                    }))
                  })), V && (0, a.jsxs)(a.Fragment, {
                    children: [r && (0, a.jsx)("div", {
                      className: ht,
                      onClick: () => $(!1)
                    }), (0, a.jsx)(z.Z, Object.assign({
                      className: !e && mt,
                      width: e ? "100%" : "300px"
                    }, {
                      children: t || at ? (0, a.jsx)(f.pF, {
                        loaderHeight: "75vh",
                        loaderWidth: e ? "100%" : "300px",
                        loaderSize: "medium"
                      }) : n ? (0, a.jsx)(z.Z, {
                        children: (0, a.jsx)(Pe.Z, Object.assign({
                          type: "error"
                        }, {
                          children: ia
                        }))
                      }) : (0, a.jsxs)(z.Z, Object.assign({
                        backgroundColor: K.colorGray0,
                        spacingInset: e ? "300 none" : "400 none",
                        className: yt
                      }, {
                        children: [(0, a.jsx)(z.Z, Object.assign({
                          spacingInset: e ? "none 300" : "none 400"
                        }, {
                          children: (0, a.jsxs)(z.Z, Object.assign({
                            spacing: "400"
                          }, {
                            children: [(0, a.jsxs)(ze.default, Object.assign({
                              alignmentHorizontal: "justify",
                              alignmentVertical: "center"
                            }, {
                              children: [(0, a.jsx)(W.default, Object.assign({
                                type: "h200"
                              }, {
                                children: aa
                              })), (0, a.jsx)(P.default, Object.assign({
                                type: "icon",
                                onClick: Ot
                              }, {
                                children: (0, a.jsx)(W.default, Object.assign({
                                  type: "b200",
                                  className: St
                                }, {
                                  children: na
                                }))
                              }))]
                            })), (0, a.jsx)(z.Z, Object.assign({
                              spacing: "400"
                            }, {
                              children: p.map((t => {
                                var n, r, s, i;
                                return (0, a.jsx)(a.Fragment, {
                                  children: (0, a.jsx)(T.default, Object.assign({
                                    backgroundColor: K.colorGray0,
                                    className: Dt
                                  }, {
                                    children: (0, a.jsx)("div", Object.assign({
                                      onClick: () => {
                                        Ut(t)
                                      }
                                    }, {
                                      children: (0, a.jsxs)(ze.default, Object.assign({
                                        alignmentVertical: "center",
                                        spacing: "300",
                                        alignmentHorizontal: "justify"
                                      }, {
                                        children: [(0, a.jsxs)(ze.default, Object.assign({
                                          backgroundColor: K.colorGray0,
                                          alignmentHorizontal: "center",
                                          alignmentVertical: "center"
                                        }, {
                                          children: [(null == t ? void 0 : t.storeImageUrl) ? (0, a.jsx)("img", {
                                            src: null == t ? void 0 : t.storeImageUrl,
                                            alt: "Profile",
                                            className: t.storeId === Pt ? pt : ut,
                                            height: At(e),
                                            width: At(e)
                                          }) : (0, a.jsx)(ze.default, Object.assign({
                                            className: t.storeId === Pt ? pt : ut,
                                            backgroundColor: (null === (r = null === (n = null == t ? void 0 : t.storeName) || void 0 === n ? void 0 : n.charAt(0)) || void 0 === r ? void 0 : r.toUpperCase()) && "#F26222",
                                            alignmentHorizontal: "center",
                                            alignmentVertical: "center",
                                            height: At(e),
                                            width: At(e)
                                          }, {
                                            children: null === (i = null === (s = null == t ? void 0 : t.storeName) || void 0 === s ? void 0 : s.charAt(0)) || void 0 === i ? void 0 : i.toUpperCase()
                                          })), (0, a.jsxs)(z.Z, Object.assign({
                                            spacing: "100"
                                          }, {
                                            children: [(0, a.jsx)(W.default, Object.assign({
                                              type: "b200"
                                            }, {
                                              children: t.storeName
                                            })), (0, a.jsx)(W.default, Object.assign({
                                              type: "b100",
                                              className: kt
                                            }, {
                                              children: "PRIMARY" === t.shopOwnership ? "Admin" : "Staff"
                                            }))]
                                          }))]
                                        })), (0, a.jsx)(ze.default, Object.assign({
                                          alignmentHorizontal: "end"
                                        }, {
                                          children: t.storeId === Pt && (0, a.jsx)(G.default, {
                                            tokens: Ze.Z,
                                            className: Lt
                                          })
                                        }))]
                                      }))
                                    }))
                                  }))
                                })
                              }))
                            }))]
                          }))
                        })), (0, a.jsx)(U.Z, {
                          size: "small"
                        }), (0, a.jsx)(z.Z, Object.assign({
                          spacingInset: e ? "none 300" : "none 400"
                        }, {
                          children: vt.map((({
                            name: t,
                            value: e
                          }) => (0, a.jsxs)(z.Z, Object.assign({
                            spacing: "200"
                          }, {
                            children: [(0, a.jsx)(W.default, Object.assign({
                              type: "b100",
                              className: kt
                            }, {
                              children: t
                            })), (0, a.jsx)(W.default, Object.assign({
                              type: "b200",
                              color: "secondary",
                              className: t === Bn && xt
                            }, {
                              children: e
                            }))]
                          }), t)))
                        })), (0, a.jsx)(U.Z, {
                          size: "small"
                        }), (0, a.jsxs)(ze.default, Object.assign({
                          alignmentHorizontal: "justify",
                          alignmentVertical: "center",
                          spacingInset: e ? "none 300" : "none 400"
                        }, {
                          children: [(0, a.jsxs)(z.Z, Object.assign({
                            spacing: "200"
                          }, {
                            children: [(0, a.jsx)(W.default, Object.assign({
                              type: "b100",
                              className: kt
                            }, {
                              children: Wn
                            })), (0, a.jsx)(W.default, Object.assign({
                              type: "b200",
                              color: "secondary"
                            }, {
                              children: `${F} â ${L}, \n                        ${jt(Y)}`
                            }))]
                          })), (0, a.jsx)(P.default, Object.assign({
                            type: "icon",
                            onClick: Nt
                          }, {
                            children: (0, a.jsx)(G.default, {
                              tokens: Ye.default,
                              className: St
                            })
                          }))]
                        })), (0, a.jsx)(U.Z, {
                          size: "small"
                        }), (0, a.jsxs)(z.Z, Object.assign({
                          spacingInset: e ? "none" : "none 400"
                        }, {
                          children: [(0, a.jsx)(z.Z, Object.assign({
                            spacingInset: e && "none 300"
                          }, {
                            children: (0, a.jsx)(W.default, Object.assign({
                              type: "b300",
                              color: "secondary"
                            }, {
                              children: Yn
                            }))
                          })), Et.map((({
                            title: t,
                            toggleStatus: n,
                            onClick: r
                          }, s) => {
                            return (0, a.jsxs)(a.Fragment, {
                              children: [(0, a.jsxs)(ze.default, Object.assign({
                                width: "100%",
                                alignmentVertical: "center",
                                alignmentHorizontal: "justify",
                                spacingInset: e && "none 400 none 300"
                              }, {
                                children: [(0, a.jsxs)(ze.default, Object.assign({
                                  spacing: "200",
                                  alignmentVertical: "center"
                                }, {
                                  children: [(0, a.jsxs)(W.default, Object.assign({
                                    type: "b300"
                                  }, {
                                    children: [t, ":"]
                                  })), (0, a.jsx)(W.default, Object.assign({
                                    type: "h100",
                                    className: St
                                  }, {
                                    children: (i = n, o = t === Ln, o ? i ? Xn : $n : i ? Qn : qn)
                                  }))]
                                })), (0, a.jsx)(Ge.Z, {
                                  checked: n,
                                  onChange: r
                                })]
                              }), t), e && (null == Et ? void 0 : Et.length) !== s + 1 && (0, a.jsx)(U.Z, {
                                size: "small"
                              })]
                            });
                            var i, o
                          }))]
                        })), (0, a.jsx)(U.Z, {
                          size: "small"
                        }), (0, a.jsx)(z.Z, Object.assign({
                          alignmentHorizontal: "start",
                          spacing: "300",
                          spacingInset: e ? "none 300" : "none 400"
                        }, {
                          children: Ct.map((({
                            image: t,
                            name: e,
                            onClick: n,
                            href: r,
                            disable: s,
                            className: i
                          }) => (0, a.jsx)(P.default, Object.assign({
                            type: "icon",
                            onClick: n,
                            className: ft,
                            href: r,
                            disabled: s
                          }, {
                            children: (0, a.jsxs)(ze.default, Object.assign({
                              spacingInset: "200 none",
                              alignmentVertical: "center",
                              className: gt
                            }, {
                              children: [t, (0, a.jsx)(W.default, Object.assign({
                                type: "b300",
                                className: `${e===Hn&&bt} ${s&&i}`
                              }, {
                                children: e
                              }))]
                            }))
                          }), e)))
                        }))]
                      }))
                    }))]
                  }), (0, a.jsx)(On, {
                    isShareStoreOpen: A,
                    handleOnCloseShareStore: g,
                    domainLink: st
                  }), d && (0, a.jsx)(f.pF, {
                    loaderSize: e ? "medium" : "large",
                    isMaskLoaderEnabled: !0
                  })]
                }))
              }))
            })
          })),
          la = (0, v.Pi)((({
            CategoriesList: t,
            isCategoryError: e,
            isLoading: n
          }) => {
            const {
              isProfileDetailsActive: r
            } = it, {
              sidebarToggle: s
            } = Fe;
            return !s && (0, a.jsxs)(z.Z, Object.assign({
              width: "100%",
              className: r && dt,
              spacingInset: "300",
              alignmentVertical: "justify",
              spacing: "none"
            }, {
              children: [(0, a.jsx)(oa, {
                isLoading: n,
                CategoriesList: t,
                isCategoryError: e
              }), r && (0, a.jsx)(f._l, {})]
            }))
          })),
          Aa = n(3491),
          ca = n.p + "b9e98197d91f2d1354d3.png",
          da = n(64230),
          wa = n.p + "70113349a9b504b4f69a.svg";
        const ga = "Returns",
          ua = "config",
          pa = "orders",
          ba = "returns",
          ha = "Store Configuration",
          ma = "Growth",
          xa = "Trust Markers",
          fa = "Instagram Feed",
          va = "instagram-feed",
          ja = "Trust Badges",
          Ea = "trust-badges",
          ya = "Contact",
          Ca = "Chat with Us",
          Oa = "WhatsApp",
          Na = [
            ["Store Configuration", "store-appearance", "google-analytics"],
            ["Settings", "settings", "profile", "custom-domain", "delivery-settings", "config", "payments", "store-timings", "social-media", "store-policies", "user-management"],
            ["Growth", "performance-marketing", "offers", "upsell-cross-sell", "sell-using-videos", "seo", "marketing-automation"],
            ["Analytics", "sales", "traffic", "operations", "return", "customer-details", "customer-segments", "reports"],
            ["Catalog", "products", "categories", "inventory", "collections"],
            ["Orders", "", "returns"],
            ["Reviews", "manage"]
          ],
          Sa = ["home", "rto-reduction-suite"];
        var ka, Ia, Ma, Ta = (0, v.Pi)((() => (0, a.jsx)(dn.ZP, Object.assign({
          open: Fe.scannerToggle
        }, {
          children: (0, a.jsxs)(z.Z, Object.assign({
            spacing: "none",
            spacingInset: "none"
          }, {
            children: [(0, a.jsxs)(H.default, Object.assign({
              alignmentHorizontal: "justify"
            }, {
              children: [(0, a.jsx)(W.default, {
                children: "Scan below to download the app"
              }), (0, a.jsx)(P.default, Object.assign({
                type: "icon",
                onClick: () => {
                  Fe.handleScannerToggle()
                },
                "data-testid": "modal"
              }, {
                children: (0, a.jsx)(G.default, {
                  tokens: da.Z
                })
              }))]
            })), (0, a.jsx)("img", {
              src: wa,
              alt: "google-play-QR"
            })]
          }))
        }))));
        ! function(t) {
          t.PRIMARY_HEADER = "primary", t.SECONDARY_HEADER = "secondary"
        }(ka || (ka = {})),
        function(t) {
          t.DO_MORE_WITH_SMARTBIZ = "Do more with the SmartBiz app", t.LOGOUT = "Logout", t.PROFILE = "Profile"
        }(Ia || (Ia = {})),
        function(t) {
          t.SMARTBIZ = "SmartBiz", t.GOOGLE_PLAY = "Google Play", t.SECURITY = "Security", t.NOTIFICATION = "Notification"
        }(Ma || (Ma = {}));
        var Ra = n(19658);
        const Ba = ["CATALOG_SYNC_IN_PROGRESS", "ONBOARDING_COMPLETE"];
        Ra.Z;
        var _a = n(69129),
          Da = n.p + "b8cd0c437e966ee56c75.svg",
          La = n(37195);
        const Fa = {
            textFontSizeB300: "10px",
            textLineHeightB300: "14px",
            textFontWeightB300: "700",
            textColorPrimary: "#FFFFFF",
            boxBorderWidth: "0px"
          },
          Pa = {
            popoverBackgroundColorFill: "white",
            popoverForegroundColorFill: "#697576"
          },
          za = {
            sideMenuBackgroundColorSurface: "#0E2B31",
            sideMenuBackgroundColorPrinciple: "#0E2B31",
            sideMenuBackgroundColorHighlight: "#0E2B31",
            sideMenuBackgroundColorSubdue: "#0E2B31",
            sideMenuLinkBackgroundColorDefault: "#0E2B31",
            sideMenuLinkBackgroundColorHover: "#00A69A",
            sideMenuLinkBackgroundColorPressed: "#00A69A",
            sideMenuLinkBackgroundColorSelected: "#00A69A",
            sideMenuBorderColor: "#00A69A",
            sideMenuLinkForegroundColorDefault: "#FFFFFF",
            sideMenuBorderRadius: "12px",
            sideMenuLinkIndicatorBorderRadius: "12px"
          },
          Ua = {
            textColorPrimary: "#FFFFFF",
            sideMenuLinkForegroundColorDefault: "#FFFFFF",
            sideMenuLinkForegroundColorDisabled: "#FFFFFF",
            sideMenuBorderRadius: "12px"
          };
        var Ga, Za = (0, v.Pi)((({
            parentMicrofrontendKey: t,
            subModuleKey: e,
            subModulePath: n,
            isNewFeature: r,
            isNotAvailableInDesktop: s,
            handleCustomOnClick: i
          }) => {
            const o = (0, N.useNavigate)(),
              {
                handleChangeActiveProfileDetails: l
              } = it,
              {
                childRoute: A,
                parentRoute: c,
                setSidebarToggle: d,
                setParentRoute: w,
                setChildRoute: g
              } = Fe,
              u = t ? (0, f.tD)(t, e) : e,
              p = () => {
                const t = !Sa.includes(c),
                  e = u.toLowerCase().replace(/\s+/g, ""),
                  a = A.replace(/-/g, "");
                return t && A === ua && u === ga || t && "" === A && "All Orders" === u || t && (e != ba && e === a || n === A) || t && A === ba && "Returns" === u
              };
            return (0, a.jsx)(Aa.MB, Object.assign({
              onClick: null != i ? i : () => {
                var a, r;
                if (t && "RETURNS_CONFIG" !== e) {
                  const [n, a] = (0, f.Xr)(t, e, !0).split("/");
                  w(n), g(a), o(`${n}/${a}`)
                } else {
                  u === ga ? (g(ua), n = ua, o(`${pa}/${ba}/${ua}`)) : (g(n), o(n));
                  const t = null === (r = null === (a = Na.find((t => t.includes(n)))) || void 0 === a ? void 0 : a[0]) || void 0 === r ? void 0 : r.toLowerCase();
                  t && w(t)
                }
                l(!1), d()
              },
              disabled: s
            }, {
              children: s ? (0, a.jsx)(_a.default, Object.assign({
                tokens: Pa
              }, {
                children: (0, a.jsx)(La.default, Object.assign({
                  position: "bottom",
                  title: "This feature is currently only available on the Mobile App",
                  id: "myTooltip"
                }, {
                  children: (0, a.jsxs)(H.default, Object.assign({
                    className: Rt,
                    spacing: "200",
                    "aria-describedby": "myTooltip"
                  }, {
                    children: [(0, a.jsx)(W.default, Object.assign({
                      type: "b200",
                      className: p() ? Tt : _t
                    }, {
                      children: u
                    })), r && (0, a.jsx)(_a.default, Object.assign({
                      tokens: Fa
                    }, {
                      children: (0, a.jsx)(z.Z, Object.assign({
                        backgroundColor: "#F26B1D",
                        className: Bt,
                        type: "fill"
                      }, {
                        children: (0, a.jsx)(W.default, Object.assign({
                          type: "b300",
                          color: "primary"
                        }, {
                          children: "NEW"
                        }))
                      }))
                    })), (0, a.jsx)("img", {
                      src: Da
                    })]
                  }))
                }))
              })) : (0, a.jsxs)(H.default, Object.assign({
                className: Rt,
                spacing: "200",
                "aria-describedby": "myTooltip"
              }, {
                children: [(0, a.jsx)(_a.default, Object.assign({
                  tokens: Ua
                }, {
                  children: (0, a.jsx)(W.default, Object.assign({
                    type: p() ? "h100" : "b200",
                    className: p() ? Tt : _t
                  }, {
                    children: u
                  }))
                })), r && (0, a.jsx)(_a.default, Object.assign({
                  tokens: Fa
                }, {
                  children: (0, a.jsx)(z.Z, Object.assign({
                    backgroundColor: "#F26B1D",
                    className: Bt,
                    type: "fill"
                  }, {
                    children: (0, a.jsx)(W.default, Object.assign({
                      type: "b300",
                      color: "primary"
                    }, {
                      children: "NEW"
                    }))
                  }))
                }))]
              }))
            }))
          })),
          Ha = (0, v.Pi)((({
            MicroFrontendsKey: t,
            children: e,
            toggleSelectedGroupedSidebar: n,
            selectedGroupedSidebar: r,
            title: s,
            icon: i
          }) => {
            const o = (0, N.useNavigate)(),
              {
                handleChangeActiveProfileDetails: l
              } = it,
              {
                setSidebarToggle: A,
                setParentRoute: c,
                parentRoute: d
              } = Fe,
              [w, g] = (0, j.useState)(!0),
              u = s ? s.toLowerCase() : (0, f.L2)(t),
              p = r === u;
            return (0, a.jsx)(Ue.default, Object.assign({
              tokens: Ua
            }, {
              children: (0, a.jsxs)(Aa.MB, Object.assign({
                onClick: () => {
                  if (e) {
                    n(u);
                    const t = (t => {
                      switch (t) {
                        case "catalog":
                          return "/catalog/products";
                        case "orders":
                          return "/orders";
                        case "analytics":
                          return "/analytics/sales";
                        case "reviews":
                          return "/reviews/manage";
                        case "store configuration":
                          return "/store-appearance";
                        case "growth":
                          return "/offers"
                      }
                    })(u);
                    r === u && g((t => !t)), o(t)
                  } else {
                    c(u);
                    const e = (0, f.L2)(t);
                    o(e), l(!1), A()
                  }
                },
                href: (0, f.L2)(t),
                linkComponents: [Za],
                selected: u === d,
                open: p && w
              }, {
                children: [(0, a.jsxs)(H.default, Object.assign({
                  spacing: "300"
                }, {
                  children: [(0, a.jsx)(Ue.default, Object.assign({
                    tokens: Ua
                  }, {
                    children: (0, a.jsx)(W.default, Object.assign({
                      type: "b200",
                      className: _t
                    }, {
                      children: s || (0, f.Er)(t)
                    }))
                  })), (0, a.jsx)("img", {
                    src: i
                  })]
                })), e]
              }))
            }))
          })),
          Ya = n.p + "3b05d780e6cc8a21b047.svg",
          Wa = n.p + "50158f1f6a5752e67cf8.svg",
          Ka = n.p + "86f895324c347ed23437.svg",
          Va = n.p + "118ff68f08fa847d62f3.svg",
          $a = n.p + "ca834dffdd117edb2ab1.svg",
          qa = n.p + "58a2aadbe41dca63c41f.svg",
          Qa = n.p + "d38ccaa90a96f7475069.svg",
          Xa = n.p + "32c280b6937c5e40f282.svg",
          Ja = n.p + "9e0dd94b0ee67c78ceb7.svg",
          tr = n.p + "f42f2971686a3239e54a.svg";
        ! function(t) {
          t.PRIMARY = "PRIMARY", t.SECONDARY = "SECONDARY"
        }(Ga || (Ga = {}));
        var er = n.p + "08bdaa420af6f88c262c.svg",
          nr = function(t, e, n, a) {
            return new(n || (n = Promise))((function(r, s) {
              function i(t) {
                try {
                  l(a.next(t))
                } catch (t) {
                  s(t)
                }
              }

              function o(t) {
                try {
                  l(a.throw(t))
                } catch (t) {
                  s(t)
                }
              }

              function l(t) {
                var e;
                t.done ? r(t.value) : (e = t.value, e instanceof n ? e : new n((function(t) {
                  t(e)
                }))).then(i, o)
              }
              l((a = a.apply(t, e || [])).next())
            }))
          };
        const {
          SMARTBIZ: ar,
          GOOGLE_PLAY: rr
        } = Ma;
        var sr = (0, v.Pi)((({
          showMobileView: t
        }) => {
          const [e, n] = (0, j.useState)(), [r, s] = (0, j.useState)(null), [i, o] = (0, j.useState)(null), [l, A] = (0, j.useState)(!0), [c, d] = (0, j.useState)(!1), [w, g] = (0, j.useState)(!1), u = (0, N.useNavigate)(), p = (0, N.useLocation)(), {
            handleChangeActiveProfileDetails: b
          } = it, {
            INVENTORY_ENABLED_STATUS: h,
            RTO_REDUCTION_SUITE_ENABLED_STATUS: m
          } = f.FeatureFlags;
          (0, j.useEffect)((() => {
            nr(void 0, void 0, void 0, (function*() {
              const t = yield(0, _.tx)();
              if ("SUCCESS" === (null == t ? void 0 : t.successCode)) {
                const e = (0, _.NU)(null == t ? void 0 : t.data);
                localStorage.setItem("storeURI", null == e ? void 0 : e.storeURI), o(t), (null == e ? void 0 : e.shopOwnership) === Ga.PRIMARY ? A(!0) : (null == e ? void 0 : e.shopOwnership) === Ga.SECONDARY && A(!1)
              }
            })), v()
          }), []), (0, j.useEffect)((() => {
            nr(void 0, void 0, void 0, (function*() {
              var t;
              const e = (0, _.NU)(null == i ? void 0 : i.data),
                n = null === (t = null == e ? void 0 : e.storeConfig) || void 0 === t ? void 0 : t.videoCommerceOnboardingStatus,
                a = null == Ba ? void 0 : Ba.includes(n);
              s(a)
            }))
          }), [i]), (0, j.useEffect)((() => {
            (() => {
              var t, a;
              const r = p.pathname.split("/");
              if ("" === r[r.length - 1] && r[r.length - 2] !== pa && r.pop(), 2 === r.length && Sa.includes(r[1])) Fe.setParentRoute(r[1]), Fe.setChildRoute(""), n("");
              else {
                let s = r.slice(1).reverse().find((t => Na.some((e => e.includes(t))))) || "";
                Number.isNaN(Number(s)) || (s = ""), Fe.setChildRoute(s);
                const i = null === (a = null === (t = Na.find((t => t.includes(s)))) || void 0 === t ? void 0 : t[0]) || void 0 === a ? void 0 : a.toLowerCase();
                i && Fe.setParentRoute(i), e === i || n(i)
              }
            })()
          }), [p.pathname]), (0, j.useEffect)((() => {
            null === r && null === l || (() => {
              const t = Object.values(f.Bj).find((t => {
                  var e;
                  return Fe.childRoute === t.path || (null === (e = Fe.childRoute) || void 0 === e ? void 0 : e.length) > 0 && t.path.endsWith(Fe.childRoute)
                })),
                a = (null == t ? void 0 : t.path) === f.Bj[f.rv.VIDEO_COMMERCE].path,
                s = (null == t ? void 0 : t.path) === f.Bj[f.rv.GOOGLE_ANALYTICS].path,
                i = (null == t ? void 0 : t.path) === f.Bj[f.rv.USER_MANAGEMENT].path,
                o = (null == t ? void 0 : t.path) === f.Bj[f.rv.MARKETING_AUTOMATION].path;
              ("" === Fe.parentRoute && !t || a && !l && !r || s && !l || o && !l || i && !Fe.isUserManagementEnabled) && (console.warn("Feature not available, navigating to home..."), u(f.Bj[f.rv.HOME].path));
              const A = e === Fe.parentRoute;
              Fe.parentRoute.length > 0 && Fe.childRoute.length > 0 && (A || n(Fe.parentRoute))
            })()
          }), [r, l]);
          const x = t => {
              n(t)
            },
            v = () => nr(void 0, void 0, void 0, (function*() {
              const t = yield(0, f.aH)(), e = yield(0, f.Ic)(h.flagName, h.defaultValue, t);
              d(e);
              const n = yield(0, f.Ic)(m.flagName, m.defaultValue, t);
              g(n)
            })),
            E = () => (0, a.jsx)(z.Z, Object.assign({
              width: "100%",
              spacingInset: "400 450"
            }, {
              children: (0, a.jsx)(U.Z, {})
            }));
          return (0, j.useEffect)((() => {
            window.addEventListener("HIDE_SIDE_BAR", (t => {
              const e = t.detail;
              Fe.setShowSideBar(!e.hideSideBar)
            }))
          })), (0, a.jsx)(Ue.default, Object.assign({
            tokens: {
              dividerColor: "#E7E9E9"
            }
          }, {
            children: Fe.showSideBar && (0, a.jsx)(Ue.default, Object.assign({
              tokens: za
            }, {
              children: (0, a.jsxs)(Aa.ZP, Object.assign({
                width: "260px",
                type: t ? "overlay" : "skinny",
                open: !t || Fe.sidebarToggle
              }, t && {
                onClose: Fe.setSidebarToggle
              }, {
                linkComponents: [Ha, Za, Aa.MB, E],
                backgroundColor: "surface"
              }, {
                children: [t && (0, a.jsx)(Aa.xc, Object.assign({
                  onClick: () => {
                    const t = (0, f.L2)(f.rv.HOME);
                    u(t), b(!1), Fe.setSidebarToggle()
                  }
                }, {
                  children: (0, a.jsx)("img", {
                    width: "74px",
                    height: "30px",
                    src: ca,
                    alt: ar
                  })
                })), (0, a.jsx)(Ha, {
                  MicroFrontendsKey: f.rv.HOME,
                  icon: Ya
                }), (0, a.jsxs)(Ha, Object.assign({
                  MicroFrontendsKey: f.rv.CATALOG,
                  selectedGroupedSidebar: e,
                  toggleSelectedGroupedSidebar: x,
                  icon: Wa
                }, {
                  children: [(0, a.jsx)(Za, {
                    parentMicrofrontendKey: f.rv.CATALOG,
                    subModuleKey: f.aP[f.rv.CATALOG].PRODUCTS
                  }), (0, a.jsx)(Za, {
                    parentMicrofrontendKey: f.rv.CATALOG,
                    subModuleKey: f.aP[f.rv.CATALOG].CATEGORIES
                  }), c && (0, a.jsx)(Za, {
                    parentMicrofrontendKey: f.rv.CATALOG,
                    subModuleKey: f.aP[f.rv.CATALOG].INVENTORY
                  }), (0, a.jsx)(Za, {
                    parentMicrofrontendKey: f.rv.CATALOG,
                    subModuleKey: f.aP[f.rv.CATALOG].COLLECTIONS
                  })]
                })), (0, a.jsxs)(Ha, Object.assign({
                  MicroFrontendsKey: f.rv.OMS_MODULE,
                  selectedGroupedSidebar: e,
                  toggleSelectedGroupedSidebar: x,
                  icon: Ka
                }, {
                  children: [(0, a.jsx)(Za, {
                    parentMicrofrontendKey: f.rv.OMS_MODULE,
                    subModuleKey: f.aP[f.rv.OMS_MODULE].ALL_ORDERS
                  }), (0, a.jsx)(Za, {
                    parentMicrofrontendKey: f.rv.OMS_MODULE,
                    subModuleKey: f.aP[f.rv.OMS_MODULE].RETURNS
                  })]
                })), (0, a.jsxs)(Ha, Object.assign({
                  MicroFrontendsKey: f.rv.ANALYTICS,
                  icon: Va,
                  selectedGroupedSidebar: e,
                  toggleSelectedGroupedSidebar: x
                }, {
                  children: [(0, a.jsx)(Za, {
                    parentMicrofrontendKey: f.rv.ANALYTICS,
                    subModuleKey: f.aP[f.rv.ANALYTICS].SALES
                  }), (0, a.jsx)(Za, {
                    parentMicrofrontendKey: f.rv.ANALYTICS,
                    subModuleKey: f.aP[f.rv.ANALYTICS].TRAFFIC
                  }), (0, a.jsx)(Za, {
                    parentMicrofrontendKey: f.rv.ANALYTICS,
                    subModuleKey: f.aP[f.rv.ANALYTICS].OPERATIONS
                  }), Fe.isCustomerSegmentsEnabled && (0, a.jsx)(Za, {
                    parentMicrofrontendKey: f.rv.ANALYTICS,
                    subModuleKey: f.aP[f.rv.ANALYTICS].CUSTOMER_SEGMENTS
                  }), (0, a.jsx)(Za, {
                    parentMicrofrontendKey: f.rv.ANALYTICS,
                    subModuleKey: f.aP[f.rv.ANALYTICS].REPORTS
                  })]
                })), Fe.isReviewsEnabled && (0, a.jsx)(Ha, Object.assign({
                  MicroFrontendsKey: f.rv.REVIEWS,
                  icon: $a,
                  selectedGroupedSidebar: e,
                  toggleSelectedGroupedSidebar: x
                }, {
                  children: (0, a.jsx)(Za, {
                    parentMicrofrontendKey: f.rv.REVIEWS,
                    subModuleKey: f.aP[f.rv.REVIEWS].MANAGE
                  })
                })), (0, a.jsx)(E, {}), (0, a.jsxs)(Ha, Object.assign({
                  title: ha,
                  selectedGroupedSidebar: e,
                  toggleSelectedGroupedSidebar: x,
                  icon: qa
                }, {
                  children: [(0, a.jsx)(Za, {
                    subModuleKey: f.Bj[f.rv.WEBSITE_APPEARANCE].name,
                    subModulePath: f.Bj[f.rv.WEBSITE_APPEARANCE].path
                  }), l && (0, a.jsx)(Za, {
                    subModuleKey: f.Bj[f.rv.GOOGLE_ANALYTICS].name,
                    subModulePath: f.Bj[f.rv.GOOGLE_ANALYTICS].path,
                    isNewFeature: !0
                  })]
                })), (0, a.jsxs)(Ha, Object.assign({
                  title: ma,
                  selectedGroupedSidebar: e,
                  toggleSelectedGroupedSidebar: x,
                  icon: Qa
                }, {
                  children: [(0, a.jsx)(Za, {
                    subModuleKey: f.Bj[f.rv.OFFERS].name,
                    subModulePath: f.Bj[f.rv.OFFERS].path
                  }), Fe.isBasketBuildingEnabled && (0, a.jsx)(Za, {
                    subModuleKey: f.Bj[f.rv.BASKET_BUILDING].name,
                    subModulePath: f.Bj[f.rv.BASKET_BUILDING].path,
                    isNewFeature: !0
                  }), (0, a.jsx)(Za, {
                    subModuleKey: f.Bj[f.rv.PERFORMANCE_MARKETING].name,
                    subModulePath: f.Bj[f.rv.PERFORMANCE_MARKETING].path
                  }), f.gO.isSEOFeatureEnabled && (0, a.jsx)(Za, {
                    subModuleKey: f.Bj[f.rv.SEO].name,
                    subModulePath: f.Bj[f.rv.SEO].path
                  }), r && l && (0, a.jsx)(Za, {
                    subModuleKey: f.Bj[f.rv.VIDEO_COMMERCE].name,
                    subModulePath: f.Bj[f.rv.VIDEO_COMMERCE].path
                  }), f.gO.isMAFeatureEnabled && l && (0, a.jsx)(Za, {
                    subModuleKey: f.Bj[f.rv.MARKETING_AUTOMATION].name,
                    subModulePath: f.Bj[f.rv.MARKETING_AUTOMATION].path
                  }), (0, a.jsx)(Za, {
                    subModuleKey: fa,
                    subModulePath: va,
                    isNotAvailableInDesktop: !0
                  })]
                })), (0, a.jsx)(Ha, Object.assign({
                  title: xa,
                  selectedGroupedSidebar: e,
                  toggleSelectedGroupedSidebar: x,
                  icon: Xa
                }, {
                  children: (0, a.jsx)(Za, {
                    subModuleKey: ja,
                    subModulePath: Ea,
                    isNotAvailableInDesktop: !0
                  })
                })), it.isWhatsAppChatBotFeatureEnabled && (0, a.jsxs)(Ha, Object.assign({
                  title: ya,
                  selectedGroupedSidebar: e,
                  toggleSelectedGroupedSidebar: x,
                  icon: er
                }, {
                  children: [(0, a.jsx)(Za, {
                    subModuleKey: Ca,
                    handleCustomOnClick: () => {
                      (null === window || void 0 === window ? void 0 : window.zE) && (it.isChatBotMessengerActive ? (window.zE("messenger", "close"), it.setIsChatBotMessengerActive(!1)) : (window.zE("messenger", "open"), it.setIsChatBotMessengerActive(!0)))
                    },
                    isNotAvailableInDesktop: !1
                  }), (0, a.jsx)(Za, {
                    subModuleKey: Oa,
                    handleCustomOnClick: () => {
                      he(`https://api.whatsapp.com/send?phone=${ge}`, "_blank")
                    },
                    isNotAvailableInDesktop: !1
                  })]
                })), w && (0, a.jsx)(Ha, {
                  MicroFrontendsKey: f.rv.RTO_REDUCTION,
                  icon: tr
                }), (0, a.jsx)(Ha, {
                  MicroFrontendsKey: f.rv.SETTINGS,
                  icon: Ja
                }), (0, a.jsx)(Ta, {})]
              }))
            }))
          }))
        }));
        const {
          SECONDARY_HEADER: ir
        } = ka, {
          SMARTBIZ: or,
          GOOGLE_PLAY: lr,
          SECURITY: Ar
        } = Ma, cr = f.gq.HOME;
        var dr = (0, v.Pi)((({
          mode: t
        }) => {
          const e = (0, N.useNavigate)(),
            n = (0, _.g0)(),
            {
              isLoading: r
            } = n,
            {
              isProfileDetailsActive: s,
              handleChangeActiveProfileDetails: i
            } = it,
            {
              setSidebarToggle: o
            } = Fe,
            {
              setHelpMenuToggle: l
            } = it,
            {
              data: A,
              isLoading: c,
              error: d
            } = (0, Re.hl)(),
            w = !!d;
          return (0, a.jsxs)(a.Fragment, {
            children: [(0, a.jsxs)(Ie.ZP, Object.assign({
              size: "medium"
            }, {
              children: [t !== ir && (0, a.jsx)(Ie.tr, {
                onClick: o,
                open: !0
              }), (0, a.jsx)(Ie.Cp, Object.assign({
                onClick: () => e(cr)
              }, {
                children: (0, a.jsx)("img", {
                  src: De,
                  alt: or,
                  width: "74px"
                })
              })), t === ir && (0, a.jsx)(P.default, Object.assign({
                onClick: () => {
                  window.location.replace(Q.sellerAppGooglePlayStore)
                },
                type: "icon"
              }, {
                children: (0, a.jsx)("img", {
                  src: Be,
                  width: "80px",
                  height: "35px",
                  alt: lr
                })
              })), t === ir ? (0, a.jsx)(P.default, Object.assign({
                onClick: () => {
                  return t = void 0, e = void 0, r = function*() {
                    const t = yield n.mutateAsync();
                    ln.isLoggedOut(), window.location.replace(null == t ? void 0 : t.redirectUrl)
                  }, new((a = void 0) || (a = Promise))((function(n, s) {
                    function i(t) {
                      try {
                        l(r.next(t))
                      } catch (t) {
                        s(t)
                      }
                    }

                    function o(t) {
                      try {
                        l(r.throw(t))
                      } catch (t) {
                        s(t)
                      }
                    }

                    function l(t) {
                      var e;
                      t.done ? n(t.value) : (e = t.value, e instanceof a ? e : new a((function(t) {
                        t(e)
                      }))).then(i, o)
                    }
                    l((r = r.apply(t, e || [])).next())
                  }));
                  var t, e, a, r
                },
                size: "small",
                type: "icon",
                minWidth: "36px",
                className: Ct
              }, {
                children: r ? (0, a.jsx)(ke.Z, {
                  size: "small"
                }) : (0, a.jsx)(G.default, {
                  tokens: Me.Z,
                  className: Ot
                })
              })) : (0, a.jsxs)(a.Fragment, {
                children: [(0, a.jsx)(P.default, Object.assign({
                  onClick: l,
                  type: "icon"
                }, {
                  children: (0, a.jsx)("img", {
                    src: _e,
                    alt: Ar
                  })
                })), (0, a.jsx)(P.default, Object.assign({
                  type: "icon",
                  size: "small",
                  onClick: () => i(!s)
                }, {
                  children: (0, a.jsx)(G.default, {
                    tokens: Te.Z
                  })
                }))]
              })]
            })), (0, a.jsx)(sr, {
              showMobileView: !0
            }), (0, a.jsx)(la, {
              isLoading: c,
              CategoriesList: null == A ? void 0 : A.categories,
              isCategoryError: w
            })]
          })
        }));
        const wr = "USER_DOES_NOT_EXIST",
          gr = "INVALID_TOKEN",
          ur = "ERR_NETWORK",
          pr = "NOT_FOUND";
        var br = t => {
            const {
              error: e,
              isErrorBoundaryFallback: n
            } = t;
            return (0, a.jsx)(z.Z, Object.assign({
              height: "100vh",
              alignmentHorizontal: "center",
              alignmentVertical: "center"
            }, {
              children: (0, a.jsx)(T.default, {
                children: (0, a.jsxs)(z.Z, Object.assign({
                  alignmentHorizontal: "center",
                  spacing: "500"
                }, {
                  children: [(0, a.jsx)("img", {
                    width: "230rem",
                    src: De,
                    alt: "Smartbiz Logo"
                  }), e ? (0, a.jsx)(Pe.Z, Object.assign({
                    toast: !0,
                    type: "error",
                    width: 800,
                    title: n ? "Something went wrong!" : "Unable to Reach Sign-In Page"
                  }, {
                    children: n ? "We're sorry, but we encountered a problem while trying to access this page. This could be due to a temporary issue with our servers or a problem with your internet connection. Please try refreshing the page or check your internet connection. If the issue persists, please contact our support team for assistance." : "We're sorry, but we encountered a problem while trying to access the sign-in page. This could be due to a temporary issue with our servers or a problem with your internet connection. Please try refreshing the page or check your internet connection. If the issue persists, please contact our support team for assistance."
                  })) : (0, a.jsx)(ke.Z, {
                    type: "linear",
                    size: "small"
                  })]
                }))
              })
            }))
          },
          hr = n(86010);
        const mr = (0, n(98388).q7)({
          prefix: "tw-"
        });

        function xr(...t) {
          return mr((0, hr.W)(t))
        }
        var fr = function(t, e) {
          var n = {};
          for (var a in t) Object.prototype.hasOwnProperty.call(t, a) && e.indexOf(a) < 0 && (n[a] = t[a]);
          if (null != t && "function" == typeof Object.getOwnPropertySymbols) {
            var r = 0;
            for (a = Object.getOwnPropertySymbols(t); r < a.length; r++) e.indexOf(a[r]) < 0 && Object.prototype.propertyIsEnumerable.call(t, a[r]) && (n[a[r]] = t[a[r]])
          }
          return n
        };

        function vr(t) {
          var {
            className: e,
            children: n,
            orientation: r = "vertical"
          } = t, s = fr(t, ["className", "children", "orientation"]);
          const i = (0, j.useRef)(null),
            o = (0, j.useRef)(null),
            l = (0, j.useCallback)((() => {
              const t = i.current;
              t && (t.classList.add("is-scrolling"), o.current && clearTimeout(o.current), o.current = setTimeout((() => {
                t.classList.remove("is-scrolling")
              }), 1e3))
            }), []);
          return (0, a.jsx)("div", Object.assign({
            "data-slot": "scroll-area",
            className: xr("tw-relative tw-overflow-hidden", e)
          }, s, {
            children: (0, a.jsx)("div", Object.assign({
              ref: i,
              "data-slot": "scroll-area-viewport",
              onScroll: l,
              className: xr("tw-w-full tw-h-full tw-rounded-[inherit]", "vertical" === r && "tw-overflow-y-auto tw-overflow-x-hidden", "horizontal" === r && "tw-overflow-x-auto tw-overflow-y-hidden", "[&::-webkit-scrollbar]:tw-w-2", "[&::-webkit-scrollbar-track]:tw-bg-transparent", "[&::-webkit-scrollbar-thumb]:tw-rounded-full [&::-webkit-scrollbar-thumb]:tw-bg-[rgba(255,255,255,0.15)]", "[&::-webkit-scrollbar-thumb:hover]:tw-bg-[rgba(255,255,255,0.25)]")
            }, {
              children: n
            }))
          }))
        }
        var jr = n(25773),
          Er = n.n(jr),
          yr = n(41352),
          Cr = function(t, e) {
            var n = {};
            for (var a in t) Object.prototype.hasOwnProperty.call(t, a) && e.indexOf(a) < 0 && (n[a] = t[a]);
            if (null != t && "function" == typeof Object.getOwnPropertySymbols) {
              var r = 0;
              for (a = Object.getOwnPropertySymbols(t); r < a.length; r++) e.indexOf(a[r]) < 0 && Object.prototype.propertyIsEnumerable.call(t, a[r]) && (n[a[r]] = t[a[r]])
            }
            return n
          };
        const Or = (0, j.createContext)({});

        function Nr({
          open: t = !1,
          onOpenChange: e,
          children: n
        }) {
          const [r, s] = (0, j.useState)(!1), [i, o] = (0, j.useState)(!1);
          (0, j.useEffect)((() => {
            if (!t) {
              o(!1);
              const t = setTimeout((() => s(!1)), 300);
              return () => clearTimeout(t)
            }
            s(!0), requestAnimationFrame((() => {
              requestAnimationFrame((() => o(!0)))
            }))
          }), [t]);
          const l = (0, j.useCallback)((t => {
            "Escape" === t.key && (null == e || e(!1))
          }), [e]);
          return (0, j.useEffect)((() => {
            if (t) return document.addEventListener("keydown", l), () => document.removeEventListener("keydown", l)
          }), [t, l]), r ? Er().createPortal((0, a.jsx)(Or.Provider, Object.assign({
            value: {
              onOpenChange: e
            }
          }, {
            children: E().Children.map(n, (t => E().isValidElement(t) ? E().cloneElement(t, {
              _visible: i
            }) : t))
          })), document.body) : null
        }

        function Sr(t) {
          var {
            side: e = "right",
            className: n,
            children: r,
            _visible: s = !1
          } = t;
          Cr(t, ["side", "className", "children", "_visible"]);
          const {
            onOpenChange: i
          } = (0, j.useContext)(Or);
          return (0, a.jsxs)("div", Object.assign({
            className: "tw-fixed tw-inset-0 tw-z-[60] tw-flex"
          }, {
            children: [(0, a.jsx)("div", {
              className: xr("tw-fixed tw-inset-0 tw-bg-black/40 tw-transition-opacity tw-duration-300 tw-cursor-pointer", s ? "tw-opacity-100" : "tw-opacity-0"),
              onClick: () => null == i ? void 0 : i(!1)
            }), (0, a.jsxs)("div", Object.assign({
              className: xr("tw-fixed tw-inset-y-0 tw-z-[60] tw-flex tw-flex-col tw-bg-[#00081C] tw-shadow-xl tw-transition-transform tw-duration-300 tw-ease-in-out", "right" === e ? "tw-right-0" : "tw-left-0", "right" === e ? s ? "tw-translate-x-0" : "tw-translate-x-full" : s ? "tw-translate-x-0" : "tw--translate-x-full", n)
            }, {
              children: [(0, a.jsx)("button", Object.assign({
                onClick: () => null == i ? void 0 : i(!1),
                className: "tw-absolute tw-right-4 tw-top-4 tw-z-10 tw-flex tw-w-6 tw-h-6 tw-items-center tw-justify-center tw-rounded-sm tw-text-[rgba(255,255,255,0.35)] tw-transition-colors tw-border-0 tw-bg-transparent tw-cursor-pointer hover:tw-text-[rgba(255,255,255,0.6)]",
                "aria-label": "Close"
              }, {
                children: (0, a.jsx)(yr.Z, {
                  className: "tw-w-4 tw-h-4"
                })
              })), r]
            }))]
          }))
        }

        function kr({
          className: t,
          children: e
        }) {
          return (0, a.jsx)("div", Object.assign({
            className: xr("tw-flex tw-flex-col", t)
          }, {
            children: e
          }))
        }

        function Ir({
          className: t,
          children: e
        }) {
          return (0, a.jsx)("h2", Object.assign({
            className: xr("tw-text-lg tw-font-bold tw-m-0", t)
          }, {
            children: e
          }))
        }

        function Mr({
          className: t,
          children: e
        }) {
          return (0, a.jsx)("p", Object.assign({
            className: xr("tw-text-sm tw-text-[rgba(255,255,255,0.5)] tw-m-0", t)
          }, {
            children: e
          }))
        }
        var Tr = n(69539),
          Rr = n(28761),
          Br = n(58621),
          _r = n(81629),
          Dr = n(47737),
          Lr = n(4844),
          Fr = n(71309),
          Pr = n(98814),
          zr = n(87764),
          Ur = function(t, e, n, a) {
            return new(n || (n = Promise))((function(r, s) {
              function i(t) {
                try {
                  l(a.next(t))
                } catch (t) {
                  s(t)
                }
              }

              function o(t) {
                try {
                  l(a.throw(t))
                } catch (t) {
                  s(t)
                }
              }

              function l(t) {
                var e;
                t.done ? r(t.value) : (e = t.value, e instanceof n ? e : new n((function(t) {
                  t(e)
                }))).then(i, o)
              }
              l((a = a.apply(t, e || [])).next())
            }))
          };
        const Gr = new class {
            constructor() {
              this.metaData = null, this.googleAdsData = null, this.razorpayData = null, this.shiprocketData = null, this.isLoading = !1, this.isLoaded = !1, this.setMetaData = t => {
                this.metaData = t
              }, this.setGoogleAdsData = t => {
                this.googleAdsData = t
              }, this.setRazorpayData = t => {
                this.razorpayData = t
              }, this.setShiprocketData = t => {
                this.shiprocketData = t
              }, this.setIsLoading = t => {
                this.isLoading = t
              }, this.setIsLoaded = t => {
                this.isLoaded = t
              }, this.fetchAll = () => {
                return t = this, e = void 0, a = function*() {
                  if (this.isLoaded || this.isLoading) return;
                  this.setIsLoading(!0);
                  const t = yield Promise.allSettled([Ur(void 0, void 0, void 0, (function*() {
                    const t = yield(0, f.aH)();
                    return (yield ue.get(`stores/${t}/ads/META/tracking-code`)).data
                  })), Ur(void 0, void 0, void 0, (function*() {
                    const t = yield(0, f.aH)();
                    return (yield ue.get(`stores/${t}/ads/GOOGLE/tracking-code`)).data
                  })), Ur(void 0, void 0, void 0, (function*() {
                    const t = yield(0, f.aH)();
                    return (yield ue.get(`stores/${t}/payments/accounts`)).data
                  })), Ur(void 0, void 0, void 0, (function*() {
                    return (yield ue.get("shipping/registrationStatus")).data
                  }))]);
                  "fulfilled" === t[0].status && this.setMetaData(t[0].value), "fulfilled" === t[1].status && this.setGoogleAdsData(t[1].value), "fulfilled" === t[2].status && this.setRazorpayData(t[2].value), "fulfilled" === t[3].status && this.setShiprocketData(t[3].value), this.setIsLoading(!1), this.setIsLoaded(!0)
                }, new((n = void 0) || (n = Promise))((function(r, s) {
                  function i(t) {
                    try {
                      l(a.next(t))
                    } catch (t) {
                      s(t)
                    }
                  }

                  function o(t) {
                    try {
                      l(a.throw(t))
                    } catch (t) {
                      s(t)
                    }
                  }

                  function l(t) {
                    var e;
                    t.done ? r(t.value) : (e = t.value, e instanceof n ? e : new n((function(t) {
                      t(e)
                    }))).then(i, o)
                  }
                  l((a = a.apply(t, e || [])).next())
                }));
                var t, e, n, a
              }, (0, st.rC)(this, {
                metaData: st.LO,
                googleAdsData: st.LO,
                razorpayData: st.LO,
                shiprocketData: st.LO,
                isLoading: st.LO,
                isLoaded: st.LO,
                setMetaData: st.aD,
                setGoogleAdsData: st.aD,
                setRazorpayData: st.aD,
                setShiprocketData: st.aD,
                setIsLoading: st.aD,
                setIsLoaded: st.aD,
                connectors: st.Fl
              })
            }
            get connectors() {
              var t, e, n, a, r;
              const s = [];
              return this.metaData && s.push({
                name: "Meta",
                connected: !0
              }), (null === (t = this.googleAdsData) || void 0 === t ? void 0 : t.accountId) && s.push({
                name: "Google Ads",
                connected: !0
              }), "activated" === (null === (e = this.razorpayData) || void 0 === e ? void 0 : e.activationStatus) && "LINKED" === (null === (n = this.razorpayData) || void 0 === n ? void 0 : n.linkStatus) && s.push({
                name: "Razorpay",
                connected: !0
              }), (null === (a = this.shiprocketData) || void 0 === a ? void 0 : a.isMerchantRegistered) && (null === (r = this.shiprocketData) || void 0 === r ? void 0 : r.isShippingEnabled) && s.push({
                name: "Shiprocket",
                connected: !0
              }), s
            }
          },
          Zr = {
            Marketplace: {
              text: "tw-text-blue-400",
              bg: "tw-bg-[rgba(59,130,246,0.1)]",
              Icon: Tr.Z
            },
            Logistics: {
              text: "tw-text-amber-400",
              bg: "tw-bg-[rgba(245,158,11,0.1)]",
              Icon: Rr.Z
            },
            Payments: {
              text: "tw-text-emerald-400",
              bg: "tw-bg-[rgba(16,185,129,0.1)]",
              Icon: Br.Z
            },
            Analytics: {
              text: "tw-text-purple-400",
              bg: "tw-bg-[rgba(168,85,247,0.1)]",
              Icon: _r.Z
            },
            Communication: {
              text: "tw-text-pink-400",
              bg: "tw-bg-[rgba(236,72,153,0.1)]",
              Icon: Dr.Z
            },
            Storefront: {
              text: "tw-text-cyan-400",
              bg: "tw-bg-[rgba(34,211,238,0.1)]",
              Icon: Lr.Z
            }
          },
          Hr = [{
            name: "Meta",
            category: "Analytics",
            description: "Conversion tracking, retargeting pixel, and campaign management for Facebook and Instagram ads.",
            tags: ["Marketing", "Analytics"]
          }, {
            name: "Google Ads",
            category: "Analytics",
            description: "Search, display, and shopping ad campaigns with conversion tracking and bid management.",
            tags: ["Marketing", "Analytics"]
          }, {
            name: "Google Analytics",
            category: "Analytics",
            description: "Web and app analytics for traffic, conversion funnels, and audience segmentation on D2C.",
            tags: ["Analytics", "Store-Builder"]
          }, {
            name: "Razorpay",
            category: "Payments",
            description: "Payment gateway for UPI, cards, wallets, and net banking with automatic settlement.",
            tags: ["Payments", "Store-Builder"]
          }, {
            name: "Shiprocket",
            category: "Logistics",
            description: "Multi-carrier shipping aggregator for label generation, tracking, and NDR management.",
            tags: ["Shipping", "Orders"]
          }, {
            name: "Amazon Marketplace",
            category: "Marketplace",
            description: "Selling Partner API for order sync, catalog management, and FBA inventory on Amazon IN & US.",
            tags: ["Listings", "Inventory", "Orders"]
          }, {
            name: "Flipkart Marketplace",
            category: "Marketplace",
            description: "Seller API integration for listings, pricing, order management, and returns on Flipkart.",
            tags: ["Listings", "Inventory", "Orders"]
          }, {
            name: "Meesho Marketplace",
            category: "Marketplace",
            description: "Supplier hub connection for catalog sync, order fulfilment, and performance tracking.",
            tags: ["Listings", "Orders"]
          }, {
            name: "Interakt",
            category: "Communication",
            description: "WhatsApp Business API platform for transactional messages, campaigns, and customer support.",
            tags: ["Marketing", "Orders"]
          }],
          Yr = {
            Meta: {
              apiVersion: "Conversions API v18",
              lastSync: "Real-time",
              dataPoints: ["Page views", "Add to cart", "Purchases", "Custom events"]
            },
            "Google Ads": {
              apiVersion: "Google Ads API v16",
              lastSync: "15 minutes ago",
              dataPoints: ["Campaigns", "Conversions", "Keywords", "Ad groups", "Bidding"]
            },
            "Google Analytics": {
              apiVersion: "GA4 Data API v1",
              lastSync: "15 minutes ago",
              dataPoints: ["Sessions", "Users", "Conversions", "Revenue", "Events"]
            },
            Razorpay: {
              apiVersion: "v1",
              lastSync: "Real-time",
              dataPoints: ["Payments", "Refunds", "Settlements", "Disputes", "Subscriptions"]
            },
            Shiprocket: {
              apiVersion: "REST API v1",
              lastSync: "1 minute ago",
              dataPoints: ["Shipments", "Tracking", "NDR", "Returns", "Rate cards"]
            },
            "Amazon Marketplace": {
              apiVersion: "SP-API v2024-11",
              lastSync: "2 minutes ago",
              dataPoints: ["Orders", "Inventory levels", "Catalog updates", "FBA shipments", "Returns"]
            },
            "Flipkart Marketplace": {
              apiVersion: "Seller API v3",
              lastSync: "5 minutes ago",
              dataPoints: ["Listings", "Orders", "Returns", "Pricing", "Performance metrics"]
            },
            "Meesho Marketplace": {
              apiVersion: "Supplier Hub v2",
              lastSync: "Not synced",
              dataPoints: ["Catalog", "Orders", "Payments", "Performance"]
            },
            Interakt: {
              apiVersion: "WhatsApp Cloud API v19",
              lastSync: "Real-time",
              dataPoints: ["Messages", "Templates", "Delivery receipts", "Media"]
            }
          };

        function Wr(t) {
          const e = Zr[t];
          return e ? (0, a.jsx)(e.Icon, {
            className: xr("tw-w-5 tw-h-5", e.text)
          }) : (0, a.jsx)(Fr.Z, {
            className: xr("tw-w-5 tw-h-5 tw-text-[rgba(255,255,255,0.35)]")
          })
        }
        const Kr = (0, v.Pi)((({
          open: t,
          onOpenChange: e
        }) => {
          const [n, r] = (0, j.useState)(null), s = new Set(Gr.connectors.map((t => t.name))), i = Hr.map((t => Object.assign(Object.assign({}, t), {
            active: !!Gr.isLoaded && s.has(t.name)
          }))), o = i.filter((t => t.active)).length, l = i.filter((t => !t.active)).length;
          return (0, a.jsx)(Nr, Object.assign({
            open: t,
            onOpenChange: t => {
              t || r(null), e(t)
            }
          }, {
            children: (0, a.jsx)(Sr, Object.assign({
              side: "right",
              className: "tw-flex tw-w-full sm:tw-w-[480px] tw-max-w-full sm:tw-max-w-[480px] tw-flex-col tw-border-l tw-border-[rgba(255,255,255,0.08)] tw-bg-[#000D26] tw-p-0 tw-text-[#e6eaf2] [&>button]:tw-hidden"
            }, {
              children: n ? (0, a.jsxs)(a.Fragment, {
                children: [(0, a.jsx)(kr, Object.assign({
                  className: "tw-shrink-0 tw-border-b tw-border-[rgba(255,255,255,0.08)] tw-px-5 tw-pt-6 tw-pb-4"
                }, {
                  children: (0, a.jsxs)("div", Object.assign({
                    className: "tw-flex tw-items-center tw-gap-3"
                  }, {
                    children: [(0, a.jsx)("button", Object.assign({
                      onClick: () => r(null),
                      className: "tw-cursor-pointer tw-rounded-md tw-p-1 tw-text-[rgba(255,255,255,0.35)] tw-transition-colors tw-border-0 tw-bg-transparent hover:tw-bg-[rgba(255,255,255,0.06)] hover:tw-text-[rgba(255,255,255,0.6)]",
                      "aria-label": "Back to connectors"
                    }, {
                      children: (0, a.jsx)(Pr.Z, {
                        className: "tw-w-4 tw-h-4"
                      })
                    })), (0, a.jsxs)("div", Object.assign({
                      className: "tw-flex tw-flex-1 tw-items-center tw-gap-2"
                    }, {
                      children: [Wr(n.category), (0, a.jsxs)("div", {
                        children: [(0, a.jsx)(Ir, Object.assign({
                          className: "tw-text-sm tw-font-semibold tw-text-[#e6eaf2]"
                        }, {
                          children: n.name
                        })), (0, a.jsxs)(Mr, Object.assign({
                          className: "tw-text-xs tw-text-[rgba(255,255,255,0.35)]"
                        }, {
                          children: [n.category, " connector"]
                        }))]
                      })]
                    })), (0, a.jsx)("button", Object.assign({
                      onClick: () => {
                        r(null), e(!1)
                      },
                      className: "tw-flex sm:tw-hidden tw-w-7 tw-h-7 tw-shrink-0 tw-cursor-pointer tw-items-center tw-justify-center tw-rounded-lg tw-text-[rgba(255,255,255,0.5)] tw-transition-colors tw-duration-150 tw-border-0 tw-bg-transparent hover:tw-bg-[rgba(255,255,255,0.06)] hover:tw-text-[rgba(255,255,255,0.8)]",
                      "aria-label": "Close panel"
                    }, {
                      children: (0, a.jsx)(yr.Z, {
                        className: "tw-w-4 tw-h-4"
                      })
                    }))]
                  }))
                })), (0, a.jsx)(vr, Object.assign({
                  className: "tw-flex-1 tw-px-5 tw-py-4 scrollbar-auto-hide"
                }, {
                  children: (0, a.jsxs)("div", Object.assign({
                    className: "tw-flex tw-flex-col tw-gap-5"
                  }, {
                    children: [(0, a.jsxs)("div", Object.assign({
                      className: "tw-flex tw-items-center tw-gap-2"
                    }, {
                      children: [(0, a.jsx)("span", {
                        className: xr("tw-w-2 tw-h-2 tw-rounded-full", n.active ? "tw-bg-emerald-400" : "tw-bg-[rgba(255,255,255,0.2)]")
                      }), (0, a.jsx)("span", Object.assign({
                        className: "tw-text-xs tw-font-medium tw-text-[rgba(255,255,255,0.5)]"
                      }, {
                        children: n.active ? "Active" : "Inactive"
                      }))]
                    })), (0, a.jsxs)("div", {
                      children: [(0, a.jsx)("h4", Object.assign({
                        className: "tw-mb-1 tw-text-[10px] tw-font-medium tw-uppercase tw-tracking-wide tw-text-[rgba(255,255,255,0.35)] tw-m-0"
                      }, {
                        children: "Description"
                      })), (0, a.jsx)("p", Object.assign({
                        className: "tw-text-sm tw-leading-relaxed tw-text-[rgba(255,255,255,0.6)] tw-m-0"
                      }, {
                        children: n.description
                      }))]
                    }), Yr[n.name] && (0, a.jsxs)(a.Fragment, {
                      children: [(0, a.jsxs)("div", {
                        children: [(0, a.jsx)("h4", Object.assign({
                          className: "tw-mb-1 tw-text-[10px] tw-font-medium tw-uppercase tw-tracking-wide tw-text-[rgba(255,255,255,0.35)] tw-m-0"
                        }, {
                          children: "API Version"
                        })), (0, a.jsx)("p", Object.assign({
                          className: "tw-text-sm tw-font-medium tw-text-[#e6eaf2] tw-m-0"
                        }, {
                          children: Yr[n.name].apiVersion
                        }))]
                      }), (0, a.jsxs)("div", {
                        children: [(0, a.jsx)("h4", Object.assign({
                          className: "tw-mb-1 tw-text-[10px] tw-font-medium tw-uppercase tw-tracking-wide tw-text-[rgba(255,255,255,0.35)] tw-m-0"
                        }, {
                          children: "Last Sync"
                        })), (0, a.jsx)("p", Object.assign({
                          className: "tw-text-sm tw-font-medium tw-text-[#e6eaf2] tw-m-0"
                        }, {
                          children: Yr[n.name].lastSync
                        }))]
                      }), (0, a.jsxs)("div", {
                        children: [(0, a.jsx)("h4", Object.assign({
                          className: "tw-mb-2 tw-text-[10px] tw-font-medium tw-uppercase tw-tracking-wide tw-text-[rgba(255,255,255,0.35)] tw-m-0"
                        }, {
                          children: "Data Points"
                        })), (0, a.jsx)("div", Object.assign({
                          className: "tw-flex tw-flex-wrap tw-gap-1.5"
                        }, {
                          children: Yr[n.name].dataPoints.map((t => (0, a.jsx)("span", Object.assign({
                            className: "tw-rounded tw-border tw-border-[rgba(255,255,255,0.08)] tw-bg-[rgba(255,255,255,0.04)] tw-px-2 tw-py-0.5 tw-text-xs tw-font-medium tw-text-[rgba(255,255,255,0.5)]"
                          }, {
                            children: t
                          }), t)))
                        }))]
                      })]
                    }), (0, a.jsxs)("div", {
                      children: [(0, a.jsx)("h4", Object.assign({
                        className: "tw-mb-2 tw-text-[10px] tw-font-medium tw-uppercase tw-tracking-wide tw-text-[rgba(255,255,255,0.35)] tw-m-0"
                      }, {
                        children: "Tags"
                      })), (0, a.jsx)("div", Object.assign({
                        className: "tw-flex tw-flex-wrap tw-gap-1.5"
                      }, {
                        children: n.tags.map((t => (0, a.jsx)("span", Object.assign({
                          className: "tw-rounded tw-border tw-border-[rgba(255,255,255,0.08)] tw-bg-[rgba(255,255,255,0.04)] tw-px-2 tw-py-0.5 tw-text-xs tw-font-medium tw-text-[rgba(255,255,255,0.5)]"
                        }, {
                          children: t
                        }), t)))
                      }))]
                    })]
                  }))
                }))]
              }) : (0, a.jsxs)(a.Fragment, {
                children: [(0, a.jsx)(kr, Object.assign({
                  className: "tw-shrink-0 tw-border-b tw-border-[rgba(255,255,255,0.08)] tw-px-5 tw-pt-6 tw-pb-4"
                }, {
                  children: (0, a.jsxs)("div", Object.assign({
                    className: "tw-flex tw-items-center tw-justify-between"
                  }, {
                    children: [(0, a.jsxs)("div", Object.assign({
                      className: "tw-flex tw-items-center tw-gap-2"
                    }, {
                      children: [(0, a.jsx)("button", Object.assign({
                        onClick: () => e(!1),
                        className: "tw-flex sm:tw-hidden tw-w-7 tw-h-7 tw-cursor-pointer tw-items-center tw-justify-center tw-rounded-lg tw-text-[rgba(255,255,255,0.5)] tw-transition-colors tw-duration-150 tw-border-0 tw-bg-transparent hover:tw-bg-[rgba(255,255,255,0.06)] hover:tw-text-[rgba(255,255,255,0.8)]",
                        "aria-label": "Close panel"
                      }, {
                        children: (0, a.jsx)(yr.Z, {
                          className: "tw-w-4 tw-h-4"
                        })
                      })), (0, a.jsx)(Fr.Z, {
                        className: "tw-w-4 tw-h-4 tw-text-emerald-400"
                      }), (0, a.jsxs)("div", {
                        children: [(0, a.jsx)(Ir, Object.assign({
                          className: "tw-text-sm tw-font-semibold tw-text-[#e6eaf2]"
                        }, {
                          children: "Manage Connectors"
                        })), (0, a.jsxs)(Mr, Object.assign({
                          className: "tw-text-xs tw-text-[rgba(255,255,255,0.35)]"
                        }, {
                          children: [o, " active, ", l, " inactive"]
                        }))]
                      })]
                    })), (0, a.jsxs)("div", Object.assign({
                      className: "tw-flex tw-items-center tw-gap-2"
                    }, {
                      children: [(0, a.jsxs)("span", Object.assign({
                        className: "tw-flex tw-items-center tw-gap-1 tw-rounded-full tw-bg-[rgba(16,185,129,0.1)] tw-px-2.5 tw-py-0.5 tw-text-[10px] tw-font-semibold tw-text-emerald-400"
                      }, {
                        children: [(0, a.jsx)("span", {
                          className: "tw-w-1.5 tw-h-1.5 tw-rounded-full tw-bg-emerald-400"
                        }), o]
                      })), (0, a.jsxs)("span", Object.assign({
                        className: "tw-flex tw-items-center tw-gap-1 tw-rounded-full tw-bg-[rgba(255,255,255,0.06)] tw-px-2.5 tw-py-0.5 tw-text-[10px] tw-font-semibold tw-text-[rgba(255,255,255,0.35)]"
                      }, {
                        children: [(0, a.jsx)("span", {
                          className: "tw-w-1.5 tw-h-1.5 tw-rounded-full tw-bg-[rgba(255,255,255,0.2)]"
                        }), l]
                      }))]
                    }))]
                  }))
                })), (0, a.jsx)(vr, Object.assign({
                  className: "tw-flex-1 tw-px-3 tw-py-2 scrollbar-auto-hide"
                }, {
                  children: (0, a.jsxs)("div", Object.assign({
                    className: "tw-flex tw-flex-col tw-gap-1"
                  }, {
                    children: [i.map((t => {
                      var e;
                      const n = null !== (e = Zr[t.category]) && void 0 !== e ? e : {
                        text: "tw-text-[rgba(255,255,255,0.5)]",
                        bg: "tw-bg-[rgba(255,255,255,0.06)]",
                        Icon: Fr.Z
                      };
                      return (0, a.jsxs)("div", Object.assign({
                        onClick: () => r(t),
                        className: "tw-group tw-relative tw-flex tw-cursor-pointer tw-items-start tw-gap-3 tw-rounded-lg tw-border tw-border-transparent tw-px-3 tw-py-3 tw-transition-colors tw-duration-150 hover:tw-border-[rgba(255,255,255,0.06)] hover:tw-bg-[rgba(255,255,255,0.02)]"
                      }, {
                        children: [(0, a.jsx)("div", Object.assign({
                          className: xr("tw-mt-0.5 tw-flex tw-w-8 tw-h-8 tw-shrink-0 tw-items-center tw-justify-center tw-rounded-lg", n.bg)
                        }, {
                          children: Wr(t.category)
                        })), (0, a.jsxs)("div", Object.assign({
                          className: "tw-min-w-0 tw-flex-1"
                        }, {
                          children: [(0, a.jsxs)("div", Object.assign({
                            className: "tw-flex tw-items-center tw-gap-2"
                          }, {
                            children: [(0, a.jsx)("p", Object.assign({
                              className: "tw-text-sm tw-font-semibold tw-text-[#e6eaf2] tw-m-0"
                            }, {
                              children: t.name
                            })), (0, a.jsx)("span", Object.assign({
                              className: xr("tw-rounded tw-px-1.5 tw-py-0.5 tw-text-[10px] tw-font-semibold", n.bg, n.text)
                            }, {
                              children: t.category
                            })), t.active && (0, a.jsx)("span", {
                              className: "tw-w-1.5 tw-h-1.5 tw-rounded-full tw-bg-emerald-400"
                            })]
                          })), (0, a.jsx)("p", Object.assign({
                            className: "tw-mt-0.5 tw-text-xs tw-leading-relaxed tw-text-[rgba(255,255,255,0.35)] tw-m-0"
                          }, {
                            children: t.description
                          })), (0, a.jsx)("div", Object.assign({
                            className: "tw-mt-1.5 tw-flex tw-flex-wrap tw-gap-1"
                          }, {
                            children: t.tags.map((t => (0, a.jsx)("span", Object.assign({
                              className: "tw-rounded tw-border tw-border-[rgba(255,255,255,0.08)] tw-bg-[rgba(255,255,255,0.04)] tw-px-1.5 tw-py-0.5 tw-text-[10px] tw-font-medium tw-text-[rgba(255,255,255,0.35)]"
                            }, {
                              children: t
                            }), t)))
                          }))]
                        }))]
                      }), t.name)
                    })), 0 === i.length && (0, a.jsxs)("div", Object.assign({
                      className: "tw-flex tw-flex-col tw-items-center tw-justify-center tw-py-16 tw-text-center"
                    }, {
                      children: [(0, a.jsx)(zr.Z, {
                        className: "tw-mb-2 tw-w-8 tw-h-8 tw-text-[rgba(255,255,255,0.2)]"
                      }), (0, a.jsx)("p", Object.assign({
                        className: "tw-text-sm tw-font-medium tw-text-[rgba(255,255,255,0.35)] tw-m-0"
                      }, {
                        children: "No connectors found"
                      }))]
                    }))]
                  }))
                }))]
              })
            }))
          }))
        }));
        var Vr = n(27057),
          $r = n(28463),
          qr = n(98082),
          Qr = n(55392),
          Xr = n(8652),
          Jr = n(41197),
          ts = n(71408),
          es = n(8368),
          ns = n(8971);
        const as = [{
            name: "Listings",
            icon: Vr.Z,
            href: "/listings",
            label: "Listings",
            color: "#7aa2ff",
            colorMuted: "rgba(122,162,255,0.7)"
          }, {
            name: "Inventory",
            icon: $r.Z,
            href: "/inventory",
            label: "Inventory",
            color: "#a78bfa",
            colorMuted: "rgba(167,139,250,0.7)"
          }, {
            name: "Marketing",
            icon: qr.Z,
            href: "/marketing",
            label: "Marketing",
            color: "#f472b6",
            colorMuted: "rgba(244,114,182,0.7)"
          }, {
            name: "Shipping",
            icon: Rr.Z,
            href: "/shipping",
            label: "Shipping",
            color: "#5eead4",
            colorMuted: "rgba(94,234,212,0.7)"
          }, {
            name: "Store Builder",
            icon: Qr.Z,
            badge: "D2C",
            href: "/store-builder",
            label: "Store Builder",
            color: "#6ee7b7",
            colorMuted: "rgba(110,231,183,0.7)"
          }, {
            name: "Payments",
            icon: Br.Z,
            href: "/payments",
            label: "Payments",
            color: "#facc15",
            colorMuted: "rgba(250,204,21,0.7)",
            disabled: !0
          }, {
            name: "Analytics",
            icon: _r.Z,
            href: "/analytics-dashboard",
            label: "Analytics",
            color: "#fb923c",
            colorMuted: "rgba(251,146,60,0.7)"
          }],
          rs = (0, v.Pi)((({
            collapsed: t = !1,
            onToggle: e,
            onNavigate: n,
            onPanelClose: r,
            onNavClick: s,
            channels: i = [],
            channelsLoading: o = !1
          }) => {
            const l = (0, N.useLocation)(),
              A = (0, N.useNavigate)(),
              c = l.pathname,
              [d, w] = (0, j.useState)(!1),
              [g, u] = (0, j.useState)(!1),
              p = () => null == e ? void 0 : e(),
              b = (t, e) => {
                null == n || n(e), A(t)
              },
              h = t => "/home" === t ? "/home" === c || "/" === c : c.startsWith(t);
            return (0, j.useEffect)((() => {
              const e = window.innerWidth <= 720;
              Fe.setIsCollapsed(!!e || t)
            }), [t]), (0, a.jsxs)("aside", Object.assign({
              className: xr("tw-relative tw-flex tw-h-full tw-shrink-0 tw-flex-col tw-overflow-hidden tw-border-r tw-border-[rgba(255,255,255,0.06)]", t ? "tw-w-14" : "tw-w-[200px]")
            }, {
              children: [(0, a.jsx)("div", {
                className: "tw-absolute tw-inset-0 tw-bg-[#000614]"
              }), (0, a.jsxs)("div", Object.assign({
                className: xr("tw-absolute tw-inset-0 tw-z-20 tw-flex tw-flex-col tw-items-center tw-py-2", t ? "tw-pointer-events-auto" : "tw-pointer-events-none tw-hidden")
              }, {
                children: [(0, a.jsx)("button", Object.assign({
                  onClick: p,
                  className: "tw-flex tw-w-8 tw-h-8 tw-cursor-pointer tw-items-center tw-justify-center tw-rounded-lg tw-text-[rgba(255,255,255,0.5)] tw-transition-colors tw-duration-150 tw-border-0 tw-bg-transparent hover:tw-bg-[rgba(255,255,255,0.06)] hover:tw-text-[rgba(255,255,255,0.8)]",
                  "aria-label": "Expand sidebar"
                }, {
                  children: (0, a.jsx)(Xr.Z, {
                    className: "tw-w-4 tw-h-4"
                  })
                })), (0, a.jsx)("button", Object.assign({
                  onClick: () => b("/home", "Home"),
                  className: xr("tw-mt-4 tw-flex tw-w-8 tw-h-8 tw-items-center tw-justify-center tw-rounded-lg tw-transition-colors tw-border-0 tw-cursor-pointer", h("/home") ? "tw-bg-[#00CCBD] tw-text-white" : "tw-text-[rgba(255,255,255,0.35)] tw-bg-transparent hover:tw-bg-[rgba(255,255,255,0.06)] hover:tw-text-[rgba(255,255,255,0.5)]"),
                  title: "AZai"
                }, {
                  children: (0, a.jsx)(Jr.Z, {
                    className: "tw-w-4 tw-h-4"
                  })
                })), (0, a.jsx)("div", Object.assign({
                  className: "tw-mt-3 tw-flex tw-flex-col tw-items-center tw-gap-1"
                }, {
                  children: as.map((t => {
                    const e = h(t.href);
                    return (0, a.jsx)("button", Object.assign({
                      onClick: () => !t.disabled && b(t.href, t.label),
                      disabled: t.disabled,
                      className: xr("tw-flex tw-w-8 tw-h-8 tw-items-center tw-justify-center tw-rounded-lg tw-transition-all tw-duration-150 tw-border-0", t.disabled ? "tw-opacity-40 tw-cursor-not-allowed" : "tw-cursor-pointer", e ? "tw-bg-[rgba(255,255,255,0.08)]" : t.disabled ? "tw-bg-transparent" : "tw-bg-transparent hover:tw-bg-[rgba(255,255,255,0.06)]"),
                      style: {
                        boxShadow: e ? `0 0 8px ${t.color}40` : void 0
                      },
                      title: t.name
                    }, {
                      children: (0, a.jsx)(t.icon, {
                        className: "tw-w-4 tw-h-4",
                        style: {
                          color: e ? t.color : t.colorMuted
                        }
                      })
                    }), t.name)
                  }))
                })), (0, a.jsx)("div", Object.assign({
                  className: "tw-mt-4 tw-flex tw-flex-col tw-items-center tw-gap-1 tw-border-t tw-border-[rgba(255,255,255,0.08)] tw-pt-3"
                }, {
                  children: (0, a.jsx)("button", Object.assign({
                    className: "tw-flex tw-w-8 tw-h-8 tw-items-center tw-justify-center tw-rounded-lg tw-text-[rgba(255,255,255,0.35)] tw-transition-colors tw-border-0 tw-bg-transparent tw-cursor-pointer hover:tw-bg-[rgba(255,255,255,0.06)] hover:tw-text-[rgba(255,255,255,0.5)]",
                    title: "Channels"
                  }, {
                    children: (0, a.jsx)(Lr.Z, {
                      className: "tw-w-4 tw-h-4"
                    })
                  }))
                })), (0, a.jsx)("div", {
                  className: "tw-flex-1"
                }), (0, a.jsx)("button", Object.assign({
                  onClick: () => w(!0),
                  className: "tw-mb-1 tw-flex tw-w-8 tw-h-8 tw-items-center tw-justify-center tw-rounded-lg tw-text-[rgba(255,255,255,0.35)] tw-transition-colors tw-border-0 tw-bg-transparent tw-cursor-pointer hover:tw-bg-[rgba(255,255,255,0.06)] hover:tw-text-[rgba(255,255,255,0.5)]",
                  title: "Connectors"
                }, {
                  children: (0, a.jsx)(Fr.Z, {
                    className: "tw-w-4 tw-h-4"
                  })
                })), (0, a.jsx)("button", Object.assign({
                  onClick: () => b("/settings", "Settings"),
                  className: "tw-mb-2 tw-flex tw-w-8 tw-h-8 tw-items-center tw-justify-center tw-rounded-lg tw-text-[rgba(255,255,255,0.35)] tw-transition-colors tw-border-0 tw-bg-transparent tw-cursor-pointer hover:tw-bg-[rgba(255,255,255,0.06)] hover:tw-text-[rgba(255,255,255,0.5)]",
                  title: "Settings"
                }, {
                  children: (0, a.jsx)(ts.Z, {
                    className: "tw-w-4 tw-h-4"
                  })
                }))]
              })), (0, a.jsxs)("div", Object.assign({
                className: xr("tw-flex tw-min-h-0 tw-w-[200px] tw-flex-1 tw-flex-col tw-text-[rgba(255,255,255,0.5)] tw-relative tw-z-10 tw-whitespace-nowrap", t ? "tw-pointer-events-none tw-hidden" : "tw-pointer-events-auto")
              }, {
                children: [(0, a.jsx)("div", Object.assign({
                  className: "tw-flex tw-items-center tw-gap-2.5 tw-px-4 tw-pt-3 tw-pb-3"
                }, {
                  children: (0, a.jsxs)("div", Object.assign({
                    className: "tw-min-w-0 tw-flex-1"
                  }, {
                    children: [(0, a.jsx)("p", Object.assign({
                      className: "tw-truncate tw-text-sm tw-font-semibold tw-leading-tight tw-text-[#e6eaf2] tw-m-0"
                    }, {
                      children: "Smart Commerce"
                    })), (0, a.jsxs)("div", Object.assign({
                      className: "tw-flex tw-items-center tw-justify-between"
                    }, {
                      children: [(0, a.jsx)("p", Object.assign({
                        className: "tw-text-[11px] tw-leading-tight tw-text-[rgba(255,255,255,0.35)] tw-m-0"
                      }, {
                        children: "Agentic commerceOS"
                      })), (0, a.jsx)("button", Object.assign({
                        onClick: p,
                        className: "tw-flex tw-w-5 tw-h-5 tw-cursor-pointer tw-items-center tw-justify-center tw-rounded tw-text-[rgba(255,255,255,0.35)] tw-transition-colors tw-border-0 tw-bg-transparent hover:tw-bg-[rgba(255,255,255,0.06)] hover:tw-text-[rgba(255,255,255,0.5)]",
                        "aria-label": "Collapse sidebar"
                      }, {
                        children: (0, a.jsx)(es.Z, {
                          className: "tw-w-3 tw-h-3"
                        })
                      }))]
                    }))]
                  }))
                })), (0, a.jsx)("div", Object.assign({
                  className: "tw-px-3 tw-pb-4"
                }, {
                  children: (0, a.jsxs)("button", Object.assign({
                    onClick: () => b("/home", "Home"),
                    className: xr("tw-group tw-relative tw-flex tw-w-full tw-items-center tw-justify-between tw-rounded-lg tw-px-2.5 tw-py-2 tw-text-sm tw-font-semibold tw-transition-colors tw-border-0 tw-cursor-pointer", h("/home") ? "tw-bg-[rgba(0,204,189,0.1)] tw-text-[#00CCBD]" : "tw-text-[rgba(255,255,255,0.5)] tw-bg-transparent hover:tw-bg-[rgba(255,255,255,0.06)] hover:tw-text-[#e6eaf2]")
                  }, {
                    children: [h("/home") && (0, a.jsx)("span", {
                      className: "tw-absolute tw-left-0 tw-top-1/2 tw-h-5 tw-w-[3px] tw--translate-y-1/2 tw-rounded-r-full tw-bg-[#00CCBD]"
                    }), (0, a.jsxs)("span", Object.assign({
                      className: "tw-flex tw-items-center tw-gap-2.5"
                    }, {
                      children: [(0, a.jsx)(Jr.Z, {
                        className: xr("tw-w-4 tw-h-4 tw-shrink-0", h("/home") ? "tw-text-[#00CCBD]" : "tw-text-[rgba(255,255,255,0.35)]")
                      }), "AZai"]
                    }))]
                  }))
                })), (0, a.jsxs)(vr, Object.assign({
                  className: "tw-flex-1"
                }, {
                  children: [(0, a.jsxs)("div", Object.assign({
                    className: "tw-px-3"
                  }, {
                    children: [(0, a.jsx)("p", Object.assign({
                      className: "tw-mb-2 tw-px-1 tw-text-[10px] tw-font-semibold tw-uppercase tw-tracking-wider tw-text-[rgba(255,255,255,0.35)] tw-m-0"
                    }, {
                      children: "Commerce Agents"
                    })), (0, a.jsx)("nav", Object.assign({
                      className: "tw-flex tw-flex-col tw-gap-0.5"
                    }, {
                      children: as.map((t => {
                        const e = h(t.href);
                        return (0, a.jsxs)("button", Object.assign({
                          onClick: () => !t.disabled && b(t.href, t.label),
                          disabled: t.disabled,
                          className: xr("tw-group tw-relative tw-flex tw-items-center tw-justify-between tw-rounded-md tw-px-2.5 tw-py-1.5 tw-text-sm tw-transition-all tw-duration-150 tw-border-0 tw-w-full tw-text-left", t.disabled ? "tw-opacity-40 tw-cursor-not-allowed" : "tw-cursor-pointer", e ? "tw-bg-[rgba(255,255,255,0.06)]" : t.disabled ? "tw-bg-transparent tw-text-[rgba(255,255,255,0.5)]" : "tw-bg-transparent hover:tw-bg-[rgba(255,255,255,0.06)] hover:tw-text-[#e6eaf2] tw-text-[rgba(255,255,255,0.5)]"),
                          style: {
                            boxShadow: e ? `0 0 8px ${t.color}40` : void 0
                          }
                        }, {
                          children: [e && (0, a.jsx)("span", {
                            className: "tw-absolute tw-left-0 tw-top-1/2 tw-h-5 tw-w-[3px] tw--translate-y-1/2 tw-rounded-r-full",
                            style: {
                              backgroundColor: t.color
                            }
                          }), (0, a.jsxs)("span", Object.assign({
                            className: "tw-flex tw-items-center tw-gap-2.5"
                          }, {
                            children: [(0, a.jsx)(t.icon, {
                              className: "tw-w-4 tw-h-4 tw-shrink-0 tw-transition-colors tw-duration-150",
                              style: {
                                color: e ? t.color : t.colorMuted
                              }
                            }), (0, a.jsxs)("span", Object.assign({
                              className: "tw-flex tw-flex-col tw-items-start"
                            }, {
                              children: [(0, a.jsx)("span", Object.assign({
                                className: "tw-text-[13px] tw-leading-tight tw-whitespace-nowrap tw-text-[#dadee4]"
                              }, {
                                children: t.name
                              })), (0, a.jsx)("span", Object.assign({
                                className: xr("tw-text-[10px]", e ? "tw-text-[rgba(255,255,255,0.5)]" : "tw-text-[rgba(255,255,255,0.35)]"),
                                style: {
                                  color: e ? t.colorMuted : void 0
                                }
                              }, {
                                children: "Agent"
                              }))]
                            }))]
                          })), t.badge && (0, a.jsx)("span", Object.assign({
                            className: "tw-mt-0.5 tw-rounded tw-px-1.5 tw-py-0.5 tw-text-[10px] tw-font-medium",
                            style: {
                              backgroundColor: e ? `${t.color}20` : `${t.color}15`,
                              color: e ? t.color : t.colorMuted
                            }
                          }, {
                            children: t.badge
                          }))]
                        }), t.name)
                      }))
                    }))]
                  })), (0, a.jsxs)("div", Object.assign({
                    className: "tw-mt-4 tw-border-t tw-border-[rgba(255,255,255,0.08)] tw-px-3 tw-pt-3"
                  }, {
                    children: [(0, a.jsx)("p", Object.assign({
                      className: "tw-mb-1.5 tw-px-1 tw-text-[10px] tw-font-semibold tw-uppercase tw-tracking-wider tw-text-[rgba(255,255,255,0.35)] tw-m-0"
                    }, {
                      children: "Channels"
                    })), (0, a.jsx)("nav", Object.assign({
                      className: "tw-flex tw-flex-col"
                    }, {
                      children: o ? (0, a.jsx)(a.Fragment, {
                        children: [1, 2, 3].map((t => (0, a.jsxs)("div", Object.assign({
                          className: "tw-flex tw-items-center tw-gap-2.5 tw-px-2.5 tw-py-1"
                        }, {
                          children: [(0, a.jsx)("span", {
                            className: "tw-w-1.5 tw-h-1.5 tw-shrink-0 tw-rounded-full tw-bg-[rgba(255,255,255,0.08)] tw-animate-pulse"
                          }), (0, a.jsx)("span", {
                            className: "tw-h-3.5 tw-rounded tw-bg-[rgba(255,255,255,0.08)] tw-animate-pulse",
                            style: {
                              width: 40 + 20 * t + "px"
                            }
                          })]
                        }), t)))
                      }) : (0, a.jsxs)(a.Fragment, {
                        children: [i.some((t => "D2C" === t.name)) && (0, a.jsxs)("button", Object.assign({
                          className: "tw-group tw-flex tw-items-center tw-gap-2.5 tw-rounded-md tw-px-2.5 tw-py-1 tw-text-sm tw-text-[rgba(255,255,255,0.5)] tw-transition-colors tw-border-0 tw-bg-transparent tw-cursor-pointer hover:tw-bg-[rgba(255,255,255,0.06)] hover:tw-text-[#e6eaf2]"
                        }, {
                          children: [(0, a.jsx)("span", {
                            className: "tw-w-1.5 tw-h-1.5 tw-shrink-0 tw-rounded-full tw-bg-blue-400"
                          }), (0, a.jsx)("span", Object.assign({
                            className: "tw-text-[13px]"
                          }, {
                            children: "D2C"
                          }))]
                        })), (() => {
                          const t = i.filter((t => "D2C" !== t.name));
                          return 0 === t.length ? null : (0, a.jsxs)("div", {
                            children: [(0, a.jsxs)("button", Object.assign({
                              onClick: () => u(!g),
                              className: "tw-group tw-flex tw-w-full tw-items-center tw-justify-between tw-rounded-md tw-px-2.5 tw-py-1 tw-text-sm tw-text-[rgba(255,255,255,0.5)] tw-transition-colors tw-border-0 tw-bg-transparent tw-cursor-pointer hover:tw-bg-[rgba(255,255,255,0.06)] hover:tw-text-[#e6eaf2]"
                            }, {
                              children: [(0, a.jsxs)("span", Object.assign({
                                className: "tw-flex tw-items-center tw-gap-2.5"
                              }, {
                                children: [(0, a.jsx)("span", {
                                  className: "tw-w-1.5 tw-h-1.5 tw-shrink-0 tw-rounded-full tw-bg-[#e07a2f]"
                                }), (0, a.jsx)("span", Object.assign({
                                  className: "tw-text-[13px]"
                                }, {
                                  children: "Marketplaces"
                                }))]
                              })), (0, a.jsx)(ns.Z, {
                                className: xr("tw-w-3.5 tw-h-3.5 tw-text-[rgba(255,255,255,0.35)] tw-transition-transform tw-duration-200", g && "tw-rotate-180")
                              })]
                            })), (0, a.jsx)("div", Object.assign({
                              className: xr("tw-overflow-hidden tw-transition-all tw-duration-200", g ? "tw-max-h-60 tw-opacity-100" : "tw-max-h-0 tw-opacity-0")
                            }, {
                              children: (0, a.jsx)("div", Object.assign({
                                className: "tw-flex tw-flex-col tw-py-0.5 tw-pl-7"
                              }, {
                                children: t.map((t => (0, a.jsx)("button", Object.assign({
                                  className: "tw-rounded-md tw-px-2.5 tw-py-1 tw-text-left tw-text-[12px] tw-text-[rgba(255,255,255,0.35)] tw-transition-colors tw-border-0 tw-bg-transparent tw-cursor-pointer hover:tw-bg-[rgba(255,255,255,0.06)] hover:tw-text-[rgba(255,255,255,0.5)]"
                                }, {
                                  children: t.name
                                }), t.name)))
                              }))
                            }))]
                          })
                        })()]
                      })
                    }))]
                  }))]
                })), (0, a.jsxs)("div", Object.assign({
                  className: "tw-shrink-0 tw-border-t tw-border-[rgba(255,255,255,0.08)] tw-px-3 tw-pt-2 tw-pb-3"
                }, {
                  children: [(0, a.jsxs)("div", Object.assign({
                    className: "tw-flex tw-items-center tw-justify-between tw-px-1"
                  }, {
                    children: [(0, a.jsx)("p", Object.assign({
                      className: "tw-text-[10px] tw-font-semibold tw-uppercase tw-tracking-wider tw-text-[rgba(255,255,255,0.35)] tw-m-0"
                    }, {
                      children: "Connectors"
                    })), (0, a.jsx)("button", Object.assign({
                      onClick: () => w(!0),
                      className: "tw-cursor-pointer tw-rounded tw-px-1.5 tw-py-0.5 tw-text-[11px] tw-font-medium tw-text-[#00CCBD] tw-transition-all tw-duration-150 tw-border-0 tw-bg-transparent hover:tw-bg-[rgba(0,204,189,0.1)] hover:tw-text-[#00E5D4] active:tw-scale-95"
                    }, {
                      children: "Manage"
                    }))]
                  })), (0, a.jsx)("div", Object.assign({
                    className: "tw-mt-1.5 tw-flex tw-flex-wrap tw-gap-x-3 tw-gap-y-1 tw-px-1"
                  }, {
                    children: ["Meta", "Google Ads", "Razorpay", "Shiprocket"].map((t => {
                      const e = Gr.isLoaded && Gr.connectors.some((e => e.name === t));
                      return (0, a.jsxs)("span", Object.assign({
                        className: "tw-flex tw-items-center tw-gap-1.5 tw-text-[12px] tw-text-[rgba(255,255,255,0.35)]"
                      }, {
                        children: [(0, a.jsx)("span", {
                          className: "tw-w-1.5 tw-h-1.5 tw-rounded-full tw-transition-colors tw-duration-300 " + (e ? "tw-bg-[#00CCBD]" : "tw-bg-[rgba(255,255,255,0.2)]")
                        }), t]
                      }), t)
                    }))
                  }))]
                })), (0, a.jsx)("div", Object.assign({
                  className: "tw-shrink-0 tw-border-t tw-border-[rgba(255,255,255,0.08)] tw-px-3 tw-py-2"
                }, {
                  children: (0, a.jsxs)("button", Object.assign({
                    onClick: () => b("/settings", "Settings"),
                    className: "tw-flex tw-w-full tw-items-center tw-gap-2.5 tw-rounded-md tw-px-2.5 tw-py-2 tw-text-sm tw-text-[rgba(255,255,255,0.5)] tw-transition-colors tw-border-0 tw-bg-transparent tw-cursor-pointer hover:tw-bg-[rgba(255,255,255,0.06)] hover:tw-text-[#e6eaf2]"
                  }, {
                    children: [(0, a.jsx)(ts.Z, {
                      className: "tw-w-4 tw-h-4 tw-text-[rgba(255,255,255,0.35)]"
                    }), (0, a.jsx)("span", Object.assign({
                      className: "tw-text-[13px]"
                    }, {
                      children: "Settings"
                    }))]
                  }))
                }))]
              })), (0, a.jsx)(Kr, {
                open: d,
                onOpenChange: t => {
                  w(t), t || null == r || r()
                }
              })]
            }))
          }));

        function ss({
          className: t = "",
          style: e
        }) {
          return (0, a.jsx)("div", {
            className: `tw-animate-pulse tw-rounded-md tw-bg-[rgba(255,255,255,0.08)] ${t}`,
            style: e
          })
        }

        function is({
          className: t = "",
          style: e
        }) {
          return (0, a.jsx)("div", {
            className: `tw-animate-pulse tw-rounded-md tw-bg-[rgba(255,255,255,0.04)] ${t}`,
            style: e
          })
        }

        function os() {
          return (0, a.jsxs)("aside", Object.assign({
            className: "tw-relative tw-flex tw-h-full tw-w-[200px] tw-shrink-0 tw-flex-col tw-overflow-hidden tw-border-r tw-border-[rgba(255,255,255,0.06)]"
          }, {
            children: [(0, a.jsx)("div", {
              className: "tw-absolute tw-inset-0 tw-bg-[#000614]"
            }), (0, a.jsxs)("div", Object.assign({
              className: "tw-flex tw-items-center tw-gap-2.5 tw-px-4 tw-pt-3 tw-pb-3"
            }, {
              children: [(0, a.jsx)(ss, {
                className: "tw-h-8 tw-w-8 tw-shrink-0 tw-rounded-lg"
              }), (0, a.jsxs)("div", Object.assign({
                className: "tw-min-w-0 tw-flex-1"
              }, {
                children: [(0, a.jsx)(ss, {
                  className: "tw-h-4 tw-w-28"
                }), (0, a.jsx)(is, {
                  className: "tw-mt-1.5 tw-h-3 tw-w-20"
                })]
              }))]
            })), (0, a.jsx)("div", Object.assign({
              className: "tw-px-3 tw-pb-4"
            }, {
              children: (0, a.jsxs)("div", Object.assign({
                className: "tw-flex tw-items-center tw-gap-2.5 tw-rounded-lg tw-px-2.5 tw-py-2"
              }, {
                children: [(0, a.jsx)(ss, {
                  className: "tw-h-4 tw-w-4 tw-shrink-0 tw-rounded"
                }), (0, a.jsx)(ss, {
                  className: "tw-h-4 tw-w-12"
                })]
              }))
            })), (0, a.jsxs)("div", Object.assign({
              className: "tw-px-3"
            }, {
              children: [(0, a.jsx)(is, {
                className: "tw-mb-2 tw-ml-1 tw-h-2.5 tw-w-24"
              }), (0, a.jsx)("nav", Object.assign({
                className: "tw-flex tw-flex-col tw-gap-0.5"
              }, {
                children: Array.from({
                  length: 7
                }).map(((t, e) => (0, a.jsxs)("div", Object.assign({
                  className: "tw-flex tw-items-center tw-justify-between tw-rounded-md tw-px-2.5 tw-py-2"
                }, {
                  children: [(0, a.jsxs)("div", Object.assign({
                    className: "tw-flex tw-items-center tw-gap-2.5"
                  }, {
                    children: [(0, a.jsx)(ss, {
                      className: "tw-h-4 tw-w-4 tw-shrink-0 tw-rounded"
                    }), (0, a.jsxs)("div", Object.assign({
                      className: "tw-flex tw-flex-col tw-gap-1"
                    }, {
                      children: [(0, a.jsx)(ss, {
                        className: "tw-h-3.5",
                        style: {
                          width: 60 + 11 * e % 40 + "px"
                        }
                      }), (0, a.jsx)(is, {
                        className: "tw-h-2.5 tw-w-8"
                      })]
                    }))]
                  })), 5 === e && (0, a.jsx)(is, {
                    className: "tw-h-4 tw-w-8 tw-rounded"
                  })]
                }), e)))
              }))]
            })), (0, a.jsxs)("div", Object.assign({
              className: "tw-mt-5 tw-border-t tw-border-[rgba(255,255,255,0.08)] tw-px-3 tw-pt-3"
            }, {
              children: [(0, a.jsx)(is, {
                className: "tw-mb-1.5 tw-ml-1 tw-h-2.5 tw-w-16"
              }), (0, a.jsx)("nav", Object.assign({
                className: "tw-flex tw-flex-col tw-gap-0.5"
              }, {
                children: Array.from({
                  length: 3
                }).map(((t, e) => (0, a.jsxs)("div", Object.assign({
                  className: "tw-flex tw-items-center tw-gap-2.5 tw-px-2.5 tw-py-1"
                }, {
                  children: [(0, a.jsx)(ss, {
                    className: "tw-h-1.5 tw-w-1.5 tw-shrink-0 tw-rounded-full"
                  }), (0, a.jsx)(ss, {
                    className: "tw-h-3.5",
                    style: {
                      width: 40 + 20 * e + "px"
                    }
                  })]
                }), e)))
              }))]
            })), (0, a.jsx)("div", {
              className: "tw-flex-1"
            }), (0, a.jsxs)("div", Object.assign({
              className: "tw-shrink-0 tw-border-t tw-border-[rgba(255,255,255,0.08)] tw-px-3 tw-pt-3 tw-pb-1"
            }, {
              children: [(0, a.jsxs)("div", Object.assign({
                className: "tw-flex tw-items-center tw-justify-between tw-px-1"
              }, {
                children: [(0, a.jsx)(is, {
                  className: "tw-h-2.5 tw-w-20"
                }), (0, a.jsx)(is, {
                  className: "tw-h-4 tw-w-12 tw-rounded"
                })]
              })), (0, a.jsx)("div", Object.assign({
                className: "tw-mt-1.5 tw-flex tw-flex-col tw-gap-1"
              }, {
                children: Array.from({
                  length: 4
                }).map(((t, e) => (0, a.jsx)(is, {
                  className: "tw-ml-1 tw-h-3",
                  style: {
                    width: 80 + 17 * e % 50 + "px"
                  }
                }, e)))
              }))]
            })), (0, a.jsxs)("div", Object.assign({
              className: "tw-shrink-0 tw-border-t tw-border-[rgba(255,255,255,0.08)] tw-px-3 tw-pt-2 tw-pb-3"
            }, {
              children: [(0, a.jsxs)("div", Object.assign({
                className: "tw-flex tw-items-center tw-justify-between tw-px-1"
              }, {
                children: [(0, a.jsx)(is, {
                  className: "tw-h-2.5 tw-w-20"
                }), (0, a.jsx)(is, {
                  className: "tw-h-4 tw-w-12 tw-rounded"
                })]
              })), (0, a.jsx)("div", Object.assign({
                className: "tw-mt-1.5 tw-flex tw-flex-wrap tw-gap-x-3 tw-gap-y-1 tw-px-1"
              }, {
                children: Array.from({
                  length: 4
                }).map(((t, e) => (0, a.jsxs)("div", Object.assign({
                  className: "tw-flex tw-items-center tw-gap-1.5"
                }, {
                  children: [(0, a.jsx)(ss, {
                    className: "tw-h-1.5 tw-w-1.5 tw-rounded-full"
                  }), (0, a.jsx)(is, {
                    className: "tw-h-3",
                    style: {
                      width: 40 + 8 * e + "px"
                    }
                  })]
                }), e)))
              }))]
            })), (0, a.jsx)("div", Object.assign({
              className: "tw-shrink-0 tw-border-t tw-border-[rgba(255,255,255,0.08)] tw-px-3 tw-py-2"
            }, {
              children: (0, a.jsxs)("div", Object.assign({
                className: "tw-flex tw-items-center tw-gap-2.5 tw-px-2.5 tw-py-2"
              }, {
                children: [(0, a.jsx)(ss, {
                  className: "tw-h-4 tw-w-4 tw-rounded"
                }), (0, a.jsx)(ss, {
                  className: "tw-h-3.5 tw-w-14"
                })]
              }))
            }))]
          }))
        }

        function ls() {
          var t, e, n, a, r;
          return e = this, n = void 0, r = function*() {
            return null === (t = yield ue.get("/support/token")) || void 0 === t ? void 0 : t.data
          }, new((a = void 0) || (a = Promise))((function(t, s) {
            function i(t) {
              try {
                l(r.next(t))
              } catch (t) {
                s(t)
              }
            }

            function o(t) {
              try {
                l(r.throw(t))
              } catch (t) {
                s(t)
              }
            }

            function l(e) {
              var n;
              e.done ? t(e.value) : (n = e.value, n instanceof a ? n : new a((function(t) {
                t(n)
              }))).then(i, o)
            }
            l((r = r.apply(e, n || [])).next())
          }))
        }
        var As = function() {
          return (0, O.useQuery)("chatBotJwtToken", ls, {
            refetchOnWindowFocus: !1,
            enabled: !1
          })
        };
        const cs = {
          modalBorderRadius: "0.75rem"
        };
        var ds = ({
            setShowBusinessDetailsModal: t
          }) => (0, a.jsx)(Ue.default, Object.assign({
            tokens: cs
          }, {
            children: (0, a.jsx)(dn.ZP, Object.assign({
              bodySpacingInset: "500 500 500 500",
              open: !0,
              width: "39rem",
              scrollContainer: "modal"
            }, {
              children: (0, a.jsx)(f.Qq, {
                remoteEntryPointUrl: f.Bj[f.rv.BUSINESS_DETAILS].remoteUrl,
                scope: f.Bj[f.rv.BUSINESS_DETAILS].scope,
                module: f.Bj[f.rv.BUSINESS_DETAILS].module,
                handleCloseModal: () => t(!1)
              })
            }))
          })),
          ws = function(t, e, n, a) {
            return new(n || (n = Promise))((function(r, s) {
              function i(t) {
                try {
                  l(a.next(t))
                } catch (t) {
                  s(t)
                }
              }

              function o(t) {
                try {
                  l(a.throw(t))
                } catch (t) {
                  s(t)
                }
              }

              function l(t) {
                var e;
                t.done ? r(t.value) : (e = t.value, e instanceof n ? e : new n((function(t) {
                  t(e)
                }))).then(i, o)
              }
              l((a = a.apply(t, e || [])).next())
            }))
          };
        const gs = () => ws(void 0, void 0, void 0, (function*() {
            const t = yield(0, f.aH)();
            try {
              return (yield ue.get(`stores/${t}/profiling/questions`)).data
            } catch (t) {
              console.error(t)
            }
          })),
          us = "api-db/resources/v2/dashboard/user/getUser",
          ps = () => ws(void 0, void 0, void 0, (function*() {
            try {
              return (yield Ae.get(us)).data
            } catch (t) {
              console.log("Error fetching seller details", t)
            }
          }));
        var bs = () => {
            const {
              refetch: t
            } = (0, O.useQuery)("BusinessDetails", gs, {
              enabled: !1
            });
            return {
              refetch: t
            }
          },
          hs = n(51160);
        const ms = (0, D.css)({
          color: K.colorForest400
        });
        var xs = ({
            handleClose: t,
            showModal: e,
            heading: n,
            description: r
          }) => (0, a.jsxs)(dn.ZP, Object.assign({
            bodySpacingInset: "none",
            open: e,
            width: "30rem"
          }, {
            children: [(0, a.jsx)(H.default, Object.assign({
              width: "100%",
              alignmentHorizontal: "end"
            }, {
              children: (0, a.jsx)(P.default, Object.assign({
                type: "icon",
                onClick: t
              }, {
                children: (0, a.jsx)(G.default, {
                  tokens: da.Z
                })
              }))
            })), (0, a.jsxs)(z.Z, Object.assign({
              width: "100%",
              spacingInset: "300 600 600 600",
              alignmentHorizontal: "center"
            }, {
              children: [n && (0, a.jsx)(W.default, Object.assign({
                type: "h600"
              }, {
                children: n
              })), (0, a.jsx)(Ue.default, Object.assign({
                palette: "blue",
                mode: "light"
              }, {
                children: (0, a.jsx)(G.default, {
                  tokens: hs.Z,
                  className: ms
                })
              })), (0, a.jsx)(W.default, Object.assign({
                alignment: "center",
                type: "b400"
              }, {
                children: r
              }))]
            }))]
          })),
          fs = n(28239);
        const {
          marketplaceConnectortasks: vs,
          status: js
        } = {
          login: "/api-sp/resources/v3/loginUser",
          logout: "/api-sp/resources/v3/logoutUser",
          shopDetails: "/api-sp/resources/v3/staff/shopSelection",
          posSession: "/api-sp/resources/v3/loginUser?sourceAppType=CONSTELLATION_SELLER_APP",
          sellerDetails: "api-db/resources/v2/dashboard/user/getUser",
          storeDetails: "/stores/",
          marketplaceConnectortasks: "marketplace-connector/tasks/",
          status: "/status"
        };
        var Es = t => (0, O.useQuery)(["TaskStatus", t], (() => (t => {
            return e = void 0, n = void 0, r = function*() {
              const e = `${vs}${t}${js}`;
              return (yield ue.get(e)).data
            }, new((a = void 0) || (a = Promise))((function(t, s) {
              function i(t) {
                try {
                  l(r.next(t))
                } catch (t) {
                  s(t)
                }
              }

              function o(t) {
                try {
                  l(r.throw(t))
                } catch (t) {
                  s(t)
                }
              }

              function l(e) {
                var n;
                e.done ? t(e.value) : (n = e.value, n instanceof a ? n : new a((function(t) {
                  t(n)
                }))).then(i, o)
              }
              l((r = r.apply(e, n || [])).next())
            }));
            var e, n, a, r
          })(t)), {
            enabled: !!t,
            refetchOnWindowFocus: !1,
            refetchInterval: !1
          }),
          ys = n(93674);
        const Cs = {
          messageOnWhatsApp: "Message on WhatsApp",
          chatWithUs: "Chat with Us"
        };
        var Os = (0, v.Pi)((({
          isMobileView: t,
          toggleModal: e,
          isModal: n,
          setIsModal: r,
          openWhatsApp: s,
          openZendesk: i
        }) => {
          const o = (0, D.css)({
              width: "auto",
              height: "auto",
              position: "relative",
              visibility: t && it.isChatBotMessengerActive ? "hidden" : "visible"
            }),
            {
              messageOnWhatsApp: l,
              chatWithUs: A
            } = Cs,
            c = it.isChatBotMessengerActive || n,
            {
              isOpen: d,
              toggle: w
            } = (0, In.b_)();
          return (0, a.jsxs)("div", Object.assign({
            className: o
          }, {
            children: [(0, a.jsx)(Z.Z, Object.assign({
              type: "secondary",
              onClick: () => {
                d && w(), e()
              }
            }, {
              children: (0, a.jsx)("div", Object.assign({
                className: Ft
              }, {
                children: (0, a.jsx)(G.default, {
                  className: (0, D.css)({
                    color: K.colorGray0
                  }),
                  tokens: c ? ys.Z : Wt
                })
              }))
            })), n && (0, a.jsxs)(a.Fragment, {
              children: [(0, a.jsx)("div", {
                className: Pt,
                onClick: () => r(!1)
              }), (0, a.jsxs)("div", Object.assign({
                className: zt
              }, {
                children: [(0, a.jsx)(Z.Z, Object.assign({
                  onClick: s,
                  type: "secondary"
                }, {
                  children: (0, a.jsx)(H.default, Object.assign({
                    className: Gt,
                    backgroundColor: "#FFFFFF",
                    width: 252,
                    height: 58,
                    alignmentHorizontal: "start"
                  }, {
                    children: (0, a.jsxs)(H.default, Object.assign({
                      spacingInset: "300, 450"
                    }, {
                      children: [(0, a.jsx)(G.default, {
                        tokens: Vt
                      }), (0, a.jsx)(W.default, {
                        children: l
                      })]
                    }))
                  }))
                })), (0, a.jsx)(Z.Z, Object.assign({
                  onClick: i,
                  type: "secondary"
                }, {
                  children: (0, a.jsx)(H.default, Object.assign({
                    className: Zt,
                    backgroundColor: "#FFFFFF",
                    width: 252,
                    height: 58,
                    alignmentHorizontal: "start"
                  }, {
                    children: (0, a.jsxs)(H.default, Object.assign({
                      spacingInset: "300, 450"
                    }, {
                      children: [(0, a.jsx)(H.default, Object.assign({
                        backgroundColor: "#00688D",
                        alignmentHorizontal: "center",
                        alignmentVertical: "center",
                        height: 24,
                        width: 24,
                        className: Ht
                      }, {
                        children: (0, a.jsx)(G.default, {
                          tokens: Kt
                        })
                      })), (0, a.jsx)(W.default, {
                        children: A
                      })]
                    }))
                  }))
                }))]
              }))]
            })]
          }))
        }));
        const Ns = 384;
        var Ss = function(t, e, n, a) {
          return new(n || (n = Promise))((function(r, s) {
            function i(t) {
              try {
                l(a.next(t))
              } catch (t) {
                s(t)
              }
            }

            function o(t) {
              try {
                l(a.throw(t))
              } catch (t) {
                s(t)
              }
            }

            function l(t) {
              var e;
              t.done ? r(t.value) : (e = t.value, e instanceof n ? e : new n((function(t) {
                t(e)
              }))).then(i, o)
            }
            l((a = a.apply(t, e || [])).next())
          }))
        };
        const ks = [500, 1e3, 2e3],
          Is = (0, v.Pi)((() => {
            const [t, e] = (0, j.useState)(!1), [n, r] = (0, j.useState)(!1), [s, i] = (0, j.useState)(), o = (0, j.useRef)(null), {
              data: l
            } = As(), {
              isOpen: A
            } = (0, In.b_)(), c = (0, D.css)({
              position: "relative",
              right: ln.isZaiChatBotEnabled && A && !location.pathname.startsWith("/store-onboarding") ? "384px" : "0px",
              transition: "right 0.3s ease-in-out"
            });
            (0, j.useEffect)((() => {
              const t = () => {
                e(window.innerWidth < 720 || window.innerHeight < 720)
              };
              return t(), window.addEventListener("resize", t), () => window.removeEventListener("resize", t)
            }), []);
            const d = (0, j.useCallback)((() => {
              var t;
              const e = null === (t = null === document || void 0 === document ? void 0 : document.getElementsByName("Messaging window")) || void 0 === t ? void 0 : t[0];
              if (e) {
                const t = 0 === e.tabIndex;
                it.setIsChatBotMessengerActive(t)
              }
            }), []);
            (0, j.useEffect)((() => {
              if (!s) return;
              const t = new MutationObserver((t => {
                t.forEach((t => {
                  t.addedNodes.forEach((t => {
                    var e, n;
                    if (t.nodeType === Node.ELEMENT_NODE) {
                      const a = t;
                      ((null === (e = a.matches) || void 0 === e ? void 0 : e.call(a, '[id*="launcher"], [class*="zEWidget"], [class*="launcher"]')) || (null === (n = a.querySelector) || void 0 === n ? void 0 : n.call(a, '[id*="launcher"], [class*="zEWidget"], [class*="launcher"]'))) && setTimeout(w, 100)
                    }
                  }))
                }))
              }));
              return t.observe(document.body, {
                childList: !0,
                subtree: !0
              }), () => t.disconnect()
            }), [s]);
            const w = () => {
              const t = ["#launcher", '[data-testid="launcher"]', ".zEWidget-launcher"];
              let e = null;
              for (const n of t)
                if (e = document.querySelector(n), e) break;
              e && (e.style.display = "none", e.style.visibility = "hidden", e.style.zIndex = "-9999"), document.querySelectorAll('[class*="zEWidget"], [id*="zendesk"]').forEach((t => {
                const e = t;
                "ze-snippet" !== e.id && (e.style.display = "none")
              }))
            };
            (0, j.useEffect)((() => {
              (null == l ? void 0 : l.authToken) && Ss(void 0, void 0, void 0, (function*() {
                const t = yield Ss(void 0, void 0, void 0, (function*() {
                  const t = yield(0, f.aH)(), e = yield(0, f.Ic)(f.FeatureFlags.WHATSAPP_CHAT_BOT_ENABLED_STATUS.flagName, f.FeatureFlags.WHATSAPP_CHAT_BOT_ENABLED_STATUS.defaultValue, t);
                  return it.setIsWhatsAppChatBotFeatureEnabled(e), i(e), e
                })), e = document.createElement("script");
                e.id = "ze-snippet", e.src = de, e.async = !0, document.body.appendChild(e), e.onload = () => {
                  window.zE("messenger", "loginUser", (t => {
                    t(null == l ? void 0 : l.authToken)
                  })), t && (w(), ks.map((t => setTimeout(w, t))))
                }
              }))
            }), [null == l ? void 0 : l.authToken]), (0, j.useEffect)((() => {
              if (!t || !it.isChatBotMessengerActive) return;
              const e = () => {
                var t;
                const e = document.getElementsByName("Messaging window")[0];
                if (null == e ? void 0 : e.contentDocument) {
                  const n = e.contentDocument.querySelector('button[aria-label="Close"]');
                  if (null == n ? void 0 : n.parentElement) {
                    o.current && (null === (t = o.current.element) || void 0 === t || t.removeEventListener("click", o.current.handler));
                    const e = () => it.setIsChatBotMessengerActive(!1);
                    n.parentElement.addEventListener("click", e), o.current = {
                      element: n.parentElement,
                      handler: e
                    }
                  }
                }
              };
              e();
              const n = ks.map((t => setTimeout(e, t)));
              return () => {
                var t;
                n.forEach(clearTimeout), o.current && (null === (t = o.current.element) || void 0 === t || t.removeEventListener("click", o.current.handler), o.current = null)
              }
            }), [t, it.isChatBotMessengerActive]), (0, j.useEffect)((() => {
              const t = setTimeout(d, 50);
              return () => clearTimeout(t)
            }), [d]);
            const g = (0, j.useCallback)((() => {
              var t;
              it.isChatBotMessengerActive ? (null === (t = window.zE) || void 0 === t || t.call(window, "messenger", "close"), r(!1), it.setIsChatBotMessengerActive(!1), setTimeout(d, 100)) : r((t => !t)), setTimeout(d, 50)
            }), [it.isChatBotMessengerActive]);
            return s ? (0, a.jsx)("div", Object.assign({
              className: c
            }, {
              children: (0, a.jsx)(Os, {
                openWhatsApp: () => {
                  "#" !== ge && he(`https://api.whatsapp.com/send?phone=${ge}`, "_blank"), r(!1)
                },
                openZendesk: () => {
                  var t, e;
                  null === (e = (t = window).zE) || void 0 === e || e.call(t, "messenger", "open"), r(!1), it.setIsChatBotMessengerActive(!0), setTimeout(d, 100)
                },
                isMobileView: t,
                isModal: n,
                setIsModal: r,
                toggleModal: g
              })
            })) : (0, a.jsx)(a.Fragment, {})
          }));
        var Ms = n(77291),
          Ts = {};
        Ts.styleTagTransform = p(), Ts.setAttributes = d(), Ts.insert = A().bind(null, "head"), Ts.domAPI = o(), Ts.insertStyleElement = g(), s()(Ms.Z, Ts), Ms.Z && Ms.Z.locals && Ms.Z.locals;
        var Rs = (0, v.Pi)((({
            width: t = 384,
            height: e = 600,
            showHeader: n = !0,
            isExpanded: r,
            onExpandToggle: s,
            welcomeMessageEl: i,
            windowBg: o,
            className: l,
            autoScroll: A,
            smoothScroll: c
          }) => {
            const d = (0, j.useRef)(null),
              {
                mountToRef: w,
                isOpen: g
              } = (0, In.b_)();
            return (0, j.useEffect)((() => {
              d.current && w(d)
            }), [w]), (0, a.jsxs)(a.Fragment, {
              children: [(0, a.jsx)("div", {
                ref: d
              }), (0, a.jsx)(In.zL, {
                width: t,
                height: e,
                onExpandToggle: s,
                isExpanded: r,
                onHistoryClick: () => {
                  console.log("History clicked")
                },
                className: `${ln.isZaiEnabledForOnboarding||ln.isZAIOrchestratorEnabled?(0,D.css)({boxShadow:"none !important",border:"none !important",backgroundColor:"transparent !important"}):""} ${l||""}`,
                showHeader: n,
                welcomeMessageEl: i,
                windowBg: o,
                autoScroll: A,
                smoothScroll: c
              })]
            })
          })),
          Bs = n(78051),
          _s = n(49461);
        const Ds = (0, D.css)({
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            gap: "20px",
            width: "100%"
          }),
          Ls = ((0, D.css)({
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            gap: "6px",
            padding: "8px 16px",
            borderRadius: "24px",
            backgroundColor: "rgba(96, 178, 255, 0.2)"
          }), (0, D.css)({
            width: "14.17px",
            height: "13.33px",
            flexShrink: 0
          }), (0, D.css)({
            fontFamily: "'Amazon Ember', Arial, sans-serif",
            fontWeight: 500,
            fontSize: "16px",
            lineHeight: "24px",
            color: "#086FE8",
            textAlign: "center",
            whiteSpace: "nowrap"
          }), (0, D.css)({
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            gap: "12px"
          })),
          Fs = (0, D.css)({
            display: "flex",
            alignItems: "flex-start",
            justifyContent: "center",
            gap: "9.12px"
          }),
          Ps = ((0, D.css)({
            width: "38px",
            height: "38px",
            flexShrink: 0
          }), (0, D.css)({
            fontFamily: "'Amazon Ember', Arial, sans-serif",
            fontWeight: 700,
            fontSize: "27.36px",
            lineHeight: "36.48px",
            color: "#FFFFFF",
            textAlign: "center",
            whiteSpace: "nowrap"
          })),
          zs = (0, D.css)({
            fontFamily: "'Amazon Ember', Arial, sans-serif",
            fontWeight: 700,
            fontSize: "36px",
            lineHeight: "48px",
            color: "#BECADA",
            textAlign: "center",
            whiteSpace: "nowrap",
            margin: 0
          }),
          Us = (0, D.css)({
            color: "#0678FF"
          });
        var Gs = ({
            size: t = 24
          }) => {
            const e = Math.round(.3875 * t);
            return (0, a.jsxs)("div", Object.assign({
              className: (0, D.css)({
                position: "relative",
                width: t,
                height: t,
                flexShrink: 0
              })
            }, {
              children: [(0, a.jsxs)("svg", Object.assign({
                width: t,
                height: t,
                viewBox: "0 0 160 160",
                fill: "none",
                xmlns: "http://www.w3.org/2000/svg",
                className: (0, D.css)({
                  display: "block"
                })
              }, {
                children: [(0, a.jsx)("circle", {
                  cx: "79.6127",
                  cy: "79.6124",
                  r: "78.4926",
                  transform: "rotate(-90 79.6127 79.6124)",
                  fill: "#0A1D21"
                }), (0, a.jsx)("circle", {
                  cx: "79.6127",
                  cy: "79.6124",
                  r: "78.4926",
                  transform: "rotate(-90 79.6127 79.6124)",
                  fill: "url(#azai_bg_grad)"
                }), (0, a.jsx)("circle", {
                  cx: "79.6127",
                  cy: "79.6124",
                  r: "78.4926",
                  transform: "rotate(-90 79.6127 79.6124)",
                  stroke: "url(#azai_border_grad)",
                  strokeWidth: "2.24015"
                }), (0, a.jsxs)("defs", {
                  children: [(0, a.jsxs)("linearGradient", Object.assign({
                    id: "azai_bg_grad",
                    x1: "137.471",
                    y1: "28.2107",
                    x2: "13.9712",
                    y2: "130.211",
                    gradientUnits: "userSpaceOnUse"
                  }, {
                    children: [(0, a.jsx)("stop", {
                      stopColor: "#00998E"
                    }), (0, a.jsx)("stop", {
                      offset: "0.5",
                      stopColor: "#384A62",
                      stopOpacity: "0.4"
                    }), (0, a.jsx)("stop", {
                      offset: "1",
                      stopColor: "#0678FF"
                    })]
                  })), (0, a.jsxs)("linearGradient", Object.assign({
                    id: "azai_border_grad",
                    x1: "170.993",
                    y1: "-11.9424",
                    x2: "-9.36629",
                    y2: "152.831",
                    gradientUnits: "userSpaceOnUse"
                  }, {
                    children: [(0, a.jsx)("stop", {
                      stopColor: "white"
                    }), (0, a.jsx)("stop", {
                      offset: "0.490385",
                      stopColor: "white",
                      stopOpacity: "0"
                    }), (0, a.jsx)("stop", {
                      offset: "1",
                      stopColor: "white"
                    })]
                  }))]
                })]
              })), (0, a.jsxs)("svg", Object.assign({
                width: e,
                height: e,
                viewBox: "0 0 62 62",
                fill: "none",
                xmlns: "http://www.w3.org/2000/svg",
                className: (0, D.css)({
                  position: "absolute",
                  top: "50%",
                  left: "50%",
                  transform: "translate(-50%, -50%)"
                })
              }, {
                children: [(0, a.jsxs)("g", Object.assign({
                  clipPath: "url(#azai_sparkle_clip)"
                }, {
                  children: [(0, a.jsx)("path", {
                    d: "M28.3486 3.89062C28.5814 3.19817 29.5349 3.21239 29.7559 3.88867L29.7568 3.8916C34.0616 16.9197 44.1502 27.1506 57.0059 31.5176C57.6884 31.7529 57.674 32.7394 57.0078 32.9629L57.0059 32.9639C44.1505 37.3307 34.0618 47.5613 29.7568 60.5889C29.5251 61.2832 28.5716 61.2698 28.3506 60.5928L28.3496 60.5908L28.1436 59.9824C23.729 47.2443 13.7556 37.2627 1.10059 32.9639H1.10156C0.417977 32.7292 0.431171 31.7421 1.09766 31.5186H1.09961C13.9555 27.1517 24.0448 16.9199 28.3496 3.8916L28.3486 3.89062Z",
                    fill: "url(#azai_sparkle_main)",
                    stroke: "white",
                    strokeWidth: "1.18674"
                  }), (0, a.jsx)("path", {
                    d: "M53.0518 0.982422C54.4034 4.57115 57.2049 7.40858 60.7529 8.77441C57.2054 10.1401 54.4036 12.9764 53.0518 16.5645C51.6998 12.9763 48.8984 10.14 45.3506 8.77441C48.8989 7.40871 51.7 4.57126 53.0518 0.982422Z",
                    fill: "url(#azai_sparkle_star1)",
                    stroke: "white",
                    strokeWidth: "1.18674"
                  }), (0, a.jsx)("path", {
                    d: "M6.35742 50.0703C7.33028 52.3418 9.11885 54.1572 11.3672 55.1357C9.11978 56.1182 7.32455 57.928 6.35547 60.2002C5.38228 57.9289 3.59422 56.113 1.3457 55.1348C3.59355 54.1523 5.38833 52.343 6.35742 50.0703Z",
                    fill: "url(#azai_sparkle_star2)",
                    stroke: "white",
                    strokeWidth: "1.18674"
                  })]
                })), (0, a.jsxs)("defs", {
                  children: [(0, a.jsxs)("linearGradient", Object.assign({
                    id: "azai_sparkle_main",
                    x1: "29.0531",
                    y1: "2.7832",
                    x2: "29.0531",
                    y2: "61.6985",
                    gradientUnits: "userSpaceOnUse"
                  }, {
                    children: [(0, a.jsx)("stop", {
                      stopColor: "white"
                    }), (0, a.jsx)("stop", {
                      offset: "1",
                      stopColor: "#CDCDCD"
                    })]
                  })), (0, a.jsxs)("linearGradient", Object.assign({
                    id: "azai_sparkle_star1",
                    x1: "53.0522",
                    y1: "0",
                    x2: "53.0522",
                    y2: "17.5485",
                    gradientUnits: "userSpaceOnUse"
                  }, {
                    children: [(0, a.jsx)("stop", {
                      stopColor: "white"
                    }), (0, a.jsx)("stop", {
                      offset: "1",
                      stopColor: "#CDCDCD"
                    })]
                  })), (0, a.jsxs)("linearGradient", Object.assign({
                    id: "azai_sparkle_star2",
                    x1: "6.35701",
                    y1: "48.9121",
                    x2: "6.35701",
                    y2: "61.3596",
                    gradientUnits: "userSpaceOnUse"
                  }, {
                    children: [(0, a.jsx)("stop", {
                      stopColor: "white"
                    }), (0, a.jsx)("stop", {
                      offset: "1",
                      stopColor: "#CDCDCD"
                    })]
                  })), (0, a.jsx)("clipPath", Object.assign({
                    id: "azai_sparkle_clip"
                  }, {
                    children: (0, a.jsx)("rect", {
                      width: "61.7107",
                      height: "61.7107",
                      fill: "white"
                    })
                  }))]
                })]
              }))]
            }))
          },
          Zs = () => (0, a.jsx)("div", Object.assign({
            className: Ds
          }, {
            children: (0, a.jsxs)("div", Object.assign({
              className: Ls
            }, {
              children: [(0, a.jsxs)("div", Object.assign({
                className: Fs
              }, {
                children: [(0, a.jsx)(Gs, {
                  size: 38
                }), (0, a.jsx)("span", Object.assign({
                  className: Ps
                }, {
                  children: "AZai"
                }))]
              })), (0, a.jsxs)("p", Object.assign({
                className: zs
              }, {
                children: ["Build your dream", (0, a.jsx)("br", {}), "e-commerce store in", " ", (0, a.jsx)("span", Object.assign({
                  className: Us
                }, {
                  children: "minutes"
                }))]
              }))]
            }))
          })),
          Hs = n.p + "33aa0ffd594370da6e48.png",
          Ys = (0, v.Pi)((({
            noHeaderOffset: t = !1
          }) => {
            const [e, n] = (0, j.useState)(!1), [r, s] = (0, j.useState)(!1), [i, o] = (0, j.useState)(!1), [l, A] = (0, j.useState)(!1), [c, d] = (0, j.useState)(!1), [w, g] = (0, j.useState)(!1), [u, p] = (0, j.useState)(!1), b = (0, j.useRef)(null), [h, m] = (0, j.useState)(!0), [x, f] = (0, j.useState)(!1), [v, E] = (0, j.useState)(!1), y = (0, j.useRef)(!1), {
              isOpen: C,
              close: O,
              open: S
            } = (0, In.b_)(), k = (0, _.g0)();
            (0, j.useEffect)((() => {
              const t = () => {
                g(!0), setTimeout((() => g(!1)), 1500)
              };
              return window.addEventListener("zai-panel-highlight", t), () => window.removeEventListener("zai-panel-highlight", t)
            }), []);
            const I = (0, N.useLocation)(),
              M = (0, j.useRef)(I.pathname),
              {
                currentStoreDetails: T
              } = ln,
              R = (0, j.useCallback)((() => {
                return t = void 0, e = void 0, a = function*() {
                  try {
                    const t = yield k.mutateAsync();
                    ln.isLoggedOut(), window.location.replace(null == t ? void 0 : t.redirectUrl)
                  } catch (t) {
                    localStorage.clear(), window.location.reload()
                  }
                }, new((n = void 0) || (n = Promise))((function(r, s) {
                  function i(t) {
                    try {
                      l(a.next(t))
                    } catch (t) {
                      s(t)
                    }
                  }

                  function o(t) {
                    try {
                      l(a.throw(t))
                    } catch (t) {
                      s(t)
                    }
                  }

                  function l(t) {
                    var e;
                    t.done ? r(t.value) : (e = t.value, e instanceof n ? e : new n((function(t) {
                      t(e)
                    }))).then(i, o)
                  }
                  l((a = a.apply(t, e || [])).next())
                }));
                var t, e, n, a
              }), [k]);
            (0, j.useEffect)((() => {
              const t = () => {
                n(window.innerWidth < 720 || window.innerHeight < 720)
              };
              return t(), window.addEventListener("resize", t), () => window.removeEventListener("resize", t)
            }), []), (0, j.useEffect)((() => {
              const t = I.pathname.startsWith("/store-onboarding"),
                e = "true" === new URLSearchParams(window.location.search).get("azai");
              window.innerWidth < 720 && (!t || !e && !ln.isZaiEnabledForOnboarding) && (m(!1), O())
            }), []);
            const B = I.pathname.startsWith("/store-onboarding"),
              L = ln.isZaiEnabledForOnboarding && B,
              F = ln.isZAIOrchestratorEnabled || L,
              P = ln.isZAIOrchestratorEnabled || L,
              z = ["/catalog", "/store-appearance", "/orders", "/analytics", "/payments", "/settings", "/delivery-settings", "/store-timings", "/profile", "/performance-marketing", "/offers", "/custom-domain", "/user-management", "/sell-using-videos", "/store-policies", "/business-details", "/reviews", "/connections", "/upsell-cross-sell", "/rto-reduction-suite"].some((t => I.pathname.startsWith(t)));
            (0, j.useEffect)((() => {
              L ? o(!0) : z && o(!1)
            }), [L, z]), (0, j.useEffect)((() => {
              !T && !L || r || s(!0)
            }), [T, L, r]), (0, j.useEffect)((() => {
              !C && F && h && !y.current && (y.current = !0, Promise.resolve().then((() => S())), i ? (E(!0), A(!0), setTimeout((() => {
                A(!1), E(!1), o(!1), m(!1), O(), y.current = !1
              }), 800)) : (f(!0), setTimeout((() => {
                f(!1), m(!1), O(), y.current = !1
              }), 500)))
            }), [C, F, h, i, S, O]), (0, j.useEffect)((() => {
              !C || h || y.current || m(!0)
            }), [C, h]);
            const U = (0, j.useCallback)((t => {
                p(!0), b.current && clearTimeout(b.current), b.current = setTimeout((() => {
                  p(!1)
                }), 3e3), t ? (d(!0), o(!0), A(!1), requestAnimationFrame((() => {
                  requestAnimationFrame((() => {
                    d(!1)
                  }))
                }))) : (A(!0), setTimeout((() => {
                  o(!1), A(!1)
                }), 500))
              }), []),
              G = (0, j.useCallback)((() => {
                console.log("ZAI ChatBot history clicked")
              }), []);
            if ((0, j.useEffect)((() => {
                M.current !== I.pathname && (i && (p(!0), b.current && clearTimeout(b.current), b.current = setTimeout((() => {
                  p(!1)
                }), 3e3), A(!0), requestAnimationFrame((() => {
                  requestAnimationFrame((() => {
                    setTimeout((() => {
                      o(!1), A(!1)
                    }), 500)
                  }))
                }))), M.current = I.pathname)
              }), [I.pathname, i]), (0, j.useEffect)((() => {
                h || o(!1)
              }), [h]), (0, j.useEffect)((() => () => {
                b.current && clearTimeout(b.current)
              }), []), !r || !T && !L) return null;
            if (F) {
              const n = Fe.isCollapsed ? 54 : 200,
                s = t ? 0 : 56,
                o = L ? window.innerHeight : window.innerHeight - s,
                A = window.innerWidth - n,
                d = e ? Math.min(A, Ns) : Ns,
                g = (i || l) && C,
                p = L ? window.innerWidth : window.innerWidth - n,
                b = L ? p : Math.round(.8 * p);
              return (0, a.jsxs)(a.Fragment, {
                children: [g && (0, a.jsxs)("div", Object.assign({
                  id: "zai-maximized",
                  style: {
                    position: "fixed",
                    top: L ? "0px" : `${s}px`,
                    left: l || c ? v ? "100vw" : `calc(100vw - ${d}px)` : L ? "0px" : `${n}px`,
                    right: 0,
                    bottom: 0,
                    zIndex: L ? 100 : 51,
                    background: P ? "radial-gradient(55.47% 20.11% at 50% 89.73%, #232944 0%, #091428 100%)" : "white",
                    overflow: "hidden",
                    display: "flex",
                    justifyContent: "center",
                    alignItems: "stretch",
                    borderRadius: L && !e ? "12px" : "0px",
                    border: L && !e ? "1px solid " + (P ? "#142E4A" : "#E9EBEF") : "0px",
                    transition: v ? "left 0.8s ease-in-out" : "left 0.5s ease-in-out"
                  }
                }, {
                  children: [L && (0, a.jsxs)("button", Object.assign({
                    onClick: R,
                    style: {
                      position: "absolute",
                      right: 16,
                      top: 16,
                      zIndex: 50
                    },
                    className: "tw-flex tw-items-center tw-gap-2 tw-border-0 tw-bg-transparent tw-px-2 tw-py-1.5 tw-text-[15px] tw-font-medium tw-text-[#0678FF] tw-transition-colors tw-cursor-pointer hover:tw-text-[#3b8ef5]"
                  }, {
                    children: [(0, a.jsx)(Bs.Z, {
                      className: "tw-w-5 tw-h-5"
                    }), "Log out"]
                  })), (0, a.jsx)("div", Object.assign({
                    style: {
                      width: `${b}px`,
                      height: "100%"
                    }
                  }, {
                    children: r && (0, a.jsx)(Rs, {
                      width: b,
                      height: o,
                      className: L ? (0, D.css)({
                        padding: e ? "16px 4% !important" : "16px 16% !important",
                        borderRadius: e ? "0 !important" : void 0
                      }) : "",
                      onExpandToggle: U,
                      onHistoryClick: G,
                      isExpanded: !0,
                      showHeader: !L,
                      welcomeMessageEl: L ? (0, a.jsx)(Zs, {}) : void 0,
                      windowBg: L ? Hs : void 0,
                      autoScroll: !0,
                      smoothScroll: !u
                    })
                  }))]
                }), "zai-maximized"), !h && !x && (0, a.jsx)("button", Object.assign({
                  onClick: () => {
                    S(), m(!0)
                  },
                  className: "tw-fixed tw-right-0 tw-top-[72px] tw-z-50 tw-flex tw-w-10 tw-h-10 tw-cursor-pointer tw-items-center tw-justify-center tw-rounded-l-lg tw-bg-[#00CCBD] tw-text-white tw-shadow-lg tw-border-0 tw-transition-all tw-duration-500 hover:tw-bg-[rgba(0,204,189,0.9)] active:tw-scale-95",
                  style: {
                    boxShadow: "0 4px 12px rgba(0, 204, 189, 0.2)"
                  },
                  "aria-label": "Open AZai chat"
                }, {
                  children: (0, a.jsx)(_s.Z, {
                    className: "tw-w-[18px] tw-h-[18px]"
                  })
                })), (0, a.jsx)("div", Object.assign({
                  id: "zai-docked",
                  style: e ? {
                    position: "fixed",
                    right: 0,
                    top: t ? 0 : 56,
                    width: d,
                    height: t ? "100%" : "calc(100vh - 56px)",
                    overflow: "hidden",
                    transition: "transform 0.5s ease-in-out",
                    transform: h && !x ? "translateX(0)" : `translateX(${d}px)`,
                    opacity: 1,
                    pointerEvents: h ? "auto" : "none",
                    zIndex: 49,
                    background: P ? "#091428" : "#ffffff",
                    boxShadow: w ? "0 0 30px 10px rgba(108, 60, 225, 0.5), 0 0 60px 20px rgba(108, 60, 225, 0.2), inset 0 0 15px rgba(108, 60, 225, 0.15)" : h ? "-4px 0 20px rgba(0,0,0,0.3)" : "none",
                    borderRadius: w ? "8px" : void 0
                  } : {
                    width: d,
                    minWidth: d,
                    height: t ? "100%" : "calc(100vh - 56px)",
                    position: "relative",
                    overflow: "hidden",
                    transition: "transform 0.5s ease-in-out, margin-right 0.5s ease-in-out",
                    transform: h && !x ? "translateX(0)" : `translateX(${d}px)`,
                    marginRight: h && !x ? 0 : -d,
                    opacity: 1,
                    pointerEvents: h ? "auto" : "none",
                    flexShrink: 0,
                    zIndex: 49,
                    boxShadow: w ? "0 0 30px 10px rgba(108, 60, 225, 0.5), 0 0 60px 20px rgba(108, 60, 225, 0.2), inset 0 0 15px rgba(108, 60, 225, 0.15)" : "none",
                    borderRadius: w ? "8px" : void 0
                  }
                }, {
                  children: r && !g && (0, a.jsx)(Rs, {
                    width: d,
                    height: t ? window.innerHeight : window.innerHeight - 56,
                    className: "",
                    onExpandToggle: U,
                    onHistoryClick: G,
                    isExpanded: !1,
                    autoScroll: !0,
                    smoothScroll: !u
                  })
                }), "zai-docked")]
              })
            }
            return (0, a.jsxs)("div", Object.assign({
              style: {
                width: C ? e ? Math.min(window.innerWidth - 40, Ns) : Ns : 0,
                minWidth: C ? e ? Math.min(window.innerWidth - 40, Ns) : Ns : 0,
                height: t ? "100%" : "calc(100vh - 56px)",
                position: "relative",
                overflow: "hidden",
                transition: "width 0.3s ease-in-out, min-width 0.3s ease-in-out, opacity 0.3s ease-in-out, box-shadow 0.4s ease-in-out",
                opacity: C ? 1 : 0,
                pointerEvents: C ? "auto" : "none",
                flexShrink: 0,
                zIndex: 49,
                boxShadow: w ? "0 0 30px 10px rgba(108, 60, 225, 0.5), 0 0 60px 20px rgba(108, 60, 225, 0.2), inset 0 0 15px rgba(108, 60, 225, 0.15)" : "none",
                borderRadius: w ? "8px" : void 0,
                animation: w ? "zai-glow-pulse 0.8s ease-in-out 2" : "none"
              }
            }, {
              children: [r && (0, a.jsx)(Rs, {
                width: e ? Math.min(window.innerWidth - 40, Ns) : Ns,
                height: t ? window.innerHeight : window.innerHeight - 56,
                className: "",
                onHistoryClick: G
              }), w && (0, a.jsx)("style", {
                children: "\n          @keyframes zai-glow-pulse {\n            0%, 100% { box-shadow: 0 0 30px 10px rgba(108, 60, 225, 0.5), 0 0 60px 20px rgba(108, 60, 225, 0.2); }\n            50% { box-shadow: 0 0 40px 15px rgba(108, 60, 225, 0.65), 0 0 80px 30px rgba(108, 60, 225, 0.3); }\n          }\n        "
              })]
            }))
          })),
          Ws = function(t, e) {
            var n = {};
            for (var a in t) Object.prototype.hasOwnProperty.call(t, a) && e.indexOf(a) < 0 && (n[a] = t[a]);
            if (null != t && "function" == typeof Object.getOwnPropertySymbols) {
              var r = 0;
              for (a = Object.getOwnPropertySymbols(t); r < a.length; r++) e.indexOf(a[r]) < 0 && Object.prototype.propertyIsEnumerable.call(t, a[r]) && (n[a[r]] = t[a[r]])
            }
            return n
          };

        function Ks(t) {
          var {
            className: e,
            style: n,
            children: r
          } = t, s = Ws(t, ["className", "style", "children"]);
          return (0, a.jsxs)("div", Object.assign({
            "data-slot": "card",
            className: xr("tw-relative tw-text-[#e6eaf2] tw-flex tw-flex-col tw-gap-6 tw-rounded-xl tw-border tw-border-[rgba(255,255,255,0.06)] tw-py-6 tw-shadow-[0_10px_30px_rgba(0,0,0,0.35)] tw-backdrop-blur-[10px] tw-transition-[filter,box-shadow] tw-duration-200 tw-ease-out hover:tw-brightness-[1.03] hover:tw-shadow-[0_12px_36px_rgba(0,0,0,0.4)]", e),
            style: Object.assign({
              background: "linear-gradient(145deg, rgba(15,23,42,0.85), rgba(10,18,36,0.65))"
            }, n)
          }, s, {
            children: [(0, a.jsx)("div", {
              className: "tw-pointer-events-none tw-absolute tw-inset-0",
              style: {
                background: "linear-gradient(135deg, rgba(59,130,246,0.08), rgba(59,130,246,0.02) 40%, transparent 70%)"
              },
              "aria-hidden": "true"
            }), r]
          }))
        }

        function Vs(t) {
          var {
            className: e
          } = t, n = Ws(t, ["className"]);
          return (0, a.jsx)("div", Object.assign({
            "data-slot": "card-content",
            className: xr("tw-px-6", e)
          }, n))
        }

        function $s(t) {
          const e = t.split("$")[0].split("||")[0].replace(/_/g, " ");
          return {
            "MYNTRA IN": "Myntra",
            "FLIPKART IN": "Flipkart",
            "AMAZON IN": "Amazon",
            SMARTBIZ: "D2C",
            SMARTHUB: "Marketplace"
          } [e] || e.toLowerCase().replace(/\b\w/g, (t => t.toUpperCase()))
        }
        const qs = {
            smartbiz: "#3b82f6",
            smarthub: "#6c3ce1",
            sa: "#f59e0b",
            Myntra: "#ff3f6c",
            Flipkart: "#f7c948",
            Amazon: "#ff9900",
            SmartBiz: "#3b82f6"
          },
          Qs = {
            smartbiz: "D2C",
            smarthub: "Marketplace",
            sa: "Assistant"
          },
          Xs = ["#3b82f6", "#6c3ce1", "#f59e0b", "#ef4444", "#10b981", "#ec4899", "#8b5cf6", "#06b6d4"];

        function Js(t, e) {
          return qs[t] || Xs[e % Xs.length]
        }

        function ti(t) {
          return /gms|sales|revenue|aov|net_sales|mtd_gms|spend|order_value/i.test(t)
        }

        function ei(t, e = !1) {
          if (null == t) return "â";
          const n = Number(t);
          return isNaN(n) ? String(t) : e ? n >= 1e5 ? "â¹" + (n / 1e5).toFixed(2) + "L" : n >= 1e3 ? "â¹" + (n / 1e3).toFixed(1) + "K" : "â¹" + n.toLocaleString("en-IN", {
            maximumFractionDigits: 2
          }) : n.toLocaleString("en-IN", {
            maximumFractionDigits: 2
          })
        }

        function ni(t) {
          return "channel" === t[0] || "metric" === t[0]
        }

        function ai(t) {
          return Object.keys(t).filter((e => {
            const n = t[e];
            return n && Array.isArray(n.columns) && Array.isArray(n.rows) && n.rows.length > 0
          }))
        }

        function ri(t) {
          return 1 === t.length && t[0].every((t => null === t || !isNaN(Number(t))))
        }

        function si(t, e) {
          if (t.length <= 1) return 0;
          const n = /count|total|quantity|amount|revenue|sales|sum|price|orders|gms|units|spend|net_sales|mtd_gms/i;
          for (let e = 0; e < t.length; e++)
            if (n.test(t[e])) return e;
          const a = /pct|rate|percentage|change/i;
          if (e)
            for (let n = 0; n < t.length; n++)
              if (!a.test(t[n]) && null !== e[n] && !isNaN(Number(e[n]))) return n;
          if (e)
            for (let n = 0; n < t.length; n++)
              if (null !== e[n] && !isNaN(Number(e[n]))) return n;
          return 0
        }

        function ii(t) {
          return li(t).toLowerCase().replace(/\b\w/g, (t => t.toUpperCase()))
        }

        function oi(t) {
          const e = li(t);
          return e.charAt(0).toUpperCase() + e.slice(1)
        }

        function li(t) {
          return t.replace(/_/g, " ").replace(/\bpct\b/gi, "%").replace(/\bpercentage\b/gi, "%").toLowerCase().replace(/\b\w/g, (t => t.toUpperCase()))
        }
        const Ai = new Set(["bi_v2_net_sales", "bi_v2_total_orders", "default_analytics_atf_net_sales", "default_analytics_atf_total_orders", "default_home_atf_net_sales", "default_home_atf_total_orders", "bi_v2_rto_rate", "bi_v2_rto_by_carrier"]);

        function ci(t) {
          return Ai.has(t)
        }

        function di({
          data: t,
          useAverage: e,
          showAggregateChange: n,
          hideBreakdown: r
        }) {
          const s = ai(t);
          if (!s.length) return null;
          const i = [];
          let o = 0,
            l = !1,
            A = !1;
          return s.forEach((e => {
            var n, a, r, s, c;
            const d = t[e];
            if (!(null == d ? void 0 : d.rows.length)) return;
            const w = ni(d.columns),
              g = si(d.columns, d.rows[0]);
            l = l || ti(d.columns[g]), A = A || /pct|rate|percentage/i.test(d.columns[g]);
            const u = g + 1;
            if (w) d.rows.forEach(((t, e) => {
              var n;
              const a = $s(String(t[0])),
                r = Number(null !== (n = t[g]) && void 0 !== n ? n : 0);
              o += r, i.push({
                label: a,
                value: r,
                color: Js(a, i.length),
                secondary: null != t[u] && "null" !== String(t[u]) ? String(t[u]) : void 0
              })
            }));
            else {
              const t = Number(null !== (a = null === (n = d.rows[0]) || void 0 === n ? void 0 : n[g]) && void 0 !== a ? a : 0);
              o += t, i.push({
                label: Qs[e] || e,
                value: t,
                color: Js(e, i.length),
                secondary: null != (null === (r = d.rows[0]) || void 0 === r ? void 0 : r[u]) && "null" !== String(null === (s = d.rows[0]) || void 0 === s ? void 0 : s[u]) ? String(null === (c = d.rows[0]) || void 0 === c ? void 0 : c[u]) : void 0
              })
            }
          })), (0, a.jsxs)("div", Object.assign({
            className: "tw-flex tw-flex-col tw-gap-3"
          }, {
            children: [(0, a.jsxs)("div", Object.assign({
              className: "tw-flex tw-items-baseline tw-gap-2"
            }, {
              children: [(0, a.jsx)("p", Object.assign({
                className: "tw-text-3xl tw-font-bold tw-text-[#e6eaf2] tw-m-0"
              }, {
                children: (() => {
                  const t = e && i.length > 0 ? o / i.length : o;
                  return A ? `${Number(t).toFixed(1)}%` : ei(t, l)
                })()
              })), (() => {
                if (!n) return null;
                let t = 0,
                  e = 0;
                if (i.forEach((n => {
                    if (!n.secondary) return;
                    const a = parseFloat(n.secondary);
                    isNaN(a) || (t += n.value * a, e += n.value)
                  })), 0 === e) return null;
                const r = t / e,
                  s = r >= 0 ? "#10b981" : "#ef4444";
                return (0, a.jsxs)("span", Object.assign({
                  className: "tw-text-sm tw-font-medium",
                  style: {
                    color: s
                  }
                }, {
                  children: [r >= 0 ? "â" : "â", " ", Math.abs(r).toFixed(1), "%"]
                }))
              })()]
            })), i.length >= 1 && !r && (0, a.jsx)("div", Object.assign({
              className: "tw-flex tw-flex-col tw-gap-1.5"
            }, {
              children: i.map((t => (0, a.jsxs)("div", Object.assign({
                className: "tw-flex tw-items-center tw-justify-between tw-text-sm"
              }, {
                children: [(0, a.jsxs)("span", Object.assign({
                  className: "tw-flex tw-items-center tw-gap-2 tw-text-[rgba(255,255,255,0.5)]"
                }, {
                  children: [(0, a.jsx)("span", {
                    className: "tw-w-2 tw-h-2 tw-rounded-full",
                    style: {
                      backgroundColor: t.color
                    }
                  }), t.label]
                })), (0, a.jsxs)("span", Object.assign({
                  className: "tw-flex tw-items-center tw-gap-2"
                }, {
                  children: [(0, a.jsx)("span", Object.assign({
                    className: "tw-font-semibold tw-text-[#e6eaf2]"
                  }, {
                    children: A ? `${Number(t.value).toFixed(1)}%` : ei(t.value, l)
                  })), t.secondary && (() => {
                    const e = parseFloat(t.secondary),
                      n = !isNaN(e),
                      r = n ? e >= 0 ? "#10b981" : "#ef4444" : "rgba(255,255,255,0.35)",
                      s = n ? `${e>=0?"â":"â"} ${Math.abs(e).toFixed(1)}%` : t.secondary;
                    return (0, a.jsx)("span", Object.assign({
                      className: "tw-text-xs tw-font-medium",
                      style: {
                        color: r
                      }
                    }, {
                      children: s
                    }))
                  })()]
                }))]
              }), t.label)))
            }))]
          }))
        }
        var wi = n(29009),
          gi = n(98687),
          ui = n(14195),
          pi = n(3023),
          bi = n(75358),
          hi = n(65657),
          mi = n(23872),
          xi = n(56880);

        function fi({
          data: t,
          height: e
        }) {
          const n = ai(t);
          if (!n.length) return null;
          const r = {},
            s = new Set;
          n.forEach((e => {
            const n = t[e];
            if (!(null == n ? void 0 : n.rows.length)) return;
            const a = n.columns,
              i = a.length >= 3 && "channel" === a[1],
              o = si(a, n.rows[0]);
            if (i) n.rows.forEach((t => {
              var e;
              const n = String(t[0]).split(" ")[0],
                a = $s(String(t[1])),
                i = Number(null !== (e = t[o]) && void 0 !== e ? e : 0);
              s.add(n), r[a] || (r[a] = {}), r[a][n] = i
            }));
            else {
              const t = Qs[e] || e,
                i = si(a, n.rows[0]);
              r[t] = {}, n.rows.forEach((e => {
                var n;
                const a = String(e[0]).split(" ")[0];
                s.add(a), r[t][a] = Number(null !== (n = e[i]) && void 0 !== n ? n : 0)
              }))
            }
          }));
          const i = Array.from(s).sort(),
            o = Object.keys(r),
            l = i.map((t => {
              const e = {
                x: t
              };
              return o.forEach((n => {
                var a;
                e[n] = null !== (a = r[n][t]) && void 0 !== a ? a : 0
              })), e
            }));
          return (0, a.jsx)(wi.h, Object.assign({
            width: "100%",
            height: e
          }, {
            children: (0, a.jsxs)(gi.w, Object.assign({
              data: l
            }, {
              children: [(0, a.jsx)(ui.q, {
                strokeDasharray: "3 3",
                stroke: "rgba(255,255,255,0.06)",
                vertical: !1
              }), (0, a.jsx)(pi.K, {
                dataKey: "x",
                tick: {
                  fontSize: 10,
                  fill: "rgba(255,255,255,0.5)"
                }
              }), (0, a.jsx)(bi.B, {
                tick: {
                  fontSize: 10,
                  fill: "rgba(255,255,255,0.5)"
                }
              }), (0, a.jsx)(hi.u, {
                contentStyle: {
                  backgroundColor: "#1a1a2e",
                  border: "1px solid rgba(255,255,255,0.1)",
                  color: "#e6eaf2"
                }
              }), o.length > 1 && (0, a.jsx)(mi.D, {}), o.map(((t, e) => (0, a.jsx)(xi.x, {
                type: "monotone",
                dataKey: t,
                name: t.toUpperCase(),
                stroke: Js(t, e),
                dot: !1
              }, t)))]
            }))
          }))
        }
        var vi = n(94831),
          ji = n(76955);

        function Ei({
          data: t,
          height: e
        }) {
          const n = ai(t);
          if (!n.length) return null;
          const r = t[n[0]],
            s = "channel" === r.columns[0];
          if (!s && ri(r.rows)) {
            const s = r.columns,
              i = s.map((e => {
                const a = {
                  x: li(e)
                };
                return n.forEach((n => {
                  var r, i, o;
                  const l = Qs[n] || n;
                  a[l] = Number(null !== (o = null === (i = null === (r = t[n]) || void 0 === r ? void 0 : r.rows[0]) || void 0 === i ? void 0 : i[s.indexOf(e)]) && void 0 !== o ? o : 0)
                })), a
              })),
              o = n.map((t => Qs[t] || t));
            return (0, a.jsx)(wi.h, Object.assign({
              width: "100%",
              height: e
            }, {
              children: (0, a.jsxs)(vi.v, Object.assign({
                data: i
              }, {
                children: [(0, a.jsx)(ui.q, {
                  strokeDasharray: "3 3",
                  stroke: "rgba(255,255,255,0.06)",
                  vertical: !1
                }), (0, a.jsx)(pi.K, {
                  dataKey: "x",
                  tick: {
                    fontSize: 10,
                    fill: "rgba(255,255,255,0.5)"
                  }
                }), (0, a.jsx)(bi.B, {
                  tick: {
                    fontSize: 10,
                    fill: "rgba(255,255,255,0.5)"
                  }
                }), (0, a.jsx)(hi.u, {
                  cursor: !1,
                  contentStyle: {
                    backgroundColor: "#1a1a2e",
                    border: "1px solid rgba(255,255,255,0.1)",
                    color: "#e6eaf2"
                  }
                }), o.length > 1 && (0, a.jsx)(mi.D, {}), o.map(((t, e) => (0, a.jsx)(ji.$, {
                  dataKey: t,
                  name: t.toUpperCase(),
                  fill: Js(t, e),
                  activeBar: !1,
                  radius: [4, 4, 0, 0]
                }, t)))]
              }))
            }))
          }
          const i = {},
            o = new Set;
          n.forEach((e => {
            const n = t[e];
            if (!(null == n ? void 0 : n.rows.length)) return;
            const a = si(n.columns, n.rows[0]);
            if (s) n.rows.forEach((t => {
              var e;
              const n = $s(String(t[0]));
              o.add(n), i[n] || (i[n] = {}), i[n][n] = Number(null !== (e = t[a]) && void 0 !== e ? e : 0)
            }));
            else {
              const t = Qs[e] || e;
              n.rows.forEach((e => {
                var n;
                if (null == e[0]) return;
                const r = String(e[0]);
                o.add(r), i[t] || (i[t] = {}), i[t][r] = Number(null !== (n = e[a]) && void 0 !== n ? n : 0)
              }))
            }
          }));
          const l = Array.from(o),
            A = Object.keys(i),
            c = l.map((t => {
              const e = {
                x: t
              };
              return A.forEach((n => {
                var a;
                e[n] = null !== (a = i[n][t]) && void 0 !== a ? a : 0
              })), e
            }));
          return (0, a.jsx)(wi.h, Object.assign({
            width: "100%",
            height: e
          }, {
            children: (0, a.jsxs)(vi.v, Object.assign({
              data: c
            }, {
              children: [(0, a.jsx)(ui.q, {
                strokeDasharray: "3 3",
                stroke: "rgba(255,255,255,0.06)",
                vertical: !1
              }), (0, a.jsx)(pi.K, {
                dataKey: "x",
                tick: {
                  fontSize: 10,
                  fill: "rgba(255,255,255,0.5)"
                }
              }), (0, a.jsx)(bi.B, {
                tick: {
                  fontSize: 10,
                  fill: "rgba(255,255,255,0.5)"
                }
              }), (0, a.jsx)(hi.u, {
                cursor: !1,
                contentStyle: {
                  backgroundColor: "#1a1a2e",
                  border: "1px solid rgba(255,255,255,0.1)",
                  color: "#e6eaf2"
                }
              }), A.length > 1 && (0, a.jsx)(mi.D, {}), A.map(((t, e) => (0, a.jsx)(ji.$, {
                dataKey: t,
                name: t.toUpperCase(),
                fill: Js(t, e),
                activeBar: !1,
                radius: [4, 4, 0, 0]
              }, t)))]
            }))
          }))
        }

        function yi({
          data: t,
          height: e
        }) {
          const n = ai(t);
          if (!n.length) return null;
          const r = t[n[0]],
            s = "channel" === r.columns[0];
          if (!s && ri(r.rows)) {
            const s = r.columns,
              i = s.map((e => {
                const a = {
                  y: li(e)
                };
                return n.forEach((n => {
                  var r, i, o;
                  const l = Qs[n] || n;
                  a[l] = Number(null !== (o = null === (i = null === (r = t[n]) || void 0 === r ? void 0 : r.rows[0]) || void 0 === i ? void 0 : i[s.indexOf(e)]) && void 0 !== o ? o : 0)
                })), a
              })),
              o = n.map((t => Qs[t] || t));
            return (0, a.jsx)(wi.h, Object.assign({
              width: "100%",
              height: e
            }, {
              children: (0, a.jsxs)(vi.v, Object.assign({
                data: i,
                layout: "vertical"
              }, {
                children: [(0, a.jsx)(ui.q, {
                  strokeDasharray: "3 3",
                  stroke: "rgba(255,255,255,0.06)",
                  vertical: !1
                }), (0, a.jsx)(pi.K, {
                  type: "number",
                  tick: {
                    fontSize: 10
                  }
                }), (0, a.jsx)(bi.B, {
                  type: "category",
                  dataKey: "y",
                  tick: {
                    fontSize: 10
                  },
                  width: 120
                }), (0, a.jsx)(hi.u, {
                  cursor: !1,
                  contentStyle: {
                    backgroundColor: "#1a1a2e",
                    border: "1px solid rgba(255,255,255,0.1)",
                    color: "#e6eaf2"
                  },
                  labelStyle: {
                    display: "none"
                  }
                }), o.length > 1 && (0, a.jsx)(mi.D, {}), o.map(((t, e) => (0, a.jsx)(ji.$, {
                  dataKey: t,
                  name: t.toUpperCase(),
                  fill: Js(t, e),
                  activeBar: !1,
                  radius: [0, 4, 4, 0]
                }, t)))]
              }))
            }))
          }
          const i = {},
            o = new Set;
          n.forEach((e => {
            const n = t[e];
            if (null == n ? void 0 : n.rows.length)
              if (s) n.rows.forEach((t => {
                var e;
                const n = $s(String(t[0]));
                o.add(n), i[n] || (i[n] = {}), i[n][n] = Number(null !== (e = t[1]) && void 0 !== e ? e : 0)
              }));
              else {
                const t = Qs[e] || e;
                n.rows.forEach((e => {
                  var n;
                  if (null == e[0]) return;
                  const a = String(e[0]);
                  o.add(a), i[t] || (i[t] = {}), i[t][a] = Number(null !== (n = e[1]) && void 0 !== n ? n : 0)
                }))
              }
          }));
          const l = Array.from(o),
            A = Object.keys(i),
            c = l.map((t => {
              const e = {
                y: t
              };
              return A.forEach((n => {
                var a;
                e[n] = null !== (a = i[n][t]) && void 0 !== a ? a : 0
              })), e
            }));
          return (0, a.jsx)(wi.h, Object.assign({
            width: "100%",
            height: e
          }, {
            children: (0, a.jsxs)(vi.v, Object.assign({
              data: c,
              layout: "vertical"
            }, {
              children: [(0, a.jsx)(ui.q, {
                strokeDasharray: "3 3",
                stroke: "rgba(255,255,255,0.06)",
                vertical: !1
              }), (0, a.jsx)(pi.K, {
                type: "number",
                tick: {
                  fontSize: 10
                }
              }), (0, a.jsx)(bi.B, {
                type: "category",
                dataKey: "y",
                tick: {
                  fontSize: 10
                },
                width: 100
              }), (0, a.jsx)(hi.u, {
                cursor: !1,
                contentStyle: {
                  backgroundColor: "#1a1a2e",
                  border: "1px solid rgba(255,255,255,0.1)",
                  color: "#e6eaf2"
                },
                labelStyle: {
                  display: "none"
                }
              }), A.length > 1 && (0, a.jsx)(mi.D, {}), A.map(((t, e) => (0, a.jsx)(ji.$, {
                dataKey: t,
                name: t.toUpperCase(),
                fill: Js(t, e),
                activeBar: !1,
                radius: [0, 4, 4, 0]
              }, t)))]
            }))
          }))
        }

        function Ci({
          data: t,
          height: e
        }) {
          const n = ai(t);
          if (!n.length) return null;
          const r = [],
            s = {};
          n.forEach((e => {
            const n = t[e];
            if (!(null == n ? void 0 : n.rows.length)) return;
            const {
              statusIdx: a,
              valueIdx: i
            } = function(t) {
              const e = t.findIndex((t => /status|orderstatus|stage/i.test(t))),
                n = t.findIndex((t => /orders|count|units|value/i.test(t)));
              return e >= 0 && n >= 0 ? {
                statusIdx: e,
                valueIdx: n
              } : {
                statusIdx: 0,
                valueIdx: 1
              }
            }(n.columns);
            s[e] = {}, n.rows.forEach((t => {
              var n;
              if (null == t[a]) return;
              const o = String(t[a]),
                l = Number(null !== (n = t[i]) && void 0 !== n ? n : 0);
              r.includes(o) || r.push(o), s[e][o] = (s[e][o] || 0) + l
            }))
          }));
          const i = n.map((t => {
            const e = {
              program: t
            };
            return r.forEach((n => {
              var a, r;
              e[n] = null !== (r = null === (a = s[t]) || void 0 === a ? void 0 : a[n]) && void 0 !== r ? r : 0
            })), e
          }));
          return (0, a.jsx)(wi.h, Object.assign({
            width: "100%",
            height: e
          }, {
            children: (0, a.jsxs)(vi.v, Object.assign({
              data: i,
              layout: "vertical"
            }, {
              children: [(0, a.jsx)(pi.K, {
                type: "number",
                tick: {
                  fontSize: 10,
                  fill: "rgba(255,255,255,0.5)"
                }
              }), (0, a.jsx)(bi.B, {
                type: "category",
                dataKey: "program",
                tick: {
                  fontSize: 10,
                  fill: "rgba(255,255,255,0.5)"
                },
                width: 100
              }), (0, a.jsx)(hi.u, {
                cursor: !1,
                contentStyle: {
                  backgroundColor: "#1a1a2e",
                  border: "1px solid rgba(255,255,255,0.1)",
                  color: "#e6eaf2"
                }
              }), r.length > 1 && (0, a.jsx)(mi.D, {
                wrapperStyle: {
                  color: "rgba(255,255,255,0.5)"
                }
              }), r.map(((t, e) => (0, a.jsx)(ji.$, {
                dataKey: t,
                name: t.toUpperCase(),
                fill: Js(t, e),
                activeBar: !1,
                radius: [0, 4, 4, 0]
              }, t)))]
            }))
          }))
        }

        function Oi({
          data: t
        }) {
          var e;
          const n = ai(t),
            r = n.length > 1;
          return (0, a.jsx)("div", Object.assign({
            className: "tw-overflow-auto tw-max-h-64"
          }, {
            children: (0, a.jsxs)("table", Object.assign({
              className: "tw-w-full tw-text-xs"
            }, {
              children: [(0, a.jsx)("thead", {
                children: (0, a.jsxs)("tr", Object.assign({
                  className: "tw-border-b tw-border-[rgba(255,255,255,0.08)]"
                }, {
                  children: [r && (0, a.jsx)("th", Object.assign({
                    className: "tw-py-2 tw-px-2 tw-text-left tw-text-[rgba(255,255,255,0.35)]"
                  }, {
                    children: "Program"
                  })), null === (e = t[n[0]]) || void 0 === e ? void 0 : e.columns.map((t => (0, a.jsx)("th", Object.assign({
                    className: "tw-py-2 tw-px-2 tw-text-left tw-text-[rgba(255,255,255,0.35)]"
                  }, {
                    children: li(t).replace(/\b\w/g, (t => t.toUpperCase()))
                  }), t)))]
                }))
              }), (0, a.jsx)("tbody", {
                children: n.flatMap((e => t[e].rows.map(((n, s) => (0, a.jsxs)("tr", Object.assign({
                  className: "tw-border-b tw-border-[rgba(255,255,255,0.06)]"
                }, {
                  children: [r && (0, a.jsx)("td", Object.assign({
                    className: "tw-py-1.5 tw-px-2 tw-text-[rgba(255,255,255,0.5)]"
                  }, {
                    children: Qs[e] || e
                  })), n.map(((n, r) => {
                    const s = "channel" === t[e].columns[r] ? $s(String(n)) : "number" == typeof n ? n.toLocaleString("en-IN", {
                      maximumFractionDigits: 2
                    }) : String(null != n ? n : "â");
                    return (0, a.jsx)("td", Object.assign({
                      className: "tw-py-1.5 tw-px-2 tw-text-[#e6eaf2]"
                    }, {
                      children: s
                    }), r)
                  }))]
                }), `${e}-${s}`)))))
              })]
            }))
          }))
        }

        function Ni({
          visualization: t,
          data: e,
          height: n,
          useAverage: r,
          showAggregateChange: s,
          hideBreakdown: i
        }) {
          if (!(ai(e).length > 0)) return (0, a.jsx)("div", Object.assign({
            className: "tw-flex tw-items-center tw-justify-center tw-text-xs tw-rounded-lg tw-border tw-border-dashed",
            style: {
              height: n,
              borderColor: "rgba(255,255,255,0.1)",
              color: "rgba(255,255,255,0.25)"
            }
          }, {
            children: "No data for this period"
          }));
          const o = function(t, e) {
            var n, a, r;
            const s = ai(e);
            if (!s.length) return t;
            const i = Math.max(...s.map((t => {
                var n, a, r;
                return null !== (r = null === (a = null === (n = e[t]) || void 0 === n ? void 0 : n.rows) || void 0 === a ? void 0 : a.length) && void 0 !== r ? r : 0
              }))),
              o = e[s[0]],
              l = null !== (a = null === (n = null == o ? void 0 : o.columns) || void 0 === n ? void 0 : n.length) && void 0 !== a ? a : 0,
              A = null === (r = null == o ? void 0 : o.columns) || void 0 === r ? void 0 : r.some((t => /date|month|week|day|time|period/.test(t.toLowerCase())));
            switch (t) {
              case "metric_card":
                if (i > 2) return A ? "line" : "bar";
                break;
              case "line":
              case "bar":
                if (i <= 1 && l <= 2 && !A) return "metric_card";
                break;
              case "funnel":
                if (i < 2) return "bar"
            }
            return t
          }(t, e);
          switch (o) {
            case "metric_card":
              return (0, a.jsx)(di, {
                data: e,
                useAverage: r,
                showAggregateChange: s,
                hideBreakdown: i
              });
            case "line":
              return (0, a.jsx)(fi, {
                data: e,
                height: n
              });
            case "bar":
              return (0, a.jsx)(Ei, {
                data: e,
                height: n
              });
            case "horizontal_bar":
              return (0, a.jsx)(yi, {
                data: e,
                height: n
              });
            case "funnel":
              return (0, a.jsx)(Ci, {
                data: e,
                height: n
              });
            case "table":
              return (0, a.jsx)(Oi, {
                data: e
              });
            default:
              return (0, a.jsxs)("p", Object.assign({
                className: "tw-text-xs tw-text-[rgba(255,255,255,0.35)]"
              }, {
                children: ["Unsupported: ", o]
              }))
          }
        }
        var Si = n(23217),
          ki = n(13742),
          Ii = n(30143);
        const Mi = {
          THEME: {
            PREVIEW: "widget.theme_preview",
            REVIEW_DETAILS: "widget.theme_review_details"
          },
          CATALOG: {
            PREVIEW: "widget.catalog_review",
            IMAGE: "widget.image_review"
          },
          INPUT: {
            SEND: "widget.input_send"
          },
          PAGE: {
            REDIRECTION: "widget.page_redirection"
          },
          STORE: {
            GET_STORE_ID: "widget.store_id_received"
          },
          BANNER: {
            PREVIEW: "widget.banner_preview"
          },
          ANALYTICS: {
            CHART: "widget.analytics_chart",
            WIDGET_PINNED: "widget.analytics_pinned"
          }
        };
        var Ti = function(t, e, n, a) {
          return new(n || (n = Promise))((function(r, s) {
            function i(t) {
              try {
                l(a.next(t))
              } catch (t) {
                s(t)
              }
            }

            function o(t) {
              try {
                l(a.throw(t))
              } catch (t) {
                s(t)
              }
            }

            function l(t) {
              var e;
              t.done ? r(t.value) : (e = t.value, e instanceof n ? e : new n((function(t) {
                t(e)
              }))).then(i, o)
            }
            l((a = a.apply(t, e || [])).next())
          }))
        };
        const {
          config: Ri
        } = (0, $t.R6)(), Bi = `${Ri.smartbizRenBaseUrl}/ren/v1/analytics/dashboard`;
        class _i {
          constructor() {
            this.abortController = null
          }
          connect(t, e, n, a) {
            var r;
            return Ti(this, void 0, void 0, (function*() {
              this.disconnect(), this.abortController = new AbortController;
              try {
                const s = new URLSearchParams;
                t.dateFrom && s.set("dateFrom", t.dateFrom), t.dateTo && s.set("dateTo", t.dateTo);
                const i = `${Bi}/${t.pageId.toUpperCase()}/widgets?${s}`,
                  o = yield fetch(i, {
                    method: "GET",
                    headers: {
                      Accept: "text/event-stream"
                    },
                    credentials: "include",
                    signal: this.abortController.signal
                  });
                if (!o.ok) return void n(new Event(`HTTP ${o.status}`));
                const l = null === (r = o.body) || void 0 === r ? void 0 : r.getReader();
                if (!l) return void n(new Event("No response body"));
                const A = new TextDecoder;
                let c = "";
                for (;;) {
                  const {
                    done: t,
                    value: n
                  } = yield l.read();
                  if (t) break;
                  c += A.decode(n, {
                    stream: !0
                  });
                  const a = c.split("\n");
                  c = a.pop() || "";
                  let r = "",
                    s = "";
                  for (const t of a)
                    if (t.startsWith("event: ")) r = t.slice(7).trim();
                    else if (t.startsWith("data: ")) s = t.slice(6);
                  else if ("" === t && s) {
                    try {
                      const t = JSON.parse(s);
                      e(t)
                    } catch (t) {
                      console.warn("Failed to parse SSE data:", s)
                    }
                    r = "", s = ""
                  }
                }
                a()
              } catch (t) {
                "AbortError" !== t.name && n(new Event(t.message || "SSE connection failed"))
              }
            }))
          }
          disconnect() {
            var t;
            null === (t = this.abortController) || void 0 === t || t.abort(), this.abortController = null
          }
        }
        const Di = {
          accept: "application/json",
          "Accept-Language": "en-US,en;q=0.8",
          "Content-Type": "multipart/form-data;"
        };
        var Li = function(t, e, n, a) {
          return new(n || (n = Promise))((function(r, s) {
            function i(t) {
              try {
                l(a.next(t))
              } catch (t) {
                s(t)
              }
            }

            function o(t) {
              try {
                l(a.throw(t))
              } catch (t) {
                s(t)
              }
            }

            function l(t) {
              var e;
              t.done ? r(t.value) : (e = t.value, e instanceof n ? e : new n((function(t) {
                t(e)
              }))).then(i, o)
            }
            l((a = a.apply(t, e || [])).next())
          }))
        };
        class Fi extends In.BI {
          validateFile(t) {
            return Li(this, void 0, void 0, (function*() {
              const e = [],
                n = [];
              t.type.startsWith("image/") || e.push({
                field: "type",
                code: "INVALID_FILE_TYPE",
                message: "File must be an image (PNG, JPEG, JPG)"
              }), ["image/png", "image/jpeg", "image/jpg"].includes(t.type) || e.push({
                field: "type",
                code: "UNSUPPORTED_FORMAT",
                message: "Supported formats: PNG, JPEG, JPG"
              });
              const a = 10485760;
              return t.size > a && e.push({
                field: "size",
                code: "FILE_TOO_LARGE",
                message: `File size must be less than ${this.formatFileSize(a)}`
              }), t.size > 5242880 && t.size <= a && n.push({
                field: "size",
                code: "LARGE_FILE_WARNING",
                message: `Large file detected (${this.formatFileSize(t.size)}). Upload may take longer.`
              }), {
                valid: 0 === e.length,
                errors: e.length > 0 ? e : void 0,
                warnings: n.length > 0 ? n : void 0
              }
            }))
          }
          performUpload(t, e, n) {
            return Li(this, void 0, void 0, (function*() {
              try {
                const o = yield this.fileToDataURL(t), l = {
                  name: t.name,
                  filename: t.name,
                  type: t.type,
                  data: o
                };
                this.updateProgress(n, {
                  status: In.Dm.UPLOADING,
                  bytesUploaded: 0
                });
                const A = setInterval((() => {
                    const e = this.getUploadProgress(n);
                    if (e && e.status === In.Dm.UPLOADING) {
                      const a = Math.min(e.bytesUploaded + .1 * t.size, .9 * t.size);
                      this.updateProgress(n, {
                        bytesUploaded: a
                      })
                    }
                  }), 200),
                  c = yield(i = l, e = void 0, a = void 0, r = void 0, s = function*() {
                    var t;
                    const e = localStorage.getItem("shopId"),
                      n = new FormData,
                      a = null === (t = i.data) || void 0 === t ? void 0 : t.replace(/^data:image\/(png|jpeg|jpg);base64,/, ""),
                      r = new Blob([a]);
                    return n.append("file", r, i.filename), (yield pe.post(`/api-sp/resources/v2/images?shop_id=${e}`, n, {
                      headers: Di,
                      timeout: 3e4
                    })).data
                  }, new(r || (r = Promise))((function(t, n) {
                    function i(t) {
                      try {
                        l(s.next(t))
                      } catch (t) {
                        n(t)
                      }
                    }

                    function o(t) {
                      try {
                        l(s.throw(t))
                      } catch (t) {
                        n(t)
                      }
                    }

                    function l(e) {
                      var n;
                      e.done ? t(e.value) : (n = e.value, n instanceof r ? n : new r((function(t) {
                        t(n)
                      }))).then(i, o)
                    }
                    l((s = s.apply(e, a || [])).next())
                  })));
                clearInterval(A), this.updateProgress(n, {
                  status: In.Dm.PROCESSING,
                  bytesUploaded: t.size
                });
                const d = c.imageId || `smartpos_${Date.now()}_${Math.random().toString(36).substr(2,9)}`;
                let w = c;
                const g = (0, $t.R6)();
                if ("string" == typeof w) switch (g.stage) {
                  case "beta":
                  case "local":
                  case "gamma":
                    w = w.replace(/https?:\/\/[^\/]+/, "https://d1y6eovjq6l2o1.cloudfront.net")
                }
                return {
                  uploadId: n,
                  fileId: d,
                  url: w,
                  originalName: t.name,
                  size: t.size,
                  mimeType: t.type,
                  uploadedAt: new Date,
                  processed: !0
                }
              } catch (t) {
                const e = t instanceof Error ? t.message : "Upload failed";
                throw new Error(`Image upload failed: ${e}`)
              }
              var e, a, r, s, i
            }))
          }
          fileToDataURL(t) {
            return new Promise(((e, n) => {
              const a = new FileReader;
              a.onload = () => {
                e(a.result)
              }, a.onerror = () => {
                n(new Error("Failed to read file"))
              }, a.readAsDataURL(t)
            }))
          }
          preprocessFile(t, e) {
            return Li(this, void 0, void 0, (function*() {
              return t
            }))
          }
          cleanup() {
            const t = Object.create(null, {
              cleanup: {
                get: () => super.cleanup
              }
            });
            var e;
            return Li(this, void 0, void 0, (function*() {
              yield null === (e = t.cleanup) || void 0 === e ? void 0 : e.call(this)
            }))
          }
        }
        var Pi = function(t, e, n, a) {
          return new(n || (n = Promise))((function(r, s) {
            function i(t) {
              try {
                l(a.next(t))
              } catch (t) {
                s(t)
              }
            }

            function o(t) {
              try {
                l(a.throw(t))
              } catch (t) {
                s(t)
              }
            }

            function l(t) {
              var e;
              t.done ? r(t.value) : (e = t.value, e instanceof n ? e : new n((function(t) {
                t(e)
              }))).then(i, o)
            }
            l((a = a.apply(t, e || [])).next())
          }))
        };
        class zi extends In.BI {
          constructor() {
            super()
          }
          getShopId() {
            const t = localStorage.getItem("shopId") || "1234";
            if (!t) throw new Error("Shop ID not found in localStorage. User may not be authenticated.");
            return t
          }
          validateFile(t) {
            return Pi(this, void 0, void 0, (function*() {
              const e = [],
                n = [];
              return t.name && 0 !== t.name.trim().length || e.push({
                field: "name",
                code: "MISSING_FILE_NAME",
                message: "File must have a name"
              }), 0 === t.size && e.push({
                field: "size",
                code: "EMPTY_FILE",
                message: "File must not be empty"
              }), t.size > 52428800 && n.push({
                field: "size",
                code: "LARGE_FILE_WARNING",
                message: `Large file detected (${this.formatFileSize(t.size)}). Upload may take longer.`
              }), {
                valid: 0 === e.length,
                errors: e.length > 0 ? e : void 0,
                warnings: n.length > 0 ? n : void 0
              }
            }))
          }
          performUpload(t, e, n) {
            return Pi(this, void 0, void 0, (function*() {
              try {
                const e = this.getShopId(),
                  a = this.getSimpleDocumentType(t.name);
                this.updateProgress(n, {
                  status: In.Dm.UPLOADING,
                  bytesUploaded: 0
                });
                const r = yield((t, e, n) => {
                  return a = void 0, r = void 0, i = function*() {
                    const a = e.replace(/\.[^/.]+$/, "").replace(/[^a-zA-Z0-9_-]/g, "_").replace(/_+/g, "_").replace(/^_|_$/g, ""),
                      r = new URLSearchParams({
                        "file-name": a || "file",
                        "document-type": n
                      }),
                      s = (yield ue.get(`/stores/${t}/presigned-url?${r.toString()}`)).data,
                      i = {};
                    return s.headers && Object.assign(i, s.headers), s.expectedBucketOwner && (i["x-amz-expected-bucket-owner"] = s.expectedBucketOwner), {
                      url: s.url,
                      key: s.key,
                      headers: i
                    }
                  }, new((s = void 0) || (s = Promise))((function(t, e) {
                    function n(t) {
                      try {
                        l(i.next(t))
                      } catch (t) {
                        e(t)
                      }
                    }

                    function o(t) {
                      try {
                        l(i.throw(t))
                      } catch (t) {
                        e(t)
                      }
                    }

                    function l(e) {
                      var a;
                      e.done ? t(e.value) : (a = e.value, a instanceof s ? a : new s((function(t) {
                        t(a)
                      }))).then(n, o)
                    }
                    l((i = i.apply(a, r || [])).next())
                  }));
                  var a, r, s, i
                })(e, t.name, a), {
                  url: s,
                  key: i,
                  headers: o
                } = r;
                yield((t, e, n, a) => new Promise(((r, s) => {
                  const i = new XMLHttpRequest;
                  i.upload.addEventListener("progress", (t => {
                    t.lengthComputable && n && n(t.loaded, t.total)
                  })), i.addEventListener("load", (() => {
                    i.status >= 200 && i.status < 300 ? r() : s(new Error(`S3 upload failed with status ${i.status}: ${i.statusText}`))
                  })), i.addEventListener("error", (() => {
                    s(new Error("Network error during S3 upload"))
                  })), i.addEventListener("abort", (() => {
                    s(new Error("S3 upload was aborted"))
                  })), i.open("PUT", t, !0), a && Object.entries(a).forEach((([t, e]) => {
                    e && i.setRequestHeader(t, e)
                  })), i.send(e)
                })))(s, t, ((t, e) => {
                  this.updateProgress(n, {
                    bytesUploaded: t
                  })
                }), o), this.updateProgress(n, {
                  status: In.Dm.PROCESSING,
                  bytesUploaded: t.size
                });
                const l = t.type || this.getMimeTypeFromExtension(t.name);
                return {
                  uploadId: n,
                  fileId: i,
                  url: i,
                  originalName: t.name,
                  size: t.size,
                  mimeType: l,
                  uploadedAt: new Date,
                  processed: !0,
                  metadata: {
                    s3Key: i,
                    presignedUrl: s,
                    documentType: a
                  }
                }
              } catch (t) {
                const e = t instanceof Error ? t.message : "Upload failed";
                throw new Error(`S3 file upload failed: ${e}`)
              }
            }))
          }
          getSimpleDocumentType(t) {
            var e;
            return (null === (e = t.split(".").pop()) || void 0 === e ? void 0 : e.toLowerCase()) || "bin"
          }
          getMimeTypeFromExtension(t) {
            var e;
            return {
              csv: "text/csv",
              xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
              xls: "application/vnd.ms-excel",
              pdf: "application/pdf",
              doc: "application/msword",
              docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
              ppt: "application/vnd.ms-powerpoint",
              pptx: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
              txt: "text/plain",
              json: "application/json",
              xml: "application/xml",
              zip: "application/zip",
              rar: "application/x-rar-compressed"
            } [(null === (e = t.split(".").pop()) || void 0 === e ? void 0 : e.toLowerCase()) || ""] || "application/octet-stream"
          }
          preprocessFile(t) {
            return Pi(this, void 0, void 0, (function*() {
              return t
            }))
          }
          cleanup() {
            const t = Object.create(null, {
              cleanup: {
                get: () => super.cleanup
              }
            });
            var e;
            return Pi(this, void 0, void 0, (function*() {
              yield null === (e = t.cleanup) || void 0 === e ? void 0 : e.call(this)
            }))
          }
        }
        var Ui = function(t, e, n, a) {
          return new(n || (n = Promise))((function(r, s) {
            function i(t) {
              try {
                l(a.next(t))
              } catch (t) {
                s(t)
              }
            }

            function o(t) {
              try {
                l(a.throw(t))
              } catch (t) {
                s(t)
              }
            }

            function l(t) {
              var e;
              t.done ? r(t.value) : (e = t.value, e instanceof n ? e : new n((function(t) {
                t(e)
              }))).then(i, o)
            }
            l((a = a.apply(t, e || [])).next())
          }))
        };
        class Gi extends In.BI {
          constructor() {
            super(), this.imageService = new Fi, this.s3Service = new zi
          }
          isImageFile(t) {
            return t.type.startsWith("image/")
          }
          getServiceForFile(t) {
            return this.isImageFile(t) ? this.imageService : this.s3Service
          }
          validateFile(t) {
            return Ui(this, void 0, void 0, (function*() {
              const e = this.getServiceForFile(t);
              return e.validateFile ? e.validateFile(t) : {
                valid: !0
              }
            }))
          }
          uploadFile(t, e = {}) {
            return Ui(this, void 0, void 0, (function*() {
              return this.getServiceForFile(t).uploadFile(t, e)
            }))
          }
          uploadFiles(t, e = {}) {
            return Ui(this, void 0, void 0, (function*() {
              const n = [];
              for (const a of t) {
                const t = yield this.uploadFile(a, e);
                n.push(t)
              }
              return n
            }))
          }
          performUpload(t, e, n) {
            return Ui(this, void 0, void 0, (function*() {
              return this.getServiceForFile(t).uploadFile(t, e)
            }))
          }
          preprocessFile(t, e) {
            return Ui(this, void 0, void 0, (function*() {
              const n = this.getServiceForFile(t);
              return n.preprocessFile ? n.preprocessFile(t, e) : t
            }))
          }
          cleanup() {
            const t = Object.create(null, {
              cleanup: {
                get: () => super.cleanup
              }
            });
            var e, n, a, r, s;
            return Ui(this, void 0, void 0, (function*() {
              yield Promise.all([null === (e = t.cleanup) || void 0 === e ? void 0 : e.call(this), null === (a = (n = this.imageService).cleanup) || void 0 === a ? void 0 : a.call(n), null === (s = (r = this.s3Service).cleanup) || void 0 === s ? void 0 : s.call(r)])
            }))
          }
        }
        const Zi = t => t && "object" == typeof t && !Array.isArray(t),
          Hi = t => Zi(t),
          Yi = t => Zi(t),
          Wi = t => Zi(t),
          Ki = t => Zi(t),
          Vi = t => Zi(t),
          $i = t => {
            var e;
            if (!Zi(t)) return !1;
            const n = null === (e = null == t ? void 0 : t.content) || void 0 === e ? void 0 : e.pageType;
            return "string" == typeof n && n.length > 0
          },
          qi = t => Zi(t),
          Qi = t => {
            var e;
            return Zi(t) && (null === (e = null == t ? void 0 : t.content) || void 0 === e ? void 0 : e.variant) && "string" == typeof t.actionName
          },
          Xi = (t, e, n, a) => r => {
            if (n)
              if (r && r.payload)
                if (e(r.payload)) try {
                  n(r.payload)
                } catch (e) {
                  console.error(`â Error executing ${t} handler:`, e)
                } else console.error(`â Invalid payload structure for ${t}:`, r.payload);
                else console.error(`â Invalid event structure for ${t}:`, r);
            else a && console.warn(`â ï¸ No handler provided for ${t}`)
          },
          Ji = (t = {}) => {
            const {
              enableLogging: e = !1,
              onThemePreview: n,
              onThemeReviewDetails: a,
              onCatalogReview: r,
              onImageReview: s,
              onInputSend: i,
              onPageRedirection: o,
              onStoreIdReceived: l,
              onBannerPreview: A
            } = t, c = (0, j.useCallback)(Xi("theme-preview", Hi, n, e), [n, e]), d = (0, j.useCallback)(Xi("theme-review-details", Yi, a, e), [a, e]), w = (0, j.useCallback)(Xi("catalog-review", Wi, r, e), [r, e]), g = (0, j.useCallback)(Xi("image-review", Ki, s, e), [s, e]), u = (0, j.useCallback)(Xi("input-send", Vi, i, e), [i, e]), p = (0, j.useCallback)(Xi("page-redirection", $i, o, e), [o, e]), b = (0, j.useCallback)(Xi("store-id-received", qi, l, e), [l, e]), h = (0, j.useCallback)(Xi("banner-preview", Qi, A, e), [A, e]);
            return (0, In.zX)(Mi.THEME.PREVIEW, n ? c : void 0), (0, In.zX)(Mi.THEME.REVIEW_DETAILS, a ? d : void 0), (0, In.zX)(Mi.CATALOG.PREVIEW, r ? w : void 0), (0, In.zX)(Mi.CATALOG.IMAGE, s ? g : void 0), (0, In.zX)(Mi.INPUT.SEND, i ? u : void 0), (0, In.zX)(Mi.PAGE.REDIRECTION, o ? p : void 0), (0, In.zX)(Mi.STORE.GET_STORE_ID, l ? b : void 0, {
              once: !0
            }), (0, In.zX)(Mi.BANNER.PREVIEW, A ? h : void 0), (0, j.useEffect)((() => {
              if (e) {
                const t = [];
                a && ("function" == typeof a ? t.push("Theme Review (â valid)") : (t.push("Theme Review (â invalid - not a function)"), console.error("â onThemeReviewDetails must be a function, received:", typeof a))), r && ("function" == typeof r ? t.push("Catalog Review (â valid)") : (t.push("Catalog Review (â invalid - not a function)"), console.error("â onCatalogReview must be a function, received:", typeof r))), s && ("function" == typeof s ? t.push("Image Review (â valid)") : (t.push("Image Review (â invalid - not a function)"), console.error("â onImageReview must be a function, received:", typeof s))), i && ("function" == typeof i ? t.push("Input Send (â valid)") : (t.push("Input Send (â invalid - not a function)"), console.error("â onInputSend must be a function, received:", typeof i))), o && ("function" == typeof o ? t.push("Page Redirection (â valid)") : (t.push("Page Redirection (â invalid - not a function)"), console.error("â onPageRedirection must be a function, received:", typeof o))), l && ("function" == typeof l ? t.push("Store Id Received (â valid)") : (t.push("Store Id Received (â invalid - not a function)"), console.error("â onStoreIdReceived must be a function, received:", typeof l)))
              }
            }), [e, a, r, s, i, o, l, A]), {
              isListening: !!(n && "function" == typeof n || a && "function" == typeof a || r && "function" == typeof r || s && "function" == typeof s || i && "function" == typeof i || o && "function" == typeof o || l && "function" == typeof l || A && "function" == typeof A)
            }
          },
          to = ["/home", "/inventory", "/listings", "/shipping", "/store-builder", "/analytics-dashboard", "/marketing"];

        function eo(t) {
          return to.some((e => t === e || t.startsWith(e + "/")))
        }
        var no = function(t, e, n, a) {
          return new(n || (n = Promise))((function(r, s) {
            function i(t) {
              try {
                l(a.next(t))
              } catch (t) {
                s(t)
              }
            }

            function o(t) {
              try {
                l(a.throw(t))
              } catch (t) {
                s(t)
              }
            }

            function l(t) {
              var e;
              t.done ? r(t.value) : (e = t.value, e instanceof n ? e : new n((function(t) {
                t(e)
              }))).then(i, o)
            }
            l((a = a.apply(t, e || [])).next())
          }))
        };
        const ao = {
            inventory: "INVENTORY",
            listings: "LISTINGS",
            shipping: "SHIPPING",
            marketing: "MARKETING",
            "store-builder": "STORE_BUILDER",
            dashboard: "DASHBOARD",
            home: "HOME"
          },
          ro = (t, e) => `/ren/v1/dashboard/${ao[t]}/${e}`;

        function so(t) {
          const e = Math.floor((Date.now() - t) / 1e3);
          if (e < 60) return "just now";
          const n = Math.floor(e / 60);
          if (n < 60) return `${n}m ago`;
          const a = Math.floor(n / 60);
          return a < 24 ? `${a}h ago` : `${Math.floor(a/24)}d ago`
        }
        const io = {
          Listings: "tw-bg-[rgba(122,162,255,0.1)] tw-text-[#7aa2ff]",
          Inventory: "tw-bg-[rgba(167,139,250,0.1)] tw-text-[#a78bfa]",
          Marketing: "tw-bg-[rgba(244,114,182,0.1)] tw-text-[#f472b6]",
          Shipping: "tw-bg-[rgba(94,234,212,0.1)] tw-text-[#5eead4]",
          "Store Builder": "tw-bg-[rgba(110,231,183,0.1)] tw-text-[#6ee7b7]",
          Analytics: "tw-bg-[rgba(251,146,60,0.1)] tw-text-[#fb923c]",
          Payments: "tw-bg-[rgba(250,204,21,0.1)] tw-text-[#facc15]"
        };

        function oo(t) {
          for (const [e, n] of Object.entries(io))
            if (t.toLowerCase().includes(e.toLowerCase())) return n;
          return "tw-bg-[rgba(0,204,189,0.1)] tw-text-[#00CCBD]"
        }

        function lo(t) {
          var e;
          const n = null !== (e = t.agentLabel[0]) && void 0 !== e ? e : "Agent";
          return {
            agent: "AZai",
            platforms: [t.program],
            agentType: n,
            agentTypeColor: oo(n),
            description: t.description,
            time: so(t.updateTimestamp),
            statusColor: "tw-bg-emerald-500"
          }
        }
        const Ao = {
          RISK: "tw-border-[rgba(248,113,113,0.2)] tw-bg-[rgba(248,113,113,0.08)] tw-text-red-400",
          CAUTION: "tw-border-[rgba(251,191,36,0.2)] tw-bg-[rgba(251,191,36,0.08)] tw-text-amber-400",
          INFO: "tw-border-[rgba(96,165,250,0.2)] tw-bg-[rgba(96,165,250,0.08)] tw-text-blue-400"
        };

        function co(t) {
          var e;
          return {
            id: t.id,
            badge: t.tag,
            badgeColor: null !== (e = Ao[t.severity]) && void 0 !== e ? e : Ao.INFO,
            title: t.title,
            description: t.description,
            actionLabel: t.clickToAction.actionLabel,
            prompt: t.clickToAction.actionQuery,
            sessionId: t.clickToAction.sessionId
          }
        }
        const wo = t => no(void 0, void 0, void 0, (function*() {
            return (yield be.get(ro(t, "agent-cards"))).data.agentCards.map(co)
          })),
          go = t => no(void 0, void 0, void 0, (function*() {
            return (yield be.get(ro(t, "activities"))).data.activities.map(lo)
          })),
          uo = {
            staleTime: 3e5,
            retry: !1
          },
          po = t => (0, O.useQuery)(["actions", t], (() => wo(t)), uo),
          bo = t => (0, O.useQuery)(["activities", t], (() => go(t)), uo);
        class ho {
          constructor(t) {
            this.navigate = t, this.handleThemeReview = (t, e) => {
              sessionStorage.setItem("AI-ThemeRecommendation", JSON.stringify(t.content)), this.navigate("/store-appearance")
            }
          }
        }
        const mo = t => new ho(t);
        class xo {
          constructor(t) {
            this.navigate = t, this.handleCatalogReview = (t, e) => {
              console.log("ð¦ Catalog review event received, navigating to add product:", {
                productTitle: t.productTitle,
                category: t.category,
                businessCategory: t.businessCategory
              }), "/catalog/products/add-product" === window.location.pathname || ((ln.isZaiEnabledForOnboarding || ln.isZAIOrchestratorEnabled) && sessionStorage.setItem("azai", "true"), this.navigate("/catalog/products/add-product")), sessionStorage.setItem("AI-CatalogAttributes", JSON.stringify(t.content))
            }, this.handleImageReview = (t, e) => {
              console.log("ð¼ï¸ Image review event received:", {
                content: t.content ? "Image data present" : "No image data"
              }), "/catalog/products/add-product" === window.location.pathname || ((ln.isZaiEnabledForOnboarding || ln.isZAIOrchestratorEnabled) && sessionStorage.setItem("azai", "true"), this.navigate("/catalog/products/add-product")), sessionStorage.setItem("AI-ImagePayload", JSON.stringify(t.content))
            }
          }
        }
        const fo = t => new xo(t);
        var vo;
        ! function(t) {
          t.HOME = "HOME", t.ACCEPT_INVITE = "ACCEPT_INVITE", t.ERROR = "ERROR", t.ANALYTICS = "ANALYTICS", t.ANALYTICS_SALES = "ANALYTICS_SALES", t.ANALYTICS_TRAFFIC = "ANALYTICS_TRAFFIC", t.ANALYTICS_OPERATIONS = "ANALYTICS_OPERATIONS", t.ANALYTICS_RETURNS = "ANALYTICS_RETURNS", t.ANALYTICS_CUSTOMERS = "ANALYTICS_CUSTOMERS", t.ANALYTICS_SEGMENTS = "ANALYTICS_SEGMENTS", t.ANALYTICS_REPORTS = "ANALYTICS_REPORTS", t.CATALOG = "CATALOG", t.CATALOG_PRODUCTS = "CATALOG_PRODUCTS", t.CATALOG_ADD_PRODUCT = "CATALOG_ADD_PRODUCT", t.CATALOG_CATEGORIES = "CATALOG_CATEGORIES", t.CATALOG_INVENTORY = "CATALOG_INVENTORY", t.CATALOG_COLLECTIONS = "CATALOG_COLLECTIONS", t.ORDERS = "ORDERS", t.ORDERS_RETURNS = "ORDERS_RETURNS", t.REVIEWS = "REVIEWS", t.REVIEWS_MANAGE = "REVIEWS_MANAGE", t.STORE_APPEARANCE = "STORE_APPEARANCE", t.GOOGLE_ANALYTICS_CONFIG = "GOOGLE_ANALYTICS_CONFIG", t.SETTINGS = "SETTINGS", t.SETTINGS_PROFILE = "SETTINGS_PROFILE", t.SETTINGS_CUSTOM_DOMAIN = "SETTINGS_CUSTOM_DOMAIN", t.SETTINGS_DELIVERY = "SETTINGS_DELIVERY", t.SETTINGS_CONFIG = "SETTINGS_CONFIG", t.SETTINGS_PAYMENTS = "SETTINGS_PAYMENTS", t.SETTINGS_STORE_TIMINGS = "SETTINGS_STORE_TIMINGS", t.SETTINGS_SOCIAL_MEDIA = "SETTINGS_SOCIAL_MEDIA", t.SETTINGS_STORE_POLICIES = "SETTINGS_STORE_POLICIES", t.SETTINGS_USER_MANAGEMENT = "SETTINGS_USER_MANAGEMENT", t.SETTINGS_TAX = "SETTINGS_TAX", t.SETTINGS_RETURN = "SETTINGS_RETURN", t.SETTINGS_REVIEWS = "SETTINGS_REVIEWS", t.GROWTH = "GROWTH", t.GROWTH_PERFORMANCE_MARKETING = "GROWTH_PERFORMANCE_MARKETING", t.GROWTH_OFFERS = "GROWTH_OFFERS", t.GROWTH_SELL_USING_VIDEOS = "GROWTH_SELL_USING_VIDEOS", t.GROWTH_SEO = "GROWTH_SEO", t.GROWTH_MARKETING_AUTOMATION = "GROWTH_MARKETING_AUTOMATION"
        }(vo || (vo = {}));
        const jo = {
            [vo.HOME]: "/home",
            [vo.ACCEPT_INVITE]: "/accept-invite",
            [vo.ERROR]: "/error",
            [vo.ANALYTICS]: "/analytics",
            [vo.ANALYTICS_SALES]: "/analytics/sales",
            [vo.ANALYTICS_TRAFFIC]: "/analytics/traffic",
            [vo.ANALYTICS_OPERATIONS]: "/analytics/operations",
            [vo.ANALYTICS_RETURNS]: "/analytics/return",
            [vo.ANALYTICS_CUSTOMERS]: "/analytics/customer-details",
            [vo.ANALYTICS_SEGMENTS]: "/analytics/customer-segments",
            [vo.ANALYTICS_REPORTS]: "/analytics/reports",
            [vo.CATALOG]: "/catalog",
            [vo.CATALOG_PRODUCTS]: "/catalog/products",
            [vo.CATALOG_ADD_PRODUCT]: "/catalog/products/add-product",
            [vo.CATALOG_CATEGORIES]: "/catalog/categories",
            [vo.CATALOG_INVENTORY]: "/catalog/inventory",
            [vo.CATALOG_COLLECTIONS]: "/catalog/collections",
            [vo.ORDERS]: "/orders",
            [vo.ORDERS_RETURNS]: "/orders/returns",
            [vo.REVIEWS]: "/reviews",
            [vo.REVIEWS_MANAGE]: "/reviews/manage",
            [vo.STORE_APPEARANCE]: "/store-appearance",
            [vo.GOOGLE_ANALYTICS_CONFIG]: "/performance-marketing/google-analytics",
            [vo.SETTINGS]: "/settings",
            [vo.SETTINGS_PROFILE]: "/settings/profile",
            [vo.SETTINGS_CUSTOM_DOMAIN]: "/settings/custom-domain",
            [vo.SETTINGS_DELIVERY]: "/settings/delivery-settings",
            [vo.SETTINGS_CONFIG]: "/settings/config",
            [vo.SETTINGS_PAYMENTS]: "/settings/payments",
            [vo.SETTINGS_STORE_TIMINGS]: "/settings/store-timings",
            [vo.SETTINGS_SOCIAL_MEDIA]: "/settings/social-media",
            [vo.SETTINGS_STORE_POLICIES]: "/settings/store-policies",
            [vo.SETTINGS_USER_MANAGEMENT]: "/settings/user-management",
            [vo.SETTINGS_TAX]: "/settings/gst-seller",
            [vo.SETTINGS_RETURN]: "/settings/orders/returns/config",
            [vo.SETTINGS_REVIEWS]: "settings/reviews",
            [vo.GROWTH]: "/growth",
            [vo.GROWTH_PERFORMANCE_MARKETING]: "/performance-marketing",
            [vo.GROWTH_OFFERS]: "/offers",
            [vo.GROWTH_SELL_USING_VIDEOS]: "/growth/sell-using-videos",
            [vo.GROWTH_SEO]: "/performance-marketing/seo",
            [vo.GROWTH_MARKETING_AUTOMATION]: "/performance-marketing/marketing-automation"
          },
          Eo = t => ({
            handlePageRedirection: e => {
              const n = function(t) {
                var e, n;
                return null !== (n = null === (e = t.content) || void 0 === e ? void 0 : e.pageType) && void 0 !== n ? n : null
              }(e);
              if (!n) return void console.error("No pageType found in payload");
              const a = function(t) {
                const e = t.toUpperCase();
                return jo[e]
              }(n);
              if (!a) return console.error(`Unknown page type: ${n}`), void console.error(`Available page types: ${Object.values(vo).join(", ")}`);
              t(a)
            }
          }),
          yo = {
            DEVELOPMENT: "beta.smartbiz.in",
            ALPHA: "alpha.smartbiz.in",
            BETA: "beta.smartbiz.in",
            GAMMA: "gamma.smartbiz.in",
            PROD: "www.smartbiz.in"
          },
          Co = new class {
            constructor() {
              this.isThemePreviewModalOpen = !1, this.isBannerPreviewModalOpen = !1, this.isLoading = !1, this.themePreviewData = null, this.themeTemplateData = null, this.bannerVariant = "A", this.bannerVariantData = null, this.bannerDeviceMode = "desktop", this.setLoading = t => {
                this.isLoading = t
              }, this.setThemePreviewData = t => {
                this.themePreviewData = t
              }, this.setThemeTemplateData = t => {
                this.themeTemplateData = t
              }, this.openThemePreviewModal = () => {
                this.isThemePreviewModalOpen = !0
              }, this.closeThemePreviewModal = () => {
                this.isThemePreviewModalOpen = !1
              }, this.openBannerPreviewModal = (t = "A") => {
                this.bannerVariant = t, this.isBannerPreviewModalOpen = !0
              }, this.closeBannerPreviewModal = () => {
                this.isBannerPreviewModalOpen = !1
              }, this.setBannerVariantData = t => {
                this.bannerVariantData = t
              }, this.setBannerDeviceMode = t => {
                this.bannerDeviceMode = t
              }, (0, st.rC)(this, {
                isThemePreviewModalOpen: st.LO,
                isBannerPreviewModalOpen: st.LO,
                isLoading: st.LO,
                themePreviewData: st.LO,
                themeTemplateData: st.LO,
                bannerVariant: st.LO,
                bannerVariantData: st.LO,
                bannerDeviceMode: st.LO,
                stageHost: st.Fl,
                openThemePreviewModal: st.aD,
                closeThemePreviewModal: st.aD,
                openBannerPreviewModal: st.aD,
                closeBannerPreviewModal: st.aD,
                setThemePreviewData: st.aD,
                setThemeTemplateData: st.aD,
                setLoading: st.aD,
                setBannerVariantData: st.aD,
                setBannerDeviceMode: st.aD
              })
            }
            get stageHost() {
              var t, e;
              const n = window.location.hostname,
                a = null !== (t = tt[n]) && void 0 !== t ? t : "DEVELOPMENT";
              return null !== (e = yo[a]) && void 0 !== e ? e : "beta.smartbiz.in"
            }
          };
        class Oo {
          constructor() {
            this.handleBannerPreview = t => {
              var e, n, a;
              Co.setBannerVariantData(null === (e = t.content) || void 0 === e ? void 0 : e.variant), (null === (n = t.content) || void 0 === n ? void 0 : n.deviceMode) && Co.setBannerDeviceMode(null === (a = t.content) || void 0 === a ? void 0 : a.deviceMode), Co.openBannerPreviewModal()
            }, this.handleBannerApply = t => {
              var e, n, a;
              Co.setBannerVariantData(null === (e = t.content) || void 0 === e ? void 0 : e.variant), console.log("Applying banner variant:", null === (a = null === (n = t.content) || void 0 === n ? void 0 : n.variant) || void 0 === a ? void 0 : a.variant_number)
            }, this.handleBannerEvent = t => {
              "apply" === t.action ? this.handleBannerApply(t) : this.handleBannerPreview(t)
            }
          }
        }
        const No = () => ({
            handleStoreIdReceived: t => {
              return e = void 0, n = void 0, r = function*() {
                var t;
                try {
                  const e = yield(0, _.tx)();
                  if (null == e ? void 0 : e.data) {
                    const n = ((t, e) => {
                        if (t.length !== e.length) return !0;
                        const n = t.map((t => t.storeId)).sort(),
                          a = e.map((t => t.storeId)).sort();
                        return JSON.stringify(n) !== JSON.stringify(a)
                      })(e.data, ln.allStoreDetails),
                      a = (0, _.NU)(e.data),
                      r = (null == a ? void 0 : a.storeId) !== (null === (t = ln.currentStoreDetails) || void 0 === t ? void 0 : t.storeId);
                    (0, st.z)((() => {
                      n && ln.handleAllStoreDetails(e.data), a && r && (localStorage.setItem("storeURI", null == a ? void 0 : a.storeURI), localStorage.setItem("shopId", a.storeId), ln.handleCurrentStoreDetails(a))
                    }))
                  }
                } catch (t) {
                  console.error("Failed to refresh store details after StoreIdReceived event:", t)
                }
              }, new((a = void 0) || (a = Promise))((function(t, s) {
                function i(t) {
                  try {
                    l(r.next(t))
                  } catch (t) {
                    s(t)
                  }
                }

                function o(t) {
                  try {
                    l(r.throw(t))
                  } catch (t) {
                    s(t)
                  }
                }

                function l(e) {
                  var n;
                  e.done ? t(e.value) : (n = e.value, n instanceof a ? n : new a((function(t) {
                    t(n)
                  }))).then(i, o)
                }
                l((r = r.apply(e, n || [])).next())
              }));
              var e, n, a, r
            }
          }),
          So = "radial-gradient(50% 50% at 50% 117.71%, #9ce5f8 0%, #0678ff 100%)",
          ko = ({
            className: t
          }) => (0, a.jsxs)("svg", Object.assign({
            width: "18",
            height: "19",
            viewBox: "0 0 18 19",
            fill: "none",
            xmlns: "http://www.w3.org/2000/svg",
            className: t
          }, {
            children: [(0, a.jsx)("mask", Object.assign({
              id: "mask0_152_32030",
              style: {
                maskType: "alpha"
              },
              maskUnits: "userSpaceOnUse",
              x: "0",
              y: "0",
              width: "18",
              height: "19"
            }, {
              children: (0, a.jsx)("circle", {
                cx: "9",
                cy: "9.5",
                r: "9",
                fill: "#D9D9D9"
              })
            })), (0, a.jsx)("g", Object.assign({
              mask: "url(#mask0_152_32030)"
            }, {
              children: (0, a.jsxs)("g", Object.assign({
                filter: "url(#filter0_f_152_32030)"
              }, {
                children: [(0, a.jsx)("circle", {
                  cx: "9.05914",
                  cy: "9.44",
                  r: "8.94",
                  fill: "url(#paint0_linear_152_32030)"
                }), (0, a.jsx)("circle", {
                  cx: "9.05914",
                  cy: "9.44",
                  r: "9.44",
                  stroke: "white"
                })]
              }))
            })), (0, a.jsxs)("defs", {
              children: [(0, a.jsxs)("filter", Object.assign({
                id: "filter0_f_152_32030",
                x: "-3.38086",
                y: "-3",
                width: "24.88",
                height: "24.88",
                filterUnits: "userSpaceOnUse",
                colorInterpolationFilters: "sRGB"
              }, {
                children: [(0, a.jsx)("feFlood", {
                  floodOpacity: "0",
                  result: "BackgroundImageFix"
                }), (0, a.jsx)("feBlend", {
                  mode: "normal",
                  in: "SourceGraphic",
                  in2: "BackgroundImageFix",
                  result: "shape"
                }), (0, a.jsx)("feGaussianBlur", {
                  stdDeviation: "1.25",
                  result: "effect1_foregroundBlur_152_32030"
                })]
              })), (0, a.jsxs)("linearGradient", Object.assign({
                id: "paint0_linear_152_32030",
                x1: "0.119141",
                y1: "9.44",
                x2: "17.9991",
                y2: "9.44",
                gradientUnits: "userSpaceOnUse"
              }, {
                children: [(0, a.jsx)("stop", {
                  stopColor: "#0D2A31"
                }), (0, a.jsx)("stop", {
                  offset: "0.350962",
                  stopColor: "#0777FF"
                }), (0, a.jsx)("stop", {
                  offset: "0.711538",
                  stopColor: "#61ECE4"
                }), (0, a.jsx)("stop", {
                  offset: "1",
                  stopColor: "#FAF6F0"
                })]
              }))]
            })]
          })),
          Io = "Disclaimer",
          Mo = (0, D.css)({
            textAlign: "center",
            color: "#7D95B5",
            paddingTop: "8px",
            paddingBottom: "8px",
            paddingLeft: "16px",
            paddingRight: "16px",
            fontFamily: "inherit",
            fontWeight: 400,
            fontStyle: "normal",
            fontSize: "12px",
            lineHeight: "16px",
            letterSpacing: "0%"
          }),
          To = (0, D.css)({
            color: "#0678FF",
            background: "none",
            border: "none",
            padding: 0,
            cursor: "pointer",
            fontFamily: "inherit",
            fontWeight: 400,
            fontSize: "12px",
            lineHeight: "16px",
            "&:hover": {
              color: "#2563eb"
            },
            "&:focus": {
              outline: "2px solid #3b82f6",
              outlineOffset: "1px",
              borderRadius: "2px"
            }
          }),
          Ro = (0, D.css)({
            position: "fixed",
            inset: 0,
            zIndex: 9999,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            backgroundColor: "rgba(0, 0, 0, 0.5)",
            padding: "16px"
          }),
          Bo = (0, D.css)({
            backgroundColor: "white",
            borderRadius: "12px",
            width: "844px",
            maxWidth: "100%",
            maxHeight: "90vh",
            display: "flex",
            flexDirection: "column",
            boxShadow: "0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.1)",
            overflow: "hidden",
            border: "1px solid #e5e7eb",
            paddingBottom: "24px",
            gap: "12px",
            opacity: 1
          }),
          _o = (0, D.css)({
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            height: "48px",
            paddingTop: "12px",
            paddingRight: "24px",
            paddingBottom: "12px",
            paddingLeft: "24px",
            backgroundColor: "#f9fafb",
            opacity: 1
          }),
          Do = (0, D.css)({
            display: "flex",
            alignItems: "center",
            gap: "8px",
            fontFamily: "'Amazon Ember', Arial, sans-serif",
            fontWeight: 700,
            fontStyle: "normal",
            fontSize: "14px",
            lineHeight: "18px",
            letterSpacing: "0%",
            color: "#384A62"
          }),
          Lo = (0, D.css)({
            background: "none",
            border: "none",
            cursor: "pointer",
            padding: "4px",
            borderRadius: "4px",
            color: "#1f2937",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            "&:hover": {
              color: "#111827",
              backgroundColor: "#f3f4f6"
            }
          }),
          Fo = (0, D.css)({
            paddingRight: "24px",
            paddingLeft: "24px",
            paddingTop: "8px",
            overflowY: "auto",
            fontFamily: "'Amazon Ember', Arial, sans-serif",
            fontWeight: 400,
            fontStyle: "normal",
            fontSize: "12px",
            lineHeight: "24px",
            letterSpacing: "0px",
            color: "#384A62",
            opacity: 1,
            gap: "10px",
            flex: 1,
            "& p": {
              marginBottom: "10px"
            },
            "& ol": {
              listStyleType: "decimal",
              listStylePosition: "inside",
              paddingLeft: "8px",
              "& li": {
                marginBottom: "10px"
              }
            }
          }),
          Po = (0, D.css)({
            padding: "4px 20px 0",
            display: "flex",
            justifyContent: "flex-end"
          }),
          zo = (0, D.css)({
            color: "white",
            borderWidth: "1px",
            borderStyle: "solid",
            borderColor: "#5C8FFF66",
            borderRadius: "8px",
            width: "71px",
            height: "32px",
            paddingTop: "4px",
            paddingRight: "12px",
            paddingBottom: "4px",
            paddingLeft: "12px",
            gap: "4px",
            fontFamily: "'Amazon Ember', Arial, sans-serif",
            fontWeight: 400,
            fontStyle: "normal",
            fontSize: "14px",
            lineHeight: "20px",
            letterSpacing: "0px",
            textAlign: "center",
            cursor: "pointer",
            transition: "background 0.2s, transform 0.2s",
            background: So,
            opacity: 1
          }),
          Uo = (0, D.css)({
            width: "20px",
            height: "20px",
            flexShrink: 0
          }),
          Go = ({
            isOpen: t,
            onClose: e
          }) => {
            const [n, r] = (0, j.useState)(!1);
            (0, j.useEffect)((() => {
              if (!t) return;
              const n = t => {
                "Escape" === t.key && e()
              };
              return document.addEventListener("keydown", n), document.body.style.overflow = "hidden", () => {
                document.removeEventListener("keydown", n), document.body.style.overflow = "unset"
              }
            }), [t, e]);
            const s = (0, j.useCallback)((t => {
              t.target === t.currentTarget && e()
            }), [e]);
            if (!t) return null;
            const i = (0, a.jsx)("div", Object.assign({
              className: Ro,
              onClick: s,
              role: "presentation",
              tabIndex: -1
            }, {
              children: (0, a.jsxs)("div", Object.assign({
                className: Bo,
                role: "dialog",
                "aria-modal": "true",
                "aria-label": Io
              }, {
                children: [(0, a.jsxs)("div", Object.assign({
                  className: _o
                }, {
                  children: [(0, a.jsxs)("div", Object.assign({
                    className: Do
                  }, {
                    children: [(0, a.jsx)(ko, {
                      className: Uo
                    }), (0, a.jsx)("span", {
                      children: Io
                    })]
                  })), (0, a.jsx)("button", Object.assign({
                    className: Lo,
                    onClick: t => {
                      t.preventDefault(), t.stopPropagation(), e()
                    },
                    "aria-label": "Close disclaimer",
                    type: "button"
                  }, {
                    children: "â"
                  }))]
                })), (0, a.jsxs)("div", Object.assign({
                  className: Fo
                }, {
                  children: [(0, a.jsx)("p", {
                    children: 'The responses and outputs generated by the Website Builder Agent, Support Agent, and Catalogue Agent (collectively, the "AI Tools") use artificial intelligence ("AI") and are provided on an "as-is" and "as-available" basis. The responses may contain errors or omissions and may be similar across users.'
                  }), (0, a.jsx)("p", {
                    children: 'Suggestions are provided on a best-effort basis and may rely on pre-existing templates within Amazon Smart Commerce Solutions Private Limited ("Amazon"). Such templates may be accessed or used by multiple users, and Amazon retains all rights, title, and copyright in these templates.'
                  }), (0, a.jsx)("p", {
                    children: 'By clicking "Proceed" the seller acknowledges and agrees that:'
                  }), (0, a.jsxs)("ol", {
                    children: [(0, a.jsx)("li", {
                      children: "They have reviewed all generated content and responses and are proceeding after verifying that the information is correct, accurate, and complete."
                    }), (0, a.jsx)("li", {
                      children: "Amazon and its affiliates are not liable for any errors, omissions, inaccuracies, or outcomes resulting from the use of AI-generated content and do not guarantee the accuracy, completeness, reliability, or timeliness of any responses."
                    }), (0, a.jsx)("li", {
                      children: "They are responsible for independently verifying the information and, where appropriate, consulting the relevant Help Pages or other applicable guidance."
                    })]
                  }), (0, a.jsx)("p", {
                    children: "For the Support Agent, the seller further acknowledges that responses may rely on publicly available information from third-party websites in addition to Amazon resources, and Amazon does not guarantee the accuracy, completeness, or reliability of such responses."
                  }), (0, a.jsx)("p", {
                    children: "Sellers must not share personal data, sensitive information, or any unlawful, harmful, infringing, or abusive content while using the AI Tools."
                  })]
                })), (0, a.jsx)("div", Object.assign({
                  className: Po
                }, {
                  children: (0, a.jsx)("button", Object.assign({
                    className: zo,
                    onClick: e,
                    onMouseEnter: () => r(!0),
                    onMouseLeave: () => r(!1),
                    style: n ? {
                      background: "radial-gradient(50% 50% at 50% 111.87%, #FFAFA0 0%, #0678FF 100%)",
                      transform: "scale(1.02)"
                    } : {
                      background: So
                    },
                    type: "button"
                  }, {
                    children: "Proceed"
                  }))
                }))]
              }))
            }));
            return (0, jr.createPortal)(i, document.body)
          },
          Zo = (0, v.Pi)((() => {
            const [t, e] = (0, j.useState)(!1);
            return (0, a.jsxs)(a.Fragment, {
              children: [(0, a.jsxs)("div", Object.assign({
                className: Mo
              }, {
                children: [(0, a.jsx)("div", Object.assign({
                  style: {
                    whiteSpace: "nowrap"
                  }
                }, {
                  children: "Responses are AI-generated and may contain errors."
                })), (0, a.jsxs)("div", {
                  children: [(0, a.jsx)("span", {
                    children: "Verify before proceeding, "
                  }), (0, a.jsx)("button", Object.assign({
                    onClick: () => e(!0),
                    className: To,
                    type: "button"
                  }, {
                    children: "See full disclaimer."
                  }))]
                })]
              })), (0, a.jsx)(Go, {
                isOpen: t,
                onClose: () => e(!1)
              })]
            })
          }));
        var Ho = n(64724);
        const Yo = (0, D.css)({
            background: "rgba(255, 255, 255, 0.8)",
            border: "1px solid #dee4ec",
            borderRadius: 12,
            padding: 12,
            display: "flex",
            flexDirection: "column",
            alignItems: "flex-end",
            justifyContent: "space-between",
            cursor: "pointer",
            minHeight: 100,
            transition: "box-shadow 0.15s ease, border-color 0.15s ease",
            "&:hover": {
              boxShadow: "0px 4px 8px 0px rgba(43, 108, 189, 0.12)",
              borderColor: "#0066DC",
              "& .card-icon": {
                color: "#0066DC"
              }
            }
          }),
          Wo = (0, D.css)({
            fontFamily: '"Amazon Ember", sans-serif',
            fontSize: 12,
            lineHeight: "16px",
            color: "#384a62",
            width: "100%"
          }),
          Ko = (0, D.css)({
            fontFamily: '"Amazon Ember", sans-serif',
            fontWeight: 700,
            color: "#ee5a46"
          }),
          Vo = (0, D.css)({
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            transform: "scaleY(-1)",
            color: "#384a62"
          });
        var $o = ({
          score: t = 20,
          maxScore: e = 100,
          prompt: n = "Help me improve my on-site conversion score"
        }) => {
          const {
            sendMessage: r
          } = (0, In.Lf)(), [s, i] = (0, j.useState)(null);
          (0, j.useEffect)((() => {
            ps().then((t => {
              (null == t ? void 0 : t.email) && i(t.email)
            }))
          }), []);
          const o = () => {
            r([{
              type: "text",
              text: n
            }])
          };
          return (0, a.jsxs)("div", Object.assign({
            className: Yo,
            onClick: o,
            role: "button",
            tabIndex: 0,
            onKeyDown: t => {
              "Enter" !== t.key && " " !== t.key || (t.preventDefault(), o())
            }
          }, {
            children: [(0, a.jsxs)("p", Object.assign({
              className: Wo
            }, {
              children: ["Your on-site conversion score is", " ", (0, a.jsxs)("span", Object.assign({
                className: Ko
              }, {
                children: [t, "/", e, ","]
              })), " ", "I can help improve"]
            })), (0, a.jsx)("div", Object.assign({
              className: `${Vo} card-icon`
            }, {
              children: (0, a.jsx)(Ho.Z, {
                size: 16
              })
            }))]
          }))
        };
        const qo = (0, D.css)({
            background: "rgba(255, 255, 255, 0.8)",
            border: "1px solid #dee4ec",
            borderRadius: 12,
            padding: 12,
            display: "flex",
            flexDirection: "column",
            alignItems: "flex-end",
            justifyContent: "space-between",
            cursor: "pointer",
            minHeight: 100,
            transition: "box-shadow 0.15s ease, border-color 0.15s ease",
            "&:hover": {
              boxShadow: "0px 4px 8px 0px rgba(43, 108, 189, 0.12)",
              borderColor: "#0066DC",
              "& .card-icon": {
                color: "#0066DC"
              }
            }
          }),
          Qo = (0, D.css)({
            fontFamily: '"Amazon Ember", sans-serif',
            fontSize: 12,
            lineHeight: "16px",
            color: "#384a62",
            width: "100%"
          }),
          Xo = (0, D.css)({
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            transform: "scaleY(-1)",
            color: "#384a62"
          });
        var Jo = ({
          text: t,
          prompt: e
        }) => {
          const {
            sendMessage: n
          } = (0, In.Lf)(), r = () => {
            n([{
              type: "text",
              text: e || t
            }])
          };
          return (0, a.jsxs)("div", Object.assign({
            className: qo,
            onClick: r,
            role: "button",
            tabIndex: 0,
            onKeyDown: t => {
              "Enter" !== t.key && " " !== t.key || (t.preventDefault(), r())
            }
          }, {
            children: [(0, a.jsx)("p", Object.assign({
              className: Qo
            }, {
              children: t
            })), (0, a.jsx)("div", Object.assign({
              className: `${Xo} card-icon`
            }, {
              children: (0, a.jsx)(Ho.Z, {
                size: 16
              })
            }))]
          }))
        };
        const {
          ERROR_SCREEN_HEADER: tl
        } = f.ErrorMessages, el = () => {
          return t = void 0, e = void 0, a = function*() {
            const {
              config: t
            } = (0, $t.R6)(), e = {
              domain: t.domain,
              associationHandle: t.associationHandle,
              returnToUrl: (0, $t.vM)(t.returnToUrlOnboarding),
              pageId: t.pageId
            }, n = {
              AuthPortalUrlRequest: JSON.stringify(e)
            };
            try {
              return (yield pe.post("api-db/resources/v2/dashboard/merchant/register", {}, {
                headers: n
              })).data
            } catch (t) {
              (0, f.LT)(Object.assign(Object.assign({}, f.ar), {
                text: tl
              }))
            }
          }, new((n = void 0) || (n = Promise))((function(r, s) {
            function i(t) {
              try {
                l(a.next(t))
              } catch (t) {
                s(t)
              }
            }

            function o(t) {
              try {
                l(a.throw(t))
              } catch (t) {
                s(t)
              }
            }

            function l(t) {
              var e;
              t.done ? r(t.value) : (e = t.value, e instanceof n ? e : new n((function(t) {
                t(e)
              }))).then(i, o)
            }
            l((a = a.apply(t, e || [])).next())
          }));
          var t, e, n, a
        };
        const {
          ERROR_SCREEN_HEADER: nl
        } = f.ErrorMessages, al = () => {
          return t = void 0, e = void 0, a = function*() {
            try {
              return (yield pe.get("api-db/resources/v2/dashboard/agreement")).data
            } catch (t) {
              (0, f.LT)(Object.assign(Object.assign({}, f.ar), {
                text: nl
              }))
            }
          }, new((n = void 0) || (n = Promise))((function(r, s) {
            function i(t) {
              try {
                l(a.next(t))
              } catch (t) {
                s(t)
              }
            }

            function o(t) {
              try {
                l(a.throw(t))
              } catch (t) {
                s(t)
              }
            }

            function l(t) {
              var e;
              t.done ? r(t.value) : (e = t.value, e instanceof n ? e : new n((function(t) {
                t(e)
              }))).then(i, o)
            }
            l((a = a.apply(t, e || [])).next())
          }));
          var t, e, n, a
        };
        var rl = () => {
          const [t, e] = (0, j.useState)(!1), [n, r] = (0, j.useState)(!1), [s, i] = (0, j.useState)(null), o = (0, O.useMutation)(el), {
            mutateAsync: l
          } = (0, _.yt)(), {
            refetch: A
          } = (0, _.xB)(!1), {
            refetch: c
          } = (() => {
            const {
              data: t,
              isLoading: e,
              error: n,
              refetch: a
            } = (0, O.useQuery)("SellerAgreement", al, {
              enabled: !1
            });
            return {
              data: t,
              isLoading: e,
              error: n,
              refetch: a
            }
          })();
          (0, j.useEffect)((() => {
            var t, n, a, r;
            t = void 0, n = void 0, r = function*() {
              try {
                const t = yield o.mutateAsync(), n = "string" == typeof t && "" === t ? {
                  success: !0
                } : t;
                if (null == n ? void 0 : n.redirectUrl) try {
                  const t = new URLSearchParams(window.location.search),
                    e = new URL(n.redirectUrl),
                    a = e.searchParams.get("openid.return_to");
                  if (a) {
                    const r = new URL(a);
                    t.forEach(((t, e) => {
                      X.has(e) && r.searchParams.set(e, t)
                    })), e.searchParams.set("openid.return_to", r.toString()), n.redirectUrl = e.toString()
                  }
                } catch (t) {}
                i(n), console.log("Redirect URL", null == n ? void 0 : n.redirectUrl), (null == n ? void 0 : n.redirectUrl) && "LOGIN_AND_SECURITY_EMAIL" === (null == n ? void 0 : n.redirectType) && e(!0), yield l(), ((null == n ? void 0 : n.success) || "" === t) && (yield A()), yield c()
              } catch (t) {
                console.error("Store onboarding API error:", t)
              }
            }, new((a = void 0) || (a = Promise))((function(e, s) {
              function i(t) {
                try {
                  l(r.next(t))
                } catch (t) {
                  s(t)
                }
              }

              function o(t) {
                try {
                  l(r.throw(t))
                } catch (t) {
                  s(t)
                }
              }

              function l(t) {
                var n;
                t.done ? e(t.value) : (n = t.value, n instanceof a ? n : new a((function(t) {
                  t(n)
                }))).then(i, o)
              }
              l((r = r.apply(t, n || [])).next())
            }))
          }), []);
          const d = () => {
            switch (null == s ? void 0 : s.redirectType) {
              case "LOGIN_AND_SECURITY_EMAIL":
                return "Add Email Address";
              case "LOGIN_AND_SECURITY_MOBILE":
                return "Add Mobile Number"
            }
          };
          return t ? (0, a.jsx)(dn.ZP, Object.assign({
            open: t,
            width: "30rem",
            bodySpacingInset: "450 450 450 450"
          }, {
            children: (0, a.jsxs)(z.Z, Object.assign({
              spacing: "400"
            }, {
              children: [(0, a.jsx)(W.default, Object.assign({
                type: "h300"
              }, {
                children: d()
              })), (0, a.jsx)(U.Z, {}), (0, a.jsx)(W.default, Object.assign({
                type: "b300",
                color: "secondary"
              }, {
                children: (() => {
                  switch (null == s ? void 0 : s.redirectType) {
                    case "LOGIN_AND_SECURITY_EMAIL":
                      return "Please add a valid email address to continue with the onboarding process.";
                    case "LOGIN_AND_SECURITY_MOBILE":
                      return "Please add a valid mobile number to continue with the onboarding process."
                  }
                })()
              })), (0, a.jsxs)(P.default, Object.assign({
                onClick: () => {
                  r(!0), (null == s ? void 0 : s.redirectUrl) ? window.location.replace(s.redirectUrl) : (e(!1), r(!1))
                },
                type: "primary",
                minWidth: "100%",
                disabled: n
              }, {
                children: [n && (0, a.jsx)(ke.Z, {
                  type: "circular",
                  size: "small"
                }), d()]
              }))]
            }))
          })) : null
        };
        const sl = "azai-app-event",
          il = new Set(Object.values(In.NW));

        function ol() {
          (0, j.useEffect)((() => {
            const t = t => {
              const e = t.detail;
              e && "string" == typeof e.type && e.type ? null != e.payload && "object" == typeof e.payload ? il.has(`app.${e.type}`) ? (0, In.aI)(e.type, e.payload) : console.error(`[useMFEEventRelay] Unrecognized event type: "${e.type}". Supported types: ${[...il].join(", ")}. Event will NOT be forwarded to the SDK.`) : console.error("[useMFEEventRelay] Invalid CustomEvent detail: payload must be a non-null object.", {
                received: e
              }) : console.error("[useMFEEventRelay] Invalid CustomEvent detail: missing or empty event type.", {
                received: e
              })
            };
            return window.addEventListener(sl, t), () => {
              window.removeEventListener(sl, t)
            }
          }), [])
        }
        var ll = n(72761),
          Al = n(41962),
          cl = function(t, e, n, a) {
            return new(n || (n = Promise))((function(r, s) {
              function i(t) {
                try {
                  l(a.next(t))
                } catch (t) {
                  s(t)
                }
              }

              function o(t) {
                try {
                  l(a.throw(t))
                } catch (t) {
                  s(t)
                }
              }

              function l(t) {
                var e;
                t.done ? r(t.value) : (e = t.value, e instanceof n ? e : new n((function(t) {
                  t(e)
                }))).then(i, o)
              }
              l((a = a.apply(t, e || [])).next())
            }))
          };

        function dl(t, e, n) {
          return cl(this, void 0, void 0, (function*() {
            return (yield ue.get(`/stores/${t}/ui-experience/layouts?layoutPath=${e}&templateType=${n}`)).data
          }))
        }

        function wl(t, e, n) {
          return cl(this, void 0, void 0, (function*() {
            return (yield ue.post(`/stores/${t}/ui-experience/drafts/${e}?action=PUBLISH`, {
              storeUrl: n
            })).data
          }))
        }
        var gl = function(t, e, n, a) {
          return new(n || (n = Promise))((function(r, s) {
            function i(t) {
              try {
                l(a.next(t))
              } catch (t) {
                s(t)
              }
            }

            function o(t) {
              try {
                l(a.throw(t))
              } catch (t) {
                s(t)
              }
            }

            function l(t) {
              var e;
              t.done ? r(t.value) : (e = t.value, e instanceof n ? e : new n((function(t) {
                t(e)
              }))).then(i, o)
            }
            l((a = a.apply(t, e || [])).next())
          }))
        };

        function ul(t, e) {
          var n, a, r, s, i;
          if (!t || "object" != typeof t) return t;
          const o = JSON.parse(JSON.stringify(t)),
            l = pl(o.children, "HERO_BANNER");
          if (!l || !(null === (n = l.children) || void 0 === n ? void 0 : n.length)) return o;
          const A = l.children[0];
          if (!(null === (a = null == A ? void 0 : A.children) || void 0 === a ? void 0 : a.length)) return o;
          const c = A.children.find((t => "IMAGE_SELECTOR" === t.type));
          if (!(null === (r = null == c ? void 0 : c.children) || void 0 === r ? void 0 : r.length)) return o;
          for (const t of c.children) {
            if ("IMAGE_DRAG_AND_DROP" !== t.type) continue;
            const n = (t.name || "").toLowerCase();
            n.includes("desktop") && (null === (s = t.values) || void 0 === s ? void 0 : s.data) ? t.values.data.url = e.desktop_url : n.includes("mobile") && (null === (i = t.values) || void 0 === i ? void 0 : i.data) && (t.values.data.url = e.mobile_url)
          }
          return o
        }

        function pl(t, e) {
          if (!t) return null;
          for (const n of t) {
            if (n.type === e) return n;
            const t = pl(n.children, e);
            if (t) return t
          }
          return null
        }

        function bl(t, e) {
          var n;
          return gl(this, void 0, void 0, (function*() {
            if (!e) return {};
            try {
              return null === (n = yield dl(t, e, "DRAFT")) || void 0 === n ? void 0 : n.layoutJson
            } catch (t) {
              return console.error(`Failed to fetch from path: ${e}`, t), {}
            }
          }))
        }
        const hl = ({
          open: t,
          onOpenChange: e,
          variant: n,
          initialDevice: r = "desktop"
        }) => {
          var s, i, o, l, A, c;
          const [d, w] = (0, j.useState)(r), [g, u] = (0, j.useState)(!1), [p, b] = (0, j.useState)(!1), [h, m] = (0, j.useState)(null), [x, f] = (0, j.useState)(""), [v, E] = (0, j.useState)(5), y = `smartbiz.in/${null!==(i=null===(s=null==ln?void 0:ln.currentStoreDetails)||void 0===s?void 0:s.storeURI)&&void 0!==i?i:"YourStore"}`, C = (0, j.useRef)(null), [O, N] = (0, j.useState)(!1);
          (0, j.useEffect)((() => {
            t ? (w(r), requestAnimationFrame((() => N(!0)))) : N(!1)
          }), [t, r]), (0, j.useEffect)((() => p ? (C.current = setInterval((() => {
            E((t => t <= 1 ? (clearInterval(C.current), b(!1), e(!1), 0) : t - 1))
          }), 1e3), () => {
            C.current && clearInterval(C.current)
          }) : (E(5), void(C.current && clearInterval(C.current)))), [p, e]);
          const S = n ? "desktop" === d ? n.desktop_url : n.mobile_url : "",
            k = null !== (o = null == n ? void 0 : n.concept) && void 0 !== o ? o : "";
          (0, j.useEffect)((() => {
            if (!t) return;
            const n = t => {
              "Escape" === t.key && e(!1)
            };
            return document.addEventListener("keydown", n), document.body.style.overflow = "hidden", () => {
              document.removeEventListener("keydown", n), document.body.style.overflow = "unset"
            }
          }), [t, e]);
          const I = (0, j.useCallback)((t => {
              t.target === t.currentTarget && e(!1)
            }), [e]),
            M = (0, j.useCallback)((() => {
              return t = void 0, e = void 0, r = function*() {
                var t, e, a;
                if (!n) return;
                const r = null === (t = ln.currentStoreDetails) || void 0 === t ? void 0 : t.storeId,
                  s = null === (e = ln.currentStoreDetails) || void 0 === e ? void 0 : e.storeURI;
                if (r && s) {
                  u(!0), m(null);
                  try {
                    const t = yield function(t, e, n) {
                      return gl(this, void 0, void 0, (function*() {
                        try {
                          const a = (yield function(t) {
                            return cl(this, void 0, void 0, (function*() {
                              return (yield ue.get(`/stores/${t}/ui-experience/drafts?ALL`)).data
                            }))
                          }(t)).find((t => "LIVE" === t.templateState));
                          if (!a) return {
                            success: !1,
                            error: "No live draft found for this store."
                          };
                          const {
                            draftId: r,
                            layouts: s
                          } = a, i = yield Promise.all(s.map((e => gl(this, void 0, void 0, (function*() {
                            const [a, r] = yield Promise.all([bl(t, e.layoutPath), bl(t, e.overrideStyleConfigPath)]);
                            return {
                              pageType: e.pageType,
                              layoutJson: "HOME_PAGE" === e.pageType ? ul(a, n) : a,
                              overrideStyleJson: r
                            }
                          }))))), o = a.universalStyleConfigPath ? yield bl(t, a.universalStyleConfigPath): {}, l = {
                            baseTemplateId: a.baseTemplateId,
                            layouts: i,
                            pageTemplateList: [],
                            themeDetails: a.themeDetails,
                            universalStyleConfig: o
                          };
                          return yield function(t, e, n) {
                            return cl(this, void 0, void 0, (function*() {
                              return (yield ue.put(`/stores/${t}/ui-experience/drafts/${e}`, n)).data
                            }))
                          }(t, r, l), yield wl(t, r, e), {
                            success: !0
                          }
                        } catch (t) {
                          return console.error("Failed to apply banner and publish:", t), {
                            success: !1,
                            error: t instanceof Error ? t.message : "Unknown error occurred"
                          }
                        }
                      }))
                    }(r, s, n);
                    if (t.success) {
                      const t = `https://${Co.stageHost}/${s.toLowerCase()}?utm_experience=preview_${Date.now()}`;
                      f(t), b(!0), (0, In.aI)("send_prompt", {
                        prompt: `I just applied the ${(null==n?void 0:n.concept)||"new"} banner ðð`
                      })
                    } else m(null !== (a = t.error) && void 0 !== a ? a : "Failed to publish banner.")
                  } catch (t) {
                    m("An unexpected error occurred.")
                  } finally {
                    u(!1)
                  }
                } else m("Store details not found. Please try again.")
              }, new((a = void 0) || (a = Promise))((function(n, s) {
                function i(t) {
                  try {
                    l(r.next(t))
                  } catch (t) {
                    s(t)
                  }
                }

                function o(t) {
                  try {
                    l(r.throw(t))
                  } catch (t) {
                    s(t)
                  }
                }

                function l(t) {
                  var e;
                  t.done ? n(t.value) : (e = t.value, e instanceof a ? e : new a((function(t) {
                    t(e)
                  }))).then(i, o)
                }
                l((r = r.apply(t, e || [])).next())
              }));
              var t, e, a, r
            }), [n, e]);
          if (!t) return null;
          const T = (0, a.jsx)("div", Object.assign({
            className: "tw-fixed tw-inset-0 tw-flex tw-items-center tw-justify-center tw-transition-opacity tw-duration-300 tw-ease-out",
            style: {
              backgroundColor: O ? "rgba(0,0,0,0.5)" : "rgba(0,0,0,0)",
              zIndex: 2147483647
            },
            onClick: I,
            role: "presentation",
            tabIndex: -1
          }, {
            children: p ? (0, a.jsxs)("div", Object.assign({
              className: "tw-rounded-xl tw-shadow-2xl tw-p-6 tw-max-w-sm tw-w-full tw-mx-4 tw-text-center tw-overflow-hidden tw-relative tw-transition-all tw-duration-300 tw-ease-out tw-border tw-border-white/10",
              style: {
                opacity: O ? 1 : 0,
                transform: O ? "scale(1) translateY(0)" : "scale(0.95) translateY(10px)",
                background: "linear-gradient(135deg, #0a1224 0%, #0d1a2d 100%)"
              }
            }, {
              children: [(0, a.jsx)("div", Object.assign({
                className: "tw-absolute tw-top-0 tw-left-0 tw-right-0 tw-h-1 tw-bg-white/5"
              }, {
                children: (0, a.jsx)("div", {
                  className: "tw-h-full tw-bg-blue-500",
                  style: {
                    width: v / 5 * 100 + "%",
                    transition: "width 1s linear"
                  }
                })
              })), (0, a.jsx)("div", Object.assign({
                className: "tw-w-12 tw-h-12 tw-mx-auto tw-mb-4 tw-rounded-full tw-bg-green-500/10 tw-flex tw-items-center tw-justify-center"
              }, {
                children: (0, a.jsx)("svg", Object.assign({
                  className: "tw-w-6 tw-h-6 tw-text-green-400",
                  fill: "none",
                  stroke: "currentColor",
                  viewBox: "0 0 24 24"
                }, {
                  children: (0, a.jsx)("path", {
                    strokeLinecap: "round",
                    strokeLinejoin: "round",
                    strokeWidth: 2,
                    d: "M5 13l4 4L19 7"
                  })
                }))
              })), (0, a.jsx)("h3", Object.assign({
                className: "tw-text-lg tw-font-semibold tw-text-white tw-mb-1"
              }, {
                children: "Banner Published"
              })), (0, a.jsx)("p", Object.assign({
                className: "tw-text-sm tw-text-slate-400 tw-mb-5"
              }, {
                children: "Your banner has been published successfully."
              })), (0, a.jsxs)("div", Object.assign({
                className: "tw-flex tw-gap-3 tw-justify-center"
              }, {
                children: [(0, a.jsx)("button", Object.assign({
                  onClick: () => {
                    b(!1), e(!1)
                  },
                  className: "tw-rounded-lg tw-border tw-border-white/10 tw-px-4 tw-py-2 tw-text-sm tw-font-medium tw-text-slate-300 tw-transition-colors hover:tw-bg-white/5"
                }, {
                  children: "Close"
                })), (0, a.jsx)("a", Object.assign({
                  href: x,
                  target: "_blank",
                  rel: "noopener noreferrer",
                  className: "tw-rounded-lg tw-bg-blue-600 tw-px-4 tw-py-2 tw-text-sm tw-font-medium tw-text-white tw-transition-colors hover:tw-bg-blue-700 tw-no-underline"
                }, {
                  children: "Preview Website"
                }))]
              }))]
            })) : (0, a.jsxs)("div", Object.assign({
              className: "tw-max-w-[1200px] tw-w-[90vw] tw-mx-4 tw-overflow-hidden tw-rounded-2xl tw-border tw-border-white/10 tw-shadow-lg tw-relative tw-flex tw-flex-col tw-transition-all tw-duration-300 tw-ease-out",
              style: {
                opacity: O ? 1 : 0,
                transform: O ? "scale(1) translateY(0)" : "scale(0.95) translateY(20px)",
                background: "linear-gradient(135deg, #0a1224 0%, #0d1a2d 100%)"
              },
              role: "dialog",
              "aria-modal": "true",
              "aria-label": `Banner Preview â Variant ${null!==(l=null==n?void 0:n.variant_number)&&void 0!==l?l:""}`
            }, {
              children: [(0, a.jsxs)("div", Object.assign({
                className: "tw-flex tw-flex-col tw-gap-3 tw-border-b tw-border-white/10 tw-px-6 tw-py-4"
              }, {
                children: [(0, a.jsxs)("div", Object.assign({
                  className: "tw-flex tw-items-center tw-justify-between"
                }, {
                  children: [(0, a.jsxs)("h2", Object.assign({
                    className: "tw-text-base tw-font-semibold tw-text-white"
                  }, {
                    children: ["Banner Preview â Variant ", null !== (A = null == n ? void 0 : n.variant_number) && void 0 !== A ? A : ""]
                  })), (0, a.jsxs)("div", Object.assign({
                    className: "tw-flex tw-flex-shrink-0 tw-items-center tw-gap-3"
                  }, {
                    children: [(0, a.jsxs)("div", Object.assign({
                      className: "tw-flex tw-items-center tw-rounded-lg tw-border tw-border-white/10 tw-bg-white/5 tw-p-0.5"
                    }, {
                      children: [(0, a.jsxs)("button", Object.assign({
                        onClick: () => w("desktop"),
                        className: "tw-flex tw-items-center tw-gap-1.5 tw-rounded-md tw-px-3 tw-py-1.5 tw-text-xs tw-font-medium tw-transition-all " + ("desktop" === d ? "tw-bg-white/10 tw-text-white tw-shadow-sm" : "tw-text-slate-400 hover:tw-text-slate-300")
                      }, {
                        children: [(0, a.jsx)(ll.Z, {
                          size: 14
                        }), "Desktop"]
                      })), (0, a.jsxs)("button", Object.assign({
                        onClick: () => w("mobile"),
                        className: "tw-flex tw-items-center tw-gap-1.5 tw-rounded-md tw-px-3 tw-py-1.5 tw-text-xs tw-font-medium tw-transition-all " + ("mobile" === d ? "tw-bg-white/10 tw-text-white tw-shadow-sm" : "tw-text-slate-400 hover:tw-text-slate-300")
                      }, {
                        children: [(0, a.jsx)(Al.Z, {
                          size: 14
                        }), "Mobile"]
                      }))]
                    })), (0, a.jsx)("button", Object.assign({
                      onClick: () => e(!1),
                      className: "tw-flex tw-h-8 tw-w-8 tw-items-center tw-justify-center tw-rounded-lg tw-text-slate-400 tw-transition-colors hover:tw-bg-white/10 hover:tw-text-slate-300",
                      "aria-label": "Close preview"
                    }, {
                      children: (0, a.jsx)(yr.Z, {
                        size: 16
                      })
                    }))]
                  }))]
                })), (0, a.jsx)("p", Object.assign({
                  className: "tw-text-xs tw-leading-relaxed tw-text-slate-400 tw-line-clamp-2"
                }, {
                  children: k
                }))]
              })), (0, a.jsx)("div", Object.assign({
                className: "tw-flex tw-flex-1 tw-items-center tw-justify-center tw-px-6 tw-py-4 tw-overflow-hidden",
                style: {
                  background: "rgba(0,8,28,0.4)"
                }
              }, {
                children: (0, a.jsxs)("div", Object.assign({
                  className: "tw-relative tw-flex tw-flex-col tw-overflow-hidden tw-rounded-xl tw-border tw-border-white/10 tw-bg-[#0d1a2d] tw-shadow-sm tw-transition-all tw-duration-500 tw-ease-out tw-h-[550px] " + ("desktop" === d ? "tw-w-full tw-max-w-[1220px]" : "tw-w-[330px]")
                }, {
                  children: [(0, a.jsxs)("div", Object.assign({
                    className: "tw-flex tw-flex-shrink-0 tw-items-center tw-gap-2 tw-border-b tw-border-white/10 tw-bg-[#0a1224] tw-px-4 tw-py-2.5"
                  }, {
                    children: [(0, a.jsxs)("div", Object.assign({
                      className: "tw-flex tw-gap-1.5"
                    }, {
                      children: [(0, a.jsx)("div", {
                        className: "tw-h-2.5 tw-w-2.5 tw-rounded-full tw-bg-red-400/70"
                      }), (0, a.jsx)("div", {
                        className: "tw-h-2.5 tw-w-2.5 tw-rounded-full tw-bg-amber-400/70"
                      }), (0, a.jsx)("div", {
                        className: "tw-h-2.5 tw-w-2.5 tw-rounded-full tw-bg-green-400/70"
                      })]
                    })), (0, a.jsx)("div", Object.assign({
                      className: "tw-ml-4 tw-flex-1 tw-rounded-md tw-bg-white/5 tw-px-3 tw-py-1"
                    }, {
                      children: (0, a.jsx)("p", Object.assign({
                        className: "tw-text-[11px] tw-text-slate-500"
                      }, {
                        children: "desktop" === d ? `https://${y}` : y
                      }))
                    }))]
                  })), (0, a.jsxs)("div", Object.assign({
                    className: "tw-flex-1 tw-overflow-y-auto"
                  }, {
                    children: [(0, a.jsx)("div", Object.assign({
                      className: "tw-relative tw-w-full tw-overflow-hidden tw-transition-all tw-duration-500 " + ("desktop" === d ? "tw-aspect-[3/1]" : "tw-aspect-[9/16]")
                    }, {
                      children: (0, a.jsx)("img", {
                        src: S,
                        alt: `IPL Banner Variant ${null!==(c=null==n?void 0:n.variant_number)&&void 0!==c?c:""} - ${k}`,
                        className: "tw-w-full tw-h-full tw-object-cover"
                      })
                    })), (0, a.jsx)("div", Object.assign({
                      className: "tw-space-y-3 tw-p-4"
                    }, {
                      children: (0, a.jsxs)("div", Object.assign({
                        className: "tw-flex tw-gap-3"
                      }, {
                        children: [(0, a.jsx)("div", {
                          className: "tw-h-16 tw-w-1/4 tw-rounded-lg tw-bg-white/5"
                        }), (0, a.jsx)("div", {
                          className: "tw-h-16 tw-w-1/4 tw-rounded-lg tw-bg-white/5"
                        }), (0, a.jsx)("div", {
                          className: "tw-h-16 tw-w-1/4 tw-rounded-lg tw-bg-white/5"
                        }), (0, a.jsx)("div", {
                          className: "tw-h-16 tw-w-1/4 tw-rounded-lg tw-bg-white/5"
                        })]
                      }))
                    }))]
                  }))]
                }))
              })), (0, a.jsxs)("div", Object.assign({
                className: "tw-flex tw-flex-shrink-0 tw-flex-col tw-gap-2 tw-border-t tw-border-white/10 tw-px-6 tw-py-3"
              }, {
                children: [h && (0, a.jsx)("p", Object.assign({
                  className: "tw-text-xs tw-text-red-400"
                }, {
                  children: h
                })), (0, a.jsxs)("div", Object.assign({
                  className: "tw-flex tw-items-center tw-justify-between"
                }, {
                  children: [(0, a.jsxs)("p", Object.assign({
                    className: "tw-text-xs tw-text-slate-500"
                  }, {
                    children: ["desktop" === d ? "1200 x 400px" : "640 x 1136px", " Â· IPL Season Campaign"]
                  })), (0, a.jsxs)("div", Object.assign({
                    className: "tw-flex tw-gap-2"
                  }, {
                    children: [(0, a.jsx)("button", Object.assign({
                      onClick: () => e(!1),
                      className: "tw-rounded-lg tw-border tw-border-white/10 tw-px-4 tw-py-1.5 tw-text-xs tw-font-medium tw-text-slate-400 tw-transition-colors hover:tw-bg-white/5",
                      disabled: g
                    }, {
                      children: "Close"
                    })), (0, a.jsx)("button", Object.assign({
                      onClick: M,
                      disabled: g || p,
                      className: "tw-rounded-lg tw-px-4 tw-py-1.5 tw-text-xs tw-font-medium tw-text-white tw-shadow-sm tw-transition-colors " + (p ? "tw-bg-green-500" : g ? "tw-bg-blue-400 tw-cursor-not-allowed" : "tw-bg-blue-500 hover:tw-bg-blue-600")
                    }, {
                      children: p ? "â Published" : g ? "Publishing..." : "Approve & Go Live"
                    }))]
                  }))]
                }))]
              }))]
            }))
          }));
          return (0, jr.createPortal)(T, document.body)
        };
        const ml = t => {
          return e = void 0, n = void 0, r = function*() {
            var e, n, a;
            const r = null !== (n = null === (e = null == t ? void 0 : t.content) || void 0 === e ? void 0 : e.id) && void 0 !== n ? n : null == t ? void 0 : t.id;
            if (r) {
              Co.setThemePreviewData(t), Co.setLoading(!0);
              try {
                const t = yield function(t) {
                  return cl(this, void 0, void 0, (function*() {
                    return (yield ue.get(`/ui-experience/templates/${t}`)).data
                  }))
                }(r);
                Co.setThemeTemplateData({
                  themeNavigationUrl: (null === (a = null == t ? void 0 : t.demoStoreInfo) || void 0 === a ? void 0 : a.storeUrl) ? `${t.demoStoreInfo.storeUrl}?templateId=${r}` : `?templateId=${r}`,
                  themeTemplateDetails: t
                }), Co.openThemePreviewModal()
              } catch (t) {
                console.error("Failed to fetch template details:", t)
              } finally {
                Co.setLoading(!1)
              }
            }
          }, new((a = void 0) || (a = Promise))((function(t, s) {
            function i(t) {
              try {
                l(r.next(t))
              } catch (t) {
                s(t)
              }
            }

            function o(t) {
              try {
                l(r.throw(t))
              } catch (t) {
                s(t)
              }
            }

            function l(e) {
              var n;
              e.done ? t(e.value) : (n = e.value, n instanceof a ? n : new a((function(t) {
                t(n)
              }))).then(i, o)
            }
            l((r = r.apply(e, n || [])).next())
          }));
          var e, n, a, r
        };
        var xl = n(64998),
          fl = function(t, e, n, a) {
            return new(n || (n = Promise))((function(r, s) {
              function i(t) {
                try {
                  l(a.next(t))
                } catch (t) {
                  s(t)
                }
              }

              function o(t) {
                try {
                  l(a.throw(t))
                } catch (t) {
                  s(t)
                }
              }

              function l(t) {
                var e;
                t.done ? r(t.value) : (e = t.value, e instanceof n ? e : new n((function(t) {
                  t(e)
                }))).then(i, o)
              }
              l((a = a.apply(t, e || [])).next())
            }))
          };

        function vl(t, e) {
          return fl(this, void 0, void 0, (function*() {
            if (!e) return {};
            try {
              return (yield dl(t, e, "DRAFT")).layoutJson
            } catch (t) {
              return console.error(`Failed to fetch layout from path: ${e}`, t), {}
            }
          }))
        }
        var jl = ({
            isOpen: t,
            onClose: e,
            themeNavigationUrl: n,
            themeTemplateDetails: r
          }) => {
            var s, i, o, l, A;
            const c = (0, N.useNavigate)(),
              d = (0, O.useQueryClient)(),
              [w, g] = (0, j.useState)("Home"),
              [u, p] = (0, j.useState)("desktop"),
              [b, h] = (0, j.useState)(!1),
              [m, x] = (0, j.useState)("main"),
              [f, v] = (0, j.useState)(""),
              [E, y] = (0, j.useState)(!1),
              [C, S] = (0, j.useState)(!1),
              [k, I] = (0, j.useState)(""),
              [M, T] = (0, j.useState)(5),
              R = (0, j.useRef)(null),
              B = (0, j.useRef)(null),
              _ = (0, j.useRef)(null),
              D = `smartbiz.in/${null!==(i=null===(s=null==ln?void 0:ln.currentStoreDetails)||void 0===s?void 0:s.storeURI)&&void 0!==i?i:"YourStore"}`,
              L = (0, j.useCallback)((() => {
                var t, e, n;
                const a = null === (t = null == r ? void 0 : r.demoStoreInfo) || void 0 === t ? void 0 : t.pageInfos,
                  s = localStorage.getItem("storeURI");
                if (a && a.length > 0) {
                  let t;
                  if ("Home" === w) t = "HOME_PAGE";
                  else if ("Product Details Page" === w) t = "PRODUCT_DETAILS_PAGE";
                  else if ("Full Page Cart" === w || "Side Cart" === w) {
                    const t = a.find((t => t.name === w));
                    if (null == t ? void 0 : t.url) return `${t.url}?mode=PREVIEW_MODAL_EDITOR${"Side Cart"===w?"&isSideCartOpen=true":""}`
                  }
                  const e = a.find((e => e.type === t));
                  if (null == e ? void 0 : e.url) return `${e.url}?mode=PREVIEW_MODAL_EDITOR`
                }
                return (null === (e = null == r ? void 0 : r.demoStoreInfo) || void 0 === e ? void 0 : e.storeUrl) ? `${r.demoStoreInfo.storeUrl}?mode=PREVIEW_MODAL_EDITOR` : `https://${null!==(n=null==s?void 0:s.toLowerCase())&&void 0!==n?n:""}`
              }), [w, r]);
            (0, j.useEffect)((() => {
              v(L())
            }), [L]), (0, j.useEffect)((() => {
              const t = t => {
                _.current && !_.current.contains(t.target) && (h(!1), x("main"))
              };
              return document.addEventListener("mousedown", t), () => document.removeEventListener("mousedown", t)
            }), []), (0, j.useEffect)((() => {
              b || x("main")
            }), [b]), (0, j.useEffect)((() => {
              if (!t) return;
              const n = t => {
                "Escape" === t.key && e()
              };
              return document.addEventListener("keydown", n), document.body.style.overflow = "hidden", () => {
                document.removeEventListener("keydown", n), document.body.style.overflow = "unset"
              }
            }), [t, e]), (0, j.useEffect)((() => C ? (R.current = setInterval((() => {
              T((t => t <= 1 ? (clearInterval(R.current), S(!1), e(), 0) : t - 1))
            }), 1e3), () => {
              R.current && clearInterval(R.current)
            }) : (T(5), void(R.current && clearInterval(R.current)))), [C, e]);
            const F = (t, e) => "HOME_PAGE" === t ? "Home" : "PRODUCT_DETAILS_PAGE" === t ? "Product Details Page" : e;
            if (!t) return null;
            const P = null === (o = null == r ? void 0 : r.demoStoreInfo) || void 0 === o ? void 0 : o.pageInfos,
              z = (0, a.jsx)("div", Object.assign({
                className: "tw-fixed tw-inset-0 tw-flex tw-items-center tw-justify-center tw-bg-black/50",
                style: {
                  zIndex: 2147483647
                },
                role: "presentation",
                tabIndex: -1
              }, {
                children: C ? (0, a.jsxs)("div", Object.assign({
                  className: "tw-rounded-xl tw-shadow-2xl tw-p-6 tw-max-w-sm tw-w-full tw-mx-4 tw-text-center tw-overflow-hidden tw-relative tw-border tw-border-white/10",
                  style: {
                    background: "linear-gradient(135deg, #0a1224 0%, #0d1a2d 100%)"
                  }
                }, {
                  children: [(0, a.jsx)("div", Object.assign({
                    className: "tw-absolute tw-top-0 tw-left-0 tw-right-0 tw-h-1 tw-bg-white/5"
                  }, {
                    children: (0, a.jsx)("div", {
                      className: "tw-h-full tw-bg-blue-500",
                      style: {
                        width: M / 5 * 100 + "%",
                        transition: "width 1s linear"
                      }
                    })
                  })), (0, a.jsx)("div", Object.assign({
                    className: "tw-w-12 tw-h-12 tw-mx-auto tw-mb-4 tw-rounded-full tw-bg-green-500/10 tw-flex tw-items-center tw-justify-center"
                  }, {
                    children: (0, a.jsx)("svg", Object.assign({
                      className: "tw-w-6 tw-h-6 tw-text-green-400",
                      fill: "none",
                      stroke: "currentColor",
                      viewBox: "0 0 24 24"
                    }, {
                      children: (0, a.jsx)("path", {
                        strokeLinecap: "round",
                        strokeLinejoin: "round",
                        strokeWidth: 2,
                        d: "M5 13l4 4L19 7"
                      })
                    }))
                  })), (0, a.jsx)("h3", Object.assign({
                    className: "tw-text-lg tw-font-semibold tw-text-white tw-mb-1"
                  }, {
                    children: "Theme Published"
                  })), (0, a.jsx)("p", Object.assign({
                    className: "tw-text-sm tw-text-slate-400 tw-mb-5"
                  }, {
                    children: "Your theme has been published successfully."
                  })), (0, a.jsxs)("div", Object.assign({
                    className: "tw-flex tw-gap-3 tw-justify-center"
                  }, {
                    children: [(0, a.jsx)("button", Object.assign({
                      onClick: () => {
                        S(!1), e()
                      },
                      className: "tw-rounded-lg tw-border tw-border-white/10 tw-px-4 tw-py-2 tw-text-sm tw-font-medium tw-text-slate-300 tw-transition-colors hover:tw-bg-white/5"
                    }, {
                      children: "Close"
                    })), (0, a.jsx)("a", Object.assign({
                      href: k,
                      target: "_blank",
                      rel: "noopener noreferrer",
                      className: "tw-rounded-lg tw-bg-blue-600 tw-px-4 tw-py-2 tw-text-sm tw-font-medium tw-text-white tw-transition-colors hover:tw-bg-blue-700 tw-no-underline"
                    }, {
                      children: "Preview Website"
                    }))]
                  }))]
                })) : (0, a.jsxs)("div", Object.assign({
                  className: "tw-w-[90vw] tw-max-w-[1200px] tw-flex tw-flex-col tw-rounded-2xl tw-border tw-border-white/10 tw-shadow-lg tw-overflow-hidden tw-relative",
                  style: {
                    background: "linear-gradient(135deg, #0a1224 0%, #0d1a2d 100%)"
                  },
                  role: "dialog",
                  "aria-modal": "true",
                  "aria-label": "Theme Template Preview"
                }, {
                  children: [(0, a.jsx)("div", Object.assign({
                    className: "tw-flex tw-flex-col tw-gap-3 tw-border-b tw-border-white/10 tw-px-6 tw-py-4"
                  }, {
                    children: (0, a.jsxs)("div", Object.assign({
                      className: "tw-flex tw-items-center tw-justify-between"
                    }, {
                      children: [(0, a.jsxs)("h2", Object.assign({
                        className: "tw-text-base tw-font-semibold tw-text-white"
                      }, {
                        children: ["Theme Preview â ", null !== (l = null == r ? void 0 : r.templateName) && void 0 !== l ? l : ""]
                      })), (0, a.jsxs)("div", Object.assign({
                        className: "tw-flex tw-flex-shrink-0 tw-items-center tw-gap-3"
                      }, {
                        children: [(0, a.jsxs)("div", Object.assign({
                          className: "tw-relative",
                          ref: _
                        }, {
                          children: [(0, a.jsxs)("button", Object.assign({
                            onClick: () => h(!b),
                            className: "tw-flex tw-items-center tw-gap-1.5 tw-rounded-lg tw-border tw-border-white/10 tw-bg-white/5 tw-px-3 tw-py-1.5 tw-text-xs tw-font-medium tw-text-white tw-transition-all hover:tw-bg-white/10"
                          }, {
                            children: [(0, a.jsx)("span", {
                              children: w
                            }), (0, a.jsx)(ns.Z, {
                              size: 14,
                              className: "tw-text-slate-400"
                            })]
                          })), (0, a.jsx)("div", Object.assign({
                            className: (b ? "tw-block" : "tw-hidden") + " tw-absolute tw-top-full tw-right-0 tw-mt-1 tw-border tw-border-white/10 tw-rounded-lg tw-shadow-lg tw-z-10 tw-w-48 tw-overflow-hidden",
                            style: {
                              background: "#0d1a2d"
                            }
                          }, {
                            children: "main" === m ? (0, a.jsxs)(a.Fragment, {
                              children: [P ? P.filter((t => "CART_PAGE" !== t.type)).map((t => (0, a.jsx)("div", Object.assign({
                                onClick: () => {
                                  g(F(t.type, t.name)), h(!1)
                                },
                                className: "tw-py-2.5 tw-px-4 hover:tw-bg-white/5 tw-cursor-pointer tw-text-xs tw-text-slate-300 tw-whitespace-nowrap"
                              }, {
                                children: F(t.type, t.name)
                              }), t.type))) : (0, a.jsxs)(a.Fragment, {
                                children: [(0, a.jsx)("div", Object.assign({
                                  onClick: () => {
                                    g("Home"), h(!1)
                                  },
                                  className: "tw-py-2.5 tw-px-4 hover:tw-bg-white/5 tw-cursor-pointer tw-text-xs tw-text-slate-300 tw-whitespace-nowrap"
                                }, {
                                  children: "Home"
                                })), (0, a.jsx)("div", Object.assign({
                                  onClick: () => {
                                    g("Product Details Page"), h(!1)
                                  },
                                  className: "tw-py-2.5 tw-px-4 hover:tw-bg-white/5 tw-cursor-pointer tw-text-xs tw-text-slate-300 tw-whitespace-nowrap"
                                }, {
                                  children: "Product Details Page"
                                }))]
                              }), (null == P ? void 0 : P.some((t => "CART_PAGE" === t.type))) && (0, a.jsxs)("div", Object.assign({
                                onClick: () => x("cart"),
                                className: "tw-py-2.5 tw-px-4 hover:tw-bg-white/5 tw-cursor-pointer tw-text-xs tw-text-slate-300 tw-whitespace-nowrap tw-flex tw-items-center tw-justify-between"
                              }, {
                                children: [(0, a.jsx)("span", {
                                  children: "Cart Page"
                                }), (0, a.jsx)(xl.Z, {
                                  size: 14,
                                  className: "tw-text-slate-400"
                                })]
                              }))]
                            }) : "cart" === m ? (0, a.jsxs)(a.Fragment, {
                              children: [(0, a.jsxs)("div", Object.assign({
                                onClick: () => x("main"),
                                className: "tw-py-2.5 tw-px-4 hover:tw-bg-white/5 tw-cursor-pointer tw-text-xs tw-text-slate-500 tw-whitespace-nowrap tw-flex tw-items-center tw-border-b tw-border-white/10"
                              }, {
                                children: [(0, a.jsx)(Pr.Z, {
                                  size: 14,
                                  className: "tw-text-slate-400 tw-mr-1.5"
                                }), (0, a.jsx)("span", {
                                  children: "Cart"
                                })]
                              })), null == P ? void 0 : P.filter((t => "CART_PAGE" === t.type)).map((t => (0, a.jsx)("div", Object.assign({
                                onClick: () => {
                                  g(t.name), h(!1)
                                },
                                className: "tw-py-2.5 tw-px-4 hover:tw-bg-white/5 tw-cursor-pointer tw-text-xs tw-text-slate-300 tw-whitespace-nowrap"
                              }, {
                                children: t.name
                              }), t.name)))]
                            }) : null
                          }))]
                        })), (0, a.jsxs)("div", Object.assign({
                          className: "tw-flex tw-items-center tw-rounded-lg tw-border tw-border-white/10 tw-bg-white/5 tw-p-0.5"
                        }, {
                          children: [(0, a.jsxs)("button", Object.assign({
                            onClick: () => p("desktop"),
                            className: "tw-flex tw-items-center tw-gap-1.5 tw-rounded-md tw-px-3 tw-py-1.5 tw-text-xs tw-font-medium tw-transition-all " + ("desktop" === u ? "tw-bg-white/10 tw-text-white tw-shadow-sm" : "tw-text-slate-400 hover:tw-text-slate-300")
                          }, {
                            children: [(0, a.jsx)(ll.Z, {
                              size: 14
                            }), "Desktop"]
                          })), (0, a.jsxs)("button", Object.assign({
                            onClick: () => p("mobile"),
                            className: "tw-flex tw-items-center tw-gap-1.5 tw-rounded-md tw-px-3 tw-py-1.5 tw-text-xs tw-font-medium tw-transition-all " + ("mobile" === u ? "tw-bg-white/10 tw-text-white tw-shadow-sm" : "tw-text-slate-400 hover:tw-text-slate-300")
                          }, {
                            children: [(0, a.jsx)(Al.Z, {
                              size: 14
                            }), "Mobile"]
                          }))]
                        })), (0, a.jsx)("button", Object.assign({
                          onClick: e,
                          className: "tw-flex tw-h-8 tw-w-8 tw-items-center tw-justify-center tw-rounded-lg tw-text-slate-400 tw-transition-colors hover:tw-bg-white/10 hover:tw-text-slate-300",
                          "aria-label": "Close preview"
                        }, {
                          children: (0, a.jsx)(yr.Z, {
                            size: 16
                          })
                        }))]
                      }))]
                    }))
                  })), (0, a.jsx)("div", Object.assign({
                    className: "tw-flex tw-flex-1 tw-w-full tw-items-center tw-justify-center tw-overflow-hidden tw-px-6 tw-py-4",
                    style: {
                      background: "rgba(0,8,28,0.4)"
                    }
                  }, {
                    children: n ? (0, a.jsxs)("div", Object.assign({
                      className: "tw-relative tw-overflow-hidden tw-rounded-xl tw-border tw-border-white/10 tw-bg-[#0d1a2d] tw-shadow-sm tw-transition-all tw-duration-500 tw-ease-out tw-h-[80vh] " + ("desktop" === u ? "tw-w-full tw-max-w-[1120px]" : "tw-w-[425px]")
                    }, {
                      children: [(0, a.jsxs)("div", Object.assign({
                        className: "tw-flex tw-items-center tw-gap-2 tw-border-b tw-border-white/10 tw-bg-[#0a1224] tw-px-4 tw-py-2.5"
                      }, {
                        children: [(0, a.jsxs)("div", Object.assign({
                          className: "tw-flex tw-gap-1.5"
                        }, {
                          children: [(0, a.jsx)("div", {
                            className: "tw-h-2.5 tw-w-2.5 tw-rounded-full tw-bg-red-400/70"
                          }), (0, a.jsx)("div", {
                            className: "tw-h-2.5 tw-w-2.5 tw-rounded-full tw-bg-amber-400/70"
                          }), (0, a.jsx)("div", {
                            className: "tw-h-2.5 tw-w-2.5 tw-rounded-full tw-bg-green-400/70"
                          })]
                        })), (0, a.jsx)("div", Object.assign({
                          className: "tw-ml-4 tw-flex-1 tw-rounded-md tw-bg-white/5 tw-px-3 tw-py-1"
                        }, {
                          children: (0, a.jsx)("p", Object.assign({
                            className: "tw-text-[11px] tw-text-slate-500"
                          }, {
                            children: "desktop" === u ? `https://${D}` : D
                          }))
                        }))]
                      })), (0, a.jsx)("iframe", {
                        ref: B,
                        className: "tw-border-0 tw-bg-white tw-w-full tw-h-full",
                        style: {
                          zoom: "desktop" === u ? .8 : 1
                        },
                        src: f || L(),
                        title: w,
                        sandbox: "allow-scripts allow-same-origin allow-forms"
                      })]
                    })) : (0, a.jsx)("div", Object.assign({
                      className: "tw-flex tw-items-center tw-justify-center tw-h-full"
                    }, {
                      children: (0, a.jsx)("p", Object.assign({
                        className: "tw-text-sm tw-text-slate-500"
                      }, {
                        children: "Preview not available"
                      }))
                    }))
                  })), (0, a.jsxs)("div", Object.assign({
                    className: "tw-flex tw-items-center tw-justify-between tw-border-t tw-border-white/10 tw-px-6 tw-py-3.5"
                  }, {
                    children: [(0, a.jsxs)("p", Object.assign({
                      className: "tw-text-xs tw-text-slate-500"
                    }, {
                      children: [null !== (A = null == r ? void 0 : r.templateName) && void 0 !== A ? A : "Theme", " Â· ", w]
                    })), (0, a.jsxs)("div", Object.assign({
                      className: "tw-flex tw-gap-2"
                    }, {
                      children: [(0, a.jsx)("button", Object.assign({
                        onClick: () => {
                          const t = r.templateId,
                            n = ln.currentStoreDetails.storeURI;
                          d.invalidateQueries(["themeTemplateData"]), e(), c(`/store-appearance/${n}/theme-editor?templateId=${t}`)
                        },
                        className: "tw-rounded-lg tw-border tw-border-white/10 tw-px-4 tw-py-1.5 tw-text-xs tw-font-medium tw-text-slate-300 tw-transition-all tw-duration-200 hover:tw-bg-white/5 hover:tw-border-white/20 hover:tw-shadow-sm hover:-tw-translate-y-0.5 active:tw-translate-y-0"
                      }, {
                        children: "Customize"
                      })), (0, a.jsx)("button", Object.assign({
                        onClick: () => {
                          return t = void 0, e = void 0, a = function*() {
                            var t;
                            const e = ln.currentStoreDetails.storeId,
                              n = ln.currentStoreDetails.storeURI;
                            if (e) {
                              y(!0);
                              try {
                                const a = yield function(t, e, n) {
                                  var a, r, s, i, o, l, A;
                                  return fl(this, void 0, void 0, (function*() {
                                    const c = null !== (a = e.supportedLayouts) && void 0 !== a ? a : [],
                                      d = ["HOME_PAGE", "PRODUCT_DETAILS_PAGE"],
                                      w = yield Promise.all(c.filter((t => d.includes(t.pageType))).map((e => fl(this, void 0, void 0, (function*() {
                                        const [n, a] = yield Promise.all([vl(t, e.layoutPath), vl(t, e.overrideStyleConfigPath)]);
                                        return {
                                          pageType: e.pageType,
                                          layoutJson: null != n ? n : "",
                                          overrideStyleJson: null != a ? a : {}
                                        }
                                      }))))), g = null !== (s = null === (r = e.supportedThemes) || void 0 === r ? void 0 : r.selectedTheme) && void 0 !== s ? s : "", u = null === (o = null === (i = e.supportedThemes) || void 0 === i ? void 0 : i.themeDetails) || void 0 === o ? void 0 : o.find((t => t.themeId === g));
                                    let p;
                                    return e.universalStyleConfigPath && (p = yield vl(t, e.universalStyleConfigPath)), {
                                      baseTemplateId: e.templateId,
                                      draftName: n,
                                      layouts: w,
                                      pageTemplateList: [],
                                      sourceDraftId: null,
                                      themeDetails: {
                                        themeId: null !== (l = null == u ? void 0 : u.themeId) && void 0 !== l ? l : g,
                                        brandColor: null !== (A = null == u ? void 0 : u.brandColor) && void 0 !== A ? A : "#000000"
                                      },
                                      universalStyleConfig: p
                                    }
                                  }))
                                }(e, r, `${r.templateId}_${Date.now()}`), s = yield function(t, e) {
                                  return cl(this, void 0, void 0, (function*() {
                                    return (yield ue.post(`/stores/${t}/ui-experience/drafts`, e)).data
                                  }))
                                }(e, a), i = null !== (t = null == s ? void 0 : s.draftId) && void 0 !== t ? t : null == s ? void 0 : s.id;
                                if (!i) return void console.error("No draftId returned from createDraft");
                                const o = `https://${Co.stageHost}/${n.toLowerCase()}?utm_experience=preview_${Date.now()}`;
                                yield wl(e, i, n), I(o), S(!0), d.invalidateQueries(["themeTemplateData"]), (0, In.aI)("send_prompt", {
                                  prompt: `I just applied the ${(null==r?void 0:r.templateName)||"new"} theme ðð`
                                })
                              } catch (t) {
                                console.error("Failed to publish draft:", t)
                              } finally {
                                y(!1)
                              }
                            } else console.error("No storeId found")
                          }, new((n = void 0) || (n = Promise))((function(r, s) {
                            function i(t) {
                              try {
                                l(a.next(t))
                              } catch (t) {
                                s(t)
                              }
                            }

                            function o(t) {
                              try {
                                l(a.throw(t))
                              } catch (t) {
                                s(t)
                              }
                            }

                            function l(t) {
                              var e;
                              t.done ? r(t.value) : (e = t.value, e instanceof n ? e : new n((function(t) {
                                t(e)
                              }))).then(i, o)
                            }
                            l((a = a.apply(t, e || [])).next())
                          }));
                          var t, e, n, a
                        },
                        disabled: E,
                        className: "tw-rounded-lg tw-px-4 tw-py-1.5 tw-text-xs tw-font-medium tw-text-white tw-shadow-sm tw-transition-all tw-duration-200 hover:-tw-translate-y-0.5 hover:tw-shadow-md active:tw-translate-y-0 " + (E ? "tw-bg-blue-400 tw-cursor-not-allowed" : "tw-bg-blue-500 hover:tw-bg-blue-600")
                      }, {
                        children: E ? "Publishing..." : "Publish"
                      }))]
                    }))]
                  }))]
                }))
              }));
            return (0, jr.createPortal)(z, document.body)
          },
          El = function(t, e, n, a) {
            return new(n || (n = Promise))((function(r, s) {
              function i(t) {
                try {
                  l(a.next(t))
                } catch (t) {
                  s(t)
                }
              }

              function o(t) {
                try {
                  l(a.throw(t))
                } catch (t) {
                  s(t)
                }
              }

              function l(t) {
                var e;
                t.done ? r(t.value) : (e = t.value, e instanceof n ? e : new n((function(t) {
                  t(e)
                }))).then(i, o)
              }
              l((a = a.apply(t, e || [])).next())
            }))
          };
        const {
          UAM_ENABLED_STATUS: yl,
          SEO_ENABLED_STATUS: Cl,
          CUSTOMER_SEGMENTS_ENABLED_STATUS: Ol,
          MA_ENABLED_STATUS: Nl,
          REVIEWS_ENABLED_STATUS: Sl,
          BASKET_BUILDING_ENABLED_STATUS: kl
        } = f.FeatureFlags, {
          PRIMARY_HEADER: Il,
          SECONDARY_HEADER: Ml
        } = ka;
        In.e4.registerWidget({
          type: "analytics_chart",
          component: function({
            title: t,
            description: e,
            visualization: n,
            queryData: r,
            layout: s,
            queries: i
          }) {
            const [o, l] = (0, j.useState)("idle"), A = {};
            for (const [t, e] of Object.entries(r || {})) A[t] = {
              columns: e.columns,
              rows: e.rows
            };
            const c = "lg" === (null == s ? void 0 : s.height) ? 400 : "sm" === (null == s ? void 0 : s.height) ? 120 : 280,
              d = Object.keys(A).length > 0,
              w = !!(t && n && i && Object.keys(i).length > 0 && Object.values(i).every((t => t.source && t.sql)));
            return (0, a.jsx)(Ks, Object.assign({
              className: "tw-my-2 tw-gap-2 tw-py-4",
              style: {
                background: "linear-gradient(145deg, #0f172a, #0a1224)"
              }
            }, {
              children: (0, a.jsxs)(Vs, Object.assign({
                className: "tw-flex tw-flex-col tw-gap-2"
              }, {
                children: [(0, a.jsx)("p", Object.assign({
                  className: "tw-text-[15px] tw-font-semibold tw-text-[#e6eaf2] tw-m-0"
                }, {
                  children: ii(t)
                })), e && (0, a.jsx)("p", Object.assign({
                  className: "tw-text-xs tw-text-[rgba(255,255,255,0.35)] tw-m-0"
                }, {
                  children: oi(e)
                })), d ? (0, a.jsx)(Ni, {
                  visualization: n,
                  data: A,
                  height: c
                }) : (0, a.jsx)("p", Object.assign({
                  className: "tw-text-xs tw-text-slate-400"
                }, {
                  children: "No data available"
                })), w && (0, a.jsxs)("button", Object.assign({
                  onClick: () => {
                    return a = this, r = void 0, c = function*() {
                      if ("pinned" !== o && "pinning" !== o && i) {
                        l("pinning");
                        try {
                          const a = yield function(t) {
                            return Ti(this, void 0, void 0, (function*() {
                              return (yield fetch(`${Bi}/${t.pageType}/widgets/pin`, {
                                method: "POST",
                                headers: {
                                  "Content-Type": "application/json"
                                },
                                credentials: "include",
                                body: JSON.stringify(t)
                              })).ok
                            }))
                          }({
                            pageType: "ANALYTICS",
                            title: t,
                            visualization: n,
                            description: e || "",
                            query: i,
                            layout: s || {
                              width: "full",
                              height: "md"
                            }
                          });
                          l(a ? "pinned" : "error"), a && window.dispatchEvent(new CustomEvent(Mi.ANALYTICS.WIDGET_PINNED))
                        } catch (t) {
                          l("error")
                        }
                      }
                    }, new((A = void 0) || (A = Promise))((function(t, e) {
                      function n(t) {
                        try {
                          i(c.next(t))
                        } catch (t) {
                          e(t)
                        }
                      }

                      function s(t) {
                        try {
                          i(c.throw(t))
                        } catch (t) {
                          e(t)
                        }
                      }

                      function i(e) {
                        var a;
                        e.done ? t(e.value) : (a = e.value, a instanceof A ? a : new A((function(t) {
                          t(a)
                        }))).then(n, s)
                      }
                      i((c = c.apply(a, r || [])).next())
                    }));
                    var a, r, A, c
                  },
                  disabled: "pinned" === o || "pinning" === o,
                  className: "tw-flex tw-items-center tw-gap-1.5 tw-px-3 tw-py-1.5 tw-rounded-lg tw-text-xs tw-font-medium tw-border tw-transition-colors tw-self-start " + ("pinned" === o ? "tw-bg-green-50 tw-text-green-700 tw-border-green-200" : "error" === o ? "tw-bg-red-50 tw-text-red-600 tw-border-red-200" : "tw-bg-white tw-text-slate-600 tw-border-slate-200 hover:tw-bg-slate-50 hover:tw-border-slate-300")
                }, {
                  children: ["pinning" === o && (0, a.jsx)(Si.Z, {
                    className: "tw-w-3.5 tw-h-3.5 tw-animate-spin"
                  }), "pinned" === o && (0, a.jsx)(ki.Z, {
                    className: "tw-w-3.5 tw-h-3.5"
                  }), ("idle" === o || "error" === o) && (0, a.jsx)(Ii.Z, {
                    className: "tw-w-3.5 tw-h-3.5"
                  }), "idle" === o && "Pin to Dashboard", "pinning" === o && "Pinning...", "pinned" === o && "Pinned to Dashboard", "error" === o && "Failed â Retry"]
                }))]
              }))
            }))
          },
          schema: {
            title: "string",
            visualization: "string",
            queryData: "object"
          }
        });
        var Tl = (0, v.Pi)((function(t) {
          var e, n;
          const r = (0, D.css)({
              display: "flex",
              height: "100vh"
            }),
            s = (0, D.css)({
              flex: 1,
              minWidth: 0,
              transition: "flex 0.3s ease-in-out, width 0.3s ease-in-out",
              position: "relative",
              overflowY: "auto"
            }),
            i = (0, D.css)({
              position: "relative",
              display: "flex",
              flexDirection: "row",
              alignItems: "stretch"
            }),
            o = (0, N.useLocation)(),
            l = (0, N.useNavigate)(),
            A = o.pathname,
            c = (0, _.SS)(),
            {
              isGetShopLoader: d,
              handleIsGetShopLoader: w,
              currentStoreDetails: g,
              handleCurrentStoreDetails: u,
              handleAllStoreDetails: p
            } = ln,
            [b, h] = (0, j.useState)(!1),
            [m, x] = (0, j.useState)(!1),
            [v, y] = (0, j.useState)(!0),
            [C, S] = (0, j.useState)(!1),
            [k, I] = (0, j.useState)("Home"),
            [P, z] = (0, j.useState)(!0),
            [U, G] = (0, j.useState)(!1),
            [Z, H] = (0, j.useState)(!1),
            [Y, W] = (0, j.useState)(!1),
            [K, V] = (0, j.useState)(!1),
            $ = (0, j.useRef)(null),
            [q, Q] = (0, j.useState)(!1),
            tt = ((0, j.useRef)(null), (0, _.OQ)()),
            et = new URLSearchParams(o.search).get("storeOnboarded"),
            [nt, at] = (0, j.useState)(!1),
            {
              data: st,
              isLoading: it,
              refetch: ot
            } = (0, B.ZP)(!0),
            {
              refetch: lt
            } = As(),
            {
              refetch: At
            } = bs(),
            {
              data: ct
            } = Es("CATALOG_SYNC"),
            {
              data: dt,
              isLoading: wt
            } = (0, O.useQuery)(["programs"], (() => no(void 0, void 0, void 0, (function*() {
              return (yield be.get("/ren/v1/programs")).data
            }))), uo),
            gt = E().useMemo((() => (null == dt ? void 0 : dt.programs) ? function(t) {
              var e;
              const n = [],
                a = t.find((t => "SMARTBIZ" === t.name));
              (null == a ? void 0 : a.isOnboarded) && n.push({
                name: "D2C",
                color: "tw-bg-blue-400"
              });
              const r = t.find((t => "SMARTHUB" === t.name));
              if ((null == r ? void 0 : r.isOnboarded) && (null === (e = r.metadata) || void 0 === e ? void 0 : e.warehouseSalesChannels)) try {
                const t = JSON.parse(r.metadata.warehouseSalesChannels).map((t => t.value));
                t.some((t => "FBA" === t || "MFN" === t)) && n.push({
                  name: "Amazon",
                  color: "tw-bg-[#00CCBD]"
                }), t.some((t => "FKSTANDARD" === t)) && n.push({
                  name: "Flipkart",
                  color: "tw-bg-[#00CCBD]"
                }), t.some((t => "MEESHO" === t)) && n.push({
                  name: "Meesho",
                  color: "tw-bg-[#00CCBD]"
                })
              } catch (t) {}
              return n
            }(dt.programs) : []), [dt]),
            ut = ["/home", "/inventory", "/listings", "/shipping", "/store-builder", "/analytics-dashboard", "/marketing"].some((t => A.startsWith(t))) || "/" === A;
          (0, j.useEffect)((() => {
            U && Z && (H(!1), $.current && clearTimeout($.current), $.current = setTimeout((() => W(!0)), 200))
          }), [A]);
          const [pt, bt] = (0, j.useState)(!1), ht = new URLSearchParams(window.location.search), mt = E().useMemo((() => {
            const t = {};
            return new URLSearchParams(window.location.search).forEach(((e, n) => {
              X.has(n) && (t[n] = e)
            })), t
          }), []), xt = (null === (e = ht.get("spapi_oauth_code")) || void 0 === e ? void 0 : e.length) > 0, ft = (null === (n = ht.get("selling_partner_id")) || void 0 === n ? void 0 : n.length) > 0;
          "true" === ht.get("azai") && ln.setIsZaiEnabledForOnboarding(!0), xt && ft && (sessionStorage.setItem("spapiOauthCode", ht.get("spapi_oauth_code")), sessionStorage.setItem("sellingPartnerId", ht.get("selling_partner_id")));
          const vt = () => El(this, void 0, void 0, (function*() {
              var t, e, n, a, r, s;
              const i = yield At(), o = "NOT_RESPONDED" === (null === (t = null == i ? void 0 : i.data) || void 0 === t ? void 0 : t.responseStatus) && (null === (n = null === (e = null == i ? void 0 : i.data) || void 0 === e ? void 0 : e.questions) || void 0 === n ? void 0 : n.length) > 0, l = "COMPLETED" === (null === (s = null === (r = null === (a = null == ct ? void 0 : ct.marketplaceConnectorTaskStatuses) || void 0 === a ? void 0 : a[0]) || void 0 === r ? void 0 : r.statusDetails) || void 0 === s ? void 0 : s.status);
              at(!(!o || l))
            })),
            jt = t => {
              const e = t.detail;
              l(null == e ? void 0 : e.key)
            };
          (0, j.useEffect)((() => {
            if (null == st ? void 0 : st.data) {
              p(null == st ? void 0 : st.data);
              const t = null == st ? void 0 : st.data,
                e = (0, _.NU)(t);
              e && u(e)
            }
          }), [null == st ? void 0 : st.data]), (0, j.useEffect)((() => {
            window.addEventListener("HIDE_SIDE_BAR", (t => {
              const e = t.detail;
              z(!e.hideSideBar)
            }))
          })), (0, j.useEffect)((() => {
            Dt && (0, In.aI)("send_prompt", {
              prompt: "Please start my onboarding"
            })
          }), [b]);
          const Et = () => El(this, void 0, void 0, (function*() {
              window.location.hostname === J ? (L.Z.remove("x-acbin", {
                domain: ".amazon.in"
              }), L.Z.remove("ubid-acbin", {
                domain: ".amazon.in"
              }), L.Z.remove("posSessionId", {
                domain: ".amazon.in"
              }), L.Z.remove("userId", {
                domain: ".amazon.in"
              })) : (L.Z.remove("x-tacbin", {
                domain: ".amazon.com"
              }), L.Z.remove("ubid-tacbin", {
                domain: ".amazon.com"
              }), L.Z.remove("posSessionId", {
                domain: ".amazon.com"
              }), L.Z.remove("userId", {
                domain: ".amazon.in"
              })), localStorage.clear(), yield tt.mutateAsync().then((t => {
                let e = null == t ? void 0 : t.redirectUrl;
                if (e && ht.toString()) try {
                  const t = new URL(e),
                    n = t.searchParams.get("openid.return_to");
                  if (n) {
                    const a = new URL(n);
                    ht.forEach(((t, e) => {
                      X.has(e) && a.searchParams.set(e, t)
                    })), t.searchParams.set("openid.return_to", a.toString()), e = t.toString()
                  }
                } catch (t) {}
                console.log("Redirect URL with QP", new URL(e)), window.location.replace(e)
              })).catch((() => {
                x(!0)
              }))
            })),
            yt = () => El(this, void 0, void 0, (function*() {
              yield Ct(), ln.isLogged(), S(!0), ot(), lt(), Ot(), Nt(), St(), kt(), It(), Tt(), Rt(), yield Bt(), yield _t(), Gr.fetchAll()
            }));
          (0, j.useEffect)((() => (f.mE.track(f.MixPanelEventName.HOME_URL_VISIT, {
            [fs.Hr]: (0, fs.lJ)()
          }), window.addEventListener("CHANGE_PATH", jt), et && localStorage.setItem("isStoreOnboarded", "true"), (0, _.gU)(), localStorage.getItem("x-tacbin") ? (null === localStorage.getItem("isUserLoggedInEventTracked") && (f.mE.track(f.MixPanelEventName.LOGIN, {
            [fs.Hr]: (0, fs.lJ)()
          }), localStorage.setItem("isUserLoggedInEventTracked", "true")), yt()) : (f.mE.track(f.MixPanelEventName.AUTH_PAGE_VISIT, {
            [fs.Hr]: (0, fs.lJ)()
          }), Et()), () => {
            window.removeEventListener("CHANGE_PATH", jt)
          })), []);
          const Ct = () => El(this, void 0, void 0, (function*() {
              w(!0), yield c.mutateAsync().then((t => {
                vt(), w(!1), ln.shopSelectionResponse = t, f.mE.track(f.MixPanelEventName.VALID_TOKEN, {
                  [fs.Hr]: (0, fs.lJ)()
                })
              })).catch((t => {
                var e, n, a, r, s, i;
                if ((null === (n = null === (e = null == t ? void 0 : t.response) || void 0 === e ? void 0 : e.data) || void 0 === n ? void 0 : n.error) === wr || (null === (r = null === (a = null == t ? void 0 : t.response) || void 0 === a ? void 0 : a.data) || void 0 === r ? void 0 : r.errorCode) === pr) {
                  if (h(!0), null === localStorage.getItem("isSignUpEventTracked") && (f.mE.track("signup"), localStorage.setItem("isSignUpEventTracked", "true")), !xt || !ft) {
                    const t = (0, $t.vM)("/store-onboarding"),
                      e = t.includes("?") ? "&" : "?",
                      n = new URLSearchParams;
                    new URLSearchParams(window.location.search).forEach(((t, e) => {
                      X.has(e) && n.set(e, t)
                    }));
                    const a = n.toString();
                    l(a ? `${t}${e}${a}` : t)
                  }
                  w(!1)
                } else(null === (i = null === (s = null == t ? void 0 : t.response) || void 0 === s ? void 0 : s.data) || void 0 === i ? void 0 : i.error) === gr ? (localStorage.clear(), Et(), w(!1)) : (null == t ? void 0 : t.code) === ur ? w(!1) : (w(!1), Et())
              }))
            })),
            Ot = () => El(this, void 0, void 0, (function*() {
              const t = yield(0, f.aH)();
              Fe.setIsUserManagementEnabled(yield(0, f.Ic)(yl.flagName, yl.defaultValue, t))
            })),
            Nt = () => El(this, void 0, void 0, (function*() {
              const t = yield(0, f.aH)(), e = yield(0, f.Ic)(Cl.flagName, Cl.defaultValue, t);
              f.gO.setIsSEOFeatureEnabled(e)
            })),
            St = () => El(this, void 0, void 0, (function*() {
              const t = yield(0, f.aH)(), e = yield(0, f.Ic)(Ol.flagName, Ol.defaultValue, t);
              Fe.setIsCustomerSegmentsEnabled(e)
            })),
            kt = () => El(this, void 0, void 0, (function*() {
              const t = yield(0, f.aH)(), e = yield(0, f.Ic)(Nl.flagName, Nl.defaultValue, t);
              f.gO.setIsMAFeatureEnabled(e)
            })),
            It = () => El(this, void 0, void 0, (function*() {
              const t = yield(0, f.aH)(), e = yield(0, f.Ic)(Sl.flagName, Sl.defaultValue, t);
              Fe.setIsReviewsEnabled(e)
            })),
            Tt = () => El(this, void 0, void 0, (function*() {
              const t = yield(0, f.aH)(), e = yield(0, f.Ic)(kl.flagName, kl.defaultValue, t);
              Fe.setIsBasketBuildingEnabled(e)
            })),
            Rt = () => El(this, void 0, void 0, (function*() {
              const t = yield(0, f.aH)(), e = yield(0, f.Ic)(f.FeatureFlags.ZAI_CHAT_BOT_ENABLED_STATUS.flagName, f.FeatureFlags.ZAI_CHAT_BOT_ENABLED_STATUS.defaultValue, t);
              ln.setIsZaiChatBotEnabled(e)
            })),
            Bt = () => El(this, void 0, void 0, (function*() {
              const t = yield(0, f.aH)(), e = yield(0, f.Ic)(f.FeatureFlags.ZAI_ORCHESTRATOR_ENABLED_STATUS.flagName, f.FeatureFlags.ZAI_ORCHESTRATOR_ENABLED_STATUS.defaultValue, t);
              ln.setIsZAIOrchestratorEnabled(e)
            })),
            _t = () => El(this, void 0, void 0, (function*() {
              const t = yield ps();
              rt((null == t ? void 0 : t.email) || "", null == t ? void 0 : t.mobileNumber) && ln.setIsZaiEnabledForOnboarding(!0)
            })),
            Dt = o.pathname.startsWith("/store-onboarding") && (b || xt || ft),
            Lt = E().useMemo((() => ln.isZAIOrchestratorEnabled || ln.isZaiEnabledForOnboarding ? new Gi : new Fi), [ln.isZAIOrchestratorEnabled, ln.isZaiEnabledForOnboarding]),
            Ft = E().useMemo((() => mo(l)), [l]),
            Pt = E().useMemo((() => fo(l)), [l]),
            zt = E().useMemo((() => Eo(l)), [l]),
            Ut = E().useMemo((() => new Oo), []),
            Gt = E().useMemo((() => No()), []);
          ol(), Ji({
              enableLogging: !0,
              onThemeReviewDetails: Ft.handleThemeReview,
              onCatalogReview: Pt.handleCatalogReview,
              onImageReview: Pt.handleImageReview,
              onPageRedirection: zt.handlePageRedirection,
              onBannerPreview: Ut.handleBannerEvent,
              onThemePreview: ml,
              onStoreIdReceived: Gt.handleStoreIdReceived
            }),
            function() {
              const t = (0, N.useLocation)(),
                e = (0, N.useNavigate)(),
                n = (0, j.useRef)(null),
                a = (0, j.useRef)(0),
                r = (0, j.useRef)(!1);
              (0, j.useEffect)((() => {
                eo(t.pathname) ? (n.current = t.pathname, a.current = 0, r.current = !1) : r.current ? a.current += 1 : (a.current = 1, r.current = !0)
              }), [t.pathname]), (0, j.useEffect)((() => {
                const t = () => {
                  setTimeout((() => {
                    if (!eo(window.location.pathname) && n.current && r.current) {
                      const t = a.current;
                      t > 0 ? window.history.go(-t) : e(n.current, {
                        replace: !0
                      }), a.current = 0, r.current = !1
                    }
                  }), 50)
                };
                return window.addEventListener("popstate", t), () => window.removeEventListener("popstate", t)
              }), [e])
            }();
          const {
            config: Zt
          } = (0, $t.R6)(), Ht = Zt.renSdkStreamUrl, Yt = E().useMemo((() => (0, a.jsx)(Zo, {})), []);
          return (0, a.jsxs)(In.$U, Object.assign({
            baseUrl: Ht,
            headers: {
              Cookie: (0, $t.Xd)()
            },
            agentId: "Zai",
            storeId: null == g ? void 0 : g.storeId,
            storeName: null == g ? void 0 : g.storeURI,
            params: mt,
            defaultOpen: !0,
            runId: mt.sessionId || void 0,
            fileUploadService: Lt,
            disclaimerContent: Yt,
            agentType: ln.isZaiEnabledForOnboarding || ln.isZAIOrchestratorEnabled ? "ZAI" : null,
            logo: ln.isZaiEnabledForOnboarding || ln.isZAIOrchestratorEnabled ? (0, a.jsx)(Gs, {
              size: 24
            }) : null,
            headerLogo: ln.isZaiEnabledForOnboarding || ln.isZAIOrchestratorEnabled ? (0, a.jsx)(Gs, {
              size: 30
            }) : void 0,
            chatbotName: ln.isZaiEnabledForOnboarding || ln.isZAIOrchestratorEnabled ? "AZai" : void 0,
            theme: ln.isZaiEnabledForOnboarding || ln.isZAIOrchestratorEnabled ? "dark" : "light",
            suggestionCards: ln.isZaiEnabledForOnboarding || ln.isZAIOrchestratorEnabled ? [(0, a.jsx)($o, {}, "cro-score"), (0, a.jsx)(Jo, {
              text: "Review Meta Ads performace"
            }, "marketing"), (0, a.jsx)(Jo, {
              text: "I want to create my brand website"
            }, "brand-website"), (0, a.jsx)(Jo, {
              text: "Do I need any 3rd party tools to set up delivery?"
            }, "delivery")] : []
          }, {
            children: [localStorage.getItem("isStoreOnboarded") && v && (0, a.jsx)(xs, {
              handleClose: () => {
                window.history.replaceState({}, "", window.location.pathname), y(!1), localStorage.removeItem("isStoreOnboarded")
              },
              showModal: v,
              heading: "Congratulations",
              description: "Your online store is successfully created"
            }), !ln.isZaiEnabledForOnboarding && (0, a.jsx)(F.Ix, {}), C && !d ? (0, a.jsx)(R.default, Object.assign({
              query: "max-width",
              props: {
                showMobileView: {
                  default: !1,
                  [An]: !0
                }
              }
            }, {
              children: ({
                showMobileView: t
              }) => (0, a.jsx)(a.Fragment, {
                children: !t || ut || Dt ? (0, a.jsxs)("div", Object.assign({
                  className: "tw-relative tw-flex tw-h-screen tw-flex-col tw-overflow-hidden tw-bg-[#00081C]"
                }, {
                  children: [(0, a.jsxs)("div", Object.assign({
                    className: "tw-pointer-events-none tw-fixed tw-inset-0 tw-z-0 tw-overflow-hidden",
                    "aria-hidden": "true"
                  }, {
                    children: [(0, a.jsx)("div", {
                      className: "tw-absolute tw-inset-0 tw-bg-[#00081C]"
                    }), (0, a.jsx)("div", {
                      className: "tw-absolute tw-left-1/2 tw-top-0 tw--translate-x-1/2",
                      style: {
                        width: 1200,
                        height: 600,
                        background: "radial-gradient(ellipse at center, rgba(0,204,189,0.06) 0%, transparent 70%)"
                      }
                    }), (0, a.jsx)("div", {
                      className: "tw-absolute tw-inset-0",
                      style: {
                        background: "linear-gradient(to bottom, #00081C 0%, #000408 100%)",
                        opacity: .6
                      }
                    })]
                  })), (0, a.jsxs)("div", Object.assign({
                    className: "tw-relative tw-z-10 tw-flex tw-min-h-0 tw-flex-1 tw-overflow-hidden"
                  }, {
                    children: [Dt ? null : pt ? (0, a.jsx)(os, {}) : (0, a.jsxs)("div", Object.assign({
                      className: "tw-relative tw-shrink-0",
                      style: {
                        width: t || U ? 54 : 200,
                        transition: "width 0.3s ease-in-out"
                      },
                      onMouseEnter: () => {
                        !t && U && (H(!0), W(!1), $.current && clearTimeout($.current))
                      }
                    }, {
                      children: [t && Z && !K && (0, a.jsx)("div", {
                        className: "tw-fixed tw-inset-0 tw-z-40",
                        onClick: () => {
                          V(!0), $.current && clearTimeout($.current), $.current = setTimeout((() => {
                            H(!1), W(!0), V(!1)
                          }), 250)
                        }
                      }), (0, a.jsx)("div", Object.assign({
                        className: "tw-h-full",
                        style: {
                          width: !t && !U || Z && !K ? 200 : 54,
                          position: t || U ? "absolute" : "relative",
                          zIndex: t || U ? 50 : "auto",
                          overflow: "hidden",
                          transition: "width 0.2s ease-out"
                        },
                        onMouseLeave: () => {
                          t || U && (H(!1), $.current && clearTimeout($.current), $.current = setTimeout((() => W(!0)), 150))
                        }
                      }, {
                        children: (0, a.jsx)(rs, {
                          collapsed: (t || Y) && !Z,
                          onToggle: () => {
                            t ? Z ? (V(!0), $.current && clearTimeout($.current), $.current = setTimeout((() => {
                              H(!1), W(!0), V(!1)
                            }), 250)) : (W(!1), H(!0)) : (G((t => {
                              const e = !t;
                              return W(e), e
                            })), H(!1))
                          },
                          onNavigate: e => {
                            I(e), t && (V(!0), $.current && clearTimeout($.current), $.current = setTimeout((() => {
                              H(!1), W(!0), V(!1)
                            }), 250))
                          },
                          onPanelClose: () => {},
                          channels: gt,
                          channelsLoading: wt
                        })
                      }))]
                    })), (0, a.jsx)("div", Object.assign({
                      className: "tw-min-w-0 tw-flex-1 tw-overflow-y-auto tw-overflow-x-hidden",
                      style: {
                        transform: "translateZ(0)",
                        isolation: "isolate",
                        background: ut ? "radial-gradient(1200px at 20% 0%, rgba(30,64,175,0.18), rgba(15,23,42,0.05) 50%, transparent 70%), linear-gradient(180deg, #0a1224 0%, #070b16 50%, #050814 100%)" : "#f0f1f2"
                      }
                    }, {
                      children: (0, a.jsxs)("main", Object.assign({
                        className: "tw-flex tw-min-w-0 tw-flex-col tw-gap-4 tw-p-4 sm:tw-gap-6 sm:tw-p-6 tw-max-w-full"
                      }, {
                        children: [nt && !ln.isZaiEnabledForOnboarding && (0, a.jsx)(ds, {
                          setShowBusinessDetailsModal: at
                        }), (!Dt || !ln.isZaiEnabledForOnboarding) && (0, a.jsx)(N.Outlet, {})]
                      }))
                    })), (ln.isZaiChatBotEnabled || ln.isZaiEnabledForOnboarding || ln.isZAIOrchestratorEnabled) && (0, a.jsx)(Ys, {
                      noHeaderOffset: !0
                    })]
                  }))]
                })) : (0, a.jsx)("div", Object.assign({
                  className: r
                }, {
                  children: (0, a.jsx)("div", Object.assign({
                    className: s
                  }, {
                    children: (0, a.jsxs)(M.ZP, Object.assign({
                      mainClassName: Mt,
                      headerComponent: Dt ? null : dr,
                      sidebarComponent: null
                    }, {
                      children: [!Dt && (0, a.jsx)(dr, {
                        mode: Dt ? Ml : Il,
                        storeDetailsLoader: it
                      }), (0, a.jsx)(T.default, Object.assign({
                        className: i,
                        width: "100%",
                        height: "100%"
                      }, {
                        children: (0, a.jsxs)("div", Object.assign({
                          id: "OUTLET-PRE",
                          className: s
                        }, {
                          children: [nt && !ln.isZaiEnabledForOnboarding && (0, a.jsx)(ds, {
                            setShowBusinessDetailsModal: at
                          }), (!Dt || !ln.isZaiEnabledForOnboarding) && (0, a.jsx)(N.Outlet, {})]
                        }))
                      }))]
                    }))
                  }))
                }))
              })
            })) : (0, a.jsx)(br, {
              error: m
            }), (0, a.jsx)(Se, {}), (0, a.jsx)(f.CM, {
              toasterAlignmentHorizontal: "end"
            }), !(ln.isZaiChatBotEnabled || ln.isZaiEnabledForOnboarding || ln.isZAIOrchestratorEnabled) && (0, a.jsx)(Is, {}), (0, a.jsx)(rl, {}), Co.isLoading && (0, a.jsx)("div", Object.assign({
              className: "tw-fixed tw-inset-0 tw-flex tw-items-center tw-justify-center tw-bg-black/50",
              style: {
                zIndex: 2147483647
              }
            }, {
              children: (0, a.jsxs)("div", Object.assign({
                className: "tw-flex tw-flex-col tw-items-center tw-gap-3 tw-rounded-2xl tw-border tw-border-white/10 tw-px-8 tw-py-6 tw-shadow-xl",
                style: {
                  background: "linear-gradient(135deg, #0a1224 0%, #0d1a2d 100%)"
                }
              }, {
                children: [(0, a.jsx)("div", {
                  className: "tw-h-8 tw-w-8 tw-animate-spin tw-rounded-full tw-border-[3px] tw-border-white/10 tw-border-t-blue-500"
                }), (0, a.jsx)("p", Object.assign({
                  className: "tw-text-sm tw-font-medium tw-text-slate-300"
                }, {
                  children: "Loading previewâ¦"
                }))]
              }))
            })), Co.bannerVariantData && (0, a.jsx)(hl, {
              open: Co.isBannerPreviewModalOpen,
              onOpenChange: t => {
                t || Co.closeBannerPreviewModal()
              },
              variant: Co.bannerVariantData,
              initialDevice: Co.bannerDeviceMode
            }), Co.themeTemplateData && (0, a.jsx)(jl, {
              isOpen: Co.isThemePreviewModalOpen,
              onClose: () => Co.closeThemePreviewModal(),
              themeNavigationUrl: Co.themeTemplateData.themeNavigationUrl,
              themeTemplateDetails: Co.themeTemplateData.themeTemplateDetails
            })]
          }))
        }));

        function Rl({
          icon: t,
          title: e,
          subtitle: n = "Updated just now",
          iconColor: r = "#00CCBD"
        }) {
          return (0, a.jsxs)("div", Object.assign({
            className: "tw-flex tw-items-center tw-gap-3"
          }, {
            children: [(0, a.jsx)("div", Object.assign({
              className: "tw-flex tw-w-8 tw-h-8 sm:tw-w-9 sm:tw-h-9 tw-items-center tw-justify-center tw-rounded-lg tw-border tw-border-[rgba(255,255,255,0.08)]",
              style: {
                backgroundColor: `${r}1A`
              }
            }, {
              children: (0, a.jsx)(t, {
                className: "tw-w-4 tw-h-4",
                style: {
                  color: r
                }
              })
            })), (0, a.jsxs)("div", {
              children: [(0, a.jsx)("h1", Object.assign({
                className: "tw-text-base sm:tw-text-lg tw-font-semibold tw-text-[#e6eaf2] tw-m-0"
              }, {
                children: e
              })), (0, a.jsx)("p", Object.assign({
                className: "tw-text-xs sm:tw-text-sm tw-text-[rgba(255,255,255,0.35)] tw-m-0"
              }, {
                children: n
              }))]
            })]
          }))
        }

        function Bl() {
          return (0, a.jsx)(Rl, {
            icon: qr.Z,
            title: "Marketing agent",
            iconColor: "#f472b6"
          })
        }
        var _l = n(47653),
          Dl = function(t, e) {
            var n = {};
            for (var a in t) Object.prototype.hasOwnProperty.call(t, a) && e.indexOf(a) < 0 && (n[a] = t[a]);
            if (null != t && "function" == typeof Object.getOwnPropertySymbols) {
              var r = 0;
              for (a = Object.getOwnPropertySymbols(t); r < a.length; r++) e.indexOf(a[r]) < 0 && Object.prototype.propertyIsEnumerable.call(t, a[r]) && (n[a[r]] = t[a[r]])
            }
            return n
          };

        function Ll(t) {
          const [e, n] = (0, j.useState)({
            templates: [],
            widgetData: {},
            errors: {},
            isLoading: !0
          }), a = (0, j.useRef)(new _i), r = (0, j.useCallback)((t => {
            switch (t.type) {
              case "templates":
                n((e => Object.assign(Object.assign({}, e), {
                  templates: t.widgets
                })));
                break;
              case "widget_data":
                n((e => Object.assign(Object.assign({}, e), {
                  widgetData: Object.assign(Object.assign({}, e.widgetData), {
                    [t.widgetId]: Object.assign(Object.assign({}, e.widgetData[t.widgetId] || {}), {
                      [t.program]: t.data
                    })
                  }),
                  errors: Object.fromEntries(Object.entries(e.errors).filter((([e]) => e !== t.widgetId)))
                })));
                break;
              case "widget_error":
                n((e => Object.assign(Object.assign({}, e), {
                  errors: Object.assign(Object.assign({}, e.errors), {
                    [t.widgetId]: Object.assign(Object.assign({}, e.errors[t.widgetId] || {}), {
                      [t.program]: t.error
                    })
                  })
                })));
                break;
              case "done":
                n((t => Object.assign(Object.assign({}, t), {
                  isLoading: !1
                })))
            }
          }), []);
          (0, j.useEffect)((() => {
            const e = a.current;
            n({
              templates: [],
              widgetData: {},
              errors: {},
              isLoading: !0
            });
            const {
              refreshKey: s
            } = t, i = Dl(t, ["refreshKey"]);
            return e.connect(i, r, (t => {
              console.error("Dashboard SSE error:", t), n((t => Object.assign(Object.assign({}, t), {
                isLoading: !1
              })))
            }), (() => n((t => Object.assign(Object.assign({}, t), {
              isLoading: !1
            }))))), () => e.disconnect()
          }), [t.amazonMerchantId, t.pageId, t.dateFrom, t.dateTo, t.refreshKey, r]);
          const s = (0, j.useMemo)((() => {
            const t = {};
            return Object.entries(e.widgetData).forEach((([e, n]) => {
              const a = function(t) {
                const e = {};
                return Object.entries(t).forEach((([t, n]) => {
                  var a, r;
                  if (!(null === (a = null == n ? void 0 : n.columns) || void 0 === a ? void 0 : a.length) || !(null === (r = null == n ? void 0 : n.rows) || void 0 === r ? void 0 : r.length)) return void(e[t] = n);
                  const s = n.columns.indexOf("channel");
                  if (-1 === s) return void(e[t] = n);
                  const i = n.columns.filter(((t, e) => e !== s)),
                    o = {};
                  n.rows.forEach((t => {
                    const e = t[s];
                    if (null == e) return;
                    const n = $s(String(e));
                    o[n] || (o[n] = []), o[n].push(t.filter(((t, e) => e !== s)))
                  })), Object.entries(o).forEach((([t, n]) => {
                    e[t] = {
                      columns: i,
                      rows: n
                    }
                  }))
                })), e
              }(n);
              t[e] = a
            })), t
          }), [e.widgetData]);
          return Object.assign(Object.assign({}, e), {
            widgetData: s
          })
        }
        const Fl = E().createContext(null);

        function Pl() {
          const t = E().useContext(Fl);
          if (!t) throw new Error("Popover compound components must be used inside <Popover>");
          return t
        }

        function zl({
          children: t
        }) {
          const [e, n] = (0, j.useState)(!1), r = (0, j.useRef)(null);
          return (0, a.jsx)(Fl.Provider, Object.assign({
            value: {
              open: e,
              setOpen: n,
              triggerRef: r
            }
          }, {
            children: t
          }))
        }

        function Ul({
          asChild: t,
          children: e
        }) {
          const {
            setOpen: n,
            triggerRef: r
          } = Pl();
          return (0, a.jsx)("div", Object.assign({
            ref: r,
            className: "tw-inline-flex",
            onClick: () => n((t => !t))
          }, {
            children: e
          }))
        }

        function Gl({
          align: t = "center",
          className: e,
          children: n
        }) {
          const {
            open: r,
            setOpen: s
          } = Pl(), i = (0, j.useRef)(null), o = (0, j.useCallback)((t => {
            i.current && !i.current.contains(t.target) && s(!1)
          }), [s]);
          return (0, j.useEffect)((() => {
            if (r) return document.addEventListener("mousedown", o), () => document.removeEventListener("mousedown", o)
          }), [r, o]), r ? (0, a.jsx)("div", Object.assign({
            ref: i,
            className: xr("tw-absolute tw-z-50 tw-mt-1 tw-rounded-lg tw-border tw-border-[rgba(255,255,255,0.08)] tw-bg-[#000D26] tw-shadow-[0_8px_30px_rgba(0,0,0,0.4)]", "start" === t && "tw-left-0", "end" === t && "tw-right-0", "center" === t && "tw-left-1/2 tw--translate-x-1/2", e)
          }, {
            children: n
          })) : null
        }

        function Zl({
          checked: t = !1,
          onCheckedChange: e,
          className: n,
          id: r
        }) {
          return (0, a.jsx)("button", Object.assign({
            role: "checkbox",
            "aria-checked": t,
            id: r,
            onClick: () => null == e ? void 0 : e(!t),
            className: xr("tw-flex tw-w-4 tw-h-4 tw-shrink-0 tw-items-center tw-justify-center tw-rounded tw-border tw-transition-colors tw-cursor-pointer", t ? "tw-bg-[#00CCBD] tw-border-[#00CCBD] tw-text-white" : "tw-border-[rgba(255,255,255,0.15)] tw-bg-transparent", n)
          }, {
            children: t && (0, a.jsx)(ki.Z, {
              className: "tw-w-3 tw-h-3"
            })
          }))
        }

        function Hl({
          kpis: t,
          enabled: e,
          onToggle: n,
          onGoalChange: r
        }) {
          return (0, a.jsxs)(zl, {
            children: [(0, a.jsx)(Ul, Object.assign({
              asChild: !0
            }, {
              children: (0, a.jsx)("button", Object.assign({
                className: "tw-text-[rgba(255,255,255,0.35)] hover:tw-text-[rgba(255,255,255,0.5)]"
              }, {
                children: (0, a.jsx)(ts.Z, {
                  className: "tw-w-3.5 tw-h-3.5"
                })
              }))
            })), (0, a.jsxs)(Gl, Object.assign({
              align: "start",
              className: "tw-w-72 tw-rounded-xl tw-border-[rgba(255,255,255,0.08)] tw-bg-[#0a1021] tw-p-0 tw-shadow-[0_8px_30px_rgba(0,0,0,0.25)]"
            }, {
              children: [(0, a.jsx)("div", Object.assign({
                className: "tw-border-b tw-border-[rgba(255,255,255,0.08)] tw-px-3 tw-py-2"
              }, {
                children: (0, a.jsx)("p", Object.assign({
                  className: "tw-text-[11px] tw-font-semibold tw-uppercase tw-tracking-wide tw-text-[rgba(255,255,255,0.35)] tw-m-0"
                }, {
                  children: "Configure KPIs"
                }))
              })), (0, a.jsx)("div", Object.assign({
                className: "tw-flex tw-flex-col tw-py-1"
              }, {
                children: t.map(((t, s) => {
                  var i;
                  return (0, a.jsxs)("div", Object.assign({
                    className: "tw-flex tw-items-center tw-gap-2 tw-px-3 tw-py-1.5"
                  }, {
                    children: [(0, a.jsx)(Zl, {
                      checked: e[s],
                      onCheckedChange: () => n(s),
                      className: "tw-w-3.5 tw-h-3.5 tw-shrink-0"
                    }), (0, a.jsx)("span", Object.assign({
                      className: "tw-min-w-0 tw-flex-1 tw-truncate tw-text-[12px] tw-text-[rgba(255,255,255,0.5)]"
                    }, {
                      children: t.title
                    })), (0, a.jsx)("input", {
                      type: "text",
                      value: null !== (i = t.target) && void 0 !== i ? i : "",
                      onChange: t => function(t, e) {
                        null == r || r(t, e)
                      }(s, t.target.value),
                      placeholder: "Goal",
                      className: "tw-h-6 tw-w-16 tw-shrink-0 tw-rounded-md tw-border tw-border-[rgba(255,255,255,0.08)] tw-bg-[#00081C] tw-px-1.5 tw-text-[11px] tw-text-[rgba(255,255,255,0.5)] tw-outline-none placeholder:tw-text-[rgba(255,255,255,0.35)] focus:tw-border-[rgba(0,204,189,0.4)]"
                    })]
                  }), t.title)
                }))
              }))]
            }))]
          })
        }
        const Yl = "kpi-config";

        function Wl(t) {
          return t ? `${Yl}-${t}` : Yl
        }

        function Kl({
          className: t = ""
        }) {
          return (0, a.jsx)("div", {
            className: `tw-animate-pulse tw-rounded-md tw-bg-[rgba(255,255,255,0.08)] ${t}`
          })
        }

        function Vl() {
          return (0, a.jsxs)("div", Object.assign({
            className: "tw-flex tw-items-center tw-gap-3"
          }, {
            children: [(0, a.jsx)(Kl, {
              className: "tw-h-8 tw-w-8 tw-rounded-lg"
            }), (0, a.jsxs)("div", Object.assign({
              className: "tw-flex tw-flex-col tw-gap-1.5"
            }, {
              children: [(0, a.jsx)(Kl, {
                className: "tw-h-5 tw-w-52"
              }), (0, a.jsx)(Kl, {
                className: "tw-h-3.5 tw-w-32"
              })]
            }))]
          }))
        }

        function $l() {
          return (0, a.jsxs)("div", Object.assign({
            className: "tw-overflow-hidden tw-rounded-xl tw-border tw-border-[rgba(255,255,255,0.06)] tw-shadow-[0_10px_30px_rgba(0,0,0,0.35)]",
            style: {
              background: "linear-gradient(145deg, rgba(15,23,42,0.85), rgba(10,18,36,0.65))"
            }
          }, {
            children: [(0, a.jsxs)("div", Object.assign({
              className: "tw-flex tw-items-center tw-justify-between tw-px-5 tw-pt-4 tw-pb-3"
            }, {
              children: [(0, a.jsxs)("div", Object.assign({
                className: "tw-flex tw-items-center tw-gap-2"
              }, {
                children: [(0, a.jsx)(Kl, {
                  className: "tw-h-3.5 tw-w-24"
                }), (0, a.jsx)(Kl, {
                  className: "tw-h-5 tw-w-5 tw-rounded-md"
                })]
              })), (0, a.jsx)(Kl, {
                className: "tw-h-7 tw-w-28 tw-rounded-lg"
              })]
            })), (0, a.jsx)("div", Object.assign({
              className: "tw-flex tw-items-stretch tw-divide-x tw-divide-[rgba(255,255,255,0.06)] tw-px-5 tw-pb-4"
            }, {
              children: Array.from({
                length: 2
              }).map(((t, e) => (0, a.jsxs)("div", Object.assign({
                className: "tw-flex tw-flex-1 tw-items-center tw-gap-3 tw-px-5 first:tw-pl-0 last:tw-pr-0"
              }, {
                children: [(0, a.jsx)(Kl, {
                  className: "tw-h-9 tw-w-9 tw-shrink-0 tw-rounded-xl"
                }), (0, a.jsxs)("div", Object.assign({
                  className: "tw-flex tw-flex-col tw-gap-2"
                }, {
                  children: [(0, a.jsx)(Kl, {
                    className: "tw-h-2.5 tw-w-24"
                  }), (0, a.jsx)(Kl, {
                    className: "tw-h-7 tw-w-28"
                  }), (0, a.jsx)(Kl, {
                    className: "tw-h-3 tw-w-20"
                  }), (0, a.jsxs)("div", Object.assign({
                    className: "tw-mt-1 tw-flex tw-items-center tw-gap-4"
                  }, {
                    children: [(0, a.jsx)(Kl, {
                      className: "tw-h-4 tw-w-20"
                    }), (0, a.jsx)(Kl, {
                      className: "tw-h-4 tw-w-28"
                    })]
                  }))]
                }))]
              }), e)))
            }))]
          }))
        }

        function ql() {
          return (0, a.jsxs)("div", Object.assign({
            className: "tw-overflow-hidden tw-rounded-xl tw-border tw-border-[rgba(255,255,255,0.06)] tw-py-3 tw-shadow-[0_10px_30px_rgba(0,0,0,0.35)]",
            style: {
              background: "linear-gradient(145deg, rgba(15,23,42,0.85), rgba(10,18,36,0.65))"
            }
          }, {
            children: [(0, a.jsx)("div", Object.assign({
              className: "tw-px-4 tw-pb-0"
            }, {
              children: (0, a.jsxs)("div", Object.assign({
                className: "tw-flex tw-items-center tw-gap-2"
              }, {
                children: [(0, a.jsx)(Kl, {
                  className: "tw-h-3.5 tw-w-3.5 tw-rounded"
                }), (0, a.jsx)(Kl, {
                  className: "tw-h-3.5 tw-w-40"
                })]
              }))
            })), (0, a.jsx)("div", Object.assign({
              className: "tw-px-4 tw-flex tw-flex-col tw-gap-0"
            }, {
              children: Array.from({
                length: 3
              }).map(((t, e) => (0, a.jsxs)("div", Object.assign({
                className: "tw-flex tw-items-start tw-justify-between tw-gap-4 tw-py-2.5 " + (e < 2 ? "tw-border-b tw-border-[rgba(255,255,255,0.08)]" : "")
              }, {
                children: [(0, a.jsxs)("div", Object.assign({
                  className: "tw-flex tw-items-start tw-gap-3"
                }, {
                  children: [(0, a.jsx)(Kl, {
                    className: "tw-mt-1.5 tw-h-2 tw-w-2 tw-shrink-0 tw-rounded-full"
                  }), (0, a.jsxs)("div", Object.assign({
                    className: "tw-flex tw-flex-col tw-gap-1.5"
                  }, {
                    children: [(0, a.jsxs)("div", Object.assign({
                      className: "tw-flex tw-items-center tw-gap-2"
                    }, {
                      children: [(0, a.jsx)(Kl, {
                        className: "tw-h-4 tw-w-10"
                      }), (0, a.jsx)(Kl, {
                        className: "tw-h-3.5 tw-w-20"
                      }), (0, a.jsx)(Kl, {
                        className: "tw-h-5 tw-w-24 tw-rounded-md"
                      })]
                    })), (0, a.jsx)(Kl, {
                      className: "tw-h-3.5 tw-w-80"
                    })]
                  }))]
                })), (0, a.jsx)(Kl, {
                  className: "tw-h-3.5 tw-w-10 tw-shrink-0"
                })]
              }), e)))
            }))]
          }))
        }

        function Ql() {
          return (0, a.jsxs)("div", Object.assign({
            className: "tw-flex tw-flex-col tw-gap-3"
          }, {
            children: [(0, a.jsxs)("div", Object.assign({
              className: "tw-flex tw-items-center tw-gap-2"
            }, {
              children: [(0, a.jsx)(Kl, {
                className: "tw-h-3.5 tw-w-3.5 tw-rounded"
              }), (0, a.jsx)(Kl, {
                className: "tw-h-3.5 tw-w-44"
              })]
            })), (0, a.jsx)("div", Object.assign({
              className: "tw-grid tw-grid-cols-1 tw-gap-4 md:tw-grid-cols-3"
            }, {
              children: Array.from({
                length: 3
              }).map(((t, e) => (0, a.jsxs)("div", Object.assign({
                className: "tw-flex tw-flex-col tw-justify-between tw-gap-3 tw-rounded-xl tw-border tw-border-[rgba(255,255,255,0.06)] tw-p-4 tw-shadow-[0_10px_30px_rgba(0,0,0,0.35)]",
                style: {
                  background: "linear-gradient(145deg, rgba(15,23,42,0.85), rgba(10,18,36,0.65))"
                }
              }, {
                children: [(0, a.jsxs)("div", Object.assign({
                  className: "tw-flex tw-flex-col tw-gap-3"
                }, {
                  children: [(0, a.jsx)(Kl, {
                    className: "tw-h-5 tw-w-36 tw-rounded-full"
                  }), (0, a.jsx)(Kl, {
                    className: "tw-h-5 tw-w-48"
                  }), (0, a.jsxs)("div", Object.assign({
                    className: "tw-flex tw-flex-col tw-gap-1.5"
                  }, {
                    children: [(0, a.jsx)(Kl, {
                      className: "tw-h-3.5 tw-w-full"
                    }), (0, a.jsx)(Kl, {
                      className: "tw-h-3.5 tw-w-4/5"
                    })]
                  }))]
                })), (0, a.jsxs)("div", Object.assign({
                  className: "tw-flex tw-items-center tw-justify-between"
                }, {
                  children: [(0, a.jsx)(Kl, {
                    className: "tw-h-3.5 tw-w-16"
                  }), (0, a.jsx)(Kl, {
                    className: "tw-h-8 tw-w-32 tw-rounded-lg"
                  })]
                }))]
              }), e)))
            }))]
          }))
        }

        function Xl() {
          return (0, a.jsxs)("div", Object.assign({
            className: "tw-flex tw-flex-col tw-gap-3"
          }, {
            children: [(0, a.jsxs)("div", Object.assign({
              className: "tw-flex tw-items-center tw-gap-2"
            }, {
              children: [(0, a.jsx)(Kl, {
                className: "tw-h-3.5 tw-w-3.5 tw-rounded"
              }), (0, a.jsx)(Kl, {
                className: "tw-h-3.5 tw-w-28"
              })]
            })), (0, a.jsx)("div", Object.assign({
              className: "tw-grid tw-grid-cols-1 tw-gap-4 md:tw-grid-cols-3"
            }, {
              children: Array.from({
                length: 3
              }).map(((t, e) => (0, a.jsxs)(Ks, Object.assign({
                className: "tw-gap-2 tw-overflow-hidden tw-py-5"
              }, {
                children: [(0, a.jsxs)(Vs, Object.assign({
                  className: "tw-flex tw-flex-col tw-gap-1"
                }, {
                  children: [(0, a.jsxs)("div", Object.assign({
                    className: "tw-flex tw-items-start tw-justify-between"
                  }, {
                    children: [(0, a.jsxs)("div", Object.assign({
                      className: "tw-flex tw-flex-col tw-gap-1"
                    }, {
                      children: [(0, a.jsx)(Kl, {
                        className: "tw-h-4 tw-w-32"
                      }), (0, a.jsx)(Kl, {
                        className: "tw-h-3 tw-w-20"
                      })]
                    })), (0, a.jsx)(Kl, {
                      className: "tw-h-5 tw-w-20 tw-rounded-full"
                    })]
                  })), (0, a.jsx)(Kl, {
                    className: "tw-h-7 tw-w-16"
                  })]
                })), (0, a.jsx)("div", {
                  className: "tw-mx-6 tw-flex tw-h-20 tw-items-center tw-justify-center tw-rounded-lg tw-bg-slate-50"
                })]
              }), e)))
            }))]
          }))
        }

        function Jl() {
          return (0, a.jsxs)("div", Object.assign({
            className: "tw-flex tw-flex-col tw-gap-6"
          }, {
            children: [(0, a.jsx)(Vl, {}), (0, a.jsx)($l, {}), (0, a.jsx)(ql, {}), (0, a.jsx)(Ql, {})]
          }))
        }
        const tA = {
            sm: 120,
            md: 280,
            medium: 280,
            lg: 400,
            large: 400
          },
          eA = {
            full: "tw-col-span-12",
            half: "tw-col-span-12 md:tw-col-span-6",
            third: "tw-col-span-12 md:tw-col-span-4"
          };

        function nA({
          amazonMerchantId: t,
          pageId: e,
          storageKey: n,
          allowedTitles: r,
          averageTitles: s,
          hideBreakdown: i
        }) {
          const {
            templates: o,
            widgetData: l,
            isLoading: A
          } = Ll({
            amazonMerchantId: t,
            pageId: e
          }), c = r ? o.filter((t => r.some((e => t.title.toLowerCase().includes(e.toLowerCase()))))) : o, d = [...c].sort(((t, e) => {
            var n, a;
            return (null !== (n = t.layout.order) && void 0 !== n ? n : 0) - (null !== (a = e.layout.order) && void 0 !== a ? a : 0) || t.widgetId.localeCompare(e.widgetId)
          })), [w, g] = (0, j.useState)([]), [u, p] = (0, j.useState)([]);
          return (0, j.useEffect)((() => {
            var t, e;
            if (d.length && d.length !== u.length) {
              const a = n ? function(t) {
                try {
                  const e = localStorage.getItem(Wl(t));
                  return e ? JSON.parse(e) : null
                } catch (t) {
                  return null
                }
              }(n) : null;
              g((null === (t = null == a ? void 0 : a.targets) || void 0 === t ? void 0 : t.length) === d.length ? a.targets : d.map((() => ""))), p((null === (e = null == a ? void 0 : a.enabled) || void 0 === e ? void 0 : e.length) === d.length ? a.enabled : d.map((() => !0)))
            }
          }), [d.length]), (0, j.useEffect)((() => {
            n && w.length && w.length === d.length && function(t, e) {
              try {
                localStorage.setItem(Wl(e), JSON.stringify(t))
              } catch (t) {}
            }({
              period: "this_month",
              targets: w,
              enabled: u
            }, n)
          }), [w, u, n, d.length]), (0, a.jsxs)("div", Object.assign({
            className: "tw-flex tw-flex-col tw-gap-4"
          }, {
            children: [(0, a.jsxs)("div", Object.assign({
              className: "tw-flex tw-items-center tw-gap-2"
            }, {
              children: [(0, a.jsx)("span", Object.assign({
                className: "tw-text-xs tw-font-semibold tw-uppercase tw-tracking-wide tw-text-[rgba(255,255,255,0.35)]"
              }, {
                children: "Key Metrics"
              })), d.length > 0 && u.length > 0 && (0, a.jsx)(Hl, {
                kpis: d.map(((t, e) => ({
                  title: t.title,
                  target: w[e]
                }))),
                enabled: u,
                onToggle: t => p((e => e.map(((e, n) => n === t ? !e : e)))),
                onGoalChange: (t, e) => g((n => n.map(((n, a) => a === t ? e : n))))
              })]
            })), 0 === o.length && A ? (0, a.jsx)($l, {}) : (0, a.jsx)("div", Object.assign({
              className: "tw-grid tw-grid-cols-12 tw-gap-3 sm:tw-gap-4"
            }, {
              children: d.map(((t, e) => {
                var n, r;
                if (u.length > 0 && !u[e]) return null;
                const o = null !== (n = tA[t.layout.height]) && void 0 !== n ? n : 280,
                  c = null !== (r = eA[t.layout.width]) && void 0 !== r ? r : "tw-col-span-12",
                  d = l[t.widgetId],
                  g = d && Object.keys(d).length > 0,
                  p = "metric_card" === t.visualization;
                return (0, a.jsx)("div", Object.assign({
                  className: c
                }, {
                  children: (0, a.jsx)(Ks, Object.assign({
                    className: "tw-gap-2 tw-py-4 tw-h-full"
                  }, {
                    children: (0, a.jsxs)(Vs, Object.assign({
                      className: "tw-flex tw-flex-col tw-gap-3"
                    }, {
                      children: [(0, a.jsx)("p", Object.assign({
                        className: p ? "tw-text-[10px] tw-font-medium tw-uppercase tw-tracking-wide tw-text-[rgba(255,255,255,0.35)] tw-m-0" : "tw-text-[15px] tw-font-semibold tw-text-[#e6eaf2] tw-m-0"
                      }, {
                        children: t.title
                      })), !p && (0, a.jsx)("p", Object.assign({
                        className: "tw-text-xs tw-text-[rgba(255,255,255,0.35)] tw-m-0 tw--mt-1"
                      }, {
                        children: t.description
                      })), g ? (0, a.jsx)(Ni, {
                        visualization: t.visualization,
                        data: d,
                        height: o,
                        useAverage: !!(null == s ? void 0 : s.some((e => t.title.toLowerCase().includes(e.toLowerCase())))),
                        showAggregateChange: ci(t.widgetId),
                        hideBreakdown: i
                      }) : A ? (0, a.jsx)("div", {
                        className: "tw-animate-pulse tw-rounded-lg tw-bg-[rgba(255,255,255,0.08)]",
                        style: {
                          height: o
                        }
                      }) : (0, a.jsxs)("div", Object.assign({
                        className: "tw-flex tw-items-center tw-justify-center tw-gap-2",
                        style: {
                          height: o
                        }
                      }, {
                        children: [(0, a.jsx)(_l.Z, {
                          className: "tw-w-4 tw-h-4 tw-text-[rgba(255,255,255,0.2)]"
                        }), (0, a.jsx)("span", Object.assign({
                          className: "tw-text-xs tw-text-[rgba(255,255,255,0.25)]"
                        }, {
                          children: "No data available"
                        }))]
                      })), w[e] && (0, a.jsxs)("span", Object.assign({
                        className: "tw-text-[11px] tw-text-[rgba(255,255,255,0.35)]"
                      }, {
                        children: ["Goal ", w[e]]
                      }))]
                    }))
                  }))
                }), t.widgetId)
              }))
            }))]
          }))
        }
        const aA = (0, v.Pi)((function() {
          var t;
          const e = null === (t = ln.currentStoreDetails) || void 0 === t ? void 0 : t.storeId;
          return e ? (0, a.jsx)(nA, {
            amazonMerchantId: e,
            pageId: "MARKETING_ATF",
            storageKey: "marketing",
            averageTitles: ["RoAS", "Click Through Rate"]
          }) : null
        }));
        var rA = n(82701),
          sA = function(t, e) {
            var n = {};
            for (var a in t) Object.prototype.hasOwnProperty.call(t, a) && e.indexOf(a) < 0 && (n[a] = t[a]);
            if (null != t && "function" == typeof Object.getOwnPropertySymbols) {
              var r = 0;
              for (a = Object.getOwnPropertySymbols(t); r < a.length; r++) e.indexOf(a[r]) < 0 && Object.prototype.propertyIsEnumerable.call(t, a[r]) && (n[a[r]] = t[a[r]])
            }
            return n
          };

        function iA(t) {
          var {
            className: e
          } = t, n = sA(t, ["className"]);
          return (0, a.jsx)("input", Object.assign({
            className: xr("tw-flex tw-h-9 tw-w-full tw-rounded-md tw-border tw-border-[rgba(255,255,255,0.08)] tw-bg-transparent tw-px-3 tw-py-1 tw-text-sm tw-text-[#e6eaf2] tw-shadow-sm tw-transition-colors tw-outline-none", "placeholder:tw-text-[rgba(255,255,255,0.25)]", "focus:tw-border-[#00CCBD] focus:tw-ring-1 focus:tw-ring-[rgba(0,204,189,0.2)]", "disabled:tw-cursor-not-allowed disabled:tw-opacity-50", e)
          }, n))
        }
        var oA = n(13766),
          lA = n(31012);
        const AA = ["All", "Pricing", "Communication", "Operations", "Growth", "Compliance"],
          cA = {
            Pricing: {
              text: "tw-text-amber-400",
              bg: "tw-bg-[rgba(245,158,11,0.1)]"
            },
            Communication: {
              text: "tw-text-emerald-400",
              bg: "tw-bg-[rgba(16,185,129,0.1)]"
            },
            Operations: {
              text: "tw-text-[#00CCBD]",
              bg: "tw-bg-[rgba(0,204,189,0.1)]"
            },
            Growth: {
              text: "tw-text-blue-400",
              bg: "tw-bg-[rgba(59,130,246,0.1)]"
            },
            Compliance: {
              text: "tw-text-rose-400",
              bg: "tw-bg-[rgba(244,63,94,0.1)]"
            }
          },
          dA = [{
            name: "Pricing Policy",
            category: "Pricing",
            description: "Dynamic pricing rules, floor prices, and discount authority by channel.",
            tags: ["Listings", "Analytics"],
            active: !0
          }, {
            name: "Markdown Authorization",
            category: "Pricing",
            description: "Eligibility rules for automatic vs. approval-gated markdowns.",
            tags: ["Listings"],
            active: !0
          }, {
            name: "Tone of Voice",
            category: "Communication",
            description: "Brand voice guidelines for all agent-generated copy, emails, and comms.",
            tags: ["Marketing"],
            active: !0
          }, {
            name: "Review Response Policy",
            category: "Communication",
            description: "Rules for responding to customer reviews across D2C and Marketplace.",
            tags: ["Orders", "Marketing"],
            active: !1
          }, {
            name: "Media & Copy Creator",
            category: "Communication",
            description: "Automated refresh of product images, hero banners, and copy across the D2C storefront.",
            tags: ["Store-Builder"],
            active: !0
          }, {
            name: "Theme Designer",
            category: "Communication",
            description: "AI-powered theme suggestions and visual design optimisations for the D2C storefront.",
            tags: ["Store-Builder"],
            active: !0
          }, {
            name: "Restock Rules",
            category: "Operations",
            description: "Reorder thresholds, safety stock targets, and PO triggers by SKU tier.",
            tags: ["Inventory"],
            active: !1
          }, {
            name: "Replenishment Forecaster",
            category: "Operations",
            description: "Forecasts FBA and MFN reorder needs by SKU family and auto-generates POs and supplier email drafts.",
            tags: ["Inventory"],
            active: !0
          }, {
            name: "Aged Inventory Cost Cutter",
            category: "Operations",
            description: "Identifies slow-moving and dead-stock SKUs on Amazon.in MFN and FBA and recommends markdown prices to clear them.",
            tags: ["Inventory"],
            active: !0
          }, {
            name: "Returns Validation",
            category: "Operations",
            description: "Eligibility checks before accepting a return request.",
            tags: ["Orders"],
            active: !1
          }, {
            name: "Shipping Cost Optimizer",
            category: "Operations",
            description: "Amazon.in MFN carrier routing, scorecard, and billing anomaly detection.",
            tags: ["Orders"],
            active: !0
          }, {
            name: "RTO Controller",
            category: "Operations",
            description: "Monitors RTO rates by carrier and zone; auto-suspends high-RTO carriers and flags RTO-prone orders for COD verification before dispatch.",
            tags: ["Orders"],
            active: !0
          }, {
            name: "Shipdate Protector",
            category: "Operations",
            description: "Ensures dispatch SLA compliance by detecting pick-queue delays and rerouting orders between fulfilment centres before the commit window closes.",
            tags: ["Orders"],
            active: !0
          }, {
            name: "Carrier Selection Logic",
            category: "Operations",
            description: "Rules for routing shipments to the optimal carrier by weight, zone, and SLA.",
            tags: ["Orders"],
            active: !1
          }, {
            name: "SLA Commitments",
            category: "Operations",
            description: "Promised dispatch and delivery windows by order type, channel, and tier.",
            tags: ["Orders"],
            active: !1
          }, {
            name: "Escalation Rules",
            category: "Operations",
            description: "Triggers and timelines for escalating issues from agents to human operators.",
            tags: ["Orders"],
            active: !1
          }, {
            name: "Customer Tier Rules",
            category: "Growth",
            description: "Segmentation logic for Platinum, Gold, Silver tiers and associated privileges.",
            tags: ["Analytics", "Marketing"],
            active: !1
          }, {
            name: "ROAS-Gated Scaling",
            category: "Growth",
            description: "Budget scaling and pause rules based on ROAS and CTR thresholds.",
            tags: ["Marketing", "Analytics"],
            active: !1
          }, {
            name: "Ad Spend Cap",
            category: "Growth",
            description: "Monthly budget ceilings and channel-level caps to prevent overspend.",
            tags: ["Marketing", "Analytics"],
            active: !1
          }, {
            name: "Seasonality & Peak Tracker",
            category: "Growth",
            description: "Monitors upcoming seasonal events and peak shopping periods to pre-prepare the storefront, banners, and inventory.",
            tags: ["Store-Builder"],
            active: !0
          }, {
            name: "Conversion Rate Auditor",
            category: "Growth",
            description: "Periodic audits of the conversion funnel to surface drop-off points and improvement actions.",
            tags: ["Store-Builder"],
            active: !0
          }, {
            name: "DNR / Do-Not-Resell",
            category: "Compliance",
            description: "Block known-fraudulent customers from returns, refunds, and new high-risk orders.",
            tags: ["Orders"],
            active: !1
          }, {
            name: "Fraud Scoring Rules",
            category: "Compliance",
            description: "Real-time order risk scoring using address, velocity, BIN, and device signals.",
            tags: ["Orders"],
            active: !1
          }, {
            name: "Listing Quality Gates",
            category: "Compliance",
            description: "Minimum content standards before a listing can go live on any channel.",
            tags: ["Listings", "Store-Builder"],
            active: !1
          }],
          wA = {
            "Pricing Policy": ["Never discount more than 20% without approval.", "Floor price = cost Ã 1.4.", "Competitor match allowed on Marketplace only.", "D2C prices must be â¥ Marketplace price at all times.", "Bulk order discount (>50 units): up to 12% auto-approved."],
            "Markdown Authorization": ["Auto-approve markdowns up to 10% on SKUs with >90 days of cover.", "Markdowns above 15% require manager sign-off.", "Seasonal clearance items exempt from floor-price rules.", "Maximum markdown cadence: once per 14 days per SKU."],
            "Tone of Voice": ["Use friendly, professional tone across all channels.", "Avoid jargon â write at an 8th-grade reading level.", "Always address the customer by first name in emails.", "Sign off with brand signature, not agent name."],
            "Review Response Policy": ["Respond to all 1-2 star reviews within 24 hours.", "Offer resolution privately before replying publicly.", "Never admit fault or liability in public replies.", "Escalate reviews mentioning safety to the legal team."],
            "Media & Copy Creator": ["Use brand-approved DAM assets only.", "Hero banners must include a CTA above the fold.", "Auto-generated copy limited to 150 characters for titles.", "All images must pass quality check before publish."],
            "Theme Designer": ["Follow brand colour palette â no custom colours without approval.", "Mobile-first design mandatory for all themes.", "Maximum 3 font families per theme.", "Seasonal themes auto-expire after campaign end date."],
            "Restock Rules": ["Safety stock = 14 days of cover for A-tier SKUs.", "B-tier SKUs: reorder at 21 days of cover.", "Auto-generate PO when stock drops below safety threshold.", "Exclude discontinued SKUs from restock triggers."],
            "Replenishment Forecaster": ["Forecast horizon: 30 days rolling by SKU family.", "Factor in seasonality and promotional calendar.", "Auto-draft POs for supplier review.", "Flag SKUs with >20% forecast variance for manual review."],
            "Aged Inventory Cost Cutter": ["Flag inventory aged >90 days as slow-moving.", "Auto-recommend 15% markdown for 90-120 day stock.", "Escalate 120+ day stock for liquidation review.", "Exclude new launches (<60 days) from ageing rules."],
            "Returns Validation": ["Validate return window (30 days for D2C, 10 for Marketplace).", "Block returns on final-sale items automatically.", "Require photo proof for damage claims above â¹500.", "Flag serial returners (>5 returns/month) for review."],
            "Shipping Cost Optimizer": ["Route orders to cheapest carrier meeting SLA.", "Flag billing anomalies >10% above contracted rate.", "Scorecard carriers monthly on cost, SLA, and damage rate.", "Auto-switch carriers if damage rate exceeds 2%."],
            "RTO Controller": ["Auto-suspend carriers with >15% RTO in any zone.", "Trigger COD verification for orders from high-RTO pin codes.", "Flag repeat RTO addresses for manual review.", "Weekly RTO trend report by carrier and zone."],
            "Shipdate Protector": ["Alert if pick-queue exceeds 80% of commit window.", "Auto-reroute to nearest fulfilment centre on delay risk.", "Escalate to ops manager if SLA breach is imminent.", "Track commit-window adherence by fulfilment centre."],
            "Carrier Selection Logic": ["Match carrier by weight slab, zone, and promised SLA.", "Prefer carriers with <1% damage rate.", "Use economy tier for non-urgent, low-value orders.", "Override allowed for premium/VIP customer tiers."],
            "SLA Commitments": ["D2C standard: dispatch within 24h, deliver within 5 days.", "Marketplace: follow channel-specific SLA windows.", "Express tier: same-day dispatch, 2-day delivery.", "Communicate delays proactively before SLA breach."],
            "Escalation Rules": ["Escalate unresolved tickets after 48 hours.", "Priority escalation for orders above â¹5,000.", "Auto-notify manager for 3+ customer follow-ups.", "Critical issues (safety, legal) escalate immediately."],
            "Customer Tier Rules": ["Platinum: >50 orders or >â¹1L annual spend.", "Gold: 20-50 orders or â¹50K-1L annual spend.", "Silver: 5-20 orders or â¹10K-50K annual spend.", "Tier benefits: free shipping, early access, priority support."],
            "ROAS-Gated Scaling": ["Scale budget only if ROAS â¥ 3.5Ã.", "Pause campaigns if ROAS drops below 2.0Ã for 3 consecutive days.", "CTR must exceed 1.2% to qualify for scaling.", "Maximum daily budget increase: 20% per scaling event."],
            "Ad Spend Cap": ["Monthly cap: â¹5L per channel unless override approved.", "Alert at 80% budget utilisation.", "Pause all campaigns at 100% cap.", "Quarterly cap review with marketing lead."],
            "Seasonality & Peak Tracker": ["Track Navratri, Diwali, IPL, Republic Day, and 15+ events.", "Trigger prep workflows 3 weeks before peak.", "Auto-scale inventory forecasts during peak windows.", "Coordinate with Store-Builder for themed storefronts."],
            "Conversion Rate Auditor": ["Audit homepage, PDP, and checkout weekly.", "Flag pages with >5% exit rate increase WoW.", "Recommend A/B tests for top drop-off points.", "Track funnel by device type (desktop vs. mobile)."],
            "DNR / Do-Not-Resell": ["Block customers with 3+ fraudulent return claims.", "Auto-reject orders from flagged addresses.", "Review DNR list monthly for false positives.", "Notify customer service of all new DNR additions."],
            "Fraud Scoring Rules": ["Score based on address, velocity, BIN, and device.", "Orders scoring >80 require manual review.", "Auto-block orders scoring >95.", "Update scoring model quarterly with new fraud patterns."],
            "Listing Quality Gates": ["Minimum 5 images per listing (1 main + 4 gallery).", "Title must be 60-200 characters.", "At least 3 bullet points in product description.", "Block publish if mandatory attributes are missing."]
          };

        function gA({
          open: t,
          onOpenChange: e
        }) {
          const [n, r] = (0, j.useState)(dA), [s, i] = (0, j.useState)(""), [o, l] = (0, j.useState)("All"), [A, c] = (0, j.useState)(null), d = n.filter((t => t.active)).length, w = n.filter((t => !t.active)).length, g = (0, j.useMemo)((() => n.filter((t => {
            const e = "All" === o || t.category === o,
              n = "" === s || t.name.toLowerCase().includes(s.toLowerCase()) || t.description.toLowerCase().includes(s.toLowerCase());
            return e && n
          }))), [n, s, o]);
          return (0, a.jsx)(Nr, Object.assign({
            open: t,
            onOpenChange: t => {
              t || c(null), e(t)
            }
          }, {
            children: (0, a.jsx)(Sr, Object.assign({
              side: "right",
              className: "tw-flex tw-w-full tw-flex-col tw-gap-0 tw-border-l tw-border-[rgba(255,255,255,0.06)] tw-bg-[#00081C] tw-p-0 sm:tw-max-w-md"
            }, {
              children: A ? (0, a.jsx)(uA, {
                skill: A,
                onBack: () => c(null)
              }) : (0, a.jsx)(pA, {
                skills: g,
                activeCount: d,
                inactiveCount: w,
                search: s,
                onSearchChange: i,
                activeCategory: o,
                onCategoryChange: l,
                onSelectSkill: c
              })
            }))
          }))
        }

        function uA({
          skill: t,
          onBack: e
        }) {
          const n = cA[t.category] || {
            bg: "tw-bg-[rgba(255,255,255,0.05)]",
            text: "tw-text-[rgba(255,255,255,0.5)]"
          };
          return (0, a.jsxs)(a.Fragment, {
            children: [(0, a.jsx)("div", Object.assign({
              className: "tw-flex tw-shrink-0 tw-items-center tw-justify-between tw-border-b tw-border-[rgba(255,255,255,0.08)] tw-px-5 tw-py-4"
            }, {
              children: (0, a.jsxs)("button", Object.assign({
                onClick: e,
                className: "tw-flex tw-cursor-pointer tw-items-center tw-gap-1.5 tw-text-sm tw-text-[rgba(255,255,255,0.5)] tw-transition-colors tw-border-0 tw-bg-transparent hover:tw-text-[#e6eaf2]"
              }, {
                children: [(0, a.jsx)(Pr.Z, {
                  className: "tw-w-4 tw-h-4"
                }), "All Skills"]
              }))
            })), (0, a.jsx)(vr, Object.assign({
              className: "tw-min-h-0 tw-flex-1"
            }, {
              children: (0, a.jsxs)("div", Object.assign({
                className: "tw-px-5 tw-py-5"
              }, {
                children: [(0, a.jsxs)("div", Object.assign({
                  className: "tw-flex tw-items-start tw-gap-3"
                }, {
                  children: [(0, a.jsx)("div", Object.assign({
                    className: "tw-flex tw-w-10 tw-h-10 tw-shrink-0 tw-items-center tw-justify-center tw-rounded-xl tw-bg-[rgba(255,255,255,0.06)] tw-text-[rgba(255,255,255,0.35)]"
                  }, {
                    children: (0, a.jsx)(oA.Z, {
                      className: "tw-w-5 tw-h-5"
                    })
                  })), (0, a.jsxs)("div", {
                    children: [(0, a.jsxs)("div", Object.assign({
                      className: "tw-flex tw-items-center tw-gap-2"
                    }, {
                      children: [(0, a.jsx)("h3", Object.assign({
                        className: "tw-text-lg tw-font-bold tw-text-[#e6eaf2] tw-m-0"
                      }, {
                        children: t.name
                      })), (0, a.jsx)("span", Object.assign({
                        className: xr("tw-rounded tw-px-1.5 tw-py-0.5 tw-text-[10px] tw-font-semibold", n.bg, n.text)
                      }, {
                        children: t.category
                      }))]
                    })), (0, a.jsx)("p", Object.assign({
                      className: "tw-mt-0.5 tw-text-[13px] tw-text-[rgba(255,255,255,0.35)] tw-m-0"
                    }, {
                      children: t.description
                    }))]
                  })]
                })), (0, a.jsx)("div", Object.assign({
                  className: "tw-mt-5 tw-flex tw-items-center tw-justify-between tw-border-t tw-border-[rgba(255,255,255,0.08)] tw-pt-4"
                }, {
                  children: (0, a.jsxs)("div", {
                    children: [(0, a.jsx)("span", Object.assign({
                      className: xr("tw-rounded-full tw-px-3 tw-py-1 tw-text-[12px] tw-font-semibold tw-leading-none", t.active ? "tw-bg-[rgba(16,185,129,0.1)] tw-text-emerald-400" : "tw-bg-[rgba(255,255,255,0.06)] tw-text-[rgba(255,255,255,0.25)]")
                    }, {
                      children: t.active ? "Active" : "Inactive"
                    })), (0, a.jsx)("p", Object.assign({
                      className: "tw-text-xs tw-text-[rgba(255,255,255,0.35)] tw-m-0"
                    }, {
                      children: t.active ? "This skill is shaping agent behaviour" : "This skill is currently disabled"
                    }))]
                  })
                })), (0, a.jsxs)("div", Object.assign({
                  className: "tw-mt-6"
                }, {
                  children: [(0, a.jsxs)("div", Object.assign({
                    className: "tw-mb-2 tw-flex tw-items-center tw-gap-2"
                  }, {
                    children: [(0, a.jsx)("span", Object.assign({
                      className: "tw-text-[rgba(255,255,255,0.35)]"
                    }, {
                      children: (0, a.jsxs)("svg", Object.assign({
                        width: "16",
                        height: "16",
                        viewBox: "0 0 24 24",
                        fill: "none",
                        stroke: "currentColor",
                        strokeWidth: "2",
                        strokeLinecap: "round",
                        strokeLinejoin: "round"
                      }, {
                        children: [(0, a.jsx)("rect", {
                          width: "18",
                          height: "18",
                          x: "3",
                          y: "3",
                          rx: "2"
                        }), (0, a.jsx)("path", {
                          d: "M7 7h10"
                        }), (0, a.jsx)("path", {
                          d: "M7 12h10"
                        }), (0, a.jsx)("path", {
                          d: "M7 17h10"
                        })]
                      }))
                    })), (0, a.jsx)("p", Object.assign({
                      className: "tw-text-xs tw-font-semibold tw-uppercase tw-tracking-wider tw-text-[rgba(255,255,255,0.35)] tw-m-0"
                    }, {
                      children: "What This Skill Does"
                    }))]
                  })), (0, a.jsx)("div", Object.assign({
                    className: "tw-rounded-xl tw-border tw-border-[rgba(255,255,255,0.08)] tw-bg-[rgba(255,255,255,0.03)] tw-px-4 tw-py-3"
                  }, {
                    children: (0, a.jsx)("p", Object.assign({
                      className: "tw-text-[13px] tw-leading-relaxed tw-text-[rgba(255,255,255,0.5)] tw-m-0"
                    }, {
                      children: t.description
                    }))
                  }))]
                })), (0, a.jsxs)("div", Object.assign({
                  className: "tw-mt-6"
                }, {
                  children: [(0, a.jsxs)("div", Object.assign({
                    className: "tw-mb-2 tw-flex tw-items-center tw-gap-2"
                  }, {
                    children: [(0, a.jsx)("span", Object.assign({
                      className: "tw-text-[rgba(255,255,255,0.35)]"
                    }, {
                      children: (0, a.jsx)(oA.Z, {
                        className: "tw-w-4 tw-h-4"
                      })
                    })), (0, a.jsx)("p", Object.assign({
                      className: "tw-text-xs tw-font-semibold tw-uppercase tw-tracking-wider tw-text-[rgba(255,255,255,0.35)] tw-m-0"
                    }, {
                      children: "Agent Guideline"
                    }))]
                  })), (0, a.jsx)("div", Object.assign({
                    className: "tw-rounded-xl tw-border tw-border-[rgba(0,204,189,0.2)] tw-bg-[rgba(0,204,189,0.06)] tw-px-4 tw-py-3.5"
                  }, {
                    children: (0, a.jsx)("ul", Object.assign({
                      className: "tw-flex tw-flex-col tw-gap-2 tw-list-none tw-p-0 tw-m-0"
                    }, {
                      children: (wA[t.name] || ["No guidelines configured for this skill yet."]).map(((t, e) => (0, a.jsxs)("li", Object.assign({
                        className: "tw-text-[13px] tw-leading-relaxed tw-text-[rgba(255,255,255,0.5)]"
                      }, {
                        children: [(0, a.jsx)("span", Object.assign({
                          className: "tw-mr-1 tw-text-[rgba(255,255,255,0.35)]"
                        }, {
                          children: "Â·"
                        })), " ", t]
                      }), e)))
                    }))
                  }))]
                })), (0, a.jsxs)("div", Object.assign({
                  className: "tw-mt-6"
                }, {
                  children: [(0, a.jsxs)("div", Object.assign({
                    className: "tw-mb-2.5 tw-flex tw-items-center tw-gap-2"
                  }, {
                    children: [(0, a.jsx)("span", Object.assign({
                      className: "tw-text-[rgba(255,255,255,0.35)]"
                    }, {
                      children: (0, a.jsx)(_s.Z, {
                        className: "tw-w-4 tw-h-4"
                      })
                    })), (0, a.jsx)("p", Object.assign({
                      className: "tw-text-xs tw-font-semibold tw-uppercase tw-tracking-wider tw-text-[rgba(255,255,255,0.35)] tw-m-0"
                    }, {
                      children: "Applied to Agents"
                    }))]
                  })), (0, a.jsx)("div", Object.assign({
                    className: "tw-flex tw-flex-wrap tw-gap-2"
                  }, {
                    children: t.tags.map((t => (0, a.jsx)("span", Object.assign({
                      className: "tw-rounded-full tw-border tw-border-[rgba(0,204,189,0.2)] tw-px-3 tw-py-1 tw-text-[13px] tw-font-medium tw-text-[#00CCBD]"
                    }, {
                      children: t
                    }), t)))
                  }))]
                }))]
              }))
            }))]
          })
        }

        function pA({
          skills: t,
          activeCount: e,
          inactiveCount: n,
          search: r,
          onSearchChange: s,
          activeCategory: i,
          onCategoryChange: o,
          onSelectSkill: l
        }) {
          return (0, a.jsxs)(a.Fragment, {
            children: [(0, a.jsxs)(kr, Object.assign({
              className: "tw-shrink-0 tw-border-b tw-border-[rgba(255,255,255,0.08)] tw-px-5 tw-pt-5 tw-pb-4"
            }, {
              children: [(0, a.jsxs)("div", Object.assign({
                className: "tw-flex tw-items-center tw-gap-3"
              }, {
                children: [(0, a.jsx)("div", Object.assign({
                  className: "tw-flex tw-w-9 tw-h-9 tw-items-center tw-justify-center tw-rounded-full tw-bg-gradient-to-br tw-from-[#00CCBD] tw-to-[rgba(0,204,189,0.7)]"
                }, {
                  children: (0, a.jsx)(_s.Z, {
                    className: "tw-w-4 tw-h-4 tw-text-[#0A1526]"
                  })
                })), (0, a.jsxs)("div", {
                  children: [(0, a.jsx)(Ir, Object.assign({
                    className: "tw-text-lg tw-font-bold tw-text-[#e6eaf2]"
                  }, {
                    children: "AI Skills"
                  })), (0, a.jsxs)(Mr, Object.assign({
                    className: "tw-text-xs tw-text-[rgba(255,255,255,0.35)]"
                  }, {
                    children: [e, " active Â· ", n, " Inactive"]
                  }))]
                })]
              })), (0, a.jsx)("p", Object.assign({
                className: "tw-mt-2 tw-text-[13px] tw-leading-relaxed tw-text-[rgba(255,255,255,0.35)] tw-m-0"
              }, {
                children: "Guidelines and policies that shape how every agent function behaves. Active skills are consumed across all applicable tabs."
              })), (0, a.jsxs)("div", Object.assign({
                className: "tw-mt-4 tw-grid tw-grid-cols-3 tw-gap-2"
              }, {
                children: [(0, a.jsxs)("div", Object.assign({
                  className: "tw-rounded-lg tw-bg-[rgba(0,204,189,0.1)] tw-px-3 tw-py-2.5"
                }, {
                  children: [(0, a.jsx)("p", Object.assign({
                    className: "tw-text-xl tw-font-bold tw-text-[#00CCBD] tw-m-0"
                  }, {
                    children: e
                  })), (0, a.jsx)("p", Object.assign({
                    className: "tw-text-[11px] tw-font-medium tw-text-[#00CCBD] tw-m-0"
                  }, {
                    children: "Active"
                  }))]
                })), (0, a.jsxs)("div", Object.assign({
                  className: "tw-rounded-lg tw-bg-[rgba(255,255,255,0.05)] tw-px-3 tw-py-2.5"
                }, {
                  children: [(0, a.jsx)("p", Object.assign({
                    className: "tw-text-xl tw-font-bold tw-text-[rgba(255,255,255,0.5)] tw-m-0"
                  }, {
                    children: n
                  })), (0, a.jsx)("p", Object.assign({
                    className: "tw-text-[11px] tw-font-medium tw-text-[rgba(255,255,255,0.35)] tw-m-0"
                  }, {
                    children: "Inactive"
                  }))]
                })), (0, a.jsxs)("div", Object.assign({
                  className: "tw-rounded-lg tw-bg-[rgba(249,115,22,0.1)] tw-px-3 tw-py-2.5"
                }, {
                  children: [(0, a.jsx)("p", Object.assign({
                    className: "tw-text-xl tw-font-bold tw-text-orange-400 tw-m-0"
                  }, {
                    children: "0"
                  })), (0, a.jsx)("p", Object.assign({
                    className: "tw-text-[11px] tw-font-medium tw-text-orange-400 tw-m-0"
                  }, {
                    children: "Custom"
                  }))]
                }))]
              })), (0, a.jsxs)("div", Object.assign({
                className: "tw-relative tw-mt-4"
              }, {
                children: [(0, a.jsx)(zr.Z, {
                  className: "tw-absolute tw-left-3 tw-top-1/2 tw-w-4 tw-h-4 tw--translate-y-1/2 tw-text-[rgba(255,255,255,0.35)]"
                }), (0, a.jsx)(iA, {
                  placeholder: "Search skills...",
                  value: r,
                  onChange: t => s(t.target.value),
                  className: "tw-h-9 tw-rounded-lg tw-border-[rgba(255,255,255,0.08)] tw-bg-[#000D26] tw-pl-9 tw-text-sm tw-text-[#e6eaf2] placeholder:tw-text-[rgba(255,255,255,0.25)] focus-visible:tw-border-[#00CCBD] focus-visible:tw-ring-[rgba(0,204,189,0.2)]"
                })]
              })), (0, a.jsx)("div", Object.assign({
                className: "tw-mt-3 tw-flex tw-flex-wrap tw-gap-1.5"
              }, {
                children: AA.map((t => (0, a.jsx)("button", Object.assign({
                  onClick: () => o(t),
                  className: xr("tw-rounded-full tw-px-3 tw-py-1 tw-text-xs tw-font-medium tw-transition-colors tw-border-0 tw-cursor-pointer", i === t ? "tw-bg-[#00CCBD] tw-text-white" : "tw-bg-[rgba(255,255,255,0.05)] tw-text-[rgba(255,255,255,0.5)] hover:tw-bg-[rgba(255,255,255,0.1)]")
                }, {
                  children: t
                }), t)))
              }))]
            })), (0, a.jsx)(vr, Object.assign({
              className: "tw-min-h-0 tw-flex-1"
            }, {
              children: (0, a.jsxs)("div", Object.assign({
                className: "tw-flex tw-flex-col tw-divide-y tw-divide-[rgba(255,255,255,0.06)] tw-px-1"
              }, {
                children: [t.map((t => {
                  const e = cA[t.category] || {
                    text: "tw-text-[rgba(255,255,255,0.5)]",
                    bg: "tw-bg-[rgba(255,255,255,0.05)]"
                  };
                  return (0, a.jsxs)("div", Object.assign({
                    className: "tw-group tw-flex tw-items-start tw-gap-3 tw-px-4 tw-py-4 tw-transition-colors hover:tw-bg-[rgba(255,255,255,0.03)]"
                  }, {
                    children: [(0, a.jsx)("div", Object.assign({
                      className: "tw-mt-0.5 tw-flex tw-w-9 tw-h-9 tw-shrink-0 tw-items-center tw-justify-center tw-rounded-lg tw-bg-[rgba(255,255,255,0.05)] tw-text-[rgba(255,255,255,0.5)] tw-transition-colors group-hover:tw-bg-[rgba(255,255,255,0.08)]"
                    }, {
                      children: (0, a.jsx)(oA.Z, {
                        className: "tw-w-4 tw-h-4"
                      })
                    })), (0, a.jsxs)("div", Object.assign({
                      className: "tw-min-w-0 tw-flex-1"
                    }, {
                      children: [(0, a.jsxs)("div", Object.assign({
                        className: "tw-flex tw-items-center tw-gap-2"
                      }, {
                        children: [(0, a.jsx)("p", Object.assign({
                          className: "tw-text-sm tw-font-semibold tw-text-[#e6eaf2] tw-m-0"
                        }, {
                          children: t.name
                        })), (0, a.jsx)("span", Object.assign({
                          className: xr("tw-rounded tw-px-1.5 tw-py-0.5 tw-text-[10px] tw-font-semibold", e.bg, e.text)
                        }, {
                          children: t.category
                        }))]
                      })), (0, a.jsx)("p", Object.assign({
                        className: "tw-mt-0.5 tw-text-xs tw-leading-relaxed tw-text-[rgba(255,255,255,0.35)] tw-m-0"
                      }, {
                        children: t.description
                      })), (0, a.jsx)("div", Object.assign({
                        className: "tw-mt-1.5 tw-flex tw-flex-wrap tw-gap-1"
                      }, {
                        children: t.tags.map((t => (0, a.jsx)("span", Object.assign({
                          className: "tw-rounded tw-border tw-border-[rgba(255,255,255,0.08)] tw-bg-[rgba(255,255,255,0.04)] tw-px-1.5 tw-py-0.5 tw-text-[10px] tw-font-medium tw-text-[rgba(255,255,255,0.35)]"
                        }, {
                          children: t
                        }), t)))
                      }))]
                    })), (0, a.jsxs)("div", Object.assign({
                      className: "tw-flex tw-shrink-0 tw-items-center tw-gap-2 tw-pt-1"
                    }, {
                      children: [(0, a.jsx)("span", Object.assign({
                        className: xr("tw-rounded-full tw-px-2.5 tw-py-1 tw-text-[11px] tw-font-semibold tw-leading-none", t.active ? "tw-bg-[rgba(16,185,129,0.1)] tw-text-emerald-400" : "tw-bg-[rgba(255,255,255,0.06)] tw-text-[rgba(255,255,255,0.25)]")
                      }, {
                        children: t.active ? "Active" : "Inactive"
                      })), (0, a.jsx)("button", Object.assign({
                        onClick: () => l(t),
                        className: "tw-cursor-pointer tw-rounded tw-p-0.5 tw-text-[rgba(255,255,255,0.25)] tw-transition-colors tw-border-0 tw-bg-transparent hover:tw-bg-[rgba(255,255,255,0.05)] hover:tw-text-[rgba(255,255,255,0.5)]",
                        "aria-label": `View ${t.name} details`
                      }, {
                        children: (0, a.jsx)(xl.Z, {
                          className: "tw-w-4 tw-h-4"
                        })
                      }))]
                    }))]
                  }), t.name)
                })), 0 === t.length && (0, a.jsxs)("div", Object.assign({
                  className: "tw-flex tw-flex-col tw-items-center tw-justify-center tw-py-16 tw-text-center"
                }, {
                  children: [(0, a.jsx)(zr.Z, {
                    className: "tw-mb-2 tw-w-8 tw-h-8 tw-text-[rgba(255,255,255,0.2)]"
                  }), (0, a.jsx)("p", Object.assign({
                    className: "tw-text-sm tw-font-medium tw-text-[rgba(255,255,255,0.35)] tw-m-0"
                  }, {
                    children: "No skills found"
                  })), (0, a.jsx)("p", Object.assign({
                    className: "tw-mt-1 tw-text-xs tw-text-[rgba(255,255,255,0.25)] tw-m-0"
                  }, {
                    children: "Try adjusting your search or filter"
                  }))]
                }))]
              }))
            })), (0, a.jsx)("div", Object.assign({
              className: "tw-shrink-0 tw-border-t tw-border-[rgba(255,255,255,0.08)] tw-bg-[#000D26] tw-px-5 tw-py-4"
            }, {
              children: (0, a.jsxs)("div", Object.assign({
                className: "tw-flex tw-items-center tw-justify-between"
              }, {
                children: [(0, a.jsxs)("div", {
                  children: [(0, a.jsx)("p", Object.assign({
                    className: "tw-text-sm tw-font-semibold tw-text-[#e6eaf2] tw-m-0"
                  }, {
                    children: "Add a Guideline Skill"
                  })), (0, a.jsx)("p", Object.assign({
                    className: "tw-mt-0.5 tw-text-xs tw-text-[rgba(255,255,255,0.35)] tw-m-0"
                  }, {
                    children: "Write a custom policy for any agent function"
                  }))]
                }), (0, a.jsxs)("button", Object.assign({
                  className: "tw-flex tw-cursor-pointer tw-items-center tw-gap-1 tw-rounded-lg tw-px-3 tw-py-1.5 tw-text-sm tw-font-semibold tw-text-[#00CCBD] tw-transition-all tw-duration-150 tw-border-0 tw-bg-transparent hover:tw-bg-[rgba(0,204,189,0.1)] active:tw-scale-95"
                }, {
                  children: [(0, a.jsx)(lA.Z, {
                    className: "tw-w-4 tw-h-4"
                  }), "Add Skill"]
                }))]
              }))
            }))]
          })
        }

        function bA({
          title: t,
          skills: e
        }) {
          const [n, r] = (0, j.useState)(!1);
          return (0, a.jsxs)(a.Fragment, {
            children: [(0, a.jsxs)("div", Object.assign({
              className: "tw-relative tw-flex tw-flex-col tw-gap-3 tw-overflow-hidden tw-rounded-xl tw-border tw-border-[rgba(255,255,255,0.06)] tw-p-4 sm:tw-p-5 tw-shadow-[0_10px_30px_rgba(0,0,0,0.35)] tw-backdrop-blur-[10px] tw-transition-[filter,box-shadow] tw-duration-200 tw-ease-out hover:tw-brightness-[1.03] hover:tw-shadow-[0_12px_36px_rgba(0,0,0,0.4)]",
              style: {
                background: "linear-gradient(145deg, rgba(15,23,42,0.85), rgba(10,18,36,0.65))"
              }
            }, {
              children: [(0, a.jsx)("div", {
                className: "tw-pointer-events-none tw-absolute tw-inset-0",
                style: {
                  background: "linear-gradient(135deg, rgba(59,130,246,0.08), rgba(59,130,246,0.02) 40%, transparent 70%)"
                },
                "aria-hidden": "true"
              }), (0, a.jsxs)("div", Object.assign({
                className: "tw-flex tw-items-center tw-justify-between"
              }, {
                children: [(0, a.jsxs)("h2", Object.assign({
                  className: "tw-flex tw-items-center tw-gap-2 tw-text-xs tw-font-semibold tw-uppercase tw-tracking-wide tw-m-0",
                  style: {
                    color: "#8d89a9"
                  }
                }, {
                  children: [(0, a.jsx)(_s.Z, {
                    className: "tw-w-3.5 tw-h-3.5 tw-text-[#00CCBD]"
                  }), t]
                })), (0, a.jsxs)("button", Object.assign({
                  onClick: () => r(!0),
                  className: "tw-flex tw-items-center tw-gap-1 tw-text-sm tw-font-medium tw-text-[#00CCBD] hover:tw-text-[#00E5D4] tw-border-0 tw-bg-transparent tw-cursor-pointer"
                }, {
                  children: ["Manage", (0, a.jsx)(rA.Z, {
                    className: "tw-w-3.5 tw-h-3.5"
                  })]
                }))]
              })), (0, a.jsx)("div", Object.assign({
                className: "tw-flex tw-flex-wrap tw-items-center tw-gap-3 sm:tw-gap-4"
              }, {
                children: e.map((t => {
                  var e;
                  return (0, a.jsxs)("span", Object.assign({
                    className: "tw-flex tw-items-center tw-gap-2 tw-text-xs sm:tw-text-sm tw-font-medium tw-text-[#bebebe]"
                  }, {
                    children: [(0, a.jsx)("span", {
                      className: `tw-w-2 tw-h-2 tw-rounded-full ${null!==(e=t.color)&&void 0!==e?e:"tw-bg-[#00CCBD]"}`
                    }), t.name]
                  }), t.name)
                }))
              }))]
            })), (0, a.jsx)(gA, {
              open: n,
              onOpenChange: r
            })]
          })
        }
        const hA = [{
          name: "Seasonality & Peak Tracker",
          color: "tw-bg-[#00CCBD]"
        }, {
          name: "Media & Copy Creator",
          color: "tw-bg-[#00CCBD]"
        }, {
          name: "Campaign Analyzer",
          color: "tw-bg-[#00CCBD]"
        }];

        function mA() {
          return (0, a.jsx)(bA, {
            title: "Marketing Agent Skills",
            skills: hA
          })
        }
        var xA = function(t, e) {
          var n = {};
          for (var a in t) Object.prototype.hasOwnProperty.call(t, a) && e.indexOf(a) < 0 && (n[a] = t[a]);
          if (null != t && "function" == typeof Object.getOwnPropertySymbols) {
            var r = 0;
            for (a = Object.getOwnPropertySymbols(t); r < a.length; r++) e.indexOf(a[r]) < 0 && Object.prototype.propertyIsEnumerable.call(t, a[r]) && (n[a[r]] = t[a[r]])
          }
          return n
        };
        const fA = {
          default: "tw-border-transparent tw-bg-[rgba(255,255,255,0.1)] tw-text-[#e6eaf2]",
          secondary: "tw-border-transparent tw-bg-[rgba(255,255,255,0.05)] tw-text-[rgba(255,255,255,0.7)]",
          destructive: "tw-border-transparent tw-bg-red-600 tw-text-white",
          outline: "tw-text-[#e6eaf2]"
        };

        function vA(t) {
          var {
            className: e,
            variant: n = "default"
          } = t, r = xA(t, ["className", "variant"]);
          return (0, a.jsx)("span", Object.assign({
            "data-slot": "badge",
            className: xr("tw-inline-flex tw-items-center tw-justify-center tw-rounded-md tw-border tw-px-2 tw-py-0.5 tw-text-xs tw-font-medium tw-w-fit tw-whitespace-nowrap tw-shrink-0 tw-gap-1 tw-transition-colors tw-overflow-hidden", fA[n], e)
          }, r))
        }

        function jA({
          module: t,
          activities: e
        }) {
          const {
            data: n,
            isLoading: r
          } = bo(t), s = t ? null != n ? n : [] : null != e ? e : [];
          return t && r ? (0, a.jsx)(ql, {}) : s.length ? (0, a.jsxs)("div", Object.assign({
            className: "tw-relative tw-overflow-hidden tw-rounded-xl tw-border tw-border-[rgba(255,255,255,0.06)] tw-py-3 tw-shadow-[0_10px_30px_rgba(0,0,0,0.35)] tw-backdrop-blur-[10px] tw-transition-[filter,box-shadow] tw-duration-200 tw-ease-out hover:tw-brightness-[1.03] hover:tw-shadow-[0_12px_36px_rgba(0,0,0,0.4)]",
            style: {
              background: "linear-gradient(145deg, rgba(15,23,42,0.85), rgba(10,18,36,0.65))"
            }
          }, {
            children: [(0, a.jsx)("div", {
              className: "tw-pointer-events-none tw-absolute tw-inset-0",
              style: {
                background: "linear-gradient(135deg, rgba(59,130,246,0.08), rgba(59,130,246,0.02) 40%, transparent 70%)"
              },
              "aria-hidden": "true"
            }), (0, a.jsx)("div", Object.assign({
              className: "tw-relative tw-px-3 sm:tw-px-4 tw-pb-0"
            }, {
              children: (0, a.jsxs)("h3", Object.assign({
                className: "tw-flex tw-items-center tw-gap-2 tw-text-xs tw-font-semibold tw-uppercase tw-tracking-wide tw-m-0",
                style: {
                  color: "#8d89a9"
                }
              }, {
                children: [(0, a.jsx)(_s.Z, {
                  className: "tw-w-3.5 tw-h-3.5 tw-text-[#00CCBD]"
                }), "Agent Activity"]
              }))
            })), (0, a.jsx)("div", Object.assign({
              className: "tw-relative tw-max-h-[196px] tw-overflow-y-auto tw-px-3 sm:tw-px-4 tw-flex tw-flex-col tw-gap-0 [&::-webkit-scrollbar]:tw-w-1.5 [&::-webkit-scrollbar-track]:tw-bg-transparent [&::-webkit-scrollbar-thumb]:tw-rounded-full [&::-webkit-scrollbar-thumb]:tw-bg-[rgba(255,255,255,0.15)] [&::-webkit-scrollbar-thumb:hover]:tw-bg-[rgba(255,255,255,0.25)]"
            }, {
              children: s.map(((t, e) => (0, a.jsxs)("div", Object.assign({
                className: "tw-flex tw-flex-col sm:tw-flex-row tw-items-start sm:tw-justify-between tw-gap-2 sm:tw-gap-4 tw-py-2 " + (e < s.length - 1 ? "tw-border-b tw-border-[rgba(255,255,255,0.08)]" : "")
              }, {
                children: [(0, a.jsxs)("div", Object.assign({
                  className: "tw-flex tw-items-start tw-gap-3"
                }, {
                  children: [(0, a.jsx)("span", {
                    className: `tw-mt-1.5 tw-w-2 tw-h-2 tw-shrink-0 tw-rounded-full ${0===e?"tw-animate-pulse":""} ${t.statusColor}`,
                    style: 0 === e ? {
                      boxShadow: "0 0 12px rgba(16, 185, 129, 0.6)"
                    } : void 0
                  }), (0, a.jsxs)("div", Object.assign({
                    className: "tw-flex tw-flex-col tw-gap-0.5"
                  }, {
                    children: [(0, a.jsx)("div", Object.assign({
                      className: "tw-flex tw-flex-wrap tw-items-center tw-gap-2"
                    }, {
                      children: (0, a.jsx)(vA, Object.assign({
                        variant: "secondary",
                        className: `tw-rounded-md tw-border tw-border-[rgba(255,255,255,0.08)] tw-px-2 tw-py-0.5 tw-text-[11px] tw-font-medium ${t.agentTypeColor}`
                      }, {
                        children: t.agentType
                      }))
                    })), t.description && (0, a.jsx)("p", Object.assign({
                      className: "tw-text-[13px] tw-leading-[1.5] tw-text-[rgba(255,255,255,0.5)] tw-m-0"
                    }, {
                      children: t.description
                    }))]
                  }))]
                })), (0, a.jsx)("div", Object.assign({
                  className: "tw-flex tw-shrink-0 tw-items-center tw-gap-2"
                }, {
                  children: t.time && (0, a.jsx)("span", Object.assign({
                    className: "tw-shrink-0 tw-text-xs tw-text-[rgba(255,255,255,0.35)]"
                  }, {
                    children: t.time
                  }))
                }))]
              }), e)))
            }))]
          })) : null
        }

        function EA() {
          return (0, a.jsx)(jA, {
            module: "marketing"
          })
        }
        var yA = function(t, e) {
          var n = {};
          for (var a in t) Object.prototype.hasOwnProperty.call(t, a) && e.indexOf(a) < 0 && (n[a] = t[a]);
          if (null != t && "function" == typeof Object.getOwnPropertySymbols) {
            var r = 0;
            for (a = Object.getOwnPropertySymbols(t); r < a.length; r++) e.indexOf(a[r]) < 0 && Object.prototype.propertyIsEnumerable.call(t, a[r]) && (n[a[r]] = t[a[r]])
          }
          return n
        };
        const CA = {
            default: "tw-bg-[#00CCBD] tw-text-white hover:tw-bg-[#00E5D4]",
            destructive: "tw-bg-red-600 tw-text-white hover:tw-bg-red-700",
            outline: "tw-border tw-border-[rgba(255,255,255,0.08)] tw-bg-transparent tw-shadow-sm hover:tw-bg-[rgba(255,255,255,0.05)]",
            secondary: "tw-bg-[rgba(255,255,255,0.05)] tw-text-[#e6eaf2] hover:tw-bg-[rgba(255,255,255,0.1)]",
            ghost: "hover:tw-bg-[rgba(255,255,255,0.05)]",
            link: "tw-text-[#00CCBD] tw-underline-offset-4 hover:tw-underline"
          },
          OA = {
            default: "tw-h-9 tw-px-4 tw-py-2",
            sm: "tw-h-8 tw-rounded-md tw-gap-1.5 tw-px-3",
            lg: "tw-h-10 tw-rounded-md tw-px-6",
            icon: "tw-w-9 tw-h-9"
          };

        function NA(t) {
          var {
            className: e,
            variant: n = "default",
            size: r = "default"
          } = t, s = yA(t, ["className", "variant", "size"]);
          return (0, a.jsx)("button", Object.assign({
            "data-slot": "button",
            className: xr("tw-inline-flex tw-items-center tw-justify-center tw-gap-2 tw-whitespace-nowrap tw-rounded-md tw-text-sm tw-font-medium tw-transition-all tw-cursor-pointer tw-border-0", "disabled:tw-pointer-events-none disabled:tw-opacity-50", CA[n], OA[r], e)
          }, s))
        }
        var SA = n(35162),
          kA = n(97369),
          IA = function(t, e, n, a) {
            return new(n || (n = Promise))((function(r, s) {
              function i(t) {
                try {
                  l(a.next(t))
                } catch (t) {
                  s(t)
                }
              }

              function o(t) {
                try {
                  l(a.throw(t))
                } catch (t) {
                  s(t)
                }
              }

              function l(t) {
                var e;
                t.done ? r(t.value) : (e = t.value, e instanceof n ? e : new n((function(t) {
                  t(e)
                }))).then(i, o)
              }
              l((a = a.apply(t, e || [])).next())
            }))
          };
        const MA = 5e3;
        let TA = null,
          RA = null;

        function BA() {
          TA && (clearInterval(TA), TA = null, RA = null, console.log("[ActionPolling] Cleared global interval"))
        }

        function _A(t, e) {
          const n = (0, O.useQueryClient)(),
            a = (0, j.useRef)(e);
          return a.current = e, (0, j.useEffect)((() => () => BA()), []), {
            startPolling: e => {
              t && function(t, e, n, r) {
                BA(), RA = t, console.log("[ActionPolling] Starting global polling for:", t, e), TA = setInterval((() => IA(this, void 0, void 0, (function*() {
                  if (RA === t) {
                    console.log("[ActionPolling] Polling...", {
                      cardId: t,
                      module: e
                    });
                    try {
                      const [s, i] = yield Promise.all([wo(e), go(e)]), o = s.some((e => e.title === t));
                      console.log("[ActionPolling] Card present (by title):", o, "count:", s.length), o || (n.setQueryData(["actions", e], s), n.setQueryData(["activities", e], i), r = t, a.current(r), BA())
                    } catch (t) {
                      console.warn("[ActionPolling] Error, retrying:", t)
                    }
                  }
                  var r
                }))), MA)
              }(e, t, n)
            },
            stopPolling: () => {
              BA()
            }
          }
        }
        const DA = 1200;

        function LA({
          module: t,
          actions: e,
          columns: n = 2,
          disableProcessing: r
        }) {
          const {
            data: s,
            isLoading: i
          } = po(t), o = t ? null != s ? s : [] : null != e ? e : [], l = 3 === n ? "md:tw-grid-cols-3" : "md:tw-grid-cols-2", [A, c] = (0, j.useState)(new Set), [d, w] = (0, j.useState)(null), [g, u] = (0, j.useState)(null), [p, b] = (0, j.useState)(!1), [h, m] = (0, j.useState)(!1), [x, f] = (0, j.useState)(null), [v, y] = (0, j.useState)(new Set), C = (0, j.useRef)(new Map);
          (0, In.zX)(In.FP.AGENT.ACTION_CARD_STATUS, (t => {
            const {
              actionCardId: e,
              status: n
            } = t.payload || {};
            if (!e) return;
            const a = null == n ? void 0 : n.toLowerCase();
            "completed" === a ? (y((t => new Set(t).add(e))), w((t => t === e ? null : t)), setTimeout((() => {
              const t = o.findIndex((t => t.id === e));
              if (-1 === t) return;
              const n = k();
              c((e => new Set(e).add(t))), requestAnimationFrame((() => I(n)))
            }), 5e3)) : "in_progress" === a ? w(e) : "failed" === a && w((t => t === e ? null : t))
          }));
          const O = (0, j.useCallback)((t => {
              console.log("[ActionPolling] Card completed:", t), w(null), f(null)
            }), []),
            {
              startPolling: N,
              stopPolling: S
            } = _A(t, O);
          E().useEffect((() => S), []);
          const k = (0, j.useCallback)((() => {
              const t = new Map;
              return C.current.forEach(((e, n) => {
                e && t.set(n, e.getBoundingClientRect())
              })), t
            }), []),
            I = (0, j.useCallback)((t => {
              requestAnimationFrame((() => {
                C.current.forEach(((e, n) => {
                  const a = t.get(n);
                  if (!e || !a) return;
                  const r = e.getBoundingClientRect(),
                    s = a.left - r.left,
                    i = a.top - r.top;
                  0 === s && 0 === i || (e.style.transform = `translate(${s}px, ${i}px)`, e.style.transition = "none", requestAnimationFrame((() => {
                    e.style.transition = "transform 400ms ease-in-out", e.style.transform = ""
                  })))
                }))
              }))
            }), []),
            M = (0, j.useCallback)(((t, e) => {
              if (!e || h) return;
              const n = o[t],
                a = (null == n ? void 0 : n.id, C.current.get(t));
              if (!a) return;
              const r = a.getBoundingClientRect();
              m(!0), u({
                index: t,
                rect: r,
                action: n
              }), b(!1), window.dispatchEvent(new CustomEvent("zai-panel-highlight")), requestAnimationFrame((() => {
                requestAnimationFrame((() => b(!0)))
              })), setTimeout((() => {
                const t = {
                  prompt: e,
                  openChat: !0,
                  sessionId: null == n ? void 0 : n.sessionId,
                  actionCardId: null == n ? void 0 : n.id
                };
                (0, In.aI)("send_prompt", t), u(null), b(!1), m(!1)
              }), DA)
            }), [o, h]),
            T = "undefined" != typeof window ? window.innerWidth - 20 : 1e3,
            R = "undefined" != typeof window ? window.innerHeight / 2 : 400,
            B = (0, j.useCallback)((() => {
              const t = document.querySelector('[style*="width: 384"]') || document.querySelector('[style*="min-width: 384"]');
              if (t) {
                const e = t.getBoundingClientRect(),
                  n = t.querySelectorAll("div");
                let a = null;
                for (const t of Array.from(n))
                  if (t.scrollHeight > t.clientHeight && t.clientHeight > 100) {
                    a = t;
                    break
                  } if (a) {
                  const {
                    scrollTop: t,
                    scrollHeight: n,
                    clientHeight: r
                  } = a;
                  if (t > 20 || n > r + 50) {
                    const t = a.getBoundingClientRect();
                    return {
                      x: e.left + e.width / 2,
                      y: t.bottom - 40
                    }
                  }
                }
                return {
                  x: e.left + e.width / 2,
                  y: e.top + 100
                }
              }
              return {
                x: T,
                y: R
              }
            }), [T, R]),
            _ = o.map(((t, e) => ({
              action: t,
              originalIndex: e
            }))).filter((({
              originalIndex: t
            }) => !A.has(t)));
          return t && i ? (0, a.jsx)(Ql, {}) : (null == o ? void 0 : o.length) ? (0, a.jsxs)("div", Object.assign({
            className: "tw-flex tw-flex-col tw-gap-3"
          }, {
            children: [(0, a.jsxs)("h2", Object.assign({
              className: "tw-flex tw-items-center tw-gap-2 tw-text-xs tw-font-semibold tw-uppercase tw-tracking-wide tw-m-0",
              style: {
                color: "#8d89a9"
              }
            }, {
              children: [(0, a.jsx)(_s.Z, {
                className: "tw-w-3.5 tw-h-3.5 tw-text-[#00CCBD]"
              }), "Ready for You to Action"]
            })), (0, a.jsx)("div", Object.assign({
              className: `tw-grid tw-grid-cols-1 tw-gap-3 sm:tw-gap-4 ${l}`
            }, {
              children: _.map((({
                action: t,
                originalIndex: e
              }) => {
                var n, r, s, i;
                return (0, a.jsx)("div", Object.assign({
                  ref: t => {
                    t ? C.current.set(e, t) : C.current.delete(e)
                  }
                }, {
                  children: (0, a.jsxs)("div", Object.assign({
                    className: "tw-relative tw-flex tw-flex-col tw-justify-between tw-gap-3 tw-overflow-hidden tw-rounded-xl tw-border tw-p-4 tw-shadow-[0_10px_30px_rgba(0,0,0,0.35)] tw-backdrop-blur-[10px] tw-transition-[filter,box-shadow] tw-duration-200 tw-ease-out hover:tw-brightness-[1.03] hover:tw-shadow-[0_12px_36px_rgba(0,0,0,0.4)] tw-h-full " + (d === (null !== (n = t.id) && void 0 !== n ? n : `idx-${e}`) ? "tw-border-[rgba(0,204,189,0.4)] tw-shadow-[0_0_20px_rgba(0,204,189,0.15)]" : "tw-border-[rgba(255,255,255,0.06)]"),
                    style: {
                      background: "linear-gradient(145deg, rgba(15,23,42,0.85), rgba(10,18,36,0.65))"
                    }
                  }, {
                    children: [(0, a.jsx)("div", {
                      className: "tw-pointer-events-none tw-absolute tw-inset-0",
                      style: {
                        background: "linear-gradient(135deg, rgba(59,130,246,0.08), rgba(59,130,246,0.02) 40%, transparent 70%)"
                      },
                      "aria-hidden": "true"
                    }), d === (null !== (r = t.id) && void 0 !== r ? r : `idx-${e}`) && !v.has(null !== (s = t.id) && void 0 !== s ? s : "") && (0, a.jsxs)("div", Object.assign({
                      className: "tw-absolute tw-inset-0 tw-z-10 tw-flex tw-flex-col tw-items-center tw-justify-center tw-gap-3 tw-rounded-xl",
                      style: {
                        background: "linear-gradient(135deg, rgba(0,204,189,0.15) 0%, rgba(0,18,50,0.95) 50%, rgba(0,204,189,0.1) 100%)",
                        backdropFilter: "blur(4px)"
                      }
                    }, {
                      children: [(0, a.jsxs)("div", Object.assign({
                        className: "tw-flex tw-items-center tw-gap-2"
                      }, {
                        children: [(0, a.jsx)(SA.Z, {
                          className: "tw-w-5 tw-h-5 tw-text-[#00CCBD] tw-animate-pulse"
                        }), (0, a.jsx)("span", Object.assign({
                          className: "tw-text-sm tw-font-semibold tw-text-[#00CCBD]"
                        }, {
                          children: "AZai is on it"
                        }))]
                      })), (0, a.jsx)("p", Object.assign({
                        className: "tw-text-xs tw-text-[rgba(255,255,255,0.5)] tw-m-0 tw-text-center tw-px-4"
                      }, {
                        children: "Taking care of this action for you..."
                      }))]
                    })), t.id && v.has(t.id) && (0, a.jsxs)("div", Object.assign({
                      className: "tw-absolute tw-inset-0 tw-z-10 tw-flex tw-flex-col tw-items-center tw-justify-center tw-gap-3 tw-rounded-xl",
                      style: {
                        background: "linear-gradient(135deg, rgba(0,204,189,0.12) 0%, rgba(0,18,50,0.92) 50%, rgba(0,204,189,0.08) 100%)",
                        backdropFilter: "blur(4px)"
                      }
                    }, {
                      children: [(0, a.jsxs)("div", Object.assign({
                        className: "tw-flex tw-items-center tw-gap-2"
                      }, {
                        children: [(0, a.jsx)(kA.Z, {
                          className: "tw-w-6 tw-h-6 tw-text-[#00CCBD]"
                        }), (0, a.jsx)("span", Object.assign({
                          className: "tw-text-sm tw-font-semibold tw-text-[#00CCBD]"
                        }, {
                          children: "Completed"
                        }))]
                      })), (0, a.jsx)("p", Object.assign({
                        className: "tw-text-xs tw-text-[rgba(255,255,255,0.5)] tw-m-0 tw-text-center tw-px-4"
                      }, {
                        children: "This action has been taken care of!"
                      }))]
                    })), (0, a.jsxs)("div", Object.assign({
                      className: "tw-relative tw-flex tw-flex-col tw-gap-3"
                    }, {
                      children: [(0, a.jsx)(vA, Object.assign({
                        variant: "outline",
                        className: `tw-w-fit tw-rounded-full tw-text-[11px] tw-font-medium ${t.badgeColor}`
                      }, {
                        children: t.badge
                      })), (0, a.jsx)("h3", Object.assign({
                        className: "tw-text-[15px] tw-font-semibold tw-leading-snug tw-text-[#e6eaf2] tw-m-0"
                      }, {
                        children: t.title
                      })), (0, a.jsx)("p", Object.assign({
                        className: "tw-text-[13px] tw-leading-[1.5] tw-text-[rgba(255,255,255,0.5)] tw-m-0"
                      }, {
                        children: t.description
                      }))]
                    })), (0, a.jsxs)("div", Object.assign({
                      className: "tw-relative tw-flex tw-items-center tw-justify-start tw-gap-3 tw-pt-4"
                    }, {
                      children: [t.category && (0, a.jsx)("span", Object.assign({
                        className: "tw-text-xs",
                        style: {
                          fontSize: "14px",
                          color: "#7d7ab1"
                        }
                      }, {
                        children: t.category
                      })), (0, a.jsx)(NA, Object.assign({
                        size: "sm",
                        variant: "ghost",
                        onClick: () => M(e, t.prompt),
                        className: "tw-cursor-pointer tw-gap-1.5 tw-px-4 tw-py-2 tw-text-[#0A1526] tw-transition-all tw-duration-200 hover:tw-brightness-[1.15] hover:tw-bg-transparent active:tw-scale-[0.97]",
                        style: {
                          borderRadius: "4.747px",
                          border: "0.791px solid #B3DAF4",
                          background: "radial-gradient(100% 100% at 50% 0%, rgba(255, 255, 255, 0.30) 0%, rgba(255, 255, 255, 0.00) 100%), linear-gradient(90deg, #78CEF7 0%, #1881A7 100%), #0678FF",
                          boxShadow: "0 3.165px 7.912px 0 rgba(59, 160, 255, 0.16), 0 4.747px 12.659px 2.179px rgba(23, 34, 49, 0.60)"
                        }
                      }, {
                        children: null !== (i = t.actionLabel) && void 0 !== i ? i : "Approve Action"
                      }))]
                    }))]
                  }))
                }), e)
              }))
            })), g && (() => {
              var t;
              const {
                rect: e,
                action: n
              } = g, r = B(), s = r.x - (e.left + e.width / 2), i = r.y - (e.top + e.height / 2);
              return (0, jr.createPortal)((0, a.jsx)("div", Object.assign({
                style: {
                  position: "fixed",
                  left: e.left,
                  top: e.top,
                  width: e.width,
                  height: e.height,
                  zIndex: 9999,
                  pointerEvents: "none",
                  transform: p ? `translate(${s}px, ${i}px) scale(0.15)` : "translate(0, 0) scale(1)",
                  opacity: p ? 0 : 1,
                  transition: `transform ${DA}ms cubic-bezier(0.4, 0, 0.2, 1), opacity ${.8*DA}ms ease-out ${.2*DA}ms`
                }
              }, {
                children: (0, a.jsxs)("div", Object.assign({
                  className: "tw-relative tw-flex tw-flex-col tw-justify-between tw-gap-3 tw-overflow-hidden tw-rounded-xl tw-border tw-border-[rgba(0,204,189,0.3)] tw-p-4 tw-shadow-xl tw-h-full",
                  style: {
                    background: "linear-gradient(145deg, rgba(15,23,42,0.85), rgba(10,18,36,0.65))"
                  }
                }, {
                  children: [(0, a.jsxs)("div", Object.assign({
                    className: "tw-flex tw-flex-col tw-gap-3"
                  }, {
                    children: [(0, a.jsx)(vA, Object.assign({
                      variant: "outline",
                      className: `tw-w-fit tw-rounded-full tw-text-[11px] tw-font-medium ${n.badgeColor}`
                    }, {
                      children: n.badge
                    })), (0, a.jsx)("h3", Object.assign({
                      className: "tw-text-[15px] tw-font-semibold tw-leading-snug tw-text-[#e6eaf2] tw-m-0"
                    }, {
                      children: n.title
                    })), (0, a.jsx)("p", Object.assign({
                      className: "tw-text-[13px] tw-leading-[1.5] tw-text-[rgba(255,255,255,0.5)] tw-m-0"
                    }, {
                      children: n.description
                    }))]
                  })), (0, a.jsx)("div", Object.assign({
                    className: "tw-relative tw-flex tw-items-center tw-justify-start tw-gap-3 tw-pt-4"
                  }, {
                    children: (0, a.jsx)(NA, Object.assign({
                      size: "sm",
                      variant: "ghost",
                      className: "tw-cursor-pointer tw-gap-1.5 tw-px-4 tw-py-2 tw-text-[#0A1526] hover:tw-bg-transparent",
                      style: {
                        borderRadius: "4.747px",
                        border: "0.791px solid #B3DAF4",
                        background: "radial-gradient(100% 100% at 50% 0%, rgba(255, 255, 255, 0.30) 0%, rgba(255, 255, 255, 0.00) 100%), linear-gradient(90deg, #78CEF7 0%, #1881A7 100%), #0678FF",
                        boxShadow: "0 3.165px 7.912px 0 rgba(59, 160, 255, 0.16), 0 4.747px 12.659px 2.179px rgba(23, 34, 49, 0.60)"
                      }
                    }, {
                      children: null !== (t = n.actionLabel) && void 0 !== t ? t : "Approve Action"
                    }))
                  }))]
                }))
              })), document.body)
            })(), (0, a.jsx)("style", {
              children: "\n        @keyframes spotlight-fade {\n          0% { opacity: 0; }\n          20% { opacity: 1; }\n          70% { opacity: 1; }\n          100% { opacity: 0; }\n        }\n      "
            })]
          })) : null
        }

        function FA() {
          return (0, a.jsx)(LA, {
            module: "marketing",
            columns: 2
          })
        }

        function PA() {
          const t = (0, N.useNavigate)();
          return (0, a.jsxs)("div", Object.assign({
            className: "tw-flex tw-flex-col tw-gap-3"
          }, {
            children: [(0, a.jsx)("h2", Object.assign({
              className: "tw-text-xs tw-font-semibold tw-uppercase tw-tracking-wide tw-text-[rgba(255,255,255,0.35)] tw-m-0"
            }, {
              children: "Quick Actions"
            })), (0, a.jsxs)("div", Object.assign({
              className: "tw-flex tw-flex-wrap tw-items-center tw-gap-3"
            }, {
              children: [(0, a.jsxs)(NA, Object.assign({
                size: "sm",
                variant: "ghost",
                className: "tw-gap-1.5 tw-text-[#0A1526] tw-cursor-pointer tw-transition-all tw-duration-150 hover:tw-brightness-[1.15] hover:tw-bg-transparent active:tw-scale-[0.97]",
                style: {
                  borderRadius: "4.747px",
                  border: "0.791px solid #B3DAF4",
                  background: "radial-gradient(100% 100% at 50% 0%, rgba(255, 255, 255, 0.30) 0%, rgba(255, 255, 255, 0.00) 100%), linear-gradient(90deg, #78CEF7 0%, #1881A7 100%), #0678FF",
                  boxShadow: "0 3.165px 7.912px 0 rgba(59, 160, 255, 0.16), 0 4.747px 12.659px 2.179px rgba(23, 34, 49, 0.60)"
                },
                onClick: () => t("/performance-marketing")
              }, {
                children: [(0, a.jsx)(_r.Z, {
                  className: "tw-w-3.5 tw-h-3.5"
                }), "Performance Marketing Setup"]
              })), (0, a.jsxs)(NA, Object.assign({
                variant: "outline",
                size: "sm",
                className: "tw-gap-1.5 tw-border tw-border-[rgba(255,255,255,0.08)] tw-bg-[rgba(255,255,255,0.03)] tw-text-[#bebebe] hover:tw-bg-[rgba(255,255,255,0.06)] hover:tw-text-[#e6eaf2]",
                onClick: () => t("/performance-marketing/marketing-automation")
              }, {
                children: [(0, a.jsx)(_s.Z, {
                  className: "tw-w-3.5 tw-h-3.5"
                }), "Marketing Automation"]
              }))]
            }))]
          }))
        }

        function zA({
          amazonMerchantId: t,
          pageId: e,
          allowedTitles: n
        }) {
          const {
            templates: r,
            widgetData: s,
            isLoading: i
          } = Ll({
            amazonMerchantId: t,
            pageId: e
          }), o = n ? r.filter((t => n.some((e => t.title.toLowerCase().includes(e.toLowerCase()))))) : r, l = [...o].sort(((t, e) => {
            var n, a;
            return (null !== (n = t.layout.order) && void 0 !== n ? n : 0) - (null !== (a = e.layout.order) && void 0 !== a ? a : 0) || t.widgetId.localeCompare(e.widgetId)
          }));
          return 0 === r.length && i ? (0, a.jsx)(Xl, {}) : (0, a.jsx)("div", Object.assign({
            className: "tw-grid tw-grid-cols-12 tw-gap-3 sm:tw-gap-4"
          }, {
            children: l.map((t => {
              var e, n;
              const r = null !== (e = tA[t.layout.height]) && void 0 !== e ? e : 280,
                o = null !== (n = eA[t.layout.width]) && void 0 !== n ? n : "tw-col-span-12",
                l = s[t.widgetId],
                A = l && Object.keys(l).length > 0,
                c = "metric_card" === t.visualization;
              return (0, a.jsx)("div", Object.assign({
                className: o
              }, {
                children: (0, a.jsx)(Ks, Object.assign({
                  className: "tw-gap-2 tw-py-4 tw-h-full"
                }, {
                  children: (0, a.jsxs)(Vs, Object.assign({
                    className: "tw-flex tw-flex-col tw-gap-3"
                  }, {
                    children: [(0, a.jsx)("p", Object.assign({
                      className: c ? "tw-text-[10px] tw-font-medium tw-uppercase tw-tracking-wide tw-text-[rgba(255,255,255,0.35)] tw-m-0" : "tw-text-[15px] tw-font-semibold tw-text-[#e6eaf2] tw-m-0"
                    }, {
                      children: t.title
                    })), !c && (0, a.jsx)("p", Object.assign({
                      className: "tw-text-xs tw-text-[rgba(255,255,255,0.35)] tw-m-0 tw--mt-1"
                    }, {
                      children: t.description
                    })), A ? (0, a.jsx)(Ni, {
                      visualization: t.visualization,
                      data: l,
                      height: r
                    }) : i ? (0, a.jsx)("div", {
                      className: "tw-animate-pulse tw-rounded-lg tw-bg-[rgba(255,255,255,0.08)]",
                      style: {
                        height: r
                      }
                    }) : (0, a.jsxs)("div", Object.assign({
                      className: "tw-flex tw-items-center tw-justify-center tw-gap-2",
                      style: {
                        height: r
                      }
                    }, {
                      children: [(0, a.jsx)(_l.Z, {
                        className: "tw-w-4 tw-h-4 tw-text-[rgba(255,255,255,0.2)]"
                      }), (0, a.jsx)("span", Object.assign({
                        className: "tw-text-xs tw-text-[rgba(255,255,255,0.25)]"
                      }, {
                        children: "No data available"
                      }))]
                    }))]
                  }))
                }))
              }), t.widgetId)
            }))
          }))
        }
        const UA = (0, v.Pi)((function() {
          var t;
          const e = null === (t = ln.currentStoreDetails) || void 0 === t ? void 0 : t.storeId;
          return e ? (0, a.jsxs)("div", Object.assign({
            className: "tw-flex tw-flex-col tw-gap-3"
          }, {
            children: [(0, a.jsxs)("h2", Object.assign({
              className: "tw-flex tw-items-center tw-gap-2 tw-text-xs tw-font-semibold tw-uppercase tw-tracking-wide tw-text-[rgba(255,255,255,0.35)] tw-m-0"
            }, {
              children: [(0, a.jsx)(SA.Z, {
                className: "tw-w-3.5 tw-h-3.5 tw-text-[#00CCBD]"
              }), "Quick Views"]
            })), (0, a.jsx)(zA, {
              amazonMerchantId: e,
              pageId: "MARKETING_BTF"
            })]
          })) : null
        }));

        function GA() {
          return (0, a.jsxs)("div", Object.assign({
            className: "tw-flex tw-flex-col tw-gap-4 sm:tw-gap-6"
          }, {
            children: [(0, a.jsx)(Bl, {}), (0, a.jsx)(aA, {}), (0, a.jsx)(mA, {}), (0, a.jsx)(EA, {}), (0, a.jsx)(FA, {}), (0, a.jsx)(PA, {}), (0, a.jsx)(UA, {})]
          }))
        }

        function ZA({
          checked: t = !1,
          onCheckedChange: e,
          className: n
        }) {
          return (0, a.jsx)("button", Object.assign({
            role: "switch",
            "aria-checked": t,
            onClick: () => null == e ? void 0 : e(!t),
            className: xr("tw-relative tw-inline-flex tw-h-5 tw-w-9 tw-shrink-0 tw-cursor-pointer tw-rounded-full tw-border-2 tw-border-transparent tw-transition-colors", t ? "tw-bg-[#00CCBD]" : "tw-bg-[rgba(255,255,255,0.15)]", n)
          }, {
            children: (0, a.jsx)("span", {
              className: xr("tw-pointer-events-none tw-inline-block tw-w-4 tw-h-4 tw-rounded-full tw-bg-white tw-shadow tw-transition-transform", t ? "tw-translate-x-4" : "tw-translate-x-0")
            })
          }))
        }
        var HA = n(57307),
          YA = function(t, e, n, a) {
            return new(n || (n = Promise))((function(r, s) {
              function i(t) {
                try {
                  l(a.next(t))
                } catch (t) {
                  s(t)
                }
              }

              function o(t) {
                try {
                  l(a.throw(t))
                } catch (t) {
                  s(t)
                }
              }

              function l(t) {
                var e;
                t.done ? r(t.value) : (e = t.value, e instanceof n ? e : new n((function(t) {
                  t(e)
                }))).then(i, o)
              }
              l((a = a.apply(t, e || [])).next())
            }))
          };
        const WA = (0, v.Pi)((() => {
            var t;
            const [e, n] = (0, j.useState)(!1), [r, s] = (0, j.useState)(!1), i = E().useRef(null), o = (0, N.useNavigate)(), {
              allStoreDetails: l,
              currentStoreDetails: A,
              handleCurrentStoreDetails: c
            } = ln, {
              storeConfig: d,
              storeAddress: w,
              mobileNumber: g,
              categoryIds: u,
              storeName: p,
              storeImageUrl: b
            } = A || {}, {
              storeActive: h,
              bopisSupported: m,
              deliverySupported: x,
              storeOpeningTime: v,
              storeClosingTime: y
            } = d || {}, {
              address: C,
              postalCode: O,
              state: S,
              city: k
            } = w || {}, I = (null === (t = null == p ? void 0 : p.charAt(0)) || void 0 === t ? void 0 : t.toUpperCase()) || "?", M = null == A ? void 0 : A.storeId, {
              mutateAsync: T
            } = (0, Re.DK)(), {
              data: R
            } = (0, Re.hl)(), B = (0, _.g0)(), D = () => YA(void 0, void 0, void 0, (function*() {
              try {
                const t = yield B.mutateAsync();
                ln.isLoggedOut(), window.location.replace(null == t ? void 0 : t.redirectUrl)
              } catch (t) {
                (0, f.LT)(Object.assign(Object.assign({}, f.ar), {
                  text: "Failed to logout"
                }))
              }
            })), L = (t, e) => YA(void 0, void 0, void 0, (function*() {
              c(Object.assign(Object.assign({}, A), {
                storeConfig: Object.assign(Object.assign({}, d), {
                  [t]: e
                })
              }));
              try {
                yield T({
                  [t]: e
                })
              } catch (n) {
                c(Object.assign(Object.assign({}, A), {
                  storeConfig: Object.assign(Object.assign({}, d), {
                    [t]: !e
                  })
                })), (0, f.LT)(Object.assign(Object.assign({}, f.ar), {
                  text: "Failed to update settings"
                }))
              }
            })), F = (0, f.lX)({
              address: C,
              state: S,
              city: k,
              postalCode: O
            }), P = v && y ? `${v} â ${y}` : "Not set";
            return (0, a.jsxs)("div", Object.assign({
              className: "tw-flex tw-flex-col tw-gap-3 sm:tw-flex-row sm:tw-items-center sm:tw-justify-between"
            }, {
              children: [(0, a.jsx)("div", Object.assign({
                className: "tw-flex tw-items-center tw-justify-between sm:tw-justify-start tw-gap-3"
              }, {
                children: (0, a.jsxs)("div", {
                  children: [(0, a.jsx)("h1", Object.assign({
                    className: "tw-text-base sm:tw-text-lg tw-font-semibold tw-text-[#e6eaf2] tw-m-0"
                  }, {
                    children: "Your business at a glance"
                  })), (0, a.jsx)("p", Object.assign({
                    className: "tw-text-xs sm:tw-text-sm tw-text-[rgba(255,255,255,0.35)] tw-m-0"
                  }, {
                    children: (new Date).toLocaleDateString("en-US", {
                      weekday: "long",
                      month: "long",
                      day: "numeric"
                    })
                  }))]
                })
              })), (0, a.jsxs)("div", Object.assign({
                className: "tw-relative"
              }, {
                children: [(0, a.jsxs)("button", Object.assign({
                  ref: i,
                  onClick: () => n((t => !t)),
                  className: "tw-flex tw-items-center tw-gap-2 tw-rounded-lg tw-px-2 tw-py-1 tw-transition-colors tw-border-0 tw-bg-transparent tw-cursor-pointer hover:tw-bg-[#000D26]"
                }, {
                  children: [b ? (0, a.jsx)("img", {
                    src: b,
                    alt: "",
                    className: "tw-w-7 tw-h-7 tw-rounded-full tw-border tw-border-[rgba(255,255,255,0.08)] tw-object-cover"
                  }) : (0, a.jsx)("div", Object.assign({
                    className: "tw-flex tw-w-7 tw-h-7 tw-items-center tw-justify-center tw-rounded-full tw-border tw-border-[rgba(255,255,255,0.08)] tw-bg-[#000D26]"
                  }, {
                    children: (0, a.jsx)("span", Object.assign({
                      className: "tw-text-[9px] tw-font-bold tw-text-[rgba(255,255,255,0.5)]"
                    }, {
                      children: I
                    }))
                  })), (0, a.jsx)("span", Object.assign({
                    className: "tw-text-[13px] tw-font-medium tw-text-[#e6eaf2]"
                  }, {
                    children: p || "Store"
                  })), (0, a.jsx)(ns.Z, {
                    className: xr("tw-w-3.5 tw-h-3.5 tw-text-[rgba(255,255,255,0.35)] tw-transition-transform", e && "tw-rotate-180")
                  })]
                })), e && (() => {
                  var t;
                  const e = null === (t = i.current) || void 0 === t ? void 0 : t.getBoundingClientRect(),
                    A = e ? e.bottom + 4 : 48,
                    d = Math.min(288, window.innerWidth - 16);
                  return (0, a.jsxs)(a.Fragment, {
                    children: [(0, a.jsx)("div", {
                      className: "tw-fixed tw-inset-0 tw-z-40",
                      onClick: () => n(!1)
                    }), (0, a.jsxs)("div", Object.assign({
                      className: "tw-fixed tw-z-50 tw-max-h-[80vh] tw-overflow-y-auto tw-overflow-x-hidden tw-rounded-xl tw-border tw-border-[rgba(255,255,255,0.08)] tw-bg-[#0a1021] tw-shadow-[0_8px_40px_rgba(0,0,0,0.4)]",
                      style: {
                        width: `${d}px`,
                        top: `${A}px`,
                        left: "50%",
                        transform: "translateX(-50%)"
                      }
                    }, {
                      children: [(0, a.jsxs)("div", Object.assign({
                        className: "tw-flex tw-items-center tw-justify-between tw-px-4 tw-pt-4 tw-pb-2"
                      }, {
                        children: [(0, a.jsx)("h3", Object.assign({
                          className: "tw-text-sm tw-font-bold tw-text-[#e6eaf2] tw-m-0"
                        }, {
                          children: "Stores"
                        })), (0, a.jsx)("button", Object.assign({
                          onClick: () => {
                            o(`/${f.gq.SETTINGS}${f.gq.PROFILE}`), n(!1)
                          },
                          className: "tw-text-xs tw-font-medium tw-text-[#00CCBD] tw-border-0 tw-bg-transparent tw-cursor-pointer hover:tw-underline"
                        }, {
                          children: "Manage"
                        }))]
                      })), (0, a.jsx)("div", Object.assign({
                        className: "tw-flex tw-flex-col tw-gap-0.5 tw-px-3 tw-pb-3"
                      }, {
                        children: l.map((t => {
                          var e, n;
                          const r = t.storeId === M,
                            s = (null === (n = null === (e = t.storeName) || void 0 === e ? void 0 : e.charAt(0)) || void 0 === n ? void 0 : n.toUpperCase()) || "?",
                            i = "PRIMARY" === t.shopOwnership ? "Admin" : "Staff";
                          return (0, a.jsxs)("button", Object.assign({
                            onClick: () => (t => YA(void 0, void 0, void 0, (function*() {
                              localStorage.setItem("shopId", t.storeId), kn(), c(t), yield(0, Nn._)(), window.dispatchEvent(new CustomEvent("CHANGE_SELECTED_SHOP", {
                                detail: {
                                  shopId: t.storeId,
                                  storeName: t.storeName
                                }
                              })), window.location.reload()
                            })))(t),
                            className: xr("tw-flex tw-items-center tw-gap-3 tw-rounded-lg tw-px-2.5 tw-py-2.5 tw-text-left tw-transition-all tw-border-0 tw-cursor-pointer hover:tw-bg-[#000D26]", r ? "tw-border tw-border-[rgba(0,204,189,0.2)] tw-bg-[rgba(0,204,189,0.06)]" : "tw-bg-transparent")
                          }, {
                            children: [t.storeImageUrl ? (0, a.jsx)("img", {
                              src: t.storeImageUrl,
                              alt: "",
                              className: "tw-w-8 tw-h-8 tw-rounded-full tw-border tw-border-[rgba(255,255,255,0.08)] tw-object-cover tw-shrink-0"
                            }) : (0, a.jsx)("div", Object.assign({
                              className: "tw-flex tw-w-8 tw-h-8 tw-shrink-0 tw-items-center tw-justify-center tw-rounded-full tw-border tw-border-[rgba(255,255,255,0.08)] tw-bg-[#000D26]"
                            }, {
                              children: (0, a.jsx)("span", Object.assign({
                                className: "tw-text-[9px] tw-font-bold tw-text-[rgba(255,255,255,0.5)]"
                              }, {
                                children: s
                              }))
                            })), (0, a.jsxs)("div", Object.assign({
                              className: "tw-flex tw-flex-1 tw-flex-col"
                            }, {
                              children: [(0, a.jsx)("span", Object.assign({
                                className: "tw-text-[13px] tw-font-medium tw-text-[#e6eaf2]"
                              }, {
                                children: t.storeName
                              })), (0, a.jsx)("span", Object.assign({
                                className: "tw-text-[11px] tw-text-[rgba(255,255,255,0.35)]"
                              }, {
                                children: i
                              }))]
                            })), r && (0, a.jsx)(ki.Z, {
                              className: "tw-w-4 tw-h-4 tw-text-[#00CCBD]"
                            })]
                          }), t.storeId)
                        }))
                      })), (0, a.jsx)("div", {
                        className: "tw-border-t tw-border-[rgba(255,255,255,0.08)]"
                      }), (0, a.jsxs)("div", Object.assign({
                        className: "tw-flex tw-flex-col tw-gap-3 tw-px-4 tw-py-3"
                      }, {
                        children: [(0, a.jsxs)("div", {
                          children: [(0, a.jsx)("p", Object.assign({
                            className: "tw-text-[10px] tw-font-medium tw-uppercase tw-tracking-wide tw-text-[rgba(255,255,255,0.35)] tw-m-0"
                          }, {
                            children: "Categories"
                          })), (0, a.jsx)("p", Object.assign({
                            className: "tw-mt-0.5 tw-text-[13px] tw-text-[rgba(255,255,255,0.5)] tw-m-0"
                          }, {
                            children: (0, f.nu)((null == R ? void 0 : R.categories) || [], u) || "Not set"
                          }))]
                        }), (0, a.jsxs)("div", {
                          children: [(0, a.jsx)("p", Object.assign({
                            className: "tw-text-[10px] tw-font-medium tw-uppercase tw-tracking-wide tw-text-[rgba(255,255,255,0.35)] tw-m-0"
                          }, {
                            children: "Store Address"
                          })), (0, a.jsx)("p", Object.assign({
                            className: "tw-mt-0.5 tw-truncate tw-text-[13px] tw-text-[rgba(255,255,255,0.5)] tw-m-0"
                          }, {
                            children: F || "Not set"
                          }))]
                        }), (0, a.jsxs)("div", {
                          children: [(0, a.jsx)("p", Object.assign({
                            className: "tw-text-[10px] tw-font-medium tw-uppercase tw-tracking-wide tw-text-[rgba(255,255,255,0.35)] tw-m-0"
                          }, {
                            children: "Store Number"
                          })), (0, a.jsx)("p", Object.assign({
                            className: "tw-mt-0.5 tw-text-[13px] tw-text-[rgba(255,255,255,0.5)] tw-m-0"
                          }, {
                            children: g ? `+91${g}` : "Not set"
                          }))]
                        })]
                      })), (0, a.jsx)("div", {
                        className: "tw-border-t tw-border-[rgba(255,255,255,0.08)]"
                      }), (0, a.jsxs)("div", {
                        children: [(0, a.jsxs)("button", Object.assign({
                          onClick: () => s((t => !t)),
                          className: "tw-flex tw-w-full tw-items-center tw-justify-between tw-px-4 tw-py-2.5 tw-text-left tw-transition-colors tw-border-0 tw-bg-transparent tw-cursor-pointer hover:tw-bg-[#000D26]"
                        }, {
                          children: [(0, a.jsx)("span", Object.assign({
                            className: "tw-text-xs tw-font-semibold tw-text-[#e6eaf2]"
                          }, {
                            children: "D2C Settings"
                          })), (0, a.jsx)(ns.Z, {
                            className: xr("tw-w-3.5 tw-h-3.5 tw-text-[rgba(255,255,255,0.35)] tw-transition-transform tw-duration-200", r && "tw-rotate-180")
                          })]
                        })), (0, a.jsx)("div", Object.assign({
                          className: xr("tw-grid tw-transition-all tw-duration-200 tw-ease-in-out", r ? "tw-grid-rows-[1fr] tw-opacity-100" : "tw-grid-rows-[0fr] tw-opacity-0")
                        }, {
                          children: (0, a.jsxs)("div", Object.assign({
                            className: "tw-overflow-hidden"
                          }, {
                            children: [(0, a.jsxs)("button", Object.assign({
                              onClick: () => {
                                o((0, f.wq)(f.gq.STORE_TIMINGS)), n(!1)
                              },
                              className: "tw-flex tw-w-full tw-items-center tw-justify-between tw-px-4 tw-py-2.5 tw-text-left tw-transition-colors tw-border-0 tw-bg-transparent tw-cursor-pointer hover:tw-bg-[#000D26]"
                            }, {
                              children: [(0, a.jsxs)("div", {
                                children: [(0, a.jsx)("p", Object.assign({
                                  className: "tw-text-[10px] tw-font-medium tw-uppercase tw-tracking-wide tw-text-[rgba(255,255,255,0.35)] tw-m-0"
                                }, {
                                  children: "Store Timings"
                                })), (0, a.jsx)("p", Object.assign({
                                  className: "tw-mt-0.5 tw-text-[12px] tw-text-[rgba(255,255,255,0.5)] tw-m-0"
                                }, {
                                  children: P
                                }))]
                              }), (0, a.jsx)(xl.Z, {
                                className: "tw-w-3.5 tw-h-3.5 tw-text-[#00CCBD]"
                              })]
                            })), (0, a.jsx)("div", {
                              className: "tw-mx-4 tw-border-t tw-border-[rgba(255,255,255,0.08)]"
                            }), (0, a.jsxs)("div", Object.assign({
                              className: "tw-flex tw-flex-col tw-gap-2 tw-px-4 tw-py-2.5"
                            }, {
                              children: [(0, a.jsxs)("div", Object.assign({
                                className: "tw-flex tw-items-center tw-justify-between"
                              }, {
                                children: [(0, a.jsxs)("span", Object.assign({
                                  className: "tw-text-[12px] tw-text-[rgba(255,255,255,0.5)]"
                                }, {
                                  children: ["Accept Orders: ", (0, a.jsx)("span", Object.assign({
                                    className: h ? "tw-font-medium tw-text-emerald-400" : "tw-text-[rgba(255,255,255,0.35)]"
                                  }, {
                                    children: h ? "Yes" : "No"
                                  }))]
                                })), (0, a.jsx)(ZA, {
                                  checked: !!h,
                                  onCheckedChange: t => L("storeActive", t)
                                })]
                              })), (0, a.jsxs)("div", Object.assign({
                                className: "tw-flex tw-items-center tw-justify-between"
                              }, {
                                children: [(0, a.jsxs)("span", Object.assign({
                                  className: "tw-text-[12px] tw-text-[rgba(255,255,255,0.5)]"
                                }, {
                                  children: ["Delivery: ", (0, a.jsx)("span", Object.assign({
                                    className: x ? "tw-font-medium tw-text-emerald-400" : "tw-text-[rgba(255,255,255,0.35)]"
                                  }, {
                                    children: x ? "On" : "Off"
                                  }))]
                                })), (0, a.jsx)(ZA, {
                                  checked: !!x,
                                  onCheckedChange: t => L("deliverySupported", t)
                                })]
                              })), (0, a.jsxs)("div", Object.assign({
                                className: "tw-flex tw-items-center tw-justify-between"
                              }, {
                                children: [(0, a.jsxs)("span", Object.assign({
                                  className: "tw-text-[12px] tw-text-[rgba(255,255,255,0.5)]"
                                }, {
                                  children: ["Pickup: ", (0, a.jsx)("span", Object.assign({
                                    className: m ? "tw-font-medium tw-text-emerald-400" : "tw-text-[rgba(255,255,255,0.35)]"
                                  }, {
                                    children: m ? "On" : "Off"
                                  }))]
                                })), (0, a.jsx)(ZA, {
                                  checked: !!m,
                                  onCheckedChange: t => L("bopisSupported", t)
                                })]
                              }))]
                            }))]
                          }))
                        }))]
                      }), (0, a.jsx)("div", {
                        className: "tw-border-t tw-border-[rgba(255,255,255,0.08)]"
                      }), (0, a.jsxs)("button", Object.assign({
                        className: "tw-flex tw-w-full tw-items-center tw-gap-2.5 tw-px-4 tw-py-3 tw-text-[13px] tw-text-[rgba(255,255,255,0.5)] tw-transition-colors tw-border-0 tw-bg-transparent tw-cursor-pointer hover:tw-bg-[#000D26]"
                      }, {
                        children: [(0, a.jsx)(HA.Z, {
                          className: "tw-w-4 tw-h-4 tw-text-[rgba(255,255,255,0.35)]"
                        }), "Share store"]
                      })), (0, a.jsx)("div", {
                        className: "tw-border-t tw-border-[rgba(255,255,255,0.08)]"
                      }), (0, a.jsxs)("button", Object.assign({
                        onClick: D,
                        className: "tw-flex tw-w-full tw-items-center tw-gap-2.5 tw-px-4 tw-py-3 tw-text-[13px] tw-text-[rgba(255,255,255,0.5)] tw-transition-colors tw-border-0 tw-bg-transparent tw-cursor-pointer hover:tw-bg-[#000D26]"
                      }, {
                        children: [(0, a.jsx)(Bs.Z, {
                          className: "tw-w-4 tw-h-4 tw-text-[rgba(255,255,255,0.35)]"
                        }), "Logout"]
                      }))]
                    }))]
                  })
                })()]
              }))]
            }))
          })),
          KA = (0, v.Pi)((function() {
            var t;
            const e = null === (t = ln.currentStoreDetails) || void 0 === t ? void 0 : t.storeId;
            return e ? (0, a.jsx)(nA, {
              amazonMerchantId: e,
              pageId: "HOME_ATF",
              storageKey: "dashboard"
            }) : null
          }));

        function VA() {
          return (0, a.jsx)(jA, {
            module: "home"
          })
        }

        function $A() {
          return (0, a.jsx)(LA, {
            module: "home",
            columns: 3
          })
        }
        var qA = (0, v.Pi)((function() {
          const [t, e] = (0, j.useState)(!1);
          return t ? (0, a.jsx)(Jl, {}) : (0, a.jsxs)("div", Object.assign({
            className: "tw-flex tw-flex-col tw-gap-4 sm:tw-gap-6"
          }, {
            children: [(0, a.jsx)(WA, {}), (0, a.jsx)(KA, {}), (0, a.jsx)(VA, {}), (0, a.jsx)($A, {})]
          }))
        }));

        function QA() {
          return (0, a.jsx)(Rl, {
            icon: $r.Z,
            title: "Inventory agent",
            iconColor: "#a78bfa"
          })
        }
        const XA = (0, v.Pi)((function() {
            var t;
            const e = null === (t = ln.currentStoreDetails) || void 0 === t ? void 0 : t.storeId;
            return e ? (0, a.jsx)(nA, {
              amazonMerchantId: e,
              pageId: "INVENTORY_ATF",
              storageKey: "inventory",
              averageTitles: ["Slow Moving", "Out of Stock"]
            }) : null
          })),
          JA = [{
            name: "Replenishment Forecaster",
            color: "tw-bg-[#00CCBD]"
          }, {
            name: "Aged Inventory Cost Cutter",
            color: "tw-bg-[#00CCBD]"
          }];

        function tc() {
          return (0, a.jsx)(bA, {
            title: "Inventory Agent Skills",
            skills: JA
          })
        }

        function ec() {
          return (0, a.jsx)(jA, {
            module: "inventory"
          })
        }

        function nc() {
          return (0, a.jsx)(LA, {
            module: "inventory",
            columns: 2
          })
        }
        var ac = n(90470),
          rc = n(28142),
          sc = n(39483);
        const ic = window.location.hostname === J ? "https://smarthub.amazon.in" : "https://smarthub-in.integ.amazon.com";

        function oc() {
          return (0, a.jsxs)("div", Object.assign({
            className: "tw-flex tw-flex-col tw-gap-3"
          }, {
            children: [(0, a.jsx)("h2", Object.assign({
              className: "tw-text-xs tw-font-semibold tw-uppercase tw-tracking-wide tw-text-[rgba(255,255,255,0.35)] tw-m-0"
            }, {
              children: "Quick Actions"
            })), (0, a.jsxs)("div", Object.assign({
              className: "tw-flex tw-flex-wrap tw-items-center tw-gap-3"
            }, {
              children: [(0, a.jsxs)(NA, Object.assign({
                size: "sm",
                variant: "ghost",
                className: "tw-gap-1.5 tw-text-[#0A1526] tw-cursor-pointer tw-transition-all tw-duration-150 hover:tw-brightness-[1.15] hover:tw-bg-transparent active:tw-scale-[0.97]",
                style: {
                  borderRadius: "4.747px",
                  border: "0.791px solid #B3DAF4",
                  background: "radial-gradient(100% 100% at 50% 0%, rgba(255, 255, 255, 0.30) 0%, rgba(255, 255, 255, 0.00) 100%), linear-gradient(90deg, #78CEF7 0%, #1881A7 100%), #0678FF",
                  boxShadow: "0 3.165px 7.912px 0 rgba(59, 160, 255, 0.16), 0 4.747px 12.659px 2.179px rgba(23, 34, 49, 0.60)"
                },
                onClick: () => window.open(`${ic}/inventory/bulk-update-inventory`, "_blank", "noopener,noreferrer")
              }, {
                children: [(0, a.jsx)(ac.Z, {
                  className: "tw-w-3.5 tw-h-3.5"
                }), "Update Inventory"]
              })), (0, a.jsxs)(NA, Object.assign({
                variant: "outline",
                size: "sm",
                className: "tw-gap-1.5 tw-border tw-border-[rgba(255,255,255,0.08)] tw-bg-[rgba(255,255,255,0.03)] tw-text-[#bebebe] hover:tw-bg-[rgba(255,255,255,0.06)] hover:tw-text-[#e6eaf2]",
                onClick: () => window.open(`${ic}/inventory/bulk-update-inventory`, "_blank", "noopener,noreferrer")
              }, {
                children: [(0, a.jsx)(rc.Z, {
                  className: "tw-w-3.5 tw-h-3.5"
                }), "Upload Inventory in Bulk"]
              })), (0, a.jsxs)(NA, Object.assign({
                variant: "outline",
                size: "sm",
                className: "tw-gap-1.5 tw-border tw-border-[rgba(255,255,255,0.08)] tw-bg-[rgba(255,255,255,0.03)] tw-text-[#bebebe] hover:tw-bg-[rgba(255,255,255,0.06)] hover:tw-text-[#e6eaf2]",
                onClick: () => window.open(`${ic}/inventory-reports-dashboard`, "_blank", "noopener,noreferrer")
              }, {
                children: [(0, a.jsx)(sc.Z, {
                  className: "tw-w-3.5 tw-h-3.5"
                }), "Inventory Dashboard"]
              }))]
            }))]
          }))
        }
        const lc = (0, v.Pi)((function() {
          var t;
          const e = null === (t = ln.currentStoreDetails) || void 0 === t ? void 0 : t.storeId;
          return e ? (0, a.jsxs)("div", Object.assign({
            className: "tw-flex tw-flex-col tw-gap-3"
          }, {
            children: [(0, a.jsxs)("h2", Object.assign({
              className: "tw-flex tw-items-center tw-gap-2 tw-text-xs tw-font-semibold tw-uppercase tw-tracking-wide tw-text-[rgba(255,255,255,0.35)] tw-m-0"
            }, {
              children: [(0, a.jsx)(SA.Z, {
                className: "tw-w-3.5 tw-h-3.5 tw-text-[#00CCBD]"
              }), "Quick Views"]
            })), (0, a.jsx)(zA, {
              amazonMerchantId: e,
              pageId: "INVENTORY_BTF"
            })]
          })) : null
        }));

        function Ac() {
          return (0, a.jsxs)("div", Object.assign({
            className: "tw-flex tw-flex-col tw-gap-4 sm:tw-gap-6"
          }, {
            children: [(0, a.jsx)(QA, {}), (0, a.jsx)(XA, {}), (0, a.jsx)(tc, {}), (0, a.jsx)(ec, {}), (0, a.jsx)(nc, {}), (0, a.jsx)(oc, {}), (0, a.jsx)(lc, {})]
          }))
        }

        function cc() {
          return (0, a.jsx)(Rl, {
            icon: Vr.Z,
            title: "Listings agent",
            iconColor: "#7aa2ff"
          })
        }
        const dc = (0, v.Pi)((function() {
            var t;
            const e = null === (t = ln.currentStoreDetails) || void 0 === t ? void 0 : t.storeId;
            return e ? (0, a.jsx)(nA, {
              amazonMerchantId: e,
              pageId: "LISTINGS_ATF",
              storageKey: "listings",
              averageTitles: ["Coverage", "Active Listings"],
              hideBreakdown: !0
            }) : null
          })),
          wc = [{
            name: "SKU Channel Gap Detection"
          }, {
            name: "Price Gap Detection"
          }, {
            name: "Missing Image Detection"
          }];

        function gc() {
          return (0, a.jsx)(bA, {
            title: "Listings Agent Skills",
            skills: wc
          })
        }

        function uc() {
          return (0, a.jsx)(jA, {
            module: "listings"
          })
        }

        function pc() {
          return (0, a.jsx)(LA, {
            module: "listings",
            columns: 3,
            showSparklesInButton: !0
          })
        }
        var bc = n(24349),
          hc = n(25070),
          mc = n(14199);
        const xc = [{
          label: "Products",
          path: "/catalog/products",
          icon: bc.Z,
          color: "tw-text-blue-400",
          bg: "tw-bg-blue-400/10 hover:tw-bg-blue-400/15 tw-border-blue-400/20"
        }, {
          label: "Categories",
          path: "/catalog/categories",
          icon: hc.Z,
          color: "tw-text-amber-400",
          bg: "tw-bg-amber-400/10 hover:tw-bg-amber-400/15 tw-border-amber-400/20"
        }, {
          label: "Collections",
          path: "/catalog/collections",
          icon: mc.Z,
          color: "tw-text-purple-400",
          bg: "tw-bg-purple-400/10 hover:tw-bg-purple-400/15 tw-border-purple-400/20"
        }];

        function fc() {
          const [t, e] = (0, j.useState)(!1), n = (0, N.useNavigate)();
          return (0, a.jsxs)("div", Object.assign({
            className: "tw-flex tw-flex-col tw-gap-3"
          }, {
            children: [(0, a.jsx)("h2", Object.assign({
              className: "tw-text-xs tw-font-semibold tw-uppercase tw-tracking-wide tw-text-[rgba(255,255,255,0.35)] tw-m-0"
            }, {
              children: "Quick Actions"
            })), (0, a.jsx)("div", Object.assign({
              className: "tw-flex tw-flex-wrap tw-items-center tw-gap-3"
            }, {
              children: (0, a.jsxs)(NA, Object.assign({
                variant: "outline",
                size: "sm",
                className: xr("tw-gap-1.5 tw-transition-colors", t ? "tw-border-[rgba(0,204,189,0.3)] tw-bg-[rgba(0,204,189,0.05)] tw-text-[#00CCBD]" : "tw-border-[rgba(255,255,255,0.08)] tw-bg-[rgba(255,255,255,0.03)] tw-text-[#bebebe] hover:tw-bg-[rgba(255,255,255,0.06)] hover:tw-text-[#e6eaf2]"),
                onClick: () => e((t => !t))
              }, {
                children: [(0, a.jsx)(Qr.Z, {
                  className: "tw-w-3.5 tw-h-3.5"
                }), "Manage D2C Listing", (0, a.jsx)(ns.Z, {
                  className: xr("tw-w-3 tw-h-3 tw-transition-transform tw-duration-200", t && "tw-rotate-180")
                })]
              }))
            })), (0, a.jsx)("div", Object.assign({
              className: xr("tw-grid tw-transition-all tw-duration-300 tw-ease-in-out", t ? "tw-grid-rows-[1fr] tw-opacity-100" : "tw-grid-rows-[0fr] tw-opacity-0")
            }, {
              children: (0, a.jsx)("div", Object.assign({
                className: "tw-overflow-hidden"
              }, {
                children: (0, a.jsx)("div", Object.assign({
                  className: "tw-flex tw-flex-wrap tw-items-center tw-gap-2 tw-pt-1 tw-pb-0.5"
                }, {
                  children: xc.map((t => (0, a.jsxs)("button", Object.assign({
                    onClick: () => n(t.path),
                    className: xr("tw-flex tw-items-center tw-gap-2 tw-rounded-full tw-border tw-px-3 tw-py-1.5 tw-text-[12px] tw-font-medium tw-transition-all tw-duration-150 tw-cursor-pointer active:tw-scale-[0.97]", t.bg)
                  }, {
                    children: [(0, a.jsx)(t.icon, {
                      className: xr("tw-w-3.5 tw-h-3.5", t.color)
                    }), (0, a.jsx)("span", Object.assign({
                      className: "tw-text-[#bebebe]"
                    }, {
                      children: t.label
                    }))]
                  }), t.label)))
                }))
              }))
            }))]
          }))
        }
        const vc = (0, v.Pi)((function() {
          var t;
          const e = null === (t = ln.currentStoreDetails) || void 0 === t ? void 0 : t.storeId;
          return e ? (0, a.jsxs)("div", Object.assign({
            className: "tw-flex tw-flex-col tw-gap-3"
          }, {
            children: [(0, a.jsxs)("h2", Object.assign({
              className: "tw-flex tw-items-center tw-gap-2 tw-text-xs tw-font-semibold tw-uppercase tw-tracking-wide tw-text-[rgba(255,255,255,0.35)] tw-m-0"
            }, {
              children: [(0, a.jsx)(SA.Z, {
                className: "tw-w-3.5 tw-h-3.5 tw-text-[#00CCBD]"
              }), "Quick Views"]
            })), (0, a.jsx)(zA, {
              amazonMerchantId: e,
              pageId: "LISTINGS_BTF"
            })]
          })) : null
        }));

        function jc() {
          return (0, a.jsxs)("div", Object.assign({
            className: "tw-flex tw-flex-col tw-gap-4 sm:tw-gap-6"
          }, {
            children: [(0, a.jsx)(cc, {}), (0, a.jsx)(dc, {}), (0, a.jsx)(gc, {}), (0, a.jsx)(uc, {}), (0, a.jsx)(pc, {}), (0, a.jsx)(fc, {}), (0, a.jsx)(vc, {})]
          }))
        }

        function Ec() {
          return (0, a.jsx)(Rl, {
            icon: Rr.Z,
            title: "Shipping Agent",
            iconColor: "#5eead4"
          })
        }
        const yc = (0, v.Pi)((function() {
            var t;
            const e = null === (t = ln.currentStoreDetails) || void 0 === t ? void 0 : t.storeId;
            return e ? (0, a.jsx)(nA, {
              amazonMerchantId: e,
              pageId: "SHIPPING_ATF",
              storageKey: "shipping",
              averageTitles: ["RTO", "Average Days to Deliver", "On-Time Shipment Rate"]
            }) : null
          })),
          Cc = [{
            name: "Shipping Cost Optimizer",
            color: "tw-bg-[#00CCBD]"
          }, {
            name: "RTO Controller",
            color: "tw-bg-[#00CCBD]"
          }, {
            name: "Shipdate Protector",
            color: "tw-bg-[#00CCBD]"
          }];

        function Oc() {
          return (0, a.jsx)(bA, {
            title: "Shipping Agent Skills",
            skills: Cc
          })
        }

        function Nc() {
          return (0, a.jsx)(jA, {
            module: "shipping"
          })
        }

        function Sc() {
          return (0, a.jsx)(LA, {
            module: "shipping",
            columns: 2
          })
        }
        var kc = n(58272);
        const Ic = window.location.hostname === J ? "https://smarthub.amazon.in" : "https://smarthub-in.integ.amazon.com";

        function Mc() {
          const t = (0, N.useNavigate)();
          return (0, a.jsxs)("div", Object.assign({
            className: "tw-flex tw-flex-col tw-gap-3"
          }, {
            children: [(0, a.jsx)("h2", Object.assign({
              className: "tw-text-xs tw-font-semibold tw-uppercase tw-tracking-wide tw-text-[rgba(255,255,255,0.35)] tw-m-0"
            }, {
              children: "Quick Actions"
            })), (0, a.jsxs)("div", Object.assign({
              className: "tw-flex tw-flex-wrap tw-items-center tw-gap-3"
            }, {
              children: [(0, a.jsxs)(NA, Object.assign({
                size: "sm",
                variant: "ghost",
                className: "tw-cursor-pointer tw-gap-1.5 tw-text-[#0A1526] tw-transition-all tw-duration-150 hover:tw-brightness-[1.15] hover:tw-bg-transparent active:tw-scale-[0.97]",
                style: {
                  borderRadius: "4.747px",
                  border: "0.791px solid #B3DAF4",
                  background: "radial-gradient(100% 100% at 50% 0%, rgba(255, 255, 255, 0.30) 0%, rgba(255, 255, 255, 0.00) 100%), linear-gradient(90deg, #78CEF7 0%, #1881A7 100%), #0678FF",
                  boxShadow: "0 3.165px 7.912px 0 rgba(59, 160, 255, 0.16), 0 4.747px 12.659px 2.179px rgba(23, 34, 49, 0.60)"
                },
                onClick: () => window.open(`${Ic}/multiPickListPack`, "_blank", "noopener,noreferrer")
              }, {
                children: [(0, a.jsx)(ac.Z, {
                  className: "tw-w-3.5 tw-h-3.5"
                }), "Process Orders"]
              })), (0, a.jsxs)(NA, Object.assign({
                variant: "outline",
                size: "sm",
                className: "tw-gap-1.5 tw-border tw-border-[rgba(255,255,255,0.08)] tw-bg-[rgba(255,255,255,0.03)] tw-text-[#bebebe] hover:tw-bg-[rgba(255,255,255,0.06)] hover:tw-text-[#e6eaf2]",
                onClick: () => t("/orders")
              }, {
                children: [(0, a.jsx)(kc.Z, {
                  className: "tw-w-3.5 tw-h-3.5"
                }), "View Flagged Orders"]
              }))]
            }))]
          }))
        }
        const Tc = (0, v.Pi)((function() {
          var t;
          const e = null === (t = ln.currentStoreDetails) || void 0 === t ? void 0 : t.storeId;
          return e ? (0, a.jsxs)("div", Object.assign({
            className: "tw-flex tw-flex-col tw-gap-3"
          }, {
            children: [(0, a.jsxs)("h2", Object.assign({
              className: "tw-flex tw-items-center tw-gap-2 tw-text-xs tw-font-semibold tw-uppercase tw-tracking-wide tw-text-[rgba(255,255,255,0.35)] tw-m-0"
            }, {
              children: [(0, a.jsx)(SA.Z, {
                className: "tw-w-3.5 tw-h-3.5 tw-text-[#00CCBD]"
              }), "Quick Views"]
            })), (0, a.jsx)(zA, {
              amazonMerchantId: e,
              pageId: "SHIPPING_BTF"
            })]
          })) : null
        }));

        function Rc() {
          return (0, a.jsxs)("div", Object.assign({
            className: "tw-flex tw-flex-col tw-gap-4 sm:tw-gap-6"
          }, {
            children: [(0, a.jsx)(Ec, {}), (0, a.jsx)(yc, {}), (0, a.jsx)(Oc, {}), (0, a.jsx)(Nc, {}), (0, a.jsx)(Sc, {}), (0, a.jsx)(Mc, {}), (0, a.jsx)(Tc, {})]
          }))
        }

        function Bc() {
          return (0, a.jsx)(Rl, {
            icon: Qr.Z,
            title: "Store Builder agent",
            iconColor: "#6ee7b7"
          })
        }
        const _c = (0, v.Pi)((function() {
            var t;
            const e = null === (t = ln.currentStoreDetails) || void 0 === t ? void 0 : t.storeId;
            return e ? (0, a.jsx)(nA, {
              amazonMerchantId: e,
              pageId: "STORE_BUILDER_ATF",
              storageKey: "store-builder",
              allowedTitles: ["Website Visits", "Conversion Rate", "Cart Abandonment"],
              averageTitles: ["Conversion Rate", "Cart Abandonment"]
            }) : null
          })),
          Dc = [{
            name: "Seasonality & Peak Tracker",
            color: "tw-bg-[#00CCBD]"
          }, {
            name: "Media & Copy Creator",
            color: "tw-bg-[#00CCBD]"
          }, {
            name: "Theme Designer",
            color: "tw-bg-[#00CCBD]"
          }, {
            name: "Conversion Rate Auditor",
            color: "tw-bg-[#00CCBD]"
          }];

        function Lc() {
          return (0, a.jsx)(bA, {
            title: "Active Skills",
            skills: Dc
          })
        }

        function Fc() {
          return (0, a.jsx)(jA, {
            module: "store-builder"
          })
        }

        function Pc() {
          return (0, a.jsx)(LA, {
            module: "store-builder",
            columns: 3,
            disableProcessing: !0
          })
        }
        var zc = n(71646),
          Uc = n(62112),
          Gc = n(9560),
          Zc = n(37838),
          Hc = n(54463),
          Yc = n(68913),
          Wc = n(38583),
          Kc = n(19858);
        const Vc = [{
          label: "Offers & Discounts",
          icon: zc.Z,
          color: "tw-text-amber-400",
          bg: "tw-bg-[rgba(251,191,36,0.1)] hover:tw-bg-[rgba(251,191,36,0.15)] tw-border-[rgba(251,191,36,0.2)]",
          href: "/offers"
        }, {
          label: "Up-sell & Cross-sell",
          icon: Uc.Z,
          color: "tw-text-emerald-400",
          bg: "tw-bg-[rgba(52,211,153,0.1)] hover:tw-bg-[rgba(52,211,153,0.15)] tw-border-[rgba(52,211,153,0.2)]",
          href: "/upsell-cross-sell"
        }, {
          label: "Reviews & Ratings",
          icon: Gc.Z,
          color: "tw-text-orange-400",
          bg: "tw-bg-[rgba(251,146,60,0.1)] hover:tw-bg-[rgba(251,146,60,0.15)] tw-border-[rgba(251,146,60,0.2)]",
          href: "/reviews/manage"
        }, {
          label: "Instagram Feed",
          icon: Zc.Z,
          color: "tw-text-pink-400",
          bg: "tw-bg-[rgba(244,114,182,0.1)] hover:tw-bg-[rgba(244,114,182,0.15)] tw-border-[rgba(244,114,182,0.2)]",
          disabled: !0
        }, {
          label: "Trust Markers",
          icon: Hc.Z,
          color: "tw-text-blue-400",
          bg: "tw-bg-[rgba(96,165,250,0.1)] hover:tw-bg-[rgba(96,165,250,0.15)] tw-border-[rgba(96,165,250,0.2)]",
          disabled: !0
        }];

        function $c() {
          const [t, e] = (0, j.useState)(!1), n = (0, N.useNavigate)();
          return (0, a.jsxs)("div", Object.assign({
            className: "tw-flex tw-flex-col tw-gap-3"
          }, {
            children: [(0, a.jsx)("h2", Object.assign({
              className: "tw-text-xs tw-font-semibold tw-uppercase tw-tracking-wide tw-text-[rgba(255,255,255,0.35)] tw-m-0"
            }, {
              children: "Quick Actions"
            })), (0, a.jsxs)("div", Object.assign({
              className: "tw-flex tw-flex-wrap tw-items-center tw-gap-3"
            }, {
              children: [(0, a.jsxs)(NA, Object.assign({
                size: "sm",
                variant: "ghost",
                className: "tw-gap-1.5 tw-text-[#0A1526] tw-cursor-pointer tw-transition-all tw-duration-150 hover:tw-brightness-[1.15] hover:tw-bg-transparent active:tw-scale-[0.97]",
                style: {
                  borderRadius: "4.747px",
                  border: "0.791px solid #B3DAF4",
                  background: "radial-gradient(100% 100% at 50% 0%, rgba(255, 255, 255, 0.30) 0%, rgba(255, 255, 255, 0.00) 100%), linear-gradient(90deg, #78CEF7 0%, #1881A7 100%), #0678FF",
                  boxShadow: "0 3.165px 7.912px 0 rgba(59, 160, 255, 0.16), 0 4.747px 12.659px 2.179px rgba(23, 34, 49, 0.60)"
                },
                onClick: () => n("/store-appearance")
              }, {
                children: [(0, a.jsx)(Yc.Z, {
                  className: "tw-w-3.5 tw-h-3.5"
                }), "Edit Website"]
              })), (0, a.jsxs)(NA, Object.assign({
                variant: "outline",
                size: "sm",
                className: "tw-gap-1.5 tw-border tw-border-[rgba(255,255,255,0.08)] tw-bg-[rgba(255,255,255,0.03)] tw-text-[#bebebe] hover:tw-bg-[rgba(255,255,255,0.06)] hover:tw-text-[#e6eaf2]",
                onClick: () => n("/store-appearance")
              }, {
                children: [(0, a.jsx)(Wc.Z, {
                  className: "tw-w-3.5 tw-h-3.5"
                }), "Explore more themes"]
              })), (0, a.jsxs)(NA, Object.assign({
                variant: "outline",
                size: "sm",
                className: xr("tw-gap-1.5 tw-transition-colors", t ? "tw-border-[rgba(0,204,189,0.3)] tw-bg-[rgba(0,204,189,0.05)] tw-text-[#00CCBD]" : "tw-border-[rgba(255,255,255,0.08)] tw-bg-[rgba(255,255,255,0.03)] tw-text-[#bebebe] hover:tw-bg-[rgba(255,255,255,0.06)] hover:tw-text-[#e6eaf2]"),
                onClick: () => e((t => !t))
              }, {
                children: [(0, a.jsx)(Kc.Z, {
                  className: "tw-w-3.5 tw-h-3.5"
                }), "Growth", (0, a.jsx)(ns.Z, {
                  className: xr("tw-w-3 tw-h-3 tw-transition-transform tw-duration-200", t && "tw-rotate-180")
                })]
              }))]
            })), (0, a.jsx)("div", Object.assign({
              className: xr("tw-grid tw-transition-all tw-duration-300 tw-ease-in-out", t ? "tw-grid-rows-[1fr] tw-opacity-100" : "tw-grid-rows-[0fr] tw-opacity-0")
            }, {
              children: (0, a.jsx)("div", Object.assign({
                className: "tw-overflow-hidden"
              }, {
                children: (0, a.jsx)("div", Object.assign({
                  className: "tw-flex tw-flex-wrap tw-items-center tw-gap-2 tw-pt-1 tw-pb-0.5"
                }, {
                  children: Vc.map((t => (0, a.jsxs)("button", Object.assign({
                    disabled: t.disabled,
                    onClick: () => t.href && !t.disabled && n(t.href),
                    className: xr("tw-flex tw-items-center tw-gap-2 tw-rounded-full tw-border tw-px-3 tw-py-1.5 tw-text-[12px] tw-font-medium tw-transition-all tw-duration-150 active:tw-scale-[0.97]", t.disabled ? "tw-opacity-40 tw-cursor-not-allowed" : "tw-cursor-pointer", t.bg)
                  }, {
                    children: [(0, a.jsx)(t.icon, {
                      className: xr("tw-w-3.5 tw-h-3.5", t.color)
                    }), (0, a.jsx)("span", Object.assign({
                      className: "tw-text-[#bebebe]"
                    }, {
                      children: t.label
                    }))]
                  }), t.label)))
                }))
              }))
            }))]
          }))
        }
        const qc = (0, v.Pi)((function() {
          var t;
          const e = null === (t = ln.currentStoreDetails) || void 0 === t ? void 0 : t.storeId;
          return e ? (0, a.jsxs)("div", Object.assign({
            className: "tw-flex tw-flex-col tw-gap-3"
          }, {
            children: [(0, a.jsxs)("h2", Object.assign({
              className: "tw-flex tw-items-center tw-gap-2 tw-text-xs tw-font-semibold tw-uppercase tw-tracking-wide tw-text-[rgba(255,255,255,0.35)] tw-m-0"
            }, {
              children: [(0, a.jsx)(SA.Z, {
                className: "tw-w-3.5 tw-h-3.5 tw-text-[#00CCBD]"
              }), "Quick Views"]
            })), (0, a.jsx)(zA, {
              amazonMerchantId: e,
              pageId: "STORE_BUILDER_BTF",
              allowedTitles: ["Website Visits", "Conversion Rate", "Cart Abandonment"]
            })]
          })) : null
        }));

        function Qc() {
          return (0, a.jsxs)("div", Object.assign({
            className: "tw-flex tw-flex-col tw-gap-4 sm:tw-gap-6"
          }, {
            children: [(0, a.jsx)(Bc, {}), (0, a.jsx)(_c, {}), (0, a.jsx)(Lc, {}), (0, a.jsx)(Fc, {}), (0, a.jsx)(Pc, {}), (0, a.jsx)($c, {}), (0, a.jsx)(qc, {})]
          }))
        }

        function Xc({
          data: t,
          useAverage: e
        }) {
          const n = ai(t);
          if (!n.length) return null;
          const r = [];
          return n.forEach((n => {
            const a = t[n];
            if (null == a ? void 0 : a.rows.length)
              if (ni(a.columns)) {
                const t = 1,
                  e = ti(a.columns[t]),
                  n = {};
                a.rows.forEach((e => {
                  var a;
                  const r = $s(String(e[0]));
                  n[r] = (n[r] || 0) + Number(null !== (a = e[t]) && void 0 !== a ? a : 0)
                })), Object.entries(n).forEach((([t, n]) => {
                  r.push({
                    label: t,
                    value: ei(n, e),
                    color: Js(t, r.length)
                  })
                }))
              } else {
                const t = a.columns.length - 1,
                  s = ti(a.columns[t]),
                  i = a.rows.reduce(((e, n) => {
                    var a;
                    return e + Number(null !== (a = n[t]) && void 0 !== a ? a : 0)
                  }), 0),
                  o = e && a.rows.length > 0 ? i / a.rows.length : i;
                r.push({
                  label: Qs[n] || n,
                  value: ei(o, s),
                  color: Js(n, r.length)
                })
              }
          })), r.length ? (0, a.jsx)("div", Object.assign({
            className: "tw-flex tw-flex-wrap tw-gap-x-4 tw-gap-y-1 tw-text-xs tw-text-[rgba(255,255,255,0.5)]"
          }, {
            children: r.map((t => (0, a.jsxs)("span", Object.assign({
              className: "tw-flex tw-items-center tw-gap-1.5"
            }, {
              children: [(0, a.jsx)("span", {
                className: "tw-w-2 tw-h-2 tw-rounded-full",
                style: {
                  backgroundColor: t.color
                }
              }), t.label, " â ", t.value]
            }), t.label)))
          })) : null
        }
        var Jc = n(13025),
          td = function(t, e, n, a) {
            return new(n || (n = Promise))((function(r, s) {
              function i(t) {
                try {
                  l(a.next(t))
                } catch (t) {
                  s(t)
                }
              }

              function o(t) {
                try {
                  l(a.throw(t))
                } catch (t) {
                  s(t)
                }
              }

              function l(t) {
                var e;
                t.done ? r(t.value) : (e = t.value, e instanceof n ? e : new n((function(t) {
                  t(e)
                }))).then(i, o)
              }
              l((a = a.apply(t, e || [])).next())
            }))
          };
        const ed = new Set(["bi_v2_rto_rate", "bi_v2_rto_by_carrier"]);

        function nd({
          template: t,
          data: e,
          errors: n,
          isLoading: r
        }) {
          var s, i;
          const o = null !== (s = tA[t.layout.height]) && void 0 !== s ? s : tA.md,
            l = null !== (i = eA[t.layout.width]) && void 0 !== i ? i : eA.full,
            A = e && Object.keys(e).length > 0,
            c = !A && n && Object.keys(n).length > 0 && !r,
            d = "metric_card" === t.visualization,
            w = "table" === t.visualization,
            g = t.widgetId.startsWith("pinned_"),
            u = ed.has(t.widgetId),
            [p, b] = (0, j.useState)(!1),
            [h, m] = (0, j.useState)(!1),
            [x, f] = (0, j.useState)(!1);
          return (0, a.jsx)("div", Object.assign({
            className: l
          }, {
            children: (0, a.jsxs)(Ks, Object.assign({
              className: "tw-gap-2 tw-py-4 tw-h-full tw-relative"
            }, {
              children: [(0, a.jsxs)(Vs, Object.assign({
                className: "tw-flex tw-flex-col tw-gap-3"
              }, {
                children: [(0, a.jsxs)("div", Object.assign({
                  className: "tw-flex tw-items-start tw-justify-between tw-gap-2"
                }, {
                  children: [(0, a.jsx)("p", Object.assign({
                    className: d ? "tw-text-[10px] tw-font-medium tw-uppercase tw-tracking-wide tw-text-[rgba(255,255,255,0.35)] tw-m-0" : "tw-text-[15px] tw-font-semibold tw-text-[#e6eaf2] tw-m-0"
                  }, {
                    children: ii(t.title || t.description)
                  })), g && (0, a.jsxs)("div", Object.assign({
                    className: "tw-flex tw-items-center tw-gap-1.5 tw-shrink-0"
                  }, {
                    children: [(0, a.jsx)("span", Object.assign({
                      className: "tw-text-[10px] tw-px-2 tw-py-0.5 tw-rounded-full tw-bg-[rgba(59,130,246,0.15)] tw-text-[rgba(59,130,246,0.8)] tw-font-medium"
                    }, {
                      children: "Pinned by you"
                    })), (0, a.jsx)("button", Object.assign({
                      onClick: () => b(!0),
                      className: "tw-p-0.5 tw-rounded tw-border-0 tw-cursor-pointer tw-text-[rgba(255,255,255,0.25)] hover:tw-text-[rgba(255,255,255,0.6)] hover:tw-bg-[rgba(255,255,255,0.05)] tw-transition-colors tw-bg-transparent",
                      title: "Unpin widget"
                    }, {
                      children: (0, a.jsx)(yr.Z, {
                        className: "tw-w-3.5 tw-h-3.5"
                      })
                    }))]
                  }))]
                })), !d && t.title && t.description && (0, a.jsx)("p", Object.assign({
                  className: "tw-text-xs tw-text-[rgba(255,255,255,0.35)] tw-m-0 tw--mt-1"
                }, {
                  children: oi(t.description)
                })), A ? (0, a.jsxs)(a.Fragment, {
                  children: [(0, a.jsx)(Ni, {
                    visualization: t.visualization,
                    data: e,
                    height: o,
                    useAverage: u,
                    showAggregateChange: ci(t.widgetId)
                  }), !d && !w && (0, a.jsx)(Xc, {
                    data: e,
                    useAverage: u
                  })]
                }) : c ? (0, a.jsx)("div", Object.assign({
                  className: "tw-flex tw-items-center tw-justify-center tw-text-[rgba(255,255,255,0.25)] tw-text-xs",
                  style: {
                    height: o
                  }
                }, {
                  children: "No data available"
                })) : (0, a.jsx)("div", Object.assign({
                  className: "tw-rounded-lg tw-animate-pulse tw-bg-[rgba(255,255,255,0.04)]",
                  style: {
                    height: o
                  }
                }, {
                  children: (0, a.jsxs)("div", Object.assign({
                    className: "tw-flex tw-items-center tw-justify-center tw-h-full tw-gap-2"
                  }, {
                    children: [(0, a.jsx)("div", {
                      className: "tw-w-1.5 tw-h-1.5 tw-rounded-full tw-bg-[rgba(255,255,255,0.15)] tw-animate-bounce",
                      style: {
                        animationDelay: "0ms"
                      }
                    }), (0, a.jsx)("div", {
                      className: "tw-w-1.5 tw-h-1.5 tw-rounded-full tw-bg-[rgba(255,255,255,0.15)] tw-animate-bounce",
                      style: {
                        animationDelay: "150ms"
                      }
                    }), (0, a.jsx)("div", {
                      className: "tw-w-1.5 tw-h-1.5 tw-rounded-full tw-bg-[rgba(255,255,255,0.15)] tw-animate-bounce",
                      style: {
                        animationDelay: "300ms"
                      }
                    })]
                  }))
                })), A && (0, a.jsxs)("button", Object.assign({
                  onClick: () => function(t, e) {
                    const n = Object.keys(e).filter((t => {
                      var n, a;
                      return (null === (a = null === (n = e[t]) || void 0 === n ? void 0 : n.rows) || void 0 === a ? void 0 : a.length) > 0
                    }));
                    if (!n.length) return;
                    const a = e[n[0]].columns,
                      r = "channel" === a[0],
                      s = [];
                    if (r) {
                      const t = a.map((t => t.replace(/_/g, " ")));
                      s.push(["Program", ...t]), n.forEach((t => {
                        const n = Qs[t] || t;
                        e[t].rows.forEach((t => {
                          s.push([n, ...t.map(((t, e) => 0 === e ? $s(String(null != t ? t : "")) : String(null != t ? t : "")))])
                        }))
                      }))
                    } else {
                      const t = a.map((t => t.replace(/_/g, " ")));
                      s.push(["Channel", ...t]), n.forEach((t => {
                        const n = Qs[t] || t;
                        e[t].rows.forEach((t => {
                          s.push([n, ...t.map((t => String(null != t ? t : "")))])
                        }))
                      }))
                    }
                    const i = s.map((t => t.map((t => {
                        const e = String(t);
                        return e.includes(",") || e.includes('"') || e.includes("\n") ? `"${e.replace(/"/g,'""')}"` : e
                      })).join(","))).join("\n"),
                      o = new Blob([i], {
                        type: "text/csv;charset=utf-8;"
                      }),
                      l = URL.createObjectURL(o),
                      A = document.createElement("a");
                    A.href = l, A.download = `${t.replace(/[^a-zA-Z0-9]/g,"_").toLowerCase()}.csv`, A.click(), setTimeout((() => URL.revokeObjectURL(l)), 100)
                  }(t.title || t.description || "export", e),
                  className: "tw-flex tw-items-center tw-gap-1.5 tw-text-[11px] tw-text-[rgba(255,255,255,0.35)] hover:tw-text-[rgba(255,255,255,0.6)] tw-bg-transparent tw-border-0 tw-cursor-pointer tw-p-0 tw-self-start tw-transition-colors"
                }, {
                  children: [(0, a.jsx)(Jc.Z, {
                    className: "tw-w-3 tw-h-3"
                  }), "Export"]
                }))]
              })), p && (0, a.jsx)("div", Object.assign({
                className: "tw-absolute tw-inset-0 tw-bg-[rgba(0,0,0,0.7)] tw-rounded-xl tw-flex tw-items-center tw-justify-center tw-z-10"
              }, {
                children: (0, a.jsxs)("div", Object.assign({
                  className: "tw-flex tw-flex-col tw-items-center tw-gap-3 tw-p-4"
                }, {
                  children: [(0, a.jsx)("p", Object.assign({
                    className: "tw-text-sm tw-text-[#e6eaf2] tw-m-0 tw-text-center"
                  }, {
                    children: "Remove this widget from your dashboard?"
                  })), x && (0, a.jsx)("p", Object.assign({
                    className: "tw-text-xs tw-text-red-400 tw-m-0"
                  }, {
                    children: "Failed to unpin â try again"
                  })), (0, a.jsxs)("div", Object.assign({
                    className: "tw-flex tw-gap-2"
                  }, {
                    children: [(0, a.jsx)("button", Object.assign({
                      onClick: () => b(!1),
                      disabled: h,
                      className: "tw-px-3 tw-py-1.5 tw-rounded-lg tw-text-xs tw-font-medium tw-border tw-border-[rgba(255,255,255,0.15)] tw-text-[rgba(255,255,255,0.6)] tw-bg-transparent tw-cursor-pointer hover:tw-bg-[rgba(255,255,255,0.05)]"
                    }, {
                      children: "Cancel"
                    })), (0, a.jsx)("button", Object.assign({
                      onClick: () => td(this, void 0, void 0, (function*() {
                        m(!0), f(!1);
                        try {
                          (yield function(t, e) {
                            return Ti(this, void 0, void 0, (function*() {
                              return (yield fetch(`${Bi}/ANALYTICS/widgets/${e}/pin`, {
                                method: "DELETE",
                                credentials: "include"
                              })).ok
                            }))
                          }(0, t.widgetId)) ? (window.dispatchEvent(new CustomEvent(Mi.ANALYTICS.WIDGET_PINNED)), b(!1)) : f(!0)
                        } catch (t) {
                          f(!0)
                        } finally {
                          m(!1)
                        }
                      })),
                      disabled: h,
                      className: "tw-px-3 tw-py-1.5 tw-rounded-lg tw-text-xs tw-font-medium tw-border-0 tw-bg-red-500 tw-text-white tw-cursor-pointer hover:tw-bg-red-600"
                    }, {
                      children: h ? "Removing..." : "Remove"
                    }))]
                  }))]
                }))
              }))]
            }))
          }))
        }
        var ad = n(81916);
        const rd = ["Today", "This Week", "Last Week", "This Month", "Last 3 Months"];

        function sd({
          amazonMerchantId: t,
          pageId: e = "analytics"
        }) {
          const [n, r] = (0, j.useState)("This Month"), [s, i] = (0, j.useState)(0);
          (0, j.useEffect)((() => {
            const t = () => i((t => t + 1));
            return window.addEventListener(Mi.ANALYTICS.WIDGET_PINNED, t), () => window.removeEventListener(Mi.ANALYTICS.WIDGET_PINNED, t)
          }), []);
          const o = function(t) {
              const e = new Date,
                n = t => t.toISOString().split("T")[0];
              switch (t) {
                case "Today":
                  return {
                    from: n(e), to: n(e)
                  };
                case "This Week": {
                  const t = new Date(e);
                  return t.setDate(e.getDate() - e.getDay()), {
                    from: n(t),
                    to: n(e)
                  }
                }
                case "Last Week": {
                  const t = new Date(e);
                  t.setDate(e.getDate() - e.getDay() - 1);
                  const a = new Date(t);
                  return a.setDate(t.getDate() - 6), {
                    from: n(a),
                    to: n(t)
                  }
                }
                case "This Month":
                  return {
                    from: n(new Date(e.getFullYear(), e.getMonth(), 1)), to: n(e)
                  };
                case "Last 3 Months": {
                  const t = new Date(e);
                  return t.setMonth(e.getMonth() - 3), {
                    from: n(t),
                    to: n(e)
                  }
                }
                default:
                  return {}
              }
            }(n),
            {
              templates: l,
              widgetData: A,
              errors: c,
              isLoading: d
            } = Ll({
              amazonMerchantId: t,
              pageId: e,
              dateFrom: o.from,
              dateTo: o.to,
              refreshKey: s
            }),
            w = t => t.widgetId.startsWith("pinned_"),
            g = l.filter((t => !w(t))),
            u = l.filter((t => w(t))),
            p = (t, e) => {
              const n = t.layout.order,
                a = e.layout.order;
              return null != n && null != a ? n - a : null != n ? -1 : null != a ? 1 : t.widgetId.localeCompare(e.widgetId)
            },
            b = [...g.sort(p), ...u.sort(p)],
            h = b.filter((t => /MTD/i.test(t.title))),
            m = b.filter((t => !/MTD/i.test(t.title))),
            x = (0, a.jsxs)("div", Object.assign({
              className: "tw-flex tw-items-center tw-gap-3 tw-overflow-x-auto tw-pb-1 tw--mb-1"
            }, {
              children: [(0, a.jsxs)("div", Object.assign({
                className: "tw-flex tw-items-center tw-gap-0.5 tw-rounded-lg tw-border tw-border-[rgba(255,255,255,0.08)] tw-bg-[#00081C] tw-p-0.5 tw-shrink-0"
              }, {
                children: [(0, a.jsx)(ad.Z, {
                  className: "tw-ml-1.5 tw-w-3 tw-h-3 tw-text-[rgba(255,255,255,0.35)]"
                }), rd.map((t => (0, a.jsx)("button", Object.assign({
                  onClick: () => r(t),
                  className: xr("tw-shrink-0 tw-rounded-md tw-px-2.5 tw-py-1 tw-text-[11px] tw-font-medium tw-transition-colors tw-border-0 tw-cursor-pointer", n === t ? "tw-bg-[#00CCBD] tw-text-white" : "tw-text-[rgba(255,255,255,0.35)] hover:tw-bg-[rgba(255,255,255,0.05)] hover:tw-text-[#e6eaf2]")
                }, {
                  children: t
                }), t)))]
              })), d && (0, a.jsx)(Si.Z, {
                className: "tw-w-4 tw-h-4 tw-animate-spin tw-text-[rgba(255,255,255,0.35)]"
              })]
            }));
          return (0, a.jsx)("div", Object.assign({
            className: "tw-flex tw-flex-col tw-gap-6"
          }, {
            children: 0 === l.length && d ? (0, a.jsxs)("div", Object.assign({
              className: "tw-flex tw-flex-col tw-items-center tw-justify-center tw-min-h-[60vh] tw-gap-4"
            }, {
              children: [(0, a.jsx)("div", Object.assign({
                className: "tw-relative tw-w-[400px] tw-h-[4px] tw-bg-[rgba(255,255,255,0.06)] tw-rounded-full tw-overflow-hidden"
              }, {
                children: (0, a.jsx)("div", {
                  className: "tw-absolute tw-h-full tw-w-2/5 tw-rounded-full tw-animate-[sweep_4s_linear_infinite]",
                  style: {
                    background: "linear-gradient(90deg, transparent 0%, rgba(59,130,246,0.05) 30%, rgba(59,130,246,0.3) 70%, #3b82f6 100%)",
                    boxShadow: "4px 0 16px 2px rgba(59,130,246,0.6), 0 0 6px rgba(59,130,246,0.3)"
                  }
                })
              })), (0, a.jsx)("p", Object.assign({
                className: "tw-text-sm tw-text-[rgba(255,255,255,0.3)] tw-m-0"
              }, {
                children: "Loading your analytical dashboards..."
              })), (0, a.jsx)("style", {
                children: "@keyframes sweep { 0% { left: -40%; } 100% { left: 100%; } }"
              })]
            })) : (0, a.jsxs)(a.Fragment, {
              children: [h.length > 0 && (0, a.jsx)("div", Object.assign({
                className: "tw-grid tw-grid-cols-12 tw-gap-3 sm:tw-gap-4"
              }, {
                children: h.map((t => (0, a.jsx)(nd, {
                  template: t,
                  data: A[t.widgetId],
                  errors: c[t.widgetId],
                  isLoading: d
                }, t.widgetId)))
              })), x, m.length > 0 && (0, a.jsx)("div", Object.assign({
                className: "tw-grid tw-grid-cols-12 tw-gap-3 sm:tw-gap-4"
              }, {
                children: m.map((t => (0, a.jsx)(nd, {
                  template: t,
                  data: A[t.widgetId],
                  errors: c[t.widgetId],
                  isLoading: d
                }, t.widgetId)))
              }))]
            })
          }))
        }
        var id = (0, v.Pi)((function() {
            var t;
            const e = null === (t = ln.currentStoreDetails) || void 0 === t ? void 0 : t.storeId;
            return e ? (0, a.jsxs)("div", Object.assign({
              className: "tw-flex tw-flex-col tw-gap-4 sm:tw-gap-6"
            }, {
              children: [(0, a.jsx)(Rl, {
                icon: _r.Z,
                title: "Analytics agent",
                iconColor: "#fb923c"
              }), (0, a.jsx)(sd, {
                amazonMerchantId: e
              })]
            })) : null
          })),
          od = n(54618);
        const ld = [{
            path: "/",
            element: (0, a.jsx)(GA, {}),
            isMatch: t => "/" === t
          }, {
            path: "/accept-invite",
            element: (0, a.jsx)(od.Z, {}),
            isMatch: t => "/accept-invite" === t
          }],
          Ad = (0, S.Pi)((({
            store: t
          }) => {
            const e = (0, N.useLocation)(),
              n = [{
                path: "/error",
                element: (0, a.jsx)(f.Z4, {})
              }, {
                path: "*",
                element: (0, a.jsx)(f.ls, {})
              }],
              r = Object.values(f.Bj),
              s = ld.find((t => t.isMatch(e.pathname)));
            return (0, a.jsx)(N.Routes, {
              children: s ? (0, a.jsx)(N.Route, {
                path: s.path,
                element: s.element
              }) : (0, a.jsxs)(N.Route, Object.assign({
                path: "/",
                element: (0, a.jsx)(Tl, {
                  store: t
                })
              }, {
                children: [(0, a.jsxs)(a.Fragment, {
                  children: [(0, a.jsx)(N.Route, {
                    path: "home",
                    element: (0, a.jsx)(qA, {})
                  }), (0, a.jsx)(N.Route, {
                    path: "inventory",
                    element: (0, a.jsx)(Ac, {})
                  }), (0, a.jsx)(N.Route, {
                    path: "listings",
                    element: (0, a.jsx)(jc, {})
                  }), (0, a.jsx)(N.Route, {
                    path: "shipping",
                    element: (0, a.jsx)(Rc, {})
                  }), (0, a.jsx)(N.Route, {
                    path: "store-builder",
                    element: (0, a.jsx)(Qc, {})
                  }), (0, a.jsx)(N.Route, {
                    path: "analytics-dashboard",
                    element: (0, a.jsx)(id, {})
                  }), (0, a.jsx)(N.Route, {
                    path: "marketing",
                    element: (0, a.jsx)(GA, {})
                  })]
                }), n.map(((t, e) => (0, j.createElement)(N.Route, Object.assign({}, t, {
                  key: e
                })))), null == r ? void 0 : r.map((t => (0, a.jsx)(N.Route, {
                  path: `/${t.path}/*`,
                  element: (0, a.jsx)(f.Qq, {
                    remoteEntryPointUrl: t.remoteUrl,
                    scope: t.scope,
                    module: t.module
                  })
                }, t.key)))]
              }))
            })
          }));
        var cd = n.p + "6b79f7c931d135eec6bc.svg",
          dd = ({
            isCollapsed: t = !0,
            size: e = 18,
            color: n = "#067586"
          }) => (0, a.jsx)("svg", Object.assign({
            width: e,
            height: e,
            viewBox: "0 0 18 18",
            fill: "none",
            xmlns: "http://www.w3.org/2000/svg",
            style: {
              transform: t ? "none" : "scaleX(-1)",
              transition: "transform 0.2s ease"
            }
          }, {
            children: (0, a.jsx)("path", {
              d: "M11.75 0.75V16.75M5.75 6.75L7.75 8.75L5.75 10.75M0.75 2.75C0.75 2.21957 0.960714 1.71086 1.33579 1.33579C1.71086 0.960714 2.21957 0.75 2.75 0.75H14.75C15.2804 0.75 15.7891 0.960714 16.1642 1.33579C16.5393 1.71086 16.75 2.21957 16.75 2.75V14.75C16.75 15.2804 16.5393 15.7891 16.1642 16.1642C15.7891 16.5393 15.2804 16.75 14.75 16.75H2.75C2.21957 16.75 1.71086 16.5393 1.33579 16.1642C0.960714 15.7891 0.75 15.2804 0.75 14.75V2.75Z",
              stroke: n,
              strokeWidth: "1.5",
              strokeLinecap: "round",
              strokeLinejoin: "round"
            })
          }));
        const {
          PRIMARY_HEADER: wd,
          SECONDARY_HEADER: gd
        } = ka, {
          SMARTBIZ: ud,
          GOOGLE_PLAY: pd,
          SECURITY: bd
        } = Ma, {
          DO_MORE_WITH_SMARTBIZ: hd,
          LOGOUT: md
        } = Ia, xd = f.gq.HOME;
        var fd = (0, v.Pi)((({
          mode: t,
          storeDetailsLoader: e
        }) => {
          const n = (0, N.useNavigate)(),
            {
              handleScannerToggle: r,
              setShowSideBar: s
            } = Fe,
            i = (0, _.g0)(),
            {
              isLoading: o
            } = i,
            {
              setHelpMenuToggle: l
            } = it,
            {
              toggle: A,
              isOpen: c
            } = (0, In.b_)(),
            {
              data: d,
              isLoading: w,
              error: g
            } = (0, Re.hl)(),
            u = !!g;
          return (0, a.jsxs)(a.Fragment, {
            children: [(0, a.jsxs)(H.default, Object.assign({
              height: "56px",
              alignmentHorizontal: "justify",
              spacingInset: t === gd ? "none 400 none 500" : ln.isZAIOrchestratorEnabled || ln.isZaiEnabledForOnboarding ? "none 500 none none" : "none 500",
              className: vt
            }, {
              children: [(0, a.jsxs)(H.default, Object.assign({
                alignmentVertical: "center",
                height: "100%"
              }, {
                children: [(ln.isZAIOrchestratorEnabled || ln.isZaiEnabledForOnboarding) && t === wd && (0, a.jsx)("div", Object.assign({
                  style: {
                    width: (Fe.isCollapsed, "54px"),
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    height: "100%",
                    flexShrink: 0
                  }
                }, {
                  children: (0, a.jsx)("button", Object.assign({
                    onClick: () => Fe.toggleCollapsed(),
                    style: {
                      background: "none",
                      border: "none",
                      cursor: "pointer",
                      padding: "4px",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center"
                    },
                    "aria-label": Fe.isCollapsed ? "Expand sidebar" : "Collapse sidebar"
                  }, {
                    children: (0, a.jsx)(dd, {
                      isCollapsed: Fe.isCollapsed
                    })
                  }))
                })), (0, a.jsx)(H.default, Object.assign({
                  width: t === wd && (ln.isZAIOrchestratorEnabled || ln.isZaiEnabledForOnboarding) ? "auto" : t === wd ? "calc(260px - 31px)" : "105px",
                  alignmentVertical: "center",
                  className: Et,
                  height: "100%"
                }, {
                  children: (0, a.jsx)(P.default, Object.assign({
                    onClick: () => {
                      n(xd), s(!0)
                    },
                    type: "icon"
                  }, {
                    children: (0, a.jsx)("img", {
                      src: De,
                      alt: ud
                    })
                  }))
                })), t === gd && (0, a.jsxs)(H.default, Object.assign({
                  alignmentHorizontal: "center",
                  alignmentVertical: "center",
                  spacingInset: "none 300"
                }, {
                  children: [(0, a.jsx)(W.default, Object.assign({
                    type: "b200"
                  }, {
                    children: hd
                  })), (0, a.jsx)(P.default, Object.assign({
                    onClick: r
                  }, {
                    children: (0, a.jsx)("img", {
                      src: cd,
                      alt: pd,
                      width: "106px"
                    })
                  }))]
                }))]
              })), t === gd ? (0, a.jsx)(P.default, Object.assign({
                size: "small",
                onClick: () => {
                  return t = void 0, e = void 0, a = function*() {
                    const t = yield i.mutateAsync();
                    ln.isLoggedOut(), window.location.replace(null == t ? void 0 : t.redirectUrl)
                  }, new((n = void 0) || (n = Promise))((function(r, s) {
                    function i(t) {
                      try {
                        l(a.next(t))
                      } catch (t) {
                        s(t)
                      }
                    }

                    function o(t) {
                      try {
                        l(a.throw(t))
                      } catch (t) {
                        s(t)
                      }
                    }

                    function l(t) {
                      var e;
                      t.done ? r(t.value) : (e = t.value, e instanceof n ? e : new n((function(t) {
                        t(e)
                      }))).then(i, o)
                    }
                    l((a = a.apply(t, e || [])).next())
                  }));
                  var t, e, n, a
                },
                minWidth: "64px"
              }, {
                children: o ? (0, a.jsx)(ke.Z, {
                  size: "small"
                }) : md
              })) : (0, a.jsxs)(H.default, Object.assign({
                alignmentVertical: "center",
                height: "100%"
              }, {
                children: [(0, a.jsx)(H.default, Object.assign({
                  alignmentVertical: "center",
                  spacingInset: "none 450",
                  height: "100%",
                  className: jt
                }, {
                  children: (0, a.jsx)(P.default, Object.assign({
                    onClick: l,
                    type: "icon"
                  }, {
                    children: (0, a.jsx)("img", {
                      src: _e,
                      alt: bd
                    })
                  }))
                })), ln.isZaiChatBotEnabled && (0, a.jsx)(In.Hv, Object.assign({
                  toggled: c,
                  onToggle: A
                }, (ln.isZaiEnabledForOnboarding || ln.isZAIOrchestratorEnabled) && {
                  label: "AZAI Mode",
                  icon: (0, a.jsx)(Gs, {
                    size: 18
                  })
                })), (0, a.jsx)(oa, {
                  isLoading: e || w,
                  CategoriesList: null == d ? void 0 : d.categories,
                  isCategoryError: u,
                  isMenuEnable: !0
                })]
              }))]
            })), (0, a.jsx)(Ta, {})]
          })
        }));
        const vd = t => {
          switch (t) {
            case "catalog":
              return "/catalog/products";
            case "orders":
              return "/orders";
            case "analytics":
              return "/analytics/sales";
            case "reviews":
              return "/reviews/manage";
            case "store configuration":
              return "/store-appearance";
            case "growth":
              return "/offers"
          }
        };
        var jd = (0, v.Pi)((({
            MicroFrontendsKey: t,
            children: e,
            toggleSelectedGroupedSidebar: n,
            selectedGroupedSidebar: r,
            title: s,
            icon: i
          }) => {
            var o, l, A, c, d, w;
            const g = (0, N.useNavigate)(),
              {
                handleChangeActiveProfileDetails: u
              } = it,
              {
                setSidebarToggle: p,
                setParentRoute: b,
                parentRoute: h,
                isCollapsed: m
              } = Fe,
              [x, v] = (0, j.useState)(!0),
              [y, C] = (0, j.useState)(!1),
              O = (0, j.useRef)(null),
              S = (0, j.useRef)(null),
              k = s ? s.toLowerCase() : (0, f.L2)(t),
              I = r === k,
              M = () => k === h,
              T = s || (0, f.Er)(t),
              R = E().Children.count(e) > 0,
              B = () => {
                if (e && !m) {
                  n(k);
                  const t = vd(k);
                  r === k && v((t => !t)), g(t)
                } else if (e && m) {
                  const t = vd(k);
                  t && (b(k), g(t))
                } else {
                  b(k);
                  const e = t ? (0, f.L2)(t) : vd(k) || k;
                  g(e), u(!1), p()
                }
              },
              _ = () => {
                S.current && (clearTimeout(S.current), S.current = null), C(!0)
              },
              D = () => {
                S.current = setTimeout((() => {
                  C(!1)
                }), 200)
              };
            if (m) {
              const t = M();
              return R ? (0, a.jsxs)("div", Object.assign({
                style: {
                  position: "relative"
                },
                onMouseEnter: _,
                onMouseLeave: D,
                ref: O
              }, {
                children: [(0, a.jsx)("div", Object.assign({
                  onClick: B,
                  role: "button",
                  tabIndex: 0,
                  onKeyDown: t => {
                    "Enter" === t.key && B()
                  },
                  style: {
                    display: "flex",
                    justifyContent: "center",
                    alignItems: "center",
                    width: "100%",
                    height: "40px",
                    cursor: "pointer",
                    backgroundColor: t ? "#00A69A" : "transparent",
                    borderRadius: "12px",
                    margin: "2px 0",
                    transition: "background-color 0.15s ease"
                  },
                  onMouseEnter: e => {
                    t || (e.currentTarget.style.backgroundColor = "#00A69A")
                  },
                  onMouseLeave: e => {
                    t || (e.currentTarget.style.backgroundColor = "transparent")
                  }
                }, {
                  children: (0, a.jsx)("img", {
                    src: i,
                    alt: T,
                    width: "20",
                    height: "20"
                  })
                })), y && O.current && (0, jr.createPortal)((0, a.jsxs)("div", Object.assign({
                  onMouseEnter: _,
                  onMouseLeave: D,
                  style: {
                    position: "fixed",
                    left: (null !== (A = null === (l = null === (o = O.current) || void 0 === o ? void 0 : o.getBoundingClientRect()) || void 0 === l ? void 0 : l.right) && void 0 !== A ? A : 0) + 4,
                    top: null !== (w = null === (d = null === (c = O.current) || void 0 === c ? void 0 : c.getBoundingClientRect()) || void 0 === d ? void 0 : d.top) && void 0 !== w ? w : 0,
                    backgroundColor: "#0E2B31",
                    borderRadius: "8px",
                    padding: "8px 0",
                    minWidth: "180px",
                    boxShadow: "0 4px 16px rgba(0,0,0,0.3)",
                    zIndex: 1e4
                  }
                }, {
                  children: [(0, a.jsx)("div", Object.assign({
                    style: {
                      padding: "4px 16px 8px",
                      borderBottom: "1px solid rgba(255,255,255,0.1)",
                      marginBottom: "4px"
                    }
                  }, {
                    children: (0, a.jsx)("span", Object.assign({
                      style: {
                        color: "#fff",
                        fontSize: "13px",
                        fontWeight: 600
                      }
                    }, {
                      children: T
                    }))
                  })), (0, a.jsx)("div", Object.assign({
                    onClick: () => C(!1)
                  }, {
                    children: e
                  }))]
                })), document.body)]
              })) : (0, a.jsx)(La.default, Object.assign({
                position: "end",
                title: T
              }, {
                children: (0, a.jsx)("div", Object.assign({
                  onClick: B,
                  role: "button",
                  tabIndex: 0,
                  onKeyDown: t => {
                    "Enter" === t.key && B()
                  },
                  style: {
                    display: "flex",
                    justifyContent: "center",
                    alignItems: "center",
                    width: "100%",
                    height: "40px",
                    cursor: "pointer",
                    backgroundColor: t ? "#00A69A" : "transparent",
                    borderRadius: "12px",
                    margin: "2px 0",
                    transition: "background-color 0.15s ease"
                  },
                  onMouseEnter: e => {
                    t || (e.currentTarget.style.backgroundColor = "#00A69A")
                  },
                  onMouseLeave: e => {
                    t || (e.currentTarget.style.backgroundColor = "transparent")
                  }
                }, {
                  children: (0, a.jsx)("img", {
                    src: i,
                    alt: T,
                    width: "20",
                    height: "20"
                  })
                }))
              }))
            }
            return (0, a.jsx)(Ue.default, Object.assign({
              tokens: Ua
            }, {
              children: (0, a.jsxs)(Aa.MB, Object.assign({
                onClick: B,
                href: (0, f.L2)(t),
                linkComponents: [Za],
                selected: M(),
                open: I && x
              }, {
                children: [(0, a.jsxs)(H.default, Object.assign({
                  spacing: "300"
                }, {
                  children: [(0, a.jsx)(Ue.default, Object.assign({
                    tokens: Ua
                  }, {
                    children: (0, a.jsx)(W.default, Object.assign({
                      type: "b200",
                      className: _t
                    }, {
                      children: T
                    }))
                  })), (0, a.jsx)("img", {
                    src: i
                  })]
                })), e]
              }))
            }))
          })),
          Ed = function(t, e, n, a) {
            return new(n || (n = Promise))((function(r, s) {
              function i(t) {
                try {
                  l(a.next(t))
                } catch (t) {
                  s(t)
                }
              }

              function o(t) {
                try {
                  l(a.throw(t))
                } catch (t) {
                  s(t)
                }
              }

              function l(t) {
                var e;
                t.done ? r(t.value) : (e = t.value, e instanceof n ? e : new n((function(t) {
                  t(e)
                }))).then(i, o)
              }
              l((a = a.apply(t, e || [])).next())
            }))
          };
        const {
          SMARTBIZ: yd,
          GOOGLE_PLAY: Cd
        } = Ma, Od = "260px", Nd = D.css`
  height: 100%;
  min-height: calc(100vh - 56px);
  display: flex;
  flex-direction: column;
  nav {
    height: 100% !important;
    min-height: calc(100vh - 56px) !important;
    flex: 1;
  }
`, Sd = D.css`
  ${Nd};
  overflow: hidden !important;
  nav {
    width: 54px !important;
    min-width: 54px !important;
    max-width: 54px !important;
    overflow: hidden !important;
  }
  nav > ul {
    padding: 0 4px !important;
    overflow-x: hidden !important;
    overflow-y: auto !important;
  }
  /* Reset Meridian SideMenuLink internal padding for collapsed mode */
  nav > ul > li > a,
  nav > ul > li > button {
    padding-left: 0 !important;
    padding-right: 0 !important;
    display: flex !important;
    justify-content: center !important;
  }
`, kd = D.css`
  ${Nd};
`;
        var Id = (0, v.Pi)((({
            showMobileView: t
          }) => {
            const [e, n] = (0, j.useState)(), [r, s] = (0, j.useState)(null), [i, o] = (0, j.useState)(null), [l, A] = (0, j.useState)(!0), [c, d] = (0, j.useState)(!1), [w, g] = (0, j.useState)(!1), u = (0, N.useNavigate)(), p = (0, N.useLocation)(), {
              handleChangeActiveProfileDetails: b
            } = it, {
              INVENTORY_ENABLED_STATUS: h,
              RTO_REDUCTION_SUITE_ENABLED_STATUS: m
            } = f.FeatureFlags, {
              isCollapsed: x
            } = Fe;
            (0, j.useEffect)((() => {
              Ed(void 0, void 0, void 0, (function*() {
                const t = yield(0, _.tx)();
                if ("SUCCESS" === (null == t ? void 0 : t.successCode)) {
                  const e = (0, _.NU)(null == t ? void 0 : t.data);
                  localStorage.setItem("storeURI", null == e ? void 0 : e.storeURI), o(t), (null == e ? void 0 : e.shopOwnership) === Ga.PRIMARY ? A(!0) : (null == e ? void 0 : e.shopOwnership) === Ga.SECONDARY && A(!1)
                }
              })), E()
            }), []), (0, j.useEffect)((() => {
              Ed(void 0, void 0, void 0, (function*() {
                var t;
                const e = (0, _.NU)(null == i ? void 0 : i.data),
                  n = null === (t = null == e ? void 0 : e.storeConfig) || void 0 === t ? void 0 : t.videoCommerceOnboardingStatus,
                  a = null == Ba ? void 0 : Ba.includes(n);
                s(a)
              }))
            }), [i]), (0, j.useEffect)((() => {
              (() => {
                var t, a;
                const r = p.pathname.split("/");
                if ("" === r[r.length - 1] && r[r.length - 2] !== pa && r.pop(), 2 === r.length && Sa.includes(r[1])) Fe.setParentRoute(r[1]), Fe.setChildRoute(""), n("");
                else {
                  let s = r.slice(1).reverse().find((t => Na.some((e => e.includes(t))))) || "";
                  Number.isNaN(Number(s)) || (s = ""), Fe.setChildRoute(s);
                  const i = null === (a = null === (t = Na.find((t => t.includes(s)))) || void 0 === t ? void 0 : t[0]) || void 0 === a ? void 0 : a.toLowerCase();
                  i && Fe.setParentRoute(i), e === i || n(i)
                }
              })()
            }), [p.pathname]), (0, j.useEffect)((() => {
              null === r && null === l || (() => {
                const t = Object.values(f.Bj).find((t => {
                    var e;
                    return Fe.childRoute === t.path || (null === (e = Fe.childRoute) || void 0 === e ? void 0 : e.length) > 0 && t.path.endsWith(Fe.childRoute)
                  })),
                  a = (null == t ? void 0 : t.path) === f.Bj[f.rv.VIDEO_COMMERCE].path,
                  s = (null == t ? void 0 : t.path) === f.Bj[f.rv.GOOGLE_ANALYTICS].path,
                  i = (null == t ? void 0 : t.path) === f.Bj[f.rv.USER_MANAGEMENT].path;
                ("" === Fe.parentRoute && !t || a && !l && !r || s && !l || i && !Fe.isUserManagementEnabled) && (console.warn("Feature not available, navigating to home..."), u(f.Bj[f.rv.HOME].path));
                const o = e === Fe.parentRoute;
                Fe.parentRoute.length > 0 && Fe.childRoute.length > 0 && (o || n(Fe.parentRoute))
              })()
            }), [r, l]);
            const v = t => {
                n(t)
              },
              E = () => Ed(void 0, void 0, void 0, (function*() {
                const t = yield(0, f.aH)(), e = yield(0, f.Ic)(h.flagName, h.defaultValue, t);
                d(e);
                const n = yield(0, f.Ic)(m.flagName, m.defaultValue, t);
                g(n)
              })),
              y = () => (0, a.jsx)(z.Z, Object.assign({
                width: "100%",
                spacingInset: x ? "400 200" : "400 450"
              }, {
                children: (0, a.jsx)(U.Z, {})
              }));
            (0, j.useEffect)((() => {
              window.addEventListener("HIDE_SIDE_BAR", (t => {
                const e = t.detail;
                Fe.setShowSideBar(!e.hideSideBar)
              }))
            }));
            const C = x ? "54px" : Od;
            return (0, a.jsx)(Ue.default, Object.assign({
              tokens: {
                dividerColor: "#E7E9E9"
              }
            }, {
              children: Fe.showSideBar && (0, a.jsx)(Ue.default, Object.assign({
                tokens: za
              }, {
                children: (0, a.jsx)("div", Object.assign({
                  className: t ? void 0 : x ? Sd : kd
                }, {
                  children: (0, a.jsxs)(Aa.ZP, Object.assign({
                    width: t ? Od : C,
                    type: t ? "overlay" : "skinny",
                    open: !t || Fe.sidebarToggle
                  }, t && {
                    onClose: Fe.setSidebarToggle
                  }, {
                    linkComponents: [jd, Za, Aa.MB, y],
                    backgroundColor: "surface"
                  }, {
                    children: [t && (0, a.jsx)(Aa.xc, Object.assign({
                      onClick: () => {
                        const t = (0, f.L2)(f.rv.HOME);
                        u(t), b(!1), Fe.setSidebarToggle()
                      }
                    }, {
                      children: (0, a.jsx)("img", {
                        width: "74px",
                        height: "30px",
                        src: ca,
                        alt: yd
                      })
                    })), (0, a.jsx)(jd, {
                      MicroFrontendsKey: f.rv.HOME,
                      icon: Ya
                    }), (0, a.jsxs)(jd, Object.assign({
                      MicroFrontendsKey: f.rv.CATALOG,
                      selectedGroupedSidebar: e,
                      toggleSelectedGroupedSidebar: v,
                      icon: Wa
                    }, {
                      children: [(0, a.jsx)(Za, {
                        parentMicrofrontendKey: f.rv.CATALOG,
                        subModuleKey: f.aP[f.rv.CATALOG].PRODUCTS
                      }), (0, a.jsx)(Za, {
                        parentMicrofrontendKey: f.rv.CATALOG,
                        subModuleKey: f.aP[f.rv.CATALOG].CATEGORIES
                      }), c && (0, a.jsx)(Za, {
                        parentMicrofrontendKey: f.rv.CATALOG,
                        subModuleKey: f.aP[f.rv.CATALOG].INVENTORY
                      }), (0, a.jsx)(Za, {
                        parentMicrofrontendKey: f.rv.CATALOG,
                        subModuleKey: f.aP[f.rv.CATALOG].COLLECTIONS
                      })]
                    })), (0, a.jsxs)(jd, Object.assign({
                      MicroFrontendsKey: f.rv.OMS_MODULE,
                      selectedGroupedSidebar: e,
                      toggleSelectedGroupedSidebar: v,
                      icon: Ka
                    }, {
                      children: [(0, a.jsx)(Za, {
                        parentMicrofrontendKey: f.rv.OMS_MODULE,
                        subModuleKey: f.aP[f.rv.OMS_MODULE].ALL_ORDERS
                      }), (0, a.jsx)(Za, {
                        parentMicrofrontendKey: f.rv.OMS_MODULE,
                        subModuleKey: f.aP[f.rv.OMS_MODULE].RETURNS
                      })]
                    })), (0, a.jsxs)(jd, Object.assign({
                      MicroFrontendsKey: f.rv.ANALYTICS,
                      icon: Va,
                      selectedGroupedSidebar: e,
                      toggleSelectedGroupedSidebar: v
                    }, {
                      children: [(0, a.jsx)(Za, {
                        parentMicrofrontendKey: f.rv.ANALYTICS,
                        subModuleKey: f.aP[f.rv.ANALYTICS].SALES
                      }), (0, a.jsx)(Za, {
                        parentMicrofrontendKey: f.rv.ANALYTICS,
                        subModuleKey: f.aP[f.rv.ANALYTICS].TRAFFIC
                      }), (0, a.jsx)(Za, {
                        parentMicrofrontendKey: f.rv.ANALYTICS,
                        subModuleKey: f.aP[f.rv.ANALYTICS].OPERATIONS
                      }), Fe.isCustomerSegmentsEnabled && (0, a.jsx)(Za, {
                        parentMicrofrontendKey: f.rv.ANALYTICS,
                        subModuleKey: f.aP[f.rv.ANALYTICS].CUSTOMER_SEGMENTS
                      }), (0, a.jsx)(Za, {
                        parentMicrofrontendKey: f.rv.ANALYTICS,
                        subModuleKey: f.aP[f.rv.ANALYTICS].REPORTS
                      })]
                    })), Fe.isReviewsEnabled && (0, a.jsx)(jd, Object.assign({
                      MicroFrontendsKey: f.rv.REVIEWS,
                      icon: $a,
                      selectedGroupedSidebar: e,
                      toggleSelectedGroupedSidebar: v
                    }, {
                      children: (0, a.jsx)(Za, {
                        parentMicrofrontendKey: f.rv.REVIEWS,
                        subModuleKey: f.aP[f.rv.REVIEWS].MANAGE
                      })
                    })), (0, a.jsx)(y, {}), (0, a.jsxs)(jd, Object.assign({
                      title: ha,
                      selectedGroupedSidebar: e,
                      toggleSelectedGroupedSidebar: v,
                      icon: qa
                    }, {
                      children: [(0, a.jsx)(Za, {
                        subModuleKey: f.Bj[f.rv.WEBSITE_APPEARANCE].name,
                        subModulePath: f.Bj[f.rv.WEBSITE_APPEARANCE].path
                      }), l && (0, a.jsx)(Za, {
                        subModuleKey: f.Bj[f.rv.GOOGLE_ANALYTICS].name,
                        subModulePath: f.Bj[f.rv.GOOGLE_ANALYTICS].path,
                        isNewFeature: !0
                      })]
                    })), (0, a.jsxs)(jd, Object.assign({
                      title: ma,
                      selectedGroupedSidebar: e,
                      toggleSelectedGroupedSidebar: v,
                      icon: Qa
                    }, {
                      children: [(0, a.jsx)(Za, {
                        subModuleKey: f.Bj[f.rv.OFFERS].name,
                        subModulePath: f.Bj[f.rv.OFFERS].path
                      }), Fe.isBasketBuildingEnabled && (0, a.jsx)(Za, {
                        subModuleKey: f.Bj[f.rv.BASKET_BUILDING].name,
                        subModulePath: f.Bj[f.rv.BASKET_BUILDING].path,
                        isNewFeature: !0
                      }), (0, a.jsx)(Za, {
                        subModuleKey: f.Bj[f.rv.PERFORMANCE_MARKETING].name,
                        subModulePath: f.Bj[f.rv.PERFORMANCE_MARKETING].path
                      }), f.gO.isSEOFeatureEnabled && (0, a.jsx)(Za, {
                        subModuleKey: f.Bj[f.rv.SEO].name,
                        subModulePath: f.Bj[f.rv.SEO].path
                      }), r && l && (0, a.jsx)(Za, {
                        subModuleKey: f.Bj[f.rv.VIDEO_COMMERCE].name,
                        subModulePath: f.Bj[f.rv.VIDEO_COMMERCE].path
                      }), f.gO.isMAFeatureEnabled && l && (0, a.jsx)(Za, {
                        subModuleKey: f.Bj[f.rv.MARKETING_AUTOMATION].name,
                        subModulePath: f.Bj[f.rv.MARKETING_AUTOMATION].path
                      }), (0, a.jsx)(Za, {
                        subModuleKey: fa,
                        subModulePath: va,
                        isNotAvailableInDesktop: !0
                      })]
                    })), (0, a.jsx)(jd, Object.assign({
                      title: xa,
                      selectedGroupedSidebar: e,
                      toggleSelectedGroupedSidebar: v,
                      icon: Xa
                    }, {
                      children: (0, a.jsx)(Za, {
                        subModuleKey: ja,
                        subModulePath: Ea,
                        isNotAvailableInDesktop: !0
                      })
                    })), it.isWhatsAppChatBotFeatureEnabled && (0, a.jsxs)(jd, Object.assign({
                      title: ya,
                      selectedGroupedSidebar: e,
                      toggleSelectedGroupedSidebar: v,
                      icon: er
                    }, {
                      children: [(0, a.jsx)(Za, {
                        subModuleKey: Ca,
                        handleCustomOnClick: () => {
                          (null === window || void 0 === window ? void 0 : window.zE) && (it.isChatBotMessengerActive ? (window.zE("messenger", "close"), it.setIsChatBotMessengerActive(!1)) : (window.zE("messenger", "open"), it.setIsChatBotMessengerActive(!0)))
                        },
                        isNotAvailableInDesktop: !1
                      }), (0, a.jsx)(Za, {
                        subModuleKey: Oa,
                        handleCustomOnClick: () => {
                          he(`https://api.whatsapp.com/send?phone=${ge}`, "_blank")
                        },
                        isNotAvailableInDesktop: !1
                      })]
                    })), w && (0, a.jsx)(jd, {
                      MicroFrontendsKey: f.rv.RTO_REDUCTION,
                      icon: tr
                    }), (0, a.jsx)(jd, {
                      MicroFrontendsKey: f.rv.SETTINGS,
                      icon: Ja
                    }), !x && (0, a.jsx)(Ta, {})]
                  }))
                }))
              }))
            }))
          })),
          Md = t => (0, O.useQuery)(["agreement"], (() => {
            return t = void 0, e = void 0, a = function*() {
              return (yield pe.get("api-db/resources/v2/dashboard/agreement/")).data
            }, new((n = void 0) || (n = Promise))((function(r, s) {
              function i(t) {
                try {
                  l(a.next(t))
                } catch (t) {
                  s(t)
                }
              }

              function o(t) {
                try {
                  l(a.throw(t))
                } catch (t) {
                  s(t)
                }
              }

              function l(t) {
                var e;
                t.done ? r(t.value) : (e = t.value, e instanceof n ? e : new n((function(t) {
                  t(e)
                }))).then(i, o)
              }
              l((a = a.apply(t, e || [])).next())
            }));
            var t, e, n, a
          }), {
            enabled: t,
            retry: !1
          }),
          Td = function(t, e, n, a) {
            return new(n || (n = Promise))((function(r, s) {
              function i(t) {
                try {
                  l(a.next(t))
                } catch (t) {
                  s(t)
                }
              }

              function o(t) {
                try {
                  l(a.throw(t))
                } catch (t) {
                  s(t)
                }
              }

              function l(t) {
                var e;
                t.done ? r(t.value) : (e = t.value, e instanceof n ? e : new n((function(t) {
                  t(e)
                }))).then(i, o)
              }
              l((a = a.apply(t, e || [])).next())
            }))
          };
        const Rd = "agreement-acceptance-wrapper",
          Bd = ["https:", "http:"],
          _d = t => {
            if (t) try {
              const e = new URL(t, window.location.origin);
              Bd.includes(e.protocol) ? window.location.replace(e.href) : window.location.replace("/")
            } catch (t) {
              window.location.replace("/")
            } else window.location.replace("/")
          };
        var Dd = (0, v.Pi)((() => {
            const {
              agreementAccepted: t
            } = ln, [e, n] = (0, j.useState)(!1), r = (0, _.g0)(), s = (0, j.useRef)(!1), i = (0, j.useRef)(null), o = (0, j.useRef)(!1), l = (0, j.useRef)(null), A = !t, {
              data: c
            } = Md(A);
            return (0, j.useLayoutEffect)((() => () => {
              var t;
              s.current = !0, null === (t = i.current) || void 0 === t || t.disconnect()
            }), [A]), (0, j.useEffect)((() => {
              var t;
              if (!A) return void(o.current = !1);
              s.current = !1, l.current = null, o.current = !1, i.current = new MutationObserver((t => {
                var e, n, a;
                if (!s.current)
                  if (o.current) t.some((t => t.removedNodes.length > 0)) && (document.getElementById(Rd) && (null === (n = l.current) || void 0 === n ? void 0 : n.isConnected) || (s.current = !0, null === (a = i.current) || void 0 === a || a.disconnect(), r.mutateAsync().then((t => {
                    _d(null == t ? void 0 : t.redirectUrl)
                  })).catch((() => {
                    window.location.replace("/")
                  }))));
                  else {
                    const t = document.getElementById(Rd),
                      n = document.querySelector("[data-agreement-modal]"),
                      a = null !== (e = null == n ? void 0 : n.closest('[role="dialog"]')) && void 0 !== e ? e : null;
                    t && a && (l.current = a, a.style.borderRadius = "12px", o.current = !0)
                  }
              })), i.current.observe(document.body, {
                childList: !0,
                subtree: !0
              });
              const e = document.getElementById(Rd),
                n = document.querySelector("[data-agreement-modal]"),
                a = null !== (t = null == n ? void 0 : n.closest('[role="dialog"]')) && void 0 !== t ? t : null;
              return e && a && (l.current = a, a.style.borderRadius = "12px", o.current = !0), () => {
                var t;
                null === (t = i.current) || void 0 === t || t.disconnect()
              }
            }), [A]), A ? (0, a.jsx)("div", Object.assign({
              id: Rd
            }, {
              children: (0, a.jsx)(dn.ZP, Object.assign({
                open: A,
                scrollContainer: "modal",
                width: "650px"
              }, {
                children: (0, a.jsx)("div", Object.assign({
                  "data-agreement-modal": !0
                }, {
                  children: (0, a.jsxs)(z.Z, Object.assign({
                    spacing: "400",
                    spacingInset: "400"
                  }, {
                    children: [(0, a.jsx)(cn.Z, Object.assign({
                      level: 3
                    }, {
                      children: "We've updated our terms"
                    })), (0, a.jsxs)(W.default, Object.assign({
                      type: "b300",
                      color: "secondary"
                    }, {
                      children: ["Please accept the updated Terms & Conditions in the", " ", (0, a.jsx)(Z.Z, Object.assign({
                        type: "secondary",
                        href: "https://support.smartbiz.in/assets/html/SmartBiz-Merchant-Agreement.html",
                        target: "_blank",
                        rel: "noopener noreferrer"
                      }, {
                        children: "Merchant Agreement"
                      })), " ", "to keep using your account."]
                    })), (0, a.jsxs)("div", Object.assign({
                      style: {
                        display: "flex",
                        gap: "16px",
                        width: "100%"
                      }
                    }, {
                      children: [(0, a.jsx)("div", Object.assign({
                        style: {
                          flex: 1
                        }
                      }, {
                        children: (0, a.jsx)(P.default, Object.assign({
                          type: "secondary",
                          onClick: () => Td(void 0, void 0, void 0, (function*() {
                            s.current = !0;
                            try {
                              const t = yield r.mutateAsync();
                              _d(null == t ? void 0 : t.redirectUrl)
                            } catch (t) {
                              window.location.replace("/")
                            }
                          })),
                          disabled: e || r.isLoading,
                          minWidth: "100%"
                        }, {
                          children: r.isLoading ? (0, a.jsx)(ke.Z, {
                            size: "small"
                          }) : "Logout"
                        }))
                      })), (0, a.jsx)("div", Object.assign({
                        style: {
                          flex: 1
                        }
                      }, {
                        children: (0, a.jsx)(P.default, Object.assign({
                          type: "primary",
                          onClick: () => Td(void 0, void 0, void 0, (function*() {
                            var t, e, a, o, A, d;
                            if (null == c ? void 0 : c.agreementId) {
                              n(!0);
                              try {
                                s.current = !0, yield(w = c.agreementId, a = void 0, o = void 0, A = void 0, d = function*() {
                                  yield pe.post(`api-db/resources/v2/dashboard/agreement/${w}/accept`)
                                }, new(A || (A = Promise))((function(t, e) {
                                  function n(t) {
                                    try {
                                      s(d.next(t))
                                    } catch (t) {
                                      e(t)
                                    }
                                  }

                                  function r(t) {
                                    try {
                                      s(d.throw(t))
                                    } catch (t) {
                                      e(t)
                                    }
                                  }

                                  function s(e) {
                                    var a;
                                    e.done ? t(e.value) : (a = e.value, a instanceof A ? a : new A((function(t) {
                                      t(a)
                                    }))).then(n, r)
                                  }
                                  s((d = d.apply(a, o || [])).next())
                                }))), ln.setAgreementAccepted(!0)
                              } catch (n) {
                                s.current = !1, document.getElementById(Rd) && (null === (t = l.current) || void 0 === t ? void 0 : t.isConnected) || (s.current = !0, null === (e = i.current) || void 0 === e || e.disconnect(), r.mutateAsync().then((t => {
                                  _d(null == t ? void 0 : t.redirectUrl)
                                })).catch((() => {
                                  window.location.replace("/")
                                })))
                              } finally {
                                n(!1)
                              }
                              var w
                            }
                          })),
                          disabled: e || r.isLoading,
                          minWidth: "100%"
                        }, {
                          children: e ? (0, a.jsx)(ke.Z, {
                            size: "small"
                          }) : "Accept"
                        }))
                      }))]
                    }))]
                  }))
                }))
              }))
            })) : null
          })),
          Ld = function(t, e, n, a) {
            return new(n || (n = Promise))((function(r, s) {
              function i(t) {
                try {
                  l(a.next(t))
                } catch (t) {
                  s(t)
                }
              }

              function o(t) {
                try {
                  l(a.throw(t))
                } catch (t) {
                  s(t)
                }
              }

              function l(t) {
                var e;
                t.done ? r(t.value) : (e = t.value, e instanceof n ? e : new n((function(t) {
                  t(e)
                }))).then(i, o)
              }
              l((a = a.apply(t, e || [])).next())
            }))
          };
        const {
          UAM_ENABLED_STATUS: Fd,
          SEO_ENABLED_STATUS: Pd,
          CUSTOMER_SEGMENTS_ENABLED_STATUS: zd,
          MA_ENABLED_STATUS: Ud,
          REVIEWS_ENABLED_STATUS: Gd,
          BASKET_BUILDING_ENABLED_STATUS: Zd,
          MERCHANT_AGREEMENT_ENABLED_STATUS: Hd
        } = f.FeatureFlags, {
          PRIMARY_HEADER: Yd,
          SECONDARY_HEADER: Wd
        } = ka;
        var Kd = (0, v.Pi)((function(t) {
          var e, n;
          (0, D.css)({
            position: "relative",
            display: "flex",
            flexDirection: "row"
          });
          const r = (0, D.css)({
              display: "flex",
              height: "100vh"
            }),
            s = (0, D.css)({
              flex: 1,
              minWidth: 0,
              transition: "flex 0.3s ease-in-out, width 0.3s ease-in-out",
              position: "relative",
              overflowY: "auto"
            }),
            {
              store: i
            } = t,
            o = (0, N.useLocation)(),
            l = (0, D.css)({
              position: "relative",
              display: "flex",
              flexDirection: "row"
            }),
            A = (0, N.useNavigate)(),
            c = (0, _.SS)(),
            {
              isGetShopLoader: d,
              handleIsGetShopLoader: w,
              currentStoreDetails: g,
              handleCurrentStoreDetails: u,
              handleAllStoreDetails: p
            } = ln,
            [b, h] = (0, j.useState)(!1),
            [m, x] = (0, j.useState)(!1),
            [v, y] = (0, j.useState)(!0),
            [C, O] = (0, j.useState)(!1),
            [S, k] = (0, j.useState)(!1),
            I = (0, _.OQ)(),
            P = new URLSearchParams(o.search).get("storeOnboarded"),
            [z, U] = (0, j.useState)(!1),
            {
              data: G,
              isLoading: Z,
              refetch: H
            } = (0, B.ZP)(!0),
            {
              data: Y,
              refetch: W
            } = As(),
            [K, V] = (0, j.useState)(!0),
            {
              refetch: $
            } = bs(),
            {
              data: q
            } = Es("CATALOG_SYNC"),
            Q = new URLSearchParams(window.location.search),
            X = (null === (e = Q.get("spapi_oauth_code")) || void 0 === e ? void 0 : e.length) > 0,
            tt = (null === (n = Q.get("selling_partner_id")) || void 0 === n ? void 0 : n.length) > 0;
          X && tt && (sessionStorage.setItem("spapiOauthCode", Q.get("spapi_oauth_code")), sessionStorage.setItem("sellingPartnerId", Q.get("selling_partner_id")));
          const et = () => Ld(this, void 0, void 0, (function*() {
              var t, e, n, a, r, s;
              const i = yield $(), o = "NOT_RESPONDED" === (null === (t = null == i ? void 0 : i.data) || void 0 === t ? void 0 : t.responseStatus) && (null === (n = null === (e = null == i ? void 0 : i.data) || void 0 === e ? void 0 : e.questions) || void 0 === n ? void 0 : n.length) > 0, l = "COMPLETED" === (null === (s = null === (r = null === (a = null == q ? void 0 : q.marketplaceConnectorTaskStatuses) || void 0 === a ? void 0 : a[0]) || void 0 === r ? void 0 : r.statusDetails) || void 0 === s ? void 0 : s.status);
              U(!(!o || l))
            })),
            nt = t => {
              const e = t.detail;
              A(null == e ? void 0 : e.key)
            };
          (0, j.useEffect)((() => {
            if (null == G ? void 0 : G.data) {
              p(null == G ? void 0 : G.data);
              const t = null == G ? void 0 : G.data,
                e = (0, _.NU)(t);
              e && u(e)
            }
          }), [null == G ? void 0 : G.data]), (0, j.useEffect)((() => {
            window.addEventListener("HIDE_SIDE_BAR", (t => {
              const e = t.detail;
              V(!e.hideSideBar)
            }))
          }));
          const at = () => Ld(this, void 0, void 0, (function*() {
              window.location.hostname === J ? (L.Z.remove("x-acbin", {
                domain: ".amazon.in"
              }), L.Z.remove("ubid-acbin", {
                domain: ".amazon.in"
              }), L.Z.remove("posSessionId", {
                domain: ".amazon.in"
              }), L.Z.remove("userId", {
                domain: ".amazon.in"
              })) : (L.Z.remove("x-tacbin", {
                domain: ".amazon.com"
              }), L.Z.remove("ubid-tacbin", {
                domain: ".amazon.com"
              }), L.Z.remove("posSessionId", {
                domain: ".amazon.com"
              }), L.Z.remove("userId", {
                domain: ".amazon.in"
              })), localStorage.clear(), yield I.mutateAsync().then((t => {
                let e = null == t ? void 0 : t.redirectUrl;
                if ("true" === Q.get("azai") && e) try {
                  const t = new URL(e),
                    n = t.searchParams.get("openid.return_to");
                  if (n) {
                    const a = new URL(n);
                    a.searchParams.set("azai", "true"), t.searchParams.set("openid.return_to", a.toString()), e = t.toString()
                  }
                } catch (t) {}
                console.log("Redirect URL with QP", new URL(e)), window.location.replace(e)
              })).catch((() => {
                x(!0)
              }))
            })),
            st = () => Ld(this, void 0, void 0, (function*() {
              yield it(), ln.isLogged(), H(), W(), ot(), lt(), At(), ct(), dt(), wt(), gt(), ut(), yield pt(), yield bt(), ht(), O(!0)
            }));
          (0, j.useEffect)((() => (f.mE.track(f.MixPanelEventName.HOME_URL_VISIT, {
            [fs.Hr]: (0, fs.lJ)()
          }), window.addEventListener("CHANGE_PATH", nt), P && localStorage.setItem("isStoreOnboarded", "true"), (0, _.gU)(), localStorage.getItem("x-tacbin") ? (null === localStorage.getItem("isUserLoggedInEventTracked") && (f.mE.track(f.MixPanelEventName.LOGIN, {
            [fs.Hr]: (0, fs.lJ)()
          }), localStorage.setItem("isUserLoggedInEventTracked", "true")), st()) : (f.mE.track(f.MixPanelEventName.AUTH_PAGE_VISIT, {
            [fs.Hr]: (0, fs.lJ)()
          }), at()), () => {
            window.removeEventListener("CHANGE_PATH", nt)
          })), []);
          const it = () => Ld(this, void 0, void 0, (function*() {
              w(!0), yield c.mutateAsync().then((t => {
                et(), w(!1), ln.shopSelectionResponse = t, f.mE.track(f.MixPanelEventName.VALID_TOKEN, {
                  [fs.Hr]: (0, fs.lJ)()
                })
              })).catch((t => {
                var e, n, a, r, s, i;
                (null === (n = null === (e = null == t ? void 0 : t.response) || void 0 === e ? void 0 : e.data) || void 0 === n ? void 0 : n.error) === wr || (null === (r = null === (a = null == t ? void 0 : t.response) || void 0 === a ? void 0 : a.data) || void 0 === r ? void 0 : r.errorCode) === pr ? (h(!0), null === localStorage.getItem("isSignUpEventTracked") && (f.mE.track("signup"), localStorage.setItem("isSignUpEventTracked", "true")), (!X || !tt) && A((0, $t.vM)("/store-onboarding")), w(!1)) : (null === (i = null === (s = null == t ? void 0 : t.response) || void 0 === s ? void 0 : s.data) || void 0 === i ? void 0 : i.error) === gr ? (localStorage.clear(), at(), w(!1)) : (null == t ? void 0 : t.code) === ur ? w(!1) : (w(!1), at())
              }))
            })),
            ot = () => Ld(this, void 0, void 0, (function*() {
              const t = yield(0, f.aH)();
              Fe.setIsUserManagementEnabled(yield(0, f.Ic)(Fd.flagName, Fd.defaultValue, t))
            })),
            lt = () => Ld(this, void 0, void 0, (function*() {
              const t = yield(0, f.aH)(), e = yield(0, f.Ic)(Pd.flagName, Pd.defaultValue, t);
              f.gO.setIsSEOFeatureEnabled(e)
            })),
            At = () => Ld(this, void 0, void 0, (function*() {
              const t = yield(0, f.aH)(), e = yield(0, f.Ic)(zd.flagName, zd.defaultValue, t);
              Fe.setIsCustomerSegmentsEnabled(e)
            })),
            ct = () => Ld(this, void 0, void 0, (function*() {
              const t = yield(0, f.aH)(), e = yield(0, f.Ic)(Ud.flagName, Ud.defaultValue, t);
              f.gO.setIsMAFeatureEnabled(e)
            })),
            dt = () => Ld(this, void 0, void 0, (function*() {
              const t = yield(0, f.aH)(), e = yield(0, f.Ic)(Gd.flagName, Gd.defaultValue, t);
              Fe.setIsReviewsEnabled(e)
            })),
            wt = () => Ld(this, void 0, void 0, (function*() {
              const t = yield(0, f.aH)(), e = yield(0, f.Ic)(Zd.flagName, Zd.defaultValue, t);
              Fe.setIsBasketBuildingEnabled(e)
            })),
            gt = () => Ld(this, void 0, void 0, (function*() {
              const t = yield(0, f.aH)(), e = yield(0, f.Ic)(Hd.flagName, Hd.defaultValue, t);
              k(e)
            })),
            ut = () => Ld(this, void 0, void 0, (function*() {
              const t = yield(0, f.aH)(), e = yield(0, f.Ic)(f.FeatureFlags.ZAI_CHAT_BOT_ENABLED_STATUS.flagName, f.FeatureFlags.ZAI_CHAT_BOT_ENABLED_STATUS.defaultValue, t);
              ln.setIsZaiChatBotEnabled(e)
            })),
            pt = () => Ld(this, void 0, void 0, (function*() {
              const t = yield(0, f.aH)(), e = yield(0, f.Ic)(f.FeatureFlags.ZAI_ORCHESTRATOR_ENABLED_STATUS.flagName, f.FeatureFlags.ZAI_ORCHESTRATOR_ENABLED_STATUS.defaultValue, t);
              ln.setIsZAIOrchestratorEnabled(e)
            })),
            bt = () => Ld(this, void 0, void 0, (function*() {
              const t = yield ps();
              rt((null == t ? void 0 : t.email) || "", null == t ? void 0 : t.mobileNumber) && ln.setIsZaiEnabledForOnboarding(!0)
            })),
            ht = () => Ld(this, void 0, void 0, (function*() {
              const t = yield ps();
              void 0 !== (null == t ? void 0 : t.agreementAccepted) && ln.setAgreementAccepted(t.agreementAccepted)
            })),
            mt = o.pathname.startsWith("/store-onboarding") && (b || X || tt),
            xt = E().useMemo((() => ln.isZAIOrchestratorEnabled ? new Gi : new Fi), [ln.isZAIOrchestratorEnabled]),
            ft = E().useMemo((() => mo(A)), [A]),
            vt = E().useMemo((() => fo(A)), [A]),
            jt = E().useMemo((() => Eo(A)), [A]),
            Et = E().useMemo((() => No()), []);
          ol();
          const {
            isListening: yt
          } = Ji({
            enableLogging: !0,
            onThemeReviewDetails: ft.handleThemeReview,
            onCatalogReview: vt.handleCatalogReview,
            onImageReview: vt.handleImageReview,
            onPageRedirection: jt.handlePageRedirection,
            onStoreIdReceived: Et.handleStoreIdReceived
          }), {
            config: Ct
          } = (0, $t.R6)(), Ot = Ct.renSdkStreamUrl, Nt = E().useMemo((() => (0, a.jsx)(Zo, {})), []);
          return (0, a.jsxs)(In.$U, Object.assign({
            baseUrl: Ot,
            headers: {
              Cookie: (window.location.hostname, (0, $t.Xd)())
            },
            agentId: "Zai",
            storeId: null == g ? void 0 : g.storeId,
            storeName: null == g ? void 0 : g.storeURI,
            defaultOpen: !0,
            runId: void 0,
            fileUploadService: xt,
            disclaimerContent: Nt,
            agentType: ln.isZaiEnabledForOnboarding || ln.isZAIOrchestratorEnabled ? "ZAI" : null,
            logo: ln.isZaiEnabledForOnboarding || ln.isZAIOrchestratorEnabled ? (0, a.jsx)(Gs, {
              size: 24
            }) : null,
            headerLogo: ln.isZaiEnabledForOnboarding || ln.isZAIOrchestratorEnabled ? (0, a.jsx)(Gs, {
              size: 30
            }) : void 0,
            chatbotName: ln.isZaiEnabledForOnboarding || ln.isZAIOrchestratorEnabled ? "AZAI" : void 0,
            suggestionCards: ln.isZaiEnabledForOnboarding || ln.isZAIOrchestratorEnabled ? [(0, a.jsx)($o, {}, "cro-score"), (0, a.jsx)(Jo, {
              text: "Review Meta Ads performace"
            }, "marketing"), (0, a.jsx)(Jo, {
              text: "I want to create my brand website"
            }, "brand-website"), (0, a.jsx)(Jo, {
              text: "Do I need any 3rd party tools to set up delivery?"
            }, "delivery")] : []
          }, {
            children: [localStorage.getItem("isStoreOnboarded") && v && (0, a.jsx)(xs, {
              handleClose: () => {
                window.history.replaceState({}, "", window.location.pathname), y(!1), localStorage.removeItem("isStoreOnboarded")
              },
              showModal: v,
              heading: "Congratulations",
              description: "Your online store is successfully created"
            }), !ln.isZaiEnabledForOnboarding && (0, a.jsx)(F.Ix, {}), C && !d ? (0, a.jsx)(R.default, Object.assign({
              query: "max-width",
              props: {
                showMobileView: {
                  default: !1,
                  [An]: !0
                }
              }
            }, {
              children: ({
                showMobileView: t
              }) => (0, a.jsxs)(a.Fragment, {
                children: [(0, a.jsx)("div", Object.assign({
                  className: r
                }, {
                  children: (0, a.jsx)("div", Object.assign({
                    className: s
                  }, {
                    children: (0, a.jsxs)(M.ZP, Object.assign({
                      mainClassName: Mt,
                      headerComponent: mt ? null : t ? dr : fd,
                      sidebarComponent: mt || t ? null : ln.isZAIOrchestratorEnabled ? Id : sr
                    }, {
                      children: [mt || t || mt || !K ? null : (0, a.jsx)(fd, {
                        mode: mt ? Wd : Yd,
                        storeDetailsLoader: Z
                      }), mt ? null : t ? (0, a.jsx)(dr, {
                        mode: mt ? Wd : Yd,
                        storeDetailsLoader: Z
                      }) : ln.isZAIOrchestratorEnabled || ln.isZaiEnabledForOnboarding ? (0, a.jsx)(Id, {
                        showMobileView: t
                      }) : (0, a.jsx)(sr, {
                        showMobileView: t
                      }), (0, a.jsxs)(T.default, Object.assign({
                        className: l,
                        width: "100%",
                        height: "100%"
                      }, {
                        children: [(0, a.jsxs)("div", Object.assign({
                          className: s
                        }, {
                          children: [z && !ln.isZaiEnabledForOnboarding && (0, a.jsx)(ds, {
                            setShowBusinessDetailsModal: U
                          }), (!mt || !ln.isZaiEnabledForOnboarding) && (0, a.jsx)(N.Outlet, {})]
                        })), (ln.isZaiChatBotEnabled || ln.isZaiEnabledForOnboarding) && !t && (0, a.jsx)(Ys, {})]
                      }))]
                    }))
                  }))
                })), S && !mt && (0, a.jsx)(Dd, {})]
              })
            })) : (0, a.jsx)(br, {
              error: m
            }), (0, a.jsx)(Se, {}), (0, a.jsx)(f.CM, {
              toasterAlignmentHorizontal: "end"
            }), (0, a.jsx)(Is, {})]
          }))
        }));
        const Vd = [{
            path: "/",
            element: (0, a.jsx)((() => ((0, j.useEffect)((() => {
              window.location.replace(ce)
            }), []), (0, a.jsx)("div", {}))), {}),
            isMatch: t => "/" === t
          }, {
            path: "/accept-invite",
            element: (0, a.jsx)(od.Z, {}),
            isMatch: t => "/accept-invite" === t
          }],
          $d = (0, S.Pi)((({
            store: t
          }) => {
            const e = (0, N.useLocation)(),
              n = [{
                path: "/error",
                element: (0, a.jsx)(f.Z4, {})
              }, {
                path: "*",
                element: (0, a.jsx)(f.ls, {})
              }],
              r = Object.values(f.Bj),
              s = Vd.find((t => t.isMatch(e.pathname)));
            return (0, a.jsx)(N.Routes, {
              children: s ? (0, a.jsx)(N.Route, {
                path: s.path,
                element: s.element
              }) : (0, a.jsxs)(N.Route, Object.assign({
                path: "/",
                element: (0, a.jsx)(Kd, {
                  store: t
                })
              }, {
                children: [n.map(((t, e) => (0, j.createElement)(N.Route, Object.assign({}, t, {
                  key: e
                })))), null == r ? void 0 : r.map((t => (0, a.jsx)(N.Route, {
                  path: `/${t.path}/*`,
                  element: (0, a.jsx)(f.Qq, {
                    remoteEntryPointUrl: t.remoteUrl,
                    scope: t.scope,
                    module: t.module
                  })
                }, t.key)))]
              }))
            })
          }));
        var qd = n(82776);
        "beta-smartbiz-seller.corp.amazon.com" !== m.MZ && m.MZ !== J || qd.Z.init({
          DEVELOPMENT: "qqu83svzr9",
          ALPHA: "qqu83svzr9",
          BETA: "qqu83svzr9",
          GAMMA: "qqu83svzr9",
          PROD: "qoqnuziygq"
        } [tt[m.MZ]]), (0, x.Q)();
        const Qd = (0, f.Ok)(),
          Xd = y.createRoot(document.getElementById("root")),
          Jd = new O.QueryClient;
        "true" === new URLSearchParams(window.location.search).get("azai") && ln.setIsZaiEnabledForOnboarding(!0);
        const tw = (0, v.Pi)((() => ln.isZAIOrchestratorEnabled || ln.isZaiEnabledForOnboarding ? (0, a.jsx)(Ad, {
          store: ln
        }) : (0, a.jsx)($d, {
          store: ln
        })));
        var ew;
        Xd.render((0, a.jsx)(E().StrictMode, {
          children: (0, a.jsx)(C.SV, Object.assign({
            fallback: (0, a.jsx)(a.Fragment, {}),
            onError: t => {
              window.location.hostname === J && (null == Qd || Qd.recordError(t)), (0, x.h)(t)
            }
          }, {
            children: (0, a.jsxs)(O.QueryClientProvider, Object.assign({
              client: Jd
            }, {
              children: [(0, a.jsx)(N.BrowserRouter, {
                children: (0, a.jsx)(tw, {})
              }), (0, a.jsx)(f.CM, {
                toasterAlignmentHorizontal: "end"
              })]
            }))
          }))
        })), ew && ew instanceof Function && n.e(131).then(n.bind(n, 82131)).then((({
          getCLS: t,
          getFID: e,
          getFCP: n,
          getLCP: a,
          getTTFB: r
        }) => {
          t(ew), e(ew), n(ew), a(ew), r(ew)
        }))
      }
    },
    i = {};

  function o(t) {
    var e = i[t];
    if (void 0 !== e) return e.exports;
    var n = i[t] = {
      id: t,
      loaded: !1,
      exports: {}
    };
    return s[t].call(n.exports, n, n.exports, o), n.loaded = !0, n.exports
  }
  o.m = s, o.c = i, o.amdO = {}, t = [], o.O = function(e, n, a, r) {
      if (!n) {
        var s = 1 / 0;
        for (c = 0; c < t.length; c++) {
          n = t[c][0], a = t[c][1], r = t[c][2];
          for (var i = !0, l = 0; l < n.length; l++)(!1 & r || s >= r) && Object.keys(o.O).every((function(t) {
            return o.O[t](n[l])
          })) ? n.splice(l--, 1) : (i = !1, r < s && (s = r));
          if (i) {
            t.splice(c--, 1);
            var A = a();
            void 0 !== A && (e = A)
          }
        }
        return e
      }
      r = r || 0;
      for (var c = t.length; c > 0 && t[c - 1][2] > r; c--) t[c] = t[c - 1];
      t[c] = [n, a, r]
    }, o.n = function(t) {
      var e = t && t.__esModule ? function() {
        return t.default
      } : function() {
        return t
      };
      return o.d(e, {
        a: e
      }), e
    }, n = Object.getPrototypeOf ? function(t) {
      return Object.getPrototypeOf(t)
    } : function(t) {
      return t.__proto__
    }, o.t = function(t, a) {
      if (1 & a && (t = this(t)), 8 & a) return t;
      if ("object" == typeof t && t) {
        if (4 & a && t.__esModule) return t;
        if (16 & a && "function" == typeof t.then) return t
      }
      var r = Object.create(null);
      o.r(r);
      var s = {};
      e = e || [null, n({}), n([]), n(n)];
      for (var i = 2 & a && t;
        "object" == typeof i && !~e.indexOf(i); i = n(i)) Object.getOwnPropertyNames(i).forEach((function(e) {
        s[e] = function() {
          return t[e]
        }
      }));
      return s.default = function() {
        return t
      }, o.d(r, s), r
    }, o.d = function(t, e) {
      for (var n in e) o.o(e, n) && !o.o(t, n) && Object.defineProperty(t, n, {
        enumerable: !0,
        get: e[n]
      })
    }, o.f = {}, o.e = function(t) {
      return Promise.all(Object.keys(o.f).reduce((function(e, n) {
        return o.f[n](t, e), e
      }), []))
    }, o.u = function(t) {
      return t + "." + t + "." + o.h() + ".js"
    }, o.h = function() {
      return "4cbdde0b4986c2c9d1d8"
    }, o.g = function() {
      if ("object" == typeof globalThis) return globalThis;
      try {
        return this || new Function("return this")()
      } catch (t) {
        if ("object" == typeof window) return window
      }
    }(), o.o = function(t, e) {
      return Object.prototype.hasOwnProperty.call(t, e)
    }, a = {}, r = "@amzn/RangoliSellerDesktopCoreReact:", o.l = function(t, e, n, s) {
      if (a[t]) a[t].push(e);
      else {
        var i, l;
        if (void 0 !== n)
          for (var A = document.getElementsByTagName("script"), c = 0; c < A.length; c++) {
            var d = A[c];
            if (d.getAttribute("src") == t || d.getAttribute("data-webpack") == r + n) {
              i = d;
              break
            }
          }
        i || (l = !0, (i = document.createElement("script")).charset = "utf-8", i.timeout = 120, o.nc && i.setAttribute("nonce", o.nc), i.setAttribute("data-webpack", r + n), i.src = t), a[t] = [e];
        var w = function(e, n) {
            i.onerror = i.onload = null, clearTimeout(g);
            var r = a[t];
            if (delete a[t], i.parentNode && i.parentNode.removeChild(i), r && r.forEach((function(t) {
                return t(n)
              })), e) return e(n)
          },
          g = setTimeout(w.bind(null, void 0, {
            type: "timeout",
            target: i
          }), 12e4);
        i.onerror = w.bind(null, i.onerror), i.onload = w.bind(null, i.onload), l && document.head.appendChild(i)
      }
    }, o.r = function(t) {
      "undefined" != typeof Symbol && Symbol.toStringTag && Object.defineProperty(t, Symbol.toStringTag, {
        value: "Module"
      }), Object.defineProperty(t, "__esModule", {
        value: !0
      })
    }, o.nmd = function(t) {
      return t.paths = [], t.children || (t.children = []), t
    },
    function() {
      o.S = {};
      var t = {},
        e = {};
      o.I = function(n, a) {
        a || (a = []);
        var r = e[n];
        if (r || (r = e[n] = {}), !(a.indexOf(r) >= 0)) {
          if (a.push(r), t[n]) return t[n];
          o.o(o.S, n) || (o.S[n] = {});
          var s = o.S[n],
            i = "@amzn/RangoliSellerDesktopCoreReact",
            l = function(t, e, n, a) {
              var r = s[t] = s[t] || {},
                o = r[e];
              (!o || !o.loaded && (!a != !o.eager ? a : i > o.from)) && (r[e] = {
                get: n,
                from: i,
                eager: !!a
              })
            },
            A = [];
          return "default" === n && (l("react-dom", "18.2.0", (function() {
            return function() {
              return o(73935)
            }
          }), 1), l("react-router-dom", "6.11.2", (function() {
            return function() {
              return o(49818)
            }
          }), 1), l("react", "18.2.0", (function() {
            return function() {
              return o(67294)
            }
          }), 1)), t[n] = A.length ? Promise.all(A).then((function() {
            return t[n] = 1
          })) : 1
        }
      }
    }(),
    function() {
      var t;
      o.g.importScripts && (t = o.g.location + "");
      var e = o.g.document;
      if (!t && e && (e.currentScript && (t = e.currentScript.src), !t)) {
        var n = e.getElementsByTagName("script");
        if (n.length)
          for (var a = n.length - 1; a > -1 && !t;) t = n[a--].src
      }
      if (!t) throw new Error("Automatic publicPath is not supported in this browser");
      t = t.replace(/#.*$/, "").replace(/\?.*$/, "").replace(/\/[^\/]+$/, "/"), o.p = t
    }(),
    function() {
      var t = function(t) {
          var e = function(t) {
              return t.split(".").map((function(t) {
                return +t == t ? +t : t
              }))
            },
            n = /^([^-+]+)?(?:-([^+]+))?(?:\+(.+))?$/.exec(t),
            a = n[1] ? e(n[1]) : [];
          return n[2] && (a.length++, a.push.apply(a, e(n[2]))), n[3] && (a.push([]), a.push.apply(a, e(n[3]))), a
        },
        e = function(t) {
          var n = t[0],
            a = "";
          if (1 === t.length) return "*";
          if (n + .5) {
            a += 0 == n ? ">=" : -1 == n ? "<" : 1 == n ? "^" : 2 == n ? "~" : n > 0 ? "=" : "!=";
            for (var r = 1, s = 1; s < t.length; s++) r--, a += "u" == (typeof(o = t[s]))[0] ? "-" : (r > 0 ? "." : "") + (r = 2, o);
            return a
          }
          var i = [];
          for (s = 1; s < t.length; s++) {
            var o = t[s];
            i.push(0 === o ? "not(" + l() + ")" : 1 === o ? "(" + l() + " || " + l() + ")" : 2 === o ? i.pop() + " " + i.pop() : e(o))
          }
          return l();

          function l() {
            return i.pop().replace(/^\((.+)\)$/, "$1")
          }
        },
        n = function(e, a) {
          if (0 in e) {
            a = t(a);
            var r = e[0],
              s = r < 0;
            s && (r = -r - 1);
            for (var i = 0, o = 1, l = !0;; o++, i++) {
              var A, c, d = o < e.length ? (typeof e[o])[0] : "";
              if (i >= a.length || "o" == (c = (typeof(A = a[i]))[0])) return !l || ("u" == d ? o > r && !s : "" == d != s);
              if ("u" == c) {
                if (!l || "u" != d) return !1
              } else if (l)
                if (d == c)
                  if (o <= r) {
                    if (A != e[o]) return !1
                  } else {
                    if (s ? A > e[o] : A < e[o]) return !1;
                    A != e[o] && (l = !1)
                  }
              else if ("s" != d && "n" != d) {
                if (s || o <= r) return !1;
                l = !1, o--
              } else {
                if (o <= r || c < d != s) return !1;
                l = !1
              } else "s" != d && "n" != d && (l = !1, o--)
            }
          }
          var w = [],
            g = w.pop.bind(w);
          for (i = 1; i < e.length; i++) {
            var u = e[i];
            w.push(1 == u ? g() | g() : 2 == u ? g() & g() : u ? n(u, a) : !g())
          }
          return !!g()
        },
        a = function(e, n) {
          var a = e[n];
          return Object.keys(a).reduce((function(e, n) {
            return !e || !a[e].loaded && function(e, n) {
              e = t(e), n = t(n);
              for (var a = 0;;) {
                if (a >= e.length) return a < n.length && "u" != (typeof n[a])[0];
                var r = e[a],
                  s = (typeof r)[0];
                if (a >= n.length) return "u" == s;
                var i = n[a],
                  o = (typeof i)[0];
                if (s != o) return "o" == s && "n" == o || "s" == o || "u" == s;
                if ("o" != s && "u" != s && r != i) return r < i;
                a++
              }
            }(e, n) ? n : e
          }), 0)
        },
        r = function(t, r, o, l) {
          var A = a(t, o);
          return n(l, A) || s(function(t, n, a, r) {
            return "Unsatisfied version " + a + " from " + (a && t[n][a].from) + " of shared singleton module " + n + " (required " + e(r) + ")"
          }(t, o, A, l)), i(t[o][A])
        },
        s = function(t) {
          "undefined" != typeof console && console.warn && console.warn(t)
        },
        i = function(t) {
          return t.loaded = 1, t.get()
        },
        l = function(t) {
          return function(e, n, a, r) {
            var s = o.I(e);
            return s && s.then ? s.then(t.bind(t, e, o.S[e], n, a, r)) : t(e, o.S[e], n, a, r)
          }
        }((function(t, e, n, a, s) {
          return e && o.o(e, n) ? r(e, 0, n, a) : s()
        })),
        A = {},
        c = {
          75166: function() {
            return l("default", "react", [1, 18, 2, 0], (function() {
              return function() {
                return o(67294)
              }
            }))
          },
          25773: function() {
            return l("default", "react-dom", [1, 18, 2, 0], (function() {
              return function() {
                return o(73935)
              }
            }))
          },
          60377: function() {
            return l("default", "react-router-dom", [1, 6, 11, 2], (function() {
              return function() {
                return o(49818)
              }
            }))
          }
        };
      [75166, 25773, 60377].forEach((function(t) {
        o.m[t] = function(e) {
          A[t] = 0, delete o.c[t];
          var n = c[t]();
          if ("function" != typeof n) throw new Error("Shared module is not available for eager consumption: " + t);
          e.exports = n()
        }
      }));
      var d = {};
      o.f.consumes = function(t, e) {
        o.o(d, t) && d[t].forEach((function(t) {
          if (o.o(A, t)) return e.push(A[t]);
          var n = function(e) {
              A[t] = 0, o.m[t] = function(n) {
                delete o.c[t], n.exports = e()
              }
            },
            a = function(e) {
              delete A[t], o.m[t] = function(n) {
                throw delete o.c[t], e
              }
            };
          try {
            var r = c[t]();
            r.then ? e.push(A[t] = r.then(n).catch(a)) : n(r)
          } catch (t) {
            a(t)
          }
        }))
      }
    }(),
    function() {
      o.b = document.baseURI || self.location.href;
      var t = {
        179: 0
      };
      o.f.j = function(e, n) {
        var a = o.o(t, e) ? t[e] : void 0;
        if (0 !== a)
          if (a) n.push(a[2]);
          else {
            var r = new Promise((function(n, r) {
              a = t[e] = [n, r]
            }));
            n.push(a[2] = r);
            var s = o.p + o.u(e),
              i = new Error;
            o.l(s, (function(n) {
              if (o.o(t, e) && (0 !== (a = t[e]) && (t[e] = void 0), a)) {
                var r = n && ("load" === n.type ? "missing" : n.type),
                  s = n && n.target && n.target.src;
                i.message = "Loading chunk " + e + " failed.\n(" + r + ": " + s + ")", i.name = "ChunkLoadError", i.type = r, i.request = s, a[1](i)
              }
            }), "chunk-" + e, e)
          }
      }, o.O.j = function(e) {
        return 0 === t[e]
      };
      var e = function(e, n) {
          var a, r, s = n[0],
            i = n[1],
            l = n[2],
            A = 0;
          if (s.some((function(e) {
              return 0 !== t[e]
            }))) {
            for (a in i) o.o(i, a) && (o.m[a] = i[a]);
            if (l) var c = l(o)
          }
          for (e && e(n); A < s.length; A++) r = s[A], o.o(t, r) && t[r] && t[r][0](), t[r] = 0;
          return o.O(c)
        },
        n = self.webpackChunk_amzn_RangoliSellerDesktopCoreReact = self.webpackChunk_amzn_RangoliSellerDesktopCoreReact || [];
      n.forEach(e.bind(null, 0)), n.push = e.bind(null, n.push.bind(n))
    }(), o.nc = void 0;
  var l = o.O(void 0, [338], (function() {
    return o(80170)
  }));
  l = o.O(l)
}();
//# sourceMappingURL=sourcemaps/main.bundle.4cbdde0b4986c2c9d1d8.js.map